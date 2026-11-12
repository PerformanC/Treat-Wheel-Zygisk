/* TODO: Format with proper coding style */
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <async_safe/log.h>
#include <api/system_properties.h>

#include "system_properties.h"
#include "private/bionic_futex.h"
#include "private/bionic_defs.h"

static system_properties sys_props;

__BIONIC_WEAK_VARIABLE_FOR_NATIVE_BRIDGE prop_area *__system_property_area__ = NULL;

#define SERIAL_DIRTY(s) ((s) & 1)
#define SERIAL_VALUE_LEN(s) ((s) >> 24)

/* INFO: Bump serial and wake waiters */
static void bump_serial(contexts *ctx) {
  prop_area *pa = contexts_get_serial_prop_area(ctx);
  atomic_store_explicit(prop_area_get_serial(pa),
    atomic_load_explicit(prop_area_get_serial(pa), memory_order_relaxed) + 1,
    memory_order_release);
  __futex_wake(prop_area_get_serial(pa), INT32_MAX);
}

typedef struct {
  uint32_t sought;
  uint32_t current;
  const prop_info *result;
} find_nth_state;

static void find_nth_cb(const prop_info *pi, void *cookie) {
  find_nth_state *s = cookie;
  if (s->current++ == s->sought) s->result = pi;
}

static uint32_t read_value(system_properties *self, const prop_info *pi, char *value) {
  uint32_t ns = atomic_load_explicit((atomic_uint_least32_t *)&pi->serial, memory_order_acquire);

  for (;;) {
    uint32_t s = ns;
    unsigned len = SERIAL_VALUE_LEN(s);

    if (__predict_false(SERIAL_DIRTY(s))) {
      prop_area *pa = contexts_get_prop_area_for_name(self->ctx, pi->name);
      if (!pa) return s;
      memcpy(value, prop_area_dirty_backup_area(pa), len + 1);
    } else {
      memcpy(value, pi->value_un.value, len + 1);
    }

    atomic_thread_fence(memory_order_acquire);
    ns = atomic_load_explicit((atomic_uint_least32_t *)&pi->serial, memory_order_relaxed);
    if (__predict_true(s == ns)) break;
    atomic_thread_fence(memory_order_acquire);
  }

  return ns;
}

bool system_properties_init(system_properties *self, const char *filename) {
  int saved = errno;

  if (self->initialized) {
    if (self->ctx) contexts_reset_access(self->ctx);
    errno = saved;
    return true;
  }

  if (strlen(filename) >= PROP_FILENAME_MAX) {
    errno = saved;
    return false;
  }

  strcpy(self->property_filename, filename);

  struct stat st;
  if (stat(self->property_filename, &st) == 0 && S_ISDIR(st.st_mode)) {
    if (access("/dev/__properties__/property_info", R_OK) == 0) {
      contexts_serialized_init(&self->contexts_data.serialized);
      self->ctx = &self->contexts_data.serialized.base;
    } else {
      contexts_split_init(&self->contexts_data.split);
      self->ctx = &self->contexts_data.split.base;
    }
  } else {
    contexts_pre_split_init(&self->contexts_data.pre_split);
    self->ctx = &self->contexts_data.pre_split.base;
  }

  if (!contexts_initialize(self->ctx, false, self->property_filename, NULL)) {
    errno = saved;
    return false;
  }

  self->initialized = true;
  errno = saved;
  return true;
}

bool system_properties_area_init(system_properties *self, const char *filename, bool *ff) {
  int saved = errno;

  if (strlen(filename) >= PROP_FILENAME_MAX) {
    errno = saved;
    return false;
  }

  strcpy(self->property_filename, filename);

  contexts_serialized_init(&self->contexts_data.serialized);
  self->ctx = &self->contexts_data.serialized.base;

  if (!contexts_initialize(self->ctx, true, self->property_filename, ff)) {
    errno = saved;
    return false;
  }

  self->initialized = true;
  errno = saved;
  return true;
}

uint32_t system_properties_area_serial(system_properties *self) {
  if (!self->initialized) return (uint32_t)-1;

  prop_area *pa = contexts_get_serial_prop_area(self->ctx);
  if (!pa) return (uint32_t)-1;

  return atomic_load_explicit(prop_area_get_serial(pa), memory_order_acquire);
}

const prop_info *system_properties_find(system_properties *self, const char *name) {
  if (!self->initialized) return NULL;

  prop_area *pa = contexts_get_prop_area_for_name(self->ctx, name);
  if (!pa) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "Access denied finding \"%s\"", name);
    return NULL;
  }

  return prop_area_find(pa, name);
}

int system_properties_read(system_properties *self, const prop_info *pi, char *name, char *value) {
  uint32_t serial = read_value(self, pi, value);

  if (name) {
    size_t nl = strlcpy(name, pi->name, PROP_NAME_MAX);
    if (nl >= PROP_NAME_MAX) {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
        "Name \"%s\" truncated in __system_property_read", pi->name);
    }
  }

  if (!strncmp(pi->name, "ro.", 3) && prop_info_is_long(pi)) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
      "The property \"%s\" is too large for __system_property_get()/__system_property_read(); use __system_property_read_callback() instead.",
      pi->name);
  }

  return (int)SERIAL_VALUE_LEN(serial);
}

void system_properties_read_callback(system_properties *self, const prop_info *pi,
  void (*cb)(void *, const char *, const char *, uint32_t), void *cookie) {
  if (!strncmp(pi->name, "ro.", 3)) {
    uint32_t s = atomic_load_explicit((atomic_uint_least32_t *)&pi->serial, memory_order_relaxed);
    const char *val = prop_info_is_long(pi) ? prop_info_long_value(pi) : pi->value_un.value;
    cb(cookie, pi->name, val, s);
    return;
  }

  char buf[PROP_VALUE_MAX];
  uint32_t s = read_value(self, pi, buf);
  cb(cookie, pi->name, buf, s);
}

int system_properties_get(system_properties *self, const char *name, char *value) {
  const prop_info *pi = system_properties_find(self, name);
  if (pi) return system_properties_read(self, pi, NULL, value);

  value[0] = 0;
  return 0;
}

int system_properties_update(system_properties *self, prop_info *pi, const char *value, unsigned int len) {
  if (!self->initialized || !self->ctx->rw || !pi || len >= PROP_VALUE_MAX) return -1;
  if (prop_info_is_long(pi)) return -1;

  prop_area *serial_pa = contexts_get_serial_prop_area(self->ctx);
  if (!serial_pa) return -1;

  prop_area *pa = contexts_get_prop_area_for_name(self->ctx, pi->name);
  if (!pa) return -1;

  uint32_t serial = atomic_load_explicit(&pi->serial, memory_order_relaxed);
  unsigned int old_len = SERIAL_VALUE_LEN(serial);

  memcpy(prop_area_dirty_backup_area(pa), pi->value_un.value, old_len + 1);

  atomic_thread_fence(memory_order_release);
  serial |= 1;
  atomic_store_explicit(&pi->serial, serial, memory_order_relaxed);

  strncpy(pi->value_un.value, value, PROP_VALUE_MAX);

  atomic_thread_fence(memory_order_release);
  if (!strncmp(pi->name, "ro.", 3)) {
    atomic_store_explicit(&pi->serial, (len << 24), memory_order_relaxed);
  } else {
    atomic_store_explicit(&pi->serial, (len << 24) | ((serial + 1) & 0xffffff), memory_order_relaxed);
  }

  /* INFO: Clear the dirty backup area to not have any leftovers */
  memset(prop_area_dirty_backup_area(pa), 0, PROP_VALUE_MAX);

  __futex_wake(&pi->serial, INT32_MAX);

  bump_serial(self->ctx);

  return 0;
}

int system_properties_add(system_properties *self, const char *name, unsigned int namelen, const char *value, unsigned int valuelen) {
  if (!self->initialized || !self->ctx->rw) return -1;
  if (valuelen >= PROP_VALUE_MAX && strncmp(name, "ro.", 3)) return -1;
  if (namelen < 1) return -1;

  prop_area *serial_pa = contexts_get_serial_prop_area(self->ctx);
  if (!serial_pa) return -1;

  prop_area *pa = contexts_get_prop_area_for_name(self->ctx, name);
  if (!pa) return -1;

  if (!prop_area_add(pa, name, namelen, value, valuelen)) return -1;

  bump_serial(self->ctx);

  return 0;
}

int system_properties_delete(system_properties *self, const char *name, bool prune) {
  if (!self->initialized || !self->ctx->rw) return -1;

  prop_area *serial_pa = contexts_get_serial_prop_area(self->ctx);
  if (!serial_pa) return -1;

  prop_area *pa = contexts_get_prop_area_for_name(self->ctx, name);
  if (!pa) return -1;

  if (!prop_area_remove(pa, name, prune)) return -1;

  bump_serial(self->ctx);

  return 0;
}

bool system_properties_compact(system_properties *self) {
  if (!self->initialized || !self->ctx->rw) return false;


  prop_area *serial_pa = contexts_get_serial_prop_area(self->ctx);
  if (!serial_pa) return false;

  if (!contexts_compact(self->ctx)) return false;

  bump_serial(self->ctx);

  return true;
}

bool system_properties_compact_context(system_properties *self, const char *context) {
  if (!self->initialized || !self->ctx->rw) return false;

  if (!context || !*context) return system_properties_compact(self);


  prop_area *serial_pa = contexts_get_serial_prop_area(self->ctx);
  if (!serial_pa) return false;

  bool found;
  bool ret = contexts_compact_context(self->ctx, context, &found);

  if (found && ret) {
    bump_serial(self->ctx);
  }

  return found && ret;
}

const char *system_properties_get_context(system_properties *self, const char *name) {
  if (!self->initialized) return NULL;
  return contexts_get_context_for_name(self->ctx, name);
}

int system_properties_foreach(system_properties *self, void (*fn)(const prop_info *, void *), void *cookie) {
  if (!self->initialized) return -1;
  contexts_for_each(self->ctx, fn, cookie);
  return 0;
}

const prop_info *system_properties_find_nth(system_properties *self, unsigned n) {
  find_nth_state s = { n, 0, NULL };
  system_properties_foreach(self, find_nth_cb, &s);
  return s.result;
}

bool system_properties_wait(system_properties *self, const prop_info *pi, uint32_t old_serial,
  uint32_t *new_serial, const struct timespec *rel_timeout) {
  atomic_uint_least32_t *sp = pi
    ? (atomic_uint_least32_t *)&pi->serial
    : prop_area_get_serial(contexts_get_serial_prop_area(self->ctx));

  uint32_t ns;
  do {
    if (__futex_wait(sp, old_serial, rel_timeout) == -ETIMEDOUT) return false;
    ns = atomic_load_explicit(sp, memory_order_acquire);
  } while (ns == old_serial);

  *new_serial = ns;
  return true;
}

uint32_t system_properties_wait_any(system_properties *self, uint32_t old_serial) {
  uint32_t ns;
  system_properties_wait(self, NULL, old_serial, &ns, NULL);
  return ns;
}

/* INFO: Public API wrappers */

__BIONIC_WEAK_FOR_NATIVE_BRIDGE int __system_properties_init(void) {
  return system_properties_init(&sys_props, PROP_FILENAME) ? 0 : -1;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE int __system_property_area_init(void) {
  bool ff;
  return system_properties_area_init(&sys_props, PROP_FILENAME, &ff) && !ff ? 0 : -1;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE uint32_t __system_property_area_serial(void) {
  return system_properties_area_serial(&sys_props);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE const prop_info *__system_property_find(const char *n) {
  return system_properties_find(&sys_props, n);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE prop_area *__system_property_get_area(const char *n) {
  return contexts_get_prop_area_for_name(sys_props.ctx, n);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE struct Contexts *__system_property_get_contexts(void) {
  return (struct Contexts *)sys_props.ctx;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE int __system_property_read(const prop_info *pi, char *n, char *v) {
  return system_properties_read(&sys_props, pi, n, v);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE void __system_property_read_callback(const prop_info *pi,
  void (*cb)(void *, const char *, const char *, uint32_t), void *c) {
  system_properties_read_callback(&sys_props, pi, cb, c);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE int __system_property_get(const char *n, char *v) {
  return system_properties_get(&sys_props, n, v);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE int __system_property_update(prop_info *pi, const char *v, unsigned int l) {
  return system_properties_update(&sys_props, pi, v, l);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE int __system_property_delete(const char *n, bool p) {
  return system_properties_delete(&sys_props, n, p);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE bool __system_property_compact(void) {
  return system_properties_compact(&sys_props);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE bool __system_property_compact_context(const char *c) {
  return system_properties_compact_context(&sys_props, c);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE const char *__system_property_get_context(const char *n) {
  return system_properties_get_context(&sys_props, n);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE int __system_property_add(const char *n, unsigned int nl, const char *v, unsigned int vl) {
  return system_properties_add(&sys_props, n, nl, v, vl);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE uint32_t __system_property_serial(const prop_info *pi) {
  return atomic_load_explicit(&pi->serial, memory_order_acquire);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE uint32_t __system_property_wait_any(uint32_t o) {
  return system_properties_wait_any(&sys_props, o);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE bool __system_property_wait(const prop_info *pi, uint32_t os, uint32_t *ns, const struct timespec *rt) {
  return system_properties_wait(&sys_props, pi, os, ns, rt);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE const prop_info *__system_property_find_nth(unsigned n) {
  return system_properties_find_nth(&sys_props, n);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE int __system_property_foreach(void (*fn)(const prop_info *, void *), void *c) {
  return system_properties_foreach(&sys_props, fn, c);
}
