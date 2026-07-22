/* TODO: Format with proper coding style */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <async_safe/log.h>

#include "system_properties.h"

/* INFO: Constants */
static const size_t PA_SIZE = 128 * 1024;
static const uint32_t PA_MAGIC = 0x504f5250;
static const uint32_t PA_VERSION = 0xfc6ed0ab;

static size_t pa_size = 0;
static size_t pa_data_size = 0;

/* INFO: Object conversion helpers */

static void *to_obj(prop_area *pa, uint_least32_t off) {
  return off > pa_data_size ? NULL : pa->data + off;
}

static inline prop_bt *to_bt(prop_area *pa, atomic_uint_least32_t *p) {
  return (prop_bt *)to_obj(pa, atomic_load_explicit(p, memory_order_consume));
}

static inline prop_info *to_info(prop_area *pa, atomic_uint_least32_t *p) {
  return (prop_info *)to_obj(pa, atomic_load_explicit(p, memory_order_consume));
}

static inline prop_bt *root(prop_area *pa) {
  return (prop_bt *)to_obj(pa, 0);
}

/* INFO: Init */

static void prop_area_init(prop_area *pa, uint32_t magic, uint32_t version) {
  pa->magic = magic;
  pa->version = version;
  atomic_init(&pa->serial, 0u);
  memset(pa->reserved, 0, sizeof(pa->reserved));

  pa->bytes_used = sizeof(prop_bt);
  pa->bytes_used += __BIONIC_ALIGN(PROP_VALUE_MAX, sizeof(uint_least32_t));
}

static void prop_bt_init(prop_bt *bt, const char *name, uint32_t namelen) {
  bt->namelen = namelen;
  memcpy(bt->name, name, namelen);
  bt->name[namelen] = '\0';

  atomic_store_explicit(&bt->prop, 0, memory_order_relaxed);
  atomic_store_explicit(&bt->left, 0, memory_order_relaxed);
  atomic_store_explicit(&bt->right, 0, memory_order_relaxed);
  atomic_store_explicit(&bt->children, 0, memory_order_relaxed);
}

void prop_info_init(prop_info *pi, const char *name, uint32_t namelen, const char *value, uint32_t valuelen) {
  memcpy(pi->name, name, namelen);
  pi->name[namelen] = '\0';
  atomic_init(&pi->serial, valuelen << 24);
  memcpy(pi->value_un.value, value, valuelen);
  pi->value_un.value[valuelen] = '\0';
}

void prop_info_init_long(prop_info *pi, const char *name, uint32_t namelen, uint32_t offset) {
  static const char err[] = "Must use __system_property_read_callback() to read";

  memcpy(pi->name, name, namelen);
  pi->name[namelen] = '\0';
  atomic_init(&pi->serial, (uint32_t)(sizeof(err) - 1) << 24 | k_long_flag);
  memcpy(pi->value_un.long_property.error_message, err, sizeof(err));
  pi->value_un.long_property.offset = offset;
}

/* INFO: Mapping */

prop_area *prop_area_map_prop_area_rw(const char *filename, const char *context, bool *fsetxattr_failed) {
  const int fd = open(filename, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_EXCL, 0444);
  if (fd < 0) {
    if (errno == EACCES) abort();
    return NULL;
  }

  if (context) {
    if (fsetxattr(fd, XATTR_NAME_SELINUX, context, strlen(context) + 1, 0) != 0) {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc", "fsetxattr failed for \"%s\"", filename);
      if (fsetxattr_failed) *fsetxattr_failed = true;
    }
  }

  if (ftruncate(fd, PA_SIZE) < 0) {
    close(fd);
    return NULL;
  }

  pa_size = PA_SIZE;
  pa_data_size = pa_size - sizeof(prop_area);

  void *mem = mmap(NULL, pa_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (mem == MAP_FAILED) return NULL;

  prop_area_init((prop_area *)mem, PA_MAGIC, PA_VERSION);
  return (prop_area *)mem;
}

prop_area *prop_area_map_prop_area(const char *filename, bool *is_rw) {
  bool rw = false;

  int fd = open(filename, O_CLOEXEC | O_NOFOLLOW | O_RDWR);
  if (fd == -1) {
    fd = open(filename, O_CLOEXEC | O_NOFOLLOW | O_RDONLY);
    if (fd == -1) return NULL;
  } else {
    rw = true;
  }

  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    return NULL;
  }

  if (st.st_size < (off_t)sizeof(prop_area)) {
    close(fd);
    return NULL;
  }

  pa_size = st.st_size;
  pa_data_size = pa_size - sizeof(prop_area);

  int prot = rw ? PROT_READ | PROT_WRITE : PROT_READ;
  void *map = mmap(NULL, pa_size, prot, MAP_SHARED, fd, 0);
  close(fd);
  if (map == MAP_FAILED) return NULL;

  prop_area *pa = (prop_area *)map;
  if (pa->magic != PA_MAGIC || pa->version != PA_VERSION) {
    munmap(pa, pa_size);
    return NULL;
  }

  if (is_rw) *is_rw = rw;
  return pa;
}

void prop_area_unmap_prop_area(prop_area **pa) {
  if (!*pa) return;
  munmap(*pa, pa_size);
  *pa = NULL;
}

/* INFO: Allocation */

static void *alloc_obj(prop_area *pa, size_t size, uint_least32_t *off) {
  size_t aligned = __BIONIC_ALIGN(size, sizeof(uint_least32_t));
  if (pa->bytes_used + aligned > pa_data_size) return NULL;

  *off = pa->bytes_used;
  pa->bytes_used += aligned;
  return pa->data + *off;
}

static prop_bt *new_bt(prop_area *pa, const char *name, uint32_t namelen, uint_least32_t *off) {
  prop_bt *bt = alloc_obj(pa, sizeof(prop_bt) + namelen + 1, off);
  if (!bt) return NULL;

  prop_bt_init(bt, name, namelen);
  return bt;
}

static prop_info *new_info(prop_area *pa, const char *name, uint32_t namelen,
  const char *value, uint32_t valuelen, uint_least32_t *off) {
  prop_info *info = alloc_obj(pa, sizeof(prop_info) + namelen + 1, off);
  if (!info) return NULL;

  if (valuelen >= PROP_VALUE_MAX) {
    uint32_t long_off;
    char *long_loc = alloc_obj(pa, valuelen + 1, &long_off);
    if (!long_loc) return NULL;

    memcpy(long_loc, value, valuelen);
    long_loc[valuelen] = '\0';
    long_off -= *off;
    prop_info_init_long(info, name, namelen, long_off);
  } else {
    prop_info_init(info, name, namelen, value, valuelen);
  }

  return info;
}

/* INFO: Trie operations */

static prop_bt *find_bt(prop_area *pa, prop_bt *bt, const char *name, uint32_t namelen, bool alloc) {
  prop_bt *cur = bt;

  while (cur) {
    int c = namelen < cur->namelen ? -1 : namelen > cur->namelen ? 1 : strncmp(name, cur->name, namelen);
    if (c == 0) return cur;

    if (c < 0) {
      if (atomic_load_explicit(&cur->left, memory_order_relaxed)) {
        cur = to_bt(pa, &cur->left);
      } else if (alloc) {
        uint_least32_t off;
        prop_bt *n = new_bt(pa, name, namelen, &off);
        if (n) atomic_store_explicit(&cur->left, off, memory_order_release);
        return n;
      } else {
        return NULL;
      }
    } else {
      if (atomic_load_explicit(&cur->right, memory_order_relaxed)) {
        cur = to_bt(pa, &cur->right);
      } else if (alloc) {
        uint_least32_t off;
        prop_bt *n = new_bt(pa, name, namelen, &off);
        if (n) atomic_store_explicit(&cur->right, off, memory_order_release);
        return n;
      } else {
        return NULL;
      }
    }
  }

  return NULL;
}

static prop_bt *traverse(prop_area *pa, prop_bt *trie, const char *name, bool alloc) {
  if (!trie) return NULL;

  const char *rem = name;
  prop_bt *cur = trie;

  for (;;) {
    const char *sep = strchr(rem, '.');
    uint32_t len = sep ? (uint32_t)(sep - rem) : (uint32_t)strlen(rem);
    if (!len) return NULL;

    prop_bt *child = NULL;
    uint_least32_t ch_off = atomic_load_explicit(&cur->children, memory_order_relaxed);
    if (ch_off) {
      child = to_bt(pa, &cur->children);
    } else if (alloc) {
      uint_least32_t o;
      child = new_bt(pa, rem, len, &o);
      if (child) atomic_store_explicit(&cur->children, o, memory_order_release);
    }
    if (!child) return NULL;

    cur = find_bt(pa, child, rem, len, alloc);
    if (!cur) return NULL;
    if (!sep) break;

    rem = sep + 1;
  }

  return cur;
}

static const prop_info *find_property(prop_area *pa, prop_bt *trie, const char *name,
  uint32_t namelen, const char *value, uint32_t valuelen, bool alloc) {
  prop_bt *cur = traverse(pa, trie, name, alloc);
  if (!cur) return NULL;

  uint_least32_t prop_off = atomic_load_explicit(&cur->prop, memory_order_relaxed);
  if (prop_off) {
    return to_info(pa, &cur->prop);
  } else if (alloc) {
    uint_least32_t off;
    prop_info *info = new_info(pa, name, namelen, value, valuelen, &off);
    if (info) atomic_store_explicit(&cur->prop, off, memory_order_release);
    return info;
  }

  return NULL;
}

static bool foreach_prop(prop_area *pa, prop_bt *trie, void (*fn)(const prop_info *, void *), void *cookie) {
  if (!trie) return true;

  if (atomic_load_explicit(&trie->left, memory_order_relaxed)) {
    if (!foreach_prop(pa, to_bt(pa, &trie->left), fn, cookie)) return false;
  }

  if (atomic_load_explicit(&trie->prop, memory_order_relaxed)) {
    prop_info *info = to_info(pa, &trie->prop);
    if (!info) return false;
    fn(info, cookie);
  }

  if (atomic_load_explicit(&trie->children, memory_order_relaxed)) {
    if (!foreach_prop(pa, to_bt(pa, &trie->children), fn, cookie)) return false;
  }

  if (atomic_load_explicit(&trie->right, memory_order_relaxed)) {
    if (!foreach_prop(pa, to_bt(pa, &trie->right), fn, cookie)) return false;
  }

  return true;
}

const prop_info *prop_area_find(prop_area *pa, const char *name) {
  if (!pa || !name) return NULL;
  return find_property(pa, root(pa), name, (uint32_t)strlen(name), NULL, 0, false);
}

bool prop_area_add(prop_area *pa, const char *name, unsigned int namelen, const char *value, unsigned int valuelen) {
  return find_property(pa, root(pa), name, namelen, value, valuelen, true);
}

bool prop_area_foreach(prop_area *pa, void (*fn)(const prop_info *, void *), void *cookie) {
  return foreach_prop(pa, root(pa), fn, cookie);
}

/* INFO: Pruning */

#define get_off(p) atomic_load_explicit(p, memory_order_relaxed)
#define set_off(p, v) atomic_store_explicit(p, v, memory_order_release)

static bool prune_trie(prop_area *pa, prop_bt *n) {
  bool leaf = true;

  if (get_off(&n->children)) {
    if (prune_trie(pa, to_bt(pa, &n->children))) set_off(&n->children, 0u);
    else leaf = false;
  }

  if (get_off(&n->left)) {
    if (prune_trie(pa, to_bt(pa, &n->left))) set_off(&n->left, 0u);
    else leaf = false;
  }

  if (get_off(&n->right)) {
    if (prune_trie(pa, to_bt(pa, &n->right))) set_off(&n->right, 0u);
    else leaf = false;
  }

  if (leaf && get_off(&n->prop) == 0) {
    memset(n, 0, sizeof(*n));
    return true;
  }

  return false;
}

bool prop_area_remove(prop_area *pa, const char *name, bool do_prune) {
  prop_bt *n = traverse(pa, root(pa), name, false);
  if (!n) return false;

  uint_least32_t prop_off = get_off(&n->prop);
  if (!prop_off) return false;

  prop_info *p = to_info(pa, &n->prop);
  set_off(&n->prop, 0u);

  if (prop_info_is_long(p)) {
    memset((void *)prop_info_long_value(p), 0, strlen(prop_info_long_value(p)));
  }

  memset(p, 0, sizeof(*p));
  if (do_prune) prune_trie(pa, root(pa));

  return true;
}

/* INFO: Compaction */

typedef struct {
  uint_least32_t old_off;
  uint_least32_t new_off;
  uint32_t size;
  uint32_t aligned;
} live_obj;

typedef struct {
  uint_least32_t prop_off;
  uint_least32_t long_off;
} long_ref;

typedef struct {
  live_obj *objs;
  size_t obj_count;
  size_t obj_cap;

  uint_least32_t *nodes;
  size_t node_count;
  size_t node_cap;

  uint_least32_t *props;
  size_t prop_count;
  size_t prop_cap;

  long_ref *longs;
  size_t long_count;
  size_t long_cap;
  bool failed;
} collect_state;

static bool push_obj(collect_state *s, live_obj o) {
  if (s->obj_count == s->obj_cap) {
    size_t c = s->obj_cap ? s->obj_cap * 2 : 64;
    live_obj *t = realloc(s->objs, c * sizeof(live_obj));
    if (!t) return false;

    s->objs = t;
    s->obj_cap = c;
  }

  s->objs[s->obj_count++] = o;
  return true;
}

static bool push_uint(uint_least32_t **arr, size_t *count, size_t *cap, uint_least32_t v) {
  if (*count == *cap) {
    size_t c = *cap ? *cap * 2 : 64;
    uint_least32_t *t = realloc(*arr, c * sizeof(uint_least32_t));
    if (!t) return false;

    *arr = t;
    *cap = c;
  }

  (*arr)[(*count)++] = v;
  return true;
}

static bool push_long(collect_state *s, long_ref r) {
  if (s->long_count == s->long_cap) {
    size_t c = s->long_cap ? s->long_cap * 2 : 16;
    long_ref *t = realloc(s->longs, c * sizeof(long_ref));
    if (!t) return false;

    s->longs = t;
    s->long_cap = c;
  }

  s->longs[s->long_count++] = r;
  return true;
}

static void collect_free(collect_state *s) {
  free(s->objs);
  free(s->nodes);
  free(s->props);
  free(s->longs);
  memset(s, 0, sizeof(*s));
}

static void collect_live(char *base, prop_bt *n, bool skip, collect_state *st) {
  if (!n || st->failed) return;

  if (!skip) {
    uint_least32_t off = (uint_least32_t)((char *)n - base);
    uint32_t sz = sizeof(prop_bt) + n->namelen + 1;

    if (!push_obj(st, (live_obj){off, 0, sz, (uint32_t)__BIONIC_ALIGN(sz, sizeof(uint_least32_t))}) ||
        !push_uint(&st->nodes, &st->node_count, &st->node_cap, off)) {
      st->failed = true;
      return;
    }
  }

  if (get_off(&n->prop)) {
    prop_info *info = (prop_info *)(base + get_off(&n->prop));
    uint32_t sz = sizeof(prop_info) + strlen(info->name) + 1;

    if (!push_obj(st, (live_obj){get_off(&n->prop), 0, sz, (uint32_t)__BIONIC_ALIGN(sz, sizeof(uint_least32_t))}) ||
        !push_uint(&st->props, &st->prop_count, &st->prop_cap, get_off(&n->prop))) {
      st->failed = true;
      return;
    }

    if (prop_info_is_long(info)) {
      const char *lv = prop_info_long_value(info);
      uint32_t lsz = strlen(lv) + 1;

      if (!push_obj(st, (live_obj){(uint_least32_t)(lv - base), 0, lsz, (uint32_t)__BIONIC_ALIGN(lsz, sizeof(uint_least32_t))}) ||
          !push_long(st, (long_ref){get_off(&n->prop), (uint_least32_t)(lv - base)})) {
        st->failed = true;
        return;
      }
    }
  }

  if (get_off(&n->left)) collect_live(base, (prop_bt *)(base + get_off(&n->left)), false, st);
  if (get_off(&n->children)) collect_live(base, (prop_bt *)(base + get_off(&n->children)), false, st);
  if (get_off(&n->right)) collect_live(base, (prop_bt *)(base + get_off(&n->right)), false, st);
}

static int cmp_obj(const void *a, const void *b) {
  const live_obj *la = a;
  const live_obj *lb = b;

  if (la->old_off < lb->old_off) return -1;
  if (la->old_off > lb->old_off) return 1;
  return 0;
}

static int cmp_long(const void *a, const void *b) {
  const long_ref *la = a;
  const long_ref *lb = b;

  if (la->prop_off < lb->prop_off) return -1;
  if (la->prop_off > lb->prop_off) return 1;
  return 0;
}

static uint_least32_t remap(const live_obj *o, size_t cnt, uint_least32_t old) {
  if (!old) return 0;

  size_t lo = 0;
  size_t hi = cnt;

  while (lo < hi) {
    size_t m = lo + (hi - lo) / 2;
    if (o[m].old_off < old) lo = m + 1;
    else hi = m;
  }

  if (lo < cnt && o[lo].old_off == old) return o[lo].new_off;
  return old;
}

static void fix_node(const live_obj *o, size_t cnt, prop_bt *n) {
  if (get_off(&n->left)) set_off(&n->left, remap(o, cnt, get_off(&n->left)));
  if (get_off(&n->right)) set_off(&n->right, remap(o, cnt, get_off(&n->right)));
  if (get_off(&n->children)) set_off(&n->children, remap(o, cnt, get_off(&n->children)));
  if (get_off(&n->prop)) set_off(&n->prop, remap(o, cnt, get_off(&n->prop)));
}

bool prop_area_compact(prop_area *pa) {
  uint32_t data_start = sizeof(prop_bt) + __BIONIC_ALIGN(PROP_VALUE_MAX, sizeof(uint_least32_t));
  uint32_t old_used = pa->bytes_used;
  if (old_used < data_start) return false;

  collect_state st;
  memset(&st, 0, sizeof(st));

  collect_live(pa->data, root(pa), true, &st);

  if (st.failed) {
    collect_free(&st);
    return false;
  }

  /* INFO: No live objects - just reset */
  if (st.obj_count == 0) {
    if (old_used != data_start) {
      pa->bytes_used = data_start;
      memset(pa->data + data_start, 0, old_used - data_start);
    }
    collect_free(&st);
    return true;
  }

  qsort(st.objs, st.obj_count, sizeof(live_obj), cmp_obj);
  if (st.long_count) qsort(st.longs, st.long_count, sizeof(long_ref), cmp_long);

  /* INFO: Assign new offsets */
  uint32_t next = data_start;
  for (size_t i = 0; i < st.obj_count; ++i) {
    st.objs[i].new_off = next;
    next += st.objs[i].aligned;
  }

  /* INFO: Move objects */
  for (size_t i = 0; i < st.obj_count; ++i) {
    if (st.objs[i].new_off != st.objs[i].old_off) {
      memmove(pa->data + st.objs[i].new_off,
              pa->data + st.objs[i].old_off,
              st.objs[i].aligned);
    }
  }

  pa->bytes_used = next;

  /* INFO: Fix up root and trie nodes */
  fix_node(st.objs, st.obj_count, root(pa));

  for (size_t i = 0; i < st.node_count; ++i) {
    uint_least32_t new_off = remap(st.objs, st.obj_count, st.nodes[i]);
    fix_node(st.objs, st.obj_count, (prop_bt *)(pa->data + new_off));
  }

  /* INFO: Fix up long-value offsets */
  for (size_t i = 0; i < st.prop_count; ++i) {
    uint_least32_t pnew = remap(st.objs, st.obj_count, st.props[i]);
    prop_info *info = (prop_info *)(pa->data + pnew);
    if (!prop_info_is_long(info)) continue;

    size_t lo = 0;
    size_t hi = st.long_count;
    while (lo < hi) {
      size_t m = lo + (hi - lo) / 2;
      if (st.longs[m].prop_off < st.props[i]) lo = m + 1;
      else hi = m;
    }

    if (lo < st.long_count && st.longs[lo].prop_off == st.props[i]) {
      uint_least32_t long_new_off = remap(st.objs, st.obj_count, st.longs[lo].long_off);
      info->value_un.long_property.offset = long_new_off - pnew;
    }
  }

  if (next < old_used) {
    memset(pa->data + next, 0, old_used - next);
  }

  collect_free(&st);
  return true;
}
