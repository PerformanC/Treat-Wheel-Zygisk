#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

#include <android/log.h>

#include "rz_daemon.h"

#ifdef DEBUG
  #define LOGD(...) do { __android_log_print(ANDROID_LOG_DEBUG, "TreatWheel", __VA_ARGS__); } while (0)
  #define LOGI(...) do { __android_log_print(ANDROID_LOG_INFO, "TreatWheel", __VA_ARGS__); } while (0)
  #define LOGW(...) do { __android_log_print(ANDROID_LOG_WARN, "TreatWheel", __VA_ARGS__); } while (0)
  #define LOGE(...) do { __android_log_print(ANDROID_LOG_ERROR, "TreatWheel", __VA_ARGS__); } while (0)
  #define LOGF(...) do { __android_log_print(ANDROID_LOG_FATAL, "TreatWheel", __VA_ARGS__); } while (0)
  #define PLOGE(msg, ...) do { __android_log_print(ANDROID_LOG_ERROR, "TreatWheel", "%s: " msg ": %s", __func__, ##__VA_ARGS__, strerror(errno)); } while (0)
#else
  #define LOGD(...)
  #define LOGI(...)
  #define LOGW(...)
  #define LOGE(...)
  #define LOGF(...)
  #define PLOGE(msg, ...)
#endif

struct map {
  uintptr_t addr_start;
  uintptr_t addr_end;
  uintptr_t addr_offset;
  uint8_t perms;
  bool is_private;
  dev_t dev;
  ino_t inode;
  char *path;
};

struct maps {
  struct map *maps;
  size_t size;
};

struct mountinfo {
  unsigned int id;
  unsigned int parent;
  dev_t device;
  char *root;
  char *target;
  char *vfs_option;
  struct {
    unsigned int shared;
    unsigned int master;
    unsigned int propagate_from;
  } optional;
  char *type;
  char *source;
  char *fs_option;
};

struct mountsinfo {
  struct mountinfo *mounts;
  size_t size;
};

enum daemon_operations {
  DAEMON_CHECK_IGNORING,
  DAEMON_CHECK_FONTS,
  DAEMON_CHECK_POINT,
  DAEMON_GET_MNT_STRING,
  DAEMON_GET_RVX_MOUNTS,
  DAEMON_GOODBYE
};

enum module_status {
  MODULE_STATUS_INJECTED,
  MODULE_STATUS_MIDPERFORMING,
  MODULE_STATUS_HIDING
};

struct module_state {
  bool is_ignoring;
  bool disable_prop_spoofing;
  bool disable_gsi_hiding;
  bool disable_zygote_mountinfo_leak_fixing;
  bool disable_maps_hiding;
  bool disable_revanced_mounts_umount;
  bool disable_custom_font_loading;
  bool disable_denylist_logic_inversion;
  bool disable_module_loading_traces_hiding;
  bool disable_frida_traces_hiding;
};

struct tw_mem_info {
  uintptr_t start;
  size_t size;
};

bool str_starts_with(const char *str, const char *needle);

bool str_ends_with(const char *str, const char *needle);

bool str_equal(const char *str1, const char *str2);

void free_maps(struct maps *maps);

struct maps *parse_maps(const char *filename);

struct mountsinfo *parse_mountinfo(const char *filename);

void free_mountsinfo(struct mountsinfo *mounts);

bool switch_mount_namespace(pid_t pid);

ssize_t write_fd(int fd, int sendfd);

int read_fd(int fd);

ssize_t write_loop(int fd, const void *buf, size_t count);

ssize_t read_loop(int fd, void *buf, size_t count);

#define write_func_def(type)              \
  ssize_t write_## type(int fd, type val)

#define read_func_def(type)               \
  ssize_t read_## type(int fd, type *val)

write_func_def(size_t);
read_func_def(size_t);

write_func_def(uint32_t);
read_func_def(uint32_t);

write_func_def(uint8_t);
read_func_def(uint8_t);

time_t mono_sec_now(void);

#ifndef UTILS_NO_SSL
  int verify_eddsa(unsigned char *to_verify, size_t to_verify_len, unsigned char *public_key, size_t public_key_len, unsigned char *signature, size_t signature_len);

  int hash_file(char *file, unsigned char **to_verify, size_t *to_verify_size);

  unsigned char *verify_rezygisk(char **files, size_t files_length, size_t *to_verify_size);
#endif

#ifdef IS_ZYGISK_LIB
  bool update_mnt_ns(enum mount_namespace_state mns_state);
#endif

struct tw_mem_info tw_get_mem_info(void);

#endif /* UTILS_H */
