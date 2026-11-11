#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <link.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>

#include <sched.h>
#include <unistd.h>
#include <linux/limits.h>
#include <android/log.h>

#include "utils.h"

bool str_starts_with(const char *str, const char *needle) {
  size_t needle_len = strlen(needle);

  if (needle_len > strlen(str)) return false;

  return strncmp(str, needle, needle_len) == 0;
}

bool str_ends_with(const char *str, const char *needle) {
  size_t str_len = strlen(str);
  size_t needle_len = strlen(needle);

  if (needle_len > str_len) return false;

  return strncmp(str + str_len - needle_len, needle, needle_len) == 0;
}

/* INFO: Comparison without able to side channel attack */
bool str_equal(const char *str1, const char *str2) {
  bool is_equal = true;

  if (strlen(str1) != strlen(str2)) return false;

  while (*str1 != '\0' && *str2 != '\0') {
    if (*str1 != *str2) is_equal = false;

    str1++;
    str2++;
  }

  return is_equal;
}

struct maps *parse_maps(const char *filename) {
  int fd = openat(AT_FDCWD, filename, O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    PLOGE("Open %s", filename);

    return NULL;
  }

  /* INFO: malloc can cause detections as it uses scudo VMAs on Android to do its work. That can
             lead to additional detections. Hence, to avoid touching more system resources, we
             use mmap directly. */
  size_t capacity = (size_t)sysconf(_SC_PAGESIZE);
  char *region = (char *)mmap(NULL, capacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (region == MAP_FAILED) {
    PLOGE("Map %s", filename);

    close(fd);

    return NULL;
  }

  size_t used = 0;
  size_t lines = 0;

  while (true) {
    size_t needed = sizeof(struct maps) + (lines + 1) * sizeof(struct map) + used + 1;
    if (needed > capacity) {
      char *grown = (char *)mremap(region, capacity, needed, MREMAP_MAYMOVE);
      if (grown == MAP_FAILED) {
        PLOGE("Grow %s", filename);

        goto cleanup;
      }

      region = grown;
      capacity = needed;
    }

    ssize_t length = read_loop(fd, region + sizeof(struct maps) + used, capacity - sizeof(struct maps) - used - 1);
    if (length == -1) {
      PLOGE("Read %s", filename);

      goto cleanup;
    }

    if (length == 0) break;

    for (ssize_t i = 0; i < length; i++) {
      char *character = region + sizeof(struct maps) + used + i;
      if (*character != '\n') continue;

      *character = '\0';
      lines++;
    }

    used += (size_t)length;
  }

  close(fd);

  if (used == 0) {
    LOGE("Empty %s", filename);

    goto cleanup;
  }

  /* INFO: The text was read right after the header, so it moves up after the
             entries, leaving the layout as header, entries and then the text. */
  char *text = region + sizeof(struct maps) + (lines + 1) * sizeof(struct map);
  memmove(text, region + sizeof(struct maps), used);
  text[used] = '\0';

  struct maps *maps = (struct maps *)region;
  maps->maps = (struct map *)(region + sizeof(struct maps));
  maps->size = 0;
  maps->region_size = capacity;

  for (char *line = text; line < text + used; line += strlen(line) + 1) {
    uintptr_t addr_start, addr_end, addr_offset;
    unsigned int dev_major, dev_minor;
    ino_t inode;
    char permissions[5] = "";
    int path_offset = 0;

    if (sscanf(line,
               "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s",
               &addr_start, &addr_end, permissions, &addr_offset, &dev_major, &dev_minor,
               &inode, &path_offset) < 7) {
      LOGE("Failed to parse %s line: %s", filename, line);

      continue;
    }

    maps->maps[maps->size++] = (struct map) {
      .addr_start = addr_start,
      .addr_end = addr_end,
      .addr_offset = addr_offset,
      .inode = inode,
      .dev = makedev(dev_major, dev_minor),
      .perms = (permissions[0] == 'r' ? PROT_READ : 0) | (permissions[1] == 'w' ? PROT_WRITE : 0) | (permissions[2] == 'x' ? PROT_EXEC : 0),
      .is_private = permissions[3] == 'p',
      .path = line[path_offset] != '\0' ? line + path_offset : NULL,
    };
  }

  return maps;

  cleanup:
    munmap(region, capacity);
    close(fd);

    return NULL;
}

void free_maps(struct maps *maps) {
  munmap(maps, maps->region_size);
}

struct mountsinfo *parse_mountinfo(const char *filename) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    PLOGE("Create socketpair");

    return NULL;
  }

  int write_fd = sockets[0];
  int read_fd = sockets[1];

  int new_pid = syscall(SYS_clone, SIGCHLD, 0);
  if (new_pid == -1) {
    PLOGE("fork");

    close(write_fd);
    close(read_fd);

    return NULL;
  }

  if (new_pid == 0) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
      LOGE("Open %s failed with %d: %s", filename, errno, strerror(errno));

      return NULL;
    }

    char line[4096 * 2];
    while (fgets(line, sizeof(line), fp) != NULL) {
      int root_start = 0, root_end = 0;
      int target_start = 0, target_end = 0;
      int vfs_option_start = 0, vfs_option_end = 0;
      int type_start = 0, type_end = 0;
      int source_start = 0, source_end = 0;
      int fs_option_start = 0, fs_option_end = 0;
      int optional_start = 0, optional_end = 0;
      unsigned int id, parent, maj, min;
      sscanf(line,
              "%u "           // (1) id
              "%u "           // (2) parent
              "%u:%u "        // (3) maj:min
              "%n%*s%n "      // (4) mountroot
              "%n%*s%n "      // (5) target
              "%n%*s%n"       // (6) vfs options (fs-independent)
              "%n%*[^-]%n - " // (7) optional fields
              "%n%*s%n "      // (8) FS type
              "%n%*s%n "      // (9) source
              "%n%*s%n",      // (10) fs options (fs specific)
              &id, &parent, &maj, &min, &root_start, &root_end, &target_start,
              &target_end, &vfs_option_start, &vfs_option_end,
              &optional_start, &optional_end, &type_start, &type_end,
              &source_start, &source_end, &fs_option_start, &fs_option_end);

      #define WRITE_AND_ASSURE(var)                                 \
      if (write_loop(write_fd, &var, sizeof(var)) != sizeof(var)) { \
        PLOGE("write " #var);                                       \
                                                                    \
        fclose(fp);                                                 \
                                                                    \
        close(write_fd);                                            \
        close(read_fd);                                             \
                                                                    \
        return NULL;                                                \
      }

      #define WRITE_STRING_AND_ASSURE(var, len)                                                  \
        size_t var ## _len = len;                                                                \
        if (write_loop(write_fd, &var ## _len, sizeof(size_t)) != sizeof(size_t)) {              \
          PLOGE("Write " #var "_len");                                                           \
                                                                                                 \
          fclose(fp);                                                                            \
                                                                                                 \
          close(write_fd);                                                                       \
          close(read_fd);                                                                        \
                                                                                                 \
          return NULL;                                                                           \
        }                                                                                        \
                                                                                                 \
        if (var ## _len != 0) {                                                                  \
          if (write_loop(write_fd, line + var ## _start, var ## _len) != (ssize_t)var ## _len) { \
            PLOGE("Write " #var);                                                                \
                                                                                                 \
            fclose(fp);                                                                          \
                                                                                                 \
            close(write_fd);                                                                     \
            close(read_fd);                                                                      \
                                                                                                 \
            return NULL;                                                                         \
          }                                                                                      \
        }

      unsigned int shared = 0;
      unsigned int master = 0;
      unsigned int propagate_from = 0;

      if (strstr(line + optional_start, "shared:")) {
        shared = atoi(strstr(line + optional_start, "shared:") + 7);
      }

      if (strstr(line + optional_start, "master:")) {
        master = atoi(strstr(line + optional_start, "master:") + 7);
      }

      if (strstr(line + optional_start, "propagate_from:")) {
        propagate_from = atoi(strstr(line + optional_start, "propagate_from:") + 15);
      }

      uint8_t has_more_maps = 1;
      if (write_loop(write_fd, &has_more_maps, sizeof(has_more_maps)) != sizeof(has_more_maps)) {
        PLOGE("Write has_more_maps");

        fclose(fp);

        close(write_fd);
        close(read_fd);

        return NULL;
      }

      WRITE_AND_ASSURE(id);
      WRITE_AND_ASSURE(parent);

      dev_t device = makedev(maj, min);
      WRITE_AND_ASSURE(device);

      WRITE_STRING_AND_ASSURE(root, root_end - root_start);
      WRITE_STRING_AND_ASSURE(target, target_end - target_start);
      WRITE_STRING_AND_ASSURE(vfs_option, vfs_option_end - vfs_option_start);

      WRITE_AND_ASSURE(shared);
      WRITE_AND_ASSURE(master);
      WRITE_AND_ASSURE(propagate_from);

      WRITE_STRING_AND_ASSURE(type, type_end - type_start);
      WRITE_STRING_AND_ASSURE(source, source_end - source_start);
      WRITE_STRING_AND_ASSURE(fs_option, fs_option_end - fs_option_start);

      #undef WRITE_AND_ASSURE
      #undef WRITE_STRING_AND_ASSURE
    }

    uint8_t has_more_maps = 0;
    write_loop(write_fd, &has_more_maps, sizeof(uint8_t));

    fclose(fp);

    _exit(0);
  }

  struct mountsinfo *mounts = (struct mountsinfo *)malloc(sizeof(struct mountsinfo));
  if (!mounts) {
    PLOGE("Allocate memory for mounts");

    close(write_fd);
    close(read_fd);

    return NULL;
  }

  mounts->mounts = NULL;

  size_t i = 0;
  while (1) {
    #define READ_AND_ASSURE(field)                                                                                            \
      if (read_loop(read_fd, &mounts->mounts[i].field, sizeof(mounts->mounts[i].field)) != sizeof(mounts->mounts[i].field)) { \
        PLOGE("Read " #field);                                                                                                \
                                                                                                                              \
        close(write_fd);                                                                                                      \
        close(read_fd);                                                                                                       \
                                                                                                                              \
        mounts->size = i;                                                                                                     \
        free_mountsinfo(mounts);                                                                                              \
                                                                                                                              \
        return NULL;                                                                                                          \
      }

    #define READ_STRING_AND_ASSURE(var)                                                       \
      size_t var ## _len = 0;                                                                 \
      if (read_loop(read_fd, &var ## _len, sizeof(size_t)) != sizeof(size_t)) {               \
        PLOGE("Read " #var "_len");                                                           \
                                                                                              \
        close(write_fd);                                                                      \
        close(read_fd);                                                                       \
                                                                                              \
        mounts->size = i;                                                                     \
        free_mountsinfo(mounts);                                                              \
                                                                                              \
        return NULL;                                                                          \
      }                                                                                       \
                                                                                              \
      if (var ## _len != 0) {                                                                 \
        mounts->mounts[i].var = (char *)malloc(var ## _len + 1);                              \
        if (!mounts->mounts[i].var) {                                                         \
          PLOGE("Allocate memory for " #var);                                                 \
                                                                                              \
          close(write_fd);                                                                    \
          close(read_fd);                                                                     \
                                                                                              \
          mounts->size = i;                                                                   \
          free_mountsinfo(mounts);                                                            \
                                                                                              \
          return NULL;                                                                        \
        }                                                                                     \
                                                                                              \
        if (read_loop(read_fd, mounts->mounts[i].var, var ## _len) != (ssize_t)var ## _len) { \
          PLOGE("Read " #var);                                                                \
                                                                                              \
          close(write_fd);                                                                    \
          close(read_fd);                                                                     \
                                                                                              \
          mounts->size = i;                                                                   \
          free_mountsinfo(mounts);                                                            \
                                                                                              \
          return NULL;                                                                        \
        }                                                                                     \
                                                                                              \
        mounts->mounts[i].var[var ## _len] = '\0';                                            \
      } else {                                                                                \
        mounts->mounts[i].var = NULL;                                                         \
      }

    uint8_t has_more_maps = 1;
    if (read_loop(read_fd, &has_more_maps, sizeof(has_more_maps)) != sizeof(has_more_maps)) {
      PLOGE("Read has_more_maps");

      close(write_fd);
      close(read_fd);

      mounts->size = i;
      free_mountsinfo(mounts);

      return NULL;
    }

    if (!has_more_maps) break;

    mounts->mounts = (struct mountinfo *)realloc(mounts->mounts, (i + 1) * sizeof(struct mountinfo));
    if (!mounts->mounts) {
      PLOGE("Allocate memory for mounts->mounts");

      close(write_fd);
      close(read_fd);

      mounts->size = i;
      free_mountsinfo(mounts);

      return NULL;
    }

    READ_AND_ASSURE(id);
    READ_AND_ASSURE(parent);
    READ_AND_ASSURE(device);

    READ_STRING_AND_ASSURE(root);
    READ_STRING_AND_ASSURE(target);
    READ_STRING_AND_ASSURE(vfs_option);

    unsigned int shared = 0;
    if (read_loop(read_fd, &shared, sizeof(shared)) != sizeof(shared)) {
      PLOGE("Read shared");

      close(write_fd);
      close(read_fd);

      mounts->size = i;
      free_mountsinfo(mounts);

      return NULL;
    }

    unsigned int master = 0;
    if (read_loop(read_fd, &master, sizeof(master)) != sizeof(master)) {
      PLOGE("Read master");

      close(write_fd);
      close(read_fd);

      mounts->size = i;
      free_mountsinfo(mounts);

      return NULL;
    }

    unsigned int propagate_from = 0;
    if (read_loop(read_fd, &propagate_from, sizeof(propagate_from)) != sizeof(propagate_from)) {
      PLOGE("Read propagate_from");

      close(write_fd);
      close(read_fd);

      mounts->size = i;
      free_mountsinfo(mounts);

      return NULL;
    }

    mounts->mounts[i].optional.shared = shared;
    mounts->mounts[i].optional.master = master;
    mounts->mounts[i].optional.propagate_from = propagate_from;

    READ_STRING_AND_ASSURE(type);
    READ_STRING_AND_ASSURE(source);
    READ_STRING_AND_ASSURE(fs_option);

    #undef READ_AND_ASSURE
    #undef READ_STRING_AND_ASSURE

    i++;
  }

  mounts->size = i;

  waitpid(new_pid, NULL, 0);

  close(write_fd);
  close(read_fd);

  return mounts;
}

void free_mountsinfo(struct mountsinfo *mounts) {
  if (mounts->mounts == NULL) {
    free(mounts);

    return;
  }

  for (size_t i = 0; i < mounts->size; i++) {
    #define FREE_IF_NULL(var) if (mounts->mounts[i].var) free((void *)mounts->mounts[i].var);

    FREE_IF_NULL(root);
    FREE_IF_NULL(target);
    FREE_IF_NULL(vfs_option);
    FREE_IF_NULL(type);
    FREE_IF_NULL(source);
    FREE_IF_NULL(fs_option);

    #undef FREE_IF_NULL
  }

  free(mounts->mounts);
  free(mounts);
}

bool switch_mount_namespace(pid_t pid) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);

  int nsfd = open(path, O_RDONLY | O_CLOEXEC);
  if (nsfd == -1) {
    PLOGE("open nsfd");

    return false;
  }

  if (setns(nsfd, CLONE_NEWNS) == -1) {
    PLOGE("setns nsfd");

    close(nsfd);

    return false;
  }

  close(nsfd);

  return true;
}

ssize_t write_fd(int fd, int sendfd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  char buf[1] = { 0 };
  
  struct iovec iov = {
    .iov_base = buf,
    .iov_len = 1
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf)
  };

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;

  memcpy(CMSG_DATA(cmsg), &sendfd, sizeof(int));

  ssize_t ret = sendmsg(fd, &msg, 0);
  if (ret == -1) {
    LOGE("sendmsg: %s", strerror(errno));

    return -1;
  }

  return ret;
}

int read_fd(int fd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];

  int cnt = 1;
  struct iovec iov = {
    .iov_base = &cnt,
    .iov_len = sizeof(cnt)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf)
  };

  ssize_t ret = recvmsg(fd, &msg, MSG_WAITALL);
  if (ret == -1) {
    LOGE("recvmsg: %s", strerror(errno));

    return -1;
  }

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == NULL) {
    LOGE("CMSG_FIRSTHDR: %s", strerror(errno));

    return -1;
  }

  int sendfd;
  memcpy(&sendfd, CMSG_DATA(cmsg), sizeof(int));

  return sendfd;
}

ssize_t write_loop(int fd, const void *buf, size_t count) {
  (void) fd; (void) buf; (void) count;

  ssize_t ret;
  size_t written = 0;

  while (written < count) {
    again:
      ret = write(fd, (const char *)buf + written, count - written);
      if (ret == -1) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
          goto again;

        return -1;
      }

      written += ret;
  }

  return written;
}

ssize_t read_loop(int fd, void *buf, size_t count) {
  (void) fd; (void) buf; (void) count;

  ssize_t ret;
  size_t read_bytes = 0;

  while (read_bytes < count) {
    again:
      ret = read(fd, (char *)buf + read_bytes, count - read_bytes);
      if (ret == -1) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
          goto again;

        return -1;
      }

      if (ret == 0)
        break;

      read_bytes += ret;
  }

  return read_bytes;
}

#define write_func(type)                       \
  ssize_t write_## type(int fd, type val) {    \
    return write_loop(fd, &val, sizeof(type)); \
  }

#define read_func(type)                      \
  ssize_t read_## type(int fd, type *val) {  \
    return read_loop(fd, val, sizeof(type)); \
  }

write_func(size_t)
read_func(size_t)

write_func(uint32_t)
read_func(uint32_t)

write_func(uint8_t)
read_func(uint8_t)

time_t mono_sec_now(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return 0;

  return ts.tv_sec;
}

#ifdef IS_ZYGISK_LIB
  bool update_mnt_ns(enum mount_namespace_state mns_state) {
    char ns_path[PATH_MAX];
    if (rezygiskd_update_mns(mns_state, ns_path, sizeof(ns_path)) == false) {
      PLOGE("Failed to update mount namespace");

      return false;
    }

    int updated_ns = open(ns_path, O_RDONLY);
    if (updated_ns == -1) {
      LOGE("Failed to open mount namespace [%s]", ns_path);

      return false;
    }

    const char *__unused mns_state_str = NULL;
    if (mns_state == Clean) mns_state_str = "clean";
    else if (mns_state == Mounted) mns_state_str = "mounted";
    else mns_state_str = "unknown";

    LOGD("set mount namespace to [%s] fd=[%d]: %s", ns_path, updated_ns, mns_state_str);
    if (setns(updated_ns, CLONE_NEWNS) == -1) {
      LOGE("Failed to set mount namespace [%s]", ns_path);

      close(updated_ns);

      return false;
    }

    close(updated_ns);

    return true;
  }
#endif

static void *_page_start(uintptr_t addr) {
  return (void *)(addr & ~(getpagesize() - 1));
}

static void *_page_end(uintptr_t addr) {
  return (void *)((addr + getpagesize() - 1) & ~(getpagesize() - 1));
}

struct tw_mem_info tw_get_mem_info(void) {
  /* INFO: Represents the address to the in-memory ELF header */
  extern const ElfW(Ehdr) __ehdr_start;

  const ElfW(Ehdr) *ehdr = &__ehdr_start;

  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_phentsize != sizeof(ElfW(Phdr)) || ehdr->e_phnum == 0) {
    LOGE("Invalid in-memory ELF header");

    return (struct tw_mem_info) { 0 };
  }

  const ElfW(Phdr) *phdrs = (const ElfW(Phdr) *)((const char *)ehdr + ehdr->e_phoff);

  ElfW(Addr) lo = UINTPTR_MAX, hi = 0;
  for (size_t i = 0; i < ehdr->e_phnum; ++i) {
    if (phdrs[i].p_type != PT_LOAD) continue;
    if (phdrs[i].p_vaddr < lo) lo = phdrs[i].p_vaddr;
    if (phdrs[i].p_vaddr + phdrs[i].p_memsz > hi) hi = phdrs[i].p_vaddr + phdrs[i].p_memsz;
  }

  if (lo == UINTPTR_MAX || hi <= lo) {
    LOGE("Failed to find a loaded segment in the in-memory ELF header");

    return (struct tw_mem_info) { 0 };
  }

  uintptr_t base = (uintptr_t)ehdr;
  uintptr_t start = (uintptr_t)_page_start(base + lo);
  uintptr_t end = (uintptr_t)_page_end(base + hi);

  return (struct tw_mem_info) {
    .start = start,
    .size = (size_t)(end - start)
  };
}
