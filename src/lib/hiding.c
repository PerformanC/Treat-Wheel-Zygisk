#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <mntent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <sched.h>
#include <unistd.h>
#include <limits.h>

#include "utils.h"
#include "elf_util.h"

#include "zygisk.h"

static struct maps* g_maps = NULL;

struct maps* get_global_maps(void) {
    return g_maps;
}

#define BIONIC_LINE_BUFFER_SIZE 1024
static char mntent_string[BIONIC_LINE_BUFFER_SIZE];
static char* mntent_line = NULL;

int do_preinitialize(void) {
    g_maps = parse_maps("/proc/self/maps");
    if(!g_maps) {
        LOGE("Failed to parse /proc/self/maps");

        return 0;
    }

    LOGI("Parsed /proc/self/maps, found %zu maps", g_maps->size);

    int pipes[2];
    if(pipe(pipes) == -1) {
        PLOGE("ZMLH: Pipe");

        return 0;
    }

    int pid = syscall(SYS_clone, SIGCHLD, 0);
    if(pid == -1) {
        PLOGE("ZMLH: Clone");

        close(pipes[0]);
        close(pipes[1]);

        return 0;
    }

    uintptr_t value = 0;
    if(pid == 0) {
        close(pipes[0]);

        FILE* fp = setmntent("/proc/self/mounts", "r");
        if(!fp) {
            PLOGE("ZMLH: setmntent mounts");

            close(pipes[1]);

            _exit(0);
        }

        while(true) {
            struct mntent* entry = getmntent(fp);
            if(entry) value = (uintptr_t) entry;
            else break;
        }
        endmntent(fp);

        if(write(pipes[1], (void*) value, BIONIC_LINE_BUFFER_SIZE) == -1) {
            PLOGE("ZMLH: Write pipe");

            close(pipes[1]);

            _exit(0);
        }

        if(write(pipes[1], &value, sizeof(value)) == -1) {
            PLOGE("ZMLH: Write pipe value");

            close(pipes[1]);

            _exit(0);
        }

        close(pipes[1]);

        _exit(0);
    }

    close(pipes[1]);

    if(read(pipes[0], mntent_string, BIONIC_LINE_BUFFER_SIZE) == -1) {
        PLOGE("ZMLH: Read pipe");

        close(pipes[0]);

        return 0;
    }

    if(read(pipes[0], &mntent_line, sizeof(mntent_line)) == -1) {
        PLOGE("ZMLH: Read pipe mntent line");

        close(pipes[0]);

        return 0;
    }

    close(pipes[0]);

    waitpid(pid, NULL, 0);

    return 1;
}

void do_deinitialize(void) {
    if(g_maps) {
        free_maps(g_maps);
        g_maps = NULL;

        LOGI("Deinitialized /proc/self/maps");
    }
}

int do_gsi_hiding(struct api_table* api_table, JNIEnv* tw_env) {
    (void) api_table;
    (void) tw_env;

    LOGI("GH: GSI hiding is enabled, hiding traces.");

    if(getenv("PHH_STEP1")) unsetenv("PHH_STEP1");
    if(getenv("PHH_STEP2")) unsetenv("PHH_STEP2");
    if(getenv("PHH_STEP3")) unsetenv("PHH_STEP3");

    LOGI("GH: Finished hiding GSI traces.");

    return 1;
}

#define BIONIC_LINE_BUFFER_SIZE 1024

int do_zygote_mountinfo_leak_hiding(struct api_table* api_table, JNIEnv* tw_env) {
    (void) api_table;
    (void) tw_env;

    LOGI("ZMLH: Zygote mountinfo leak hiding is enabled, hiding traces.");

    if(!mntent_line) {
        LOGE("ZMLH: mntent_line is NULL, cannot hide zygote mountinfo leak traces.");

        return 0;
    }

    memcpy(mntent_line, mntent_string, BIONIC_LINE_BUFFER_SIZE);

    LOGI("ZMLH: Finished hiding Zygote mountinfo leak traces.");

    return 1;
}

int do_maps_hiding(struct api_table* api_table, JNIEnv* tw_env) {
    (void) api_table;
    (void) tw_env;

    LOGI("MH: Maps hiding is enabled, hiding traces.");

    struct stat st;
    if(stat("/data", &st) == -1) {
        PLOGE("MH: Stat /data");

        return 0;
    }

    if(g_maps != NULL && g_maps->size == 0) {
        LOGI("MH: No suspicious maps found, returning.");

        return 1;
    }

    for(size_t i = 0; i < g_maps->size; i++) {
        struct map* map = &g_maps->maps[i];

        if(map->path == NULL || map->dev != st.st_dev ||
            str_starts_with(map->path, "/data/adb/modules/rezygisk/") == true ||
            str_starts_with(map->path, "/data/adb/modules/treat_wheel/") == true ||
            (str_starts_with(map->path, "/data/adb/") == false &&
            str_starts_with(map->path, "/data/local/tmp/") == false)
            ) {
            continue;
            }

        LOGI("MH: Hiding suspicious map: %p - %p\nPath: %s", (void *)map->addr_start, (void *)map->addr_end, map->path);

        size_t size = (size_t) (map->addr_end - map->addr_start);
        void* copy = mmap(NULL, size, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if(copy == MAP_FAILED) {
            PLOGE("MH: mmap failed.");
            continue;
        }
        if((map->perms & PROT_READ) == 0 && mprotect((void*) map->addr_start, size, PROT_READ) == -1) {
            PLOGE("MH: mprotect failed.");
            continue;
        }

        memcpy(copy, (void*) map->addr_start, size);
        if(mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, (void*) map->addr_start) == MAP_FAILED) {
            PLOGE("MH: mremap failed.");
            continue;
        }
        mprotect((void*) map->addr_start, size, map->perms);

        if (map->perms & PROT_EXEC) {
            __builtin___clear_cache((char*) map->addr_start, (char*) (map->addr_start + size));
        }
    }

    LOGI("MH: Finished hiding maps traces.");

    return 1;
}

int do_revanced_mounts_umount(struct api_table* api_table, JNIEnv* tw_env, const char* process_name) {
    (void) api_table;
    (void) tw_env;

    LOGI("RVU: Revanced mounts umount is enabled, hiding traces.");

    enum daemon_operations op = DAEMON_GET_RVX_MOUNTS;
    if(write(cfd, &op, sizeof(op)) == -1) {
        PLOGE("RVU: Write operation");

        return 0;
    }

    LOGD("RVU: Waiting for ReVanced mounts data...");

    pid_t pid = getpid();
    if(write_loop(cfd, &pid, sizeof(pid)) == -1) {
        PLOGE("RVU: Write pid");

        return 0;
    }

    size_t process_name_len = strlen(process_name);
    if(write_loop(cfd, &process_name_len, sizeof(process_name_len)) == -1) {
        PLOGE("RVU: Write process_name_len");

        return 0;
    }

    if(write_loop(cfd, process_name, process_name_len) == -1) {
        PLOGE("RVU: Write process_name");

        return 0;
    }

    uint8_t has_rvx_checked;
    if(read(cfd, &has_rvx_checked, sizeof(has_rvx_checked)) == -1) {
        PLOGE("RVU: Read has_rvx_checked");

        return 0;
    }

    if(has_rvx_checked == 0) {
        LOGI("RVU: Something went wrong, returning.");

        return 1;
    }

    LOGI("RVU: Finished hiding revanced mounts traces.");

    return 1;
}

int do_custom_font_loading(struct api_table* api_table, JNIEnv* tw_env) {
    (void) api_table;
    (void) tw_env;

    LOGI("CFL: Custom font loading is enabled, hiding traces.");

    enum daemon_operations op = DAEMON_CHECK_FONTS;
    if(write(cfd, &op, sizeof(op)) == -1) {
        PLOGE("CFL: Write operation");

        return 0;
    }

    uint8_t finished_verifying;
    if(read(cfd, &finished_verifying, sizeof(finished_verifying)) == -1) {
        PLOGE("CFL: Read verification");

        return 0;
    }

    if(finished_verifying == 0) {
        LOGI("CFL: No custom fonts to be loaded, returning.");

        return 1;
    }

    size_t fonts_length;
    if(read_loop(cfd, &fonts_length, sizeof(fonts_length)) == -1) {
        PLOGE("CFL: Read fonts length");

        return 0;
    }

    int* fonts_fds = (int*) calloc(fonts_length, sizeof(int));
    if(!fonts_fds) {
        PLOGE("CFL: Allocate memory for fonts fds");

        return 0;
    }

    for(size_t i = 0; i < fonts_length; i++) {
        fonts_fds[i] = read_fd(cfd);
        if(fonts_fds[i] == -1) {
            PLOGE("CFL: Read font cfd");

            for(size_t j = 0; j < i; j++) {
                if(fonts_fds[j] == 0) continue;

                close(fonts_fds[j]);
            }
            free(fonts_fds);

            return 0;
        }

        LOGI("CFL: Found font cfd: %d", fonts_fds[i]);
    }

    jclass font_class = (*tw_env)->FindClass(tw_env, "android/graphics/Typeface");
    if(font_class == NULL) {
        LOGE("CFL: Failed to find Typeface class");

        for(size_t j = 0; j < fonts_length; j++) {
            if(fonts_fds[j] == 0) continue;

            close(fonts_fds[j]);
        }
        free(fonts_fds);

        return 0;
    }

    jmethodID native_warm_up_cache = (*tw_env)->GetStaticMethodID(tw_env, font_class, "nativeWarmUpCache", "(Ljava/lang/String;)V");
    if(native_warm_up_cache == NULL) {
        LOGE("CFL: Failed to find nativeWarmUpCache method");

        (*tw_env)->ExceptionClear(tw_env);

        for(size_t j = 0; j < fonts_length; j++) {
            if(fonts_fds[j] == 0) continue;

            close(fonts_fds[j]);
        }
        free(fonts_fds);

        return 0;
    }

    for(size_t i = 0; i < fonts_length; i++) {
        if(fonts_fds[i] == 0) continue;

        char tmp_file_path[PATH_MAX];
        snprintf(tmp_file_path, sizeof(tmp_file_path), "/proc/self/fd/%d", fonts_fds[i]);

        (*tw_env)->CallStaticVoidMethod(tw_env, font_class, native_warm_up_cache, (*tw_env)->NewStringUTF(tw_env, tmp_file_path));

        if((*tw_env)->ExceptionCheck(tw_env)) {
            LOGE("CFL: Exception occurred while calling nativeWarmUpCache");

            (*tw_env)->ExceptionClear(tw_env);

            goto cleanup;
        }

        LOGI("CFL: Warmed up cache for font cfd: %d", fonts_fds[i]);

        continue;

    cleanup:
        for(size_t j = 0; j < fonts_length; j++) {
            close(fonts_fds[j]);
        }
        free(fonts_fds);

        return 0;
    }

    for(size_t i = 0; i < fonts_length; i++) {
        if(fonts_fds[i] == 0) continue;

        close(fonts_fds[i]);
    }

    free(fonts_fds);

    LOGI("CFL: Finished hiding custom font loading traces.");

    return 1;
}

int do_denylist_logic_inversion(struct api_table* api_table, JNIEnv* tw_env, enum process_flags flags) {
    (void) api_table;
    (void) tw_env;

    LOGI("DLI: Denylist logic inversion is enabled, inverting logic.");

    if((flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) {
        LOGI("DLI: Process is Root Manager, skipping.");

        return 1;
    }

    if((flags & PROCESS_ON_DENYLIST) == PROCESS_ON_DENYLIST) {
        LOGI("DLI: Process is on denylist, setting mount namespace to Mounted.");

        update_mnt_ns(Mounted);
    } else {
        LOGI("DLI: Process is not on denylist, setting mount namespace to Clean.");

        update_mnt_ns(Clean);
    }

    LOGI("DLI: Finished inverting denylist logic.");

    return 1;
}

struct AtExitEntry {
    void (*func_ptr)(void*);

    void* arg;
    void* dso_handle;
};

struct AtExitArray {
    struct AtExitEntry* array_;
    size_t size_;
    size_t extracted_count_;
    size_t capacity_;
    // An entry can be appended by a __cxa_finalize callback. Track the number of appends so we
    // restart concurrent __cxa_finalize passes.
    uint64_t total_appends_;
};

static size_t system_page_size = 0;

static inline uintptr_t _page_start(uintptr_t addr) {
    return addr & ~(system_page_size - 1);
}

static inline uintptr_t _page_end(uintptr_t addr) {
    return _page_start(addr + system_page_size - 1);
}

void set_writable(struct AtExitArray* array, bool writable, size_t start_idx, size_t num_entries) {
    if(array == NULL || array->array_ == NULL) return;

    size_t start_byte = _page_start(start_idx * sizeof(struct AtExitEntry));
    size_t stop_byte = _page_end((start_idx + num_entries) * sizeof(struct AtExitEntry));
    size_t byte_len = stop_byte - start_byte;

    int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    if(mprotect((char*) array->array_ + start_byte, byte_len, prot) != 0) {
        LOGE("Failed to mprotect atexit array: %s", strerror(errno));

        return;
    }

    LOGI("Atexit array set to %s writable from index %zu to %zu", writable ? "writable" : "read-only", start_idx, start_idx + num_entries - 1);
}

struct map_range {
    uintptr_t start;
    uintptr_t end;
};

int do_atexit_hiding(struct api_table* api_table, JNIEnv* tw_env) {
    (void) api_table;
    (void) tw_env;

    LOGI("AH: Atexit hiding is enabled, hiding traces.");

    long new_system_page_size = sysconf(_SC_PAGESIZE);
    if(new_system_page_size <= 0) {
        LOGE("AH: Failed to get system page size");

        return 0;
    }
    system_page_size = (size_t) new_system_page_size;

    struct elf_img* libc = elf_create("libc.so", NULL);
    if(!libc) {
        LOGE("AH: Failed to create elf image for libc.so");

        return 0;
    }

    struct AtExitArray* atexit_array = (struct AtExitArray*) getSymbAddress(libc, "_ZL7g_array.0");
    if(!atexit_array) {
        atexit_array = (struct AtExitArray*) getSymbAddress(libc, "_ZL7g_array");
        if(!atexit_array) {
            LOGE("AH: Failed to find atexit array");

            elf_destroy(libc);

            return 0;
        }
    }

    set_writable(atexit_array, true, 0, atexit_array->size_);
    size_t old_size = atexit_array->size_;

    LOGD("AH: Found atexit array at %p with size %zu and capacity %zu", (void *)atexit_array->array_, atexit_array->size_, atexit_array->capacity_);

    /* TODO: Optimize by quickly iterating to see which is the real end (without counting
               the Zygisk module handlers), and set the size to there, and before that, memset
               the old ones. */
    for(size_t i = atexit_array->size_; i > 0; i--) {
        struct AtExitEntry* entry = &atexit_array->array_[i - 1];

        if(entry->func_ptr == NULL) {
            size_t remove_index = i - 1;
            if(remove_index + 1 < atexit_array->size_) memmove(&atexit_array->array_[remove_index], &atexit_array->array_[remove_index + 1], (atexit_array->size_ - remove_index - 1) * sizeof(struct AtExitEntry));

            atexit_array->size_--;
            atexit_array->total_appends_--;

            LOGD("AH: Removed atexit entry at index %zu, new size is %zu", remove_index, atexit_array->size_);

            continue;
        }

        Dl_info info;
        if(dladdr((void*) entry->func_ptr, &info) == 0) {
            LOGE("AH: Failed to get dladdr for atexit entry at index %zu (%p), skipping", i - 1, (void *)entry->func_ptr);

            continue;
        }

        if(strstr(info.dli_fname, "libminikin.so") != NULL) {
            LOGD("AH: Found Minikin entry at index %zu, stopping.", i - 1);

            break;
        }

        // LOGD("AH: Atexit entry at index %zu: func_ptr=%p (%s), arg=%p, dso_handle=%p", i - 1, (void *)entry->func_ptr, info.dli_fname, entry->arg, entry->dso_handle);
    }

    size_t old_bytes = _page_end(old_size * sizeof(struct AtExitEntry));
    size_t new_bytes = _page_end(atexit_array->size_ * sizeof(struct AtExitEntry));
    if(new_bytes < old_bytes) {
        madvise(atexit_array->array_ + new_bytes, old_bytes - new_bytes, MADV_DONTNEED);
    }

    set_writable(atexit_array, false, 0, atexit_array->size_);

    elf_destroy(libc);

    LOGI("AH: Finished hiding __cxa_atexit traces.");

    return 1;
}

typedef void SoInfo;

int do_frida_hiding(struct api_table* api_table, JNIEnv* tw_env) {
    (void) api_table;
    (void) tw_env;

    LOGI("FH: Frida hiding is enabled, hiding traces.");

    struct elf_img* linker = elf_create("/linker", NULL);
    if(!linker) {
        LOGE("FH: Failed to create elf image for linker");

        return 0;
    }

    void (*protected_data_protect)(void) = (void (*)(void)) getSymbAddress(linker, "__dl__ZN18ProtectedDataGuardD2Ev");
    if(!protected_data_protect) {
        LOGE("FH: Failed to find protected_data_protect");

        elf_destroy(linker);

        return 0;
    }

    void (*protected_data_unprotect)(void) = (void (*)(void)) getSymbAddress(linker, "__dl__ZN18ProtectedDataGuardC2Ev");
    if(!protected_data_unprotect) {
        LOGE("FH: Failed to find protected_data_unprotect");

        elf_destroy(linker);

        return 0;
    }

    const char*(*get_realpath)(void*) = (const char *(*)(void*)) getSymbAddress(linker, "__dl__ZNK6soinfo12get_realpathEv");
    if(!get_realpath) {
        LOGE("FH: Failed to find get_realpath");

        elf_destroy(linker);

        return 0;
    }

    void (*soinfo_unload)(SoInfo*) = (void (*)(SoInfo*)) getSymbAddressByPrefix(linker, "__dl__ZL13soinfo_unloadP6soinfo");
    if(!soinfo_unload) {
        LOGE("FH: Failed to find soinfo_unload");

        elf_destroy(linker);

        return 0;
    }

    SoInfo*(*solist_get_head)(void) = (SoInfo *(*)(void)) getSymbAddress(linker, "__dl__Z15solist_get_headv");
    if(!solist_get_head) {
        LOGE("FH: Failed to find solist_get_head");

        elf_destroy(linker);

        return 0;
    }

    SoInfo* head = solist_get_head();
    if(!head) {
        LOGE("FH: solist_get_head returned NULL");

        elf_destroy(linker);

        return 0;
    }

    LOGI("FH: Found head of SoInfo list at %p", head);

    SoInfo* somain = getSymbValueByPrefix(linker, "__dl__ZL6somain");
    if(somain == NULL) {
        LOGE("FH: Failed to find somain __dl__ZL6somain");

        elf_destroy(linker);

        return 0;
    }

    SoInfo*(*solist_get_vdso)(void) = (SoInfo *(*)(void)) getSymbAddress(linker, "__dl__Z15solist_get_vdsov");
    if(solist_get_vdso == NULL) {
        LOGE("FH: Failed to find solist_get_vdso");

        elf_destroy(linker);

        return 0;
    }

    SoInfo* vdso = solist_get_vdso();
    LOGI("FH: Found vdso at %p", vdso);

    SoInfo* solinker = getSymbValueByPrefix(linker, "__dl__ZL8solinker");
    if(solinker == NULL) {
        LOGE("FH: Failed to find solinker __dl__ZL8solinker");

        elf_destroy(linker);

        return 0;
    }

    LOGD("FH: Found solinker at %p", solinker);

    int solist_next_offset = -1;
    int solist_size_offset = -1;
    int solist_size_constructors_called_offset = -1;

    for(size_t i = 0; i < 1024 / sizeof(void*); i++) {
        SoInfo* possible_next = *(void**) ((uintptr_t) solist_get_head() + i * sizeof(void*));

        if(solist_next_offset == -1 && (possible_next == somain || possible_next == solinker || (vdso != NULL && possible_next == vdso))) solist_next_offset = i * sizeof(void*);

        size_t possible_size_of_somain = *(size_t*) ((uintptr_t) somain + i * sizeof(void*));

        if(solist_size_offset == -1 && (possible_size_of_somain < 0x100000 && possible_size_of_somain > 0x100)) solist_size_offset = i * sizeof(void*);

        if(solist_size_constructors_called_offset == -1) {
            uintptr_t field_solinker = (uintptr_t) solinker + i * sizeof(void*);
            struct link_map* map = (struct link_map*) field_solinker;

            size_t index_gap = (sizeof(struct link_map) + sizeof(void*) - 1) / sizeof(void*);
            uintptr_t look_forward = (uintptr_t) field_solinker + index_gap * sizeof(void*);

            bool* is_constructors_called = (bool*) look_forward;
            if(*is_constructors_called == true && map->l_name == get_realpath(solinker)) solist_size_constructors_called_offset = look_forward - (uintptr_t) solinker;
        }

        if(solist_next_offset != -1 && solist_size_offset != -1 && solist_size_constructors_called_offset != -1) break;
    }

    if(solist_next_offset == -1 || solist_size_offset == -1 || solist_size_constructors_called_offset == -1) {
        LOGE("FH: Failed to find solist_next offset, solist_size_offset or solist_size_constructors_called_offset");

        elf_destroy(linker);

        return 0;
    }

    LOGI("FH: Found solist_next offset at %d", solist_next_offset);
    LOGI("FH: Found solist_size_offset at %d", solist_size_offset);
    LOGI("FH: Found solist_size_constructors_called_offset at %d", solist_size_constructors_called_offset);

    bool found_frida = false;
    for(SoInfo* so = head; so; so = *(SoInfo**) ((uintptr_t) so + solist_next_offset)) {
        const char* realpath = get_realpath(so);
        if(!realpath || (!str_equal(realpath, "/memfd:frida-agent-64.so") && !str_equal(realpath, "/memfd:frida-agent-32.so"))) continue;

        LOGI("FH: Found frida SoInfo at %p with realpath %s, removing from list", so, realpath);

        found_frida = true;

        (*protected_data_unprotect)();
        *(size_t*) ((uintptr_t) so + solist_size_offset) = 0;
        *(bool*) ((uintptr_t) so + solist_size_constructors_called_offset) = false;
        soinfo_unload(so);
        (*protected_data_protect)();

        break;
    }

    if(found_frida) {
        size_t* g_module_load_counter = (size_t*) getSymbAddress(linker, "__dl__ZL21g_module_load_counter");
        if(g_module_load_counter) {
            LOGI("FH: Found g_module_load_counter at %p, decrementing", (void *)g_module_load_counter);

            (*g_module_load_counter)--;
        }

        size_t* g_module_unload_counter = (size_t*) getSymbAddress(linker, "__dl__ZL23g_module_unload_counter");
        if(g_module_unload_counter) {
            LOGI("FH: Found g_module_unload_counter at %p, decrementing", (void *)g_module_unload_counter);

            (*g_module_unload_counter)--;
        }
    }

    elf_destroy(linker);

    LOGI("FH: Finished hiding Frida traces.");

    return 1;
}
