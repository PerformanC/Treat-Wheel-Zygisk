BUILD_PATH = build/src
ZYGISK_PATH = $(BUILD_PATH)/zygisk
CMD_PATH = $(BUILD_PATH)/cmd

ARCHS ?= arm64-v8a armeabi-v7a x86 x64
ARCH ?= arm64-v8a

API_LEVEL ?= 34

TARGET_arm64-v8a = aarch64-linux-android$(API_LEVEL)
TARGET_armeabi-v7a = armv7a-linux-androideabi$(API_LEVEL)
TARGET_x86 = i686-linux-android$(API_LEVEL)
TARGET_x64 = x86_64-linux-android$(API_LEVEL)

CFILES_ZYGISK = src/lib/elf_util.c src/lib/hiding.c src/lib/main.c src/lib/rz_daemon.c src/lib/utils.c
CFILES_CMD = src/cmd/main.c src/cmd/utils.c src/lib/utils.c src/system_properties/src/*.c

CFLAGS = -llog -fvisibility=hidden -fvisibility-inlines-hidden -Wpedantic     \
         -Wall -Wextra -Werror -Wformat -Wuninitialized -Wshadow -std=c99     \
         -Wno-unused-function -D_GNU_SOURCE -fPIC -Wno-c2x-extensions         \
         -Wno-gnu-zero-variadic-macro-arguments                               \
		 -Wno-gnu-statement-expression-from-macro-expansion


ifeq ($(TERMUX_VERSION),)
	ADB_PUSH := adb push
	ADB_SHELL := adb shell 

	ifeq ($(IS_GITHUB_ACTION),true)
		CC ?= $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
		STRIP ?= $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
	else
		CC ?= $(ANDROID_HOME)/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
		STRIP ?= $(ANDROID_HOME)/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
	endif
else
	ADB_PUSH := su -c cp -r
	CC ?= clang
	STRIP ?= llvm-strip
endif

ifeq ($(BUILD_TYPE), debug)
	CFLAGS += -DDEBUG -O0 -g
else
	CFLAGS += -flto=full -s -Wl,--strip-all -Wl,--exclude-libs,ALL -Wl,--as-needed
endif


CLANG ?= $(CC)

.PHONY: all build release debug installModule installModuleAndReboot updateWebUI

all: debug

debug:
	$(MAKE) -s build BUILD_TYPE=debug
release:
	$(MAKE) -s build BUILD_TYPE=release

build:
	@echo Creating required directories...
	@mkdir -p $(ZYGISK_PATH) > /dev/null
	@mkdir -p $(CMD_PATH) > /dev/null

	@for arch in $(ARCHS); do  \
	  echo "Compiling for $$arch...";  \
	  $(MAKE) -s compile_arch ARCH=$$arch;  \
	done

	@echo Copying module.prop file...
	@cp $(BUILD_PATH)/../module.prop $(BUILD_PATH)/module.prop

	@echo Creating zip...

	@rm -rf $(BUILD_PATH)/webroot
	@cp -r src/webroot $(BUILD_PATH)

	@if [ "$(IS_GITHUB_ACTION)" = "true" ]; then \
		echo Detected CI environment. Modifying web UI for CI build...; \
		sed -i 's/ display: none;//g' $(BUILD_PATH)/webroot/js/pages/home/index.html; \
	fi

	@rm -rf ../build/TreatWheel.zip
	@(cd $(BUILD_PATH) && zip -r ../TreatWheel.zip .) > /dev/null

compile_arch:
	@mkdir -p $(ZYGISK_PATH)/$(ARCH) > /dev/null
	@mkdir -p $(CMD_PATH)/$(ARCH) > /dev/null

	@$(CLANG) --target=$(TARGET_$(ARCH)) -fPIC -DIS_ZYGISK_LIB $(CFILES_ZYGISK) $(CFLAGS) -nostartfiles -shared -o $(ZYGISK_PATH)/$(ARCH)/libexample.so
	@$(CLANG) --target=$(TARGET_$(ARCH)) -fPIC -DIS_CMD $(CFILES_CMD) $(CFLAGS) -Isrc/system_properties/include -DUTILS_NO_SSL -o $(CMD_PATH)/$(ARCH)/treat-wheel

	@$(STRIP) --strip-all $(ZYGISK_PATH)/$(ARCH)/libexample.so
	@$(STRIP) --strip-all $(CMD_PATH)/$(ARCH)/treat-wheel

clean:
	@echo Cleaning build artifacts...
	@rm -rf $(BUILD_PATH)/cmd
	@rm -rf $(BUILD_PATH)/zygisk
	@rm -rf $(BUILD_PATH)/webroot
	@rm -rf ../build/TreatWheel.zip > /dev/null

installModule: build
	$(ADB_PUSH) build/TreatWheel.zip /data/local/tmp
	@$(ADB_SHELL)su -M -c "magisk --install-module /data/local/tmp/TreatWheel.zip 2&>/dev/null"|| \
	$(ADB_SHELL)su -c "ksud module install /data/local/tmp/TreatWheel.zip 2&>/dev/null"||        \
	$(ADB_SHELL)su -c "apd module install /data/local/tmp/TreatWheel.zip 2&>/dev/null"           \
	&& $(ADB_SHELL)su -c rm /data/local/tmp/TreatWheel.zip                                       \
	|| echo "[X] Could not find valid CLI to install the module"

installModuleAndReboot: installModule
	$(ADB_SHELL)su -c reboot

updateWebUI:
	@echo Updating web UI...
	@$(ADB_SHELL)su -c "rm -rf /data/local/tmp/webroot"
	@$(ADB_PUSH) src/webroot /data/local/tmp/webroot
	@$(ADB_SHELL)su -c "rm -rf /data/adb/modules/treat_wheel/webroot"
	@$(ADB_SHELL)su -c "cp -r /data/local/tmp/webroot /data/adb/modules/treat_wheel"
	@$(ADB_SHELL)su -c "rm -rf /data/local/tmp/webroot"
