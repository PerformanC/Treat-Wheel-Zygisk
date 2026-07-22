include common.mk

CFILES_ZYGISK = src/lib/elf_util.c src/lib/hiding.c src/lib/main.c src/lib/rz_daemon.c src/lib/utils.c
CFILES_CMD = src/cmd/main.c src/cmd/utils.c src/lib/utils.c src/system_properties/src/*.c

CFLAGS = -llog -fvisibility=hidden -fvisibility-inlines-hidden -Wpedantic     \
         -Wall -Wextra -Werror -Wformat -Wuninitialized -Wshadow -std=c99     \
         -Wno-unused-function -D_GNU_SOURCE -fPIC -Wno-c2x-extensions         \
         -Wno-gnu-zero-variadic-macro-arguments                               \
		 -Wno-gnu-statement-expression-from-macro-expansion

ifeq ($(BUILD_TYPE), debug)
	CFLAGS += -DDEBUG -O0 -g
else
	CFLAGS += -flto=full -s -Wl,--strip-all -Wl,--exclude-libs,ALL -Wl,--as-needed
endif

ifeq ($(TERMUX_VERSION),)
	ADB_PUSH := adb push
	ADB_SHELL := adb shell 
else
	ADB_PUSH := su -c cp -r
endif

VERSION ?= $(VER_CODE)-$(COMMIT_HASH)-$(BUILD_TYPE)
MODULE_ZIP ?= TreatWheel-$(VER_NAME)-$(VERSION).zip
ZIP_OUT ?= $(BUILD_DIR)/out/$(MODULE_ZIP)

.PHONY: all build release debug installModule installModuleAndReboot updateWebUI

debug:
	$(MAKE) -s build BUILD_TYPE=debug
release:
	$(MAKE) -s build BUILD_TYPE=release

all: debug release

build:
	@echo Creating required directories...
	@mkdir -p $(ZYGISK_PATH) > /dev/null
	@mkdir -p $(CMD_PATH) > /dev/null
	@mkdir -p $(BUILD_DIR)/out > /dev/null
	@cp -r module/src/* $(TYPE_DIR)

	@for arch in $(ARCHS); do  \
	  echo "Compiling for $$arch...";  \
	  $(MAKE) -s compile_arch ARCH=$$arch;  \
	done

	@echo Preparing module.prop...
	@sed -e 's/$${moduleId}/$(MODULE_ID)/g'                                             \
	    -e 's/$${moduleName}/$(MODULE_NAME)/g'                                          \
	    -e 's/$${versionName}/$(VER_NAME) ($(VERSION))/g' \
	    -e 's/$${versionCode}/$(VER_CODE)/g'                                            \
	    module/src/module.prop > $(TYPE_DIR)/module.prop

	@echo Creating zip...

	@rm -rf $(TYPE_DIR)/webroot
	@cp -r src/webroot $(TYPE_DIR)

	@if [ "$(IS_GITHUB_ACTION)" = "true" ]; then \
		echo Detected CI environment. Modifying web UI for CI build...; \
		sed -i 's/ display: none;//g' $(TYPE_DIR)/webroot/js/pages/home/index.html; \
	fi

	@rm -rf $(ZIP_OUT)
	@(cd $(TYPE_DIR) && zip -r ../out/$(MODULE_ZIP) .) > /dev/null

compile_arch:
	@mkdir -p $(ZYGISK_PATH)/$(ARCH) > /dev/null
	@mkdir -p $(CMD_PATH)/$(ARCH) > /dev/null

	@$(CLANG) --target=$(TARGET_$(ARCH)) -fPIC -DIS_ZYGISK_LIB $(CFILES_ZYGISK) $(CFLAGS) -nostartfiles -shared -o $(ZYGISK_PATH)/$(ARCH)/libexample.so
	@$(CLANG) --target=$(TARGET_$(ARCH)) -fPIC -DIS_CMD $(CFILES_CMD) $(CFLAGS) -Isrc/system_properties/include -DUTILS_NO_SSL -o $(CMD_PATH)/$(ARCH)/treat-wheel

	@$(STRIP) --strip-all $(ZYGISK_PATH)/$(ARCH)/libexample.so
	@$(STRIP) --strip-all $(CMD_PATH)/$(ARCH)/treat-wheel

clean:
	@echo Cleaning build artifacts...
	@rm -rf $(BUILD_DIR)

installModule: build
	$(ADB_PUSH) $(ZIP_OUT) /data/local/tmp
	@$(ADB_SHELL)su -M -c "magisk --install-module /data/local/tmp/$(MODULE_ZIP) 2&>/dev/null"|| \
	$(ADB_SHELL)su -c "ksud module install /data/local/tmp/$(MODULE_ZIP) 2&>/dev/null"||        \
	$(ADB_SHELL)su -c "apd module install /data/local/tmp/$(MODULE_ZIP) 2&>/dev/null"           \
	&& $(ADB_SHELL)su -c rm /data/local/tmp/$(MODULE_ZIP)                                       \
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
