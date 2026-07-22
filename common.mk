ROOT_DIR ?= .
BUILD_TYPE ?= debug
API_LEVEL ?= 34
ARCHS ?= arm64-v8a armeabi-v7a x86 x64
ARCH ?= arm64-v8a

VER_NAME ?= v0.0.10
VER_CODE ?= $(shell git -C "$(ROOT_DIR)" rev-list HEAD --count 2>/dev/null || echo 1)
COMMIT_HASH ?= $(shell git -C "$(ROOT_DIR)" rev-parse --verify --short HEAD 2>/dev/null || echo unknown)

MODULE_ID ?= treat_wheel
MODULE_NAME ?= Treat Wheel

NDK_VERSION ?= 29.0.14206865
ANDROID_HOME ?= $(HOME)/Android/Sdk
NDK_PATH ?= $(ANDROID_HOME)/ndk/$(NDK_VERSION)
TOOLCHAIN ?= $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64

ifeq ($(TERMUX_VERSION),)
	CC = $(TOOLCHAIN)/bin/clang
	STRIP = $(TOOLCHAIN)/bin/llvm-strip
	SYSROOT ?= $(TOOLCHAIN)/sysroot
else
	CC = clang
	STRIP = llvm-strip
endif
CLANG ?= $(CC)

BUILD_DIR = $(ROOT_DIR)/build
TYPE_DIR = $(BUILD_DIR)/$(BUILD_TYPE)
ZYGISK_PATH = $(TYPE_DIR)/zygisk
CMD_PATH = $(TYPE_DIR)/cmd

TARGET_arm64-v8a = aarch64-linux-android$(API_LEVEL)
TARGET_armeabi-v7a = armv7a-linux-androideabi$(API_LEVEL)
TARGET_x86 = i686-linux-android$(API_LEVEL)
TARGET_x64 = x86_64-linux-android$(API_LEVEL)

ifneq ($(SYSROOT),)
	CC_ARCH = $(CC) --target=$(TARGET_$(ARCH)) --sysroot=$(SYSROOT)
else
	CC_ARCH = $(CC) --target=$(TARGET_$(ARCH))
endif
