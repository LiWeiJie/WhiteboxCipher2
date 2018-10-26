#
# Application.mk
# For Android AisinoSSL Library
#
# ONLY SUPPORT 32bits OS
#


LOCAL_PATH := $(call my-dir)


include $(CLEAR_VARS)
APP_BUILD_SCRIPT := WhiteboxCipher2.mk
NDK_APP_DST_DIR := ./android-lib/$(TARGET_ARCH_ABI)

include $(CLEAR_VARS)

LOCAL_MODULE := MatrixLib
LOCAL_SRC_FILES := lib/android/armeabi-v7a/libMatrixLib.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := AisinoSSL
LOCAL_SRC_FILES := lib/android/armeabi-v7a/libaisinossl.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)

APP_ABI := armeabi-v7a
# PARTICULAR SUPPORT x64
#LOCAL_LDFLAGS:=$(LOCAL_PATH)/lib/android/armeabi-v7a/libMatrixLib.so
#LOCAL_LDFLAGS+=$(LOCAL_PATH)/lib/android/armeabi-v7a/libaisinossl.so
APP_PLATFORM := android-14 # >= 4.0

APP_STL := c++_static # OLLVM
APP_CPPFLAGS += -frtti -fexceptions -fvisibility=hidden

# Required Modules
#LOCAL_LDFLAGS := -L./lib/android/armeabi-v7a libMatrixLib.so
#LOCAL_LDFLAGS := -L./lib/android/armeabi-v7a libaisinossl.so




MY_HEADER_FILES_PATH := $(LOCAL_PATH)/include/

MY_SOURCE_FILES_PATH := $(LOCAL_PATH)/library/

# Debug / Production
ifeq ($(DEBUG),1)
APP_CFLAGS += -O0 -g
APP_OPTIM := debug
else
APP_CFLAGS += -O3
APP_OPTIM := release
endif

# Include headers
LOCAL_C_INCLUDES := $(MY_HEADER_FILES_PATH)
LOCAL_LDFLAGS += -fuse-ld=bfd

$(warning  $(LOCAL_C_INCLUDES))

# Include source files
MY_FILES_SUFFIX := %.c
rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

MY_ALL_FILES := $(foreach src_path,$(MY_SOURCE_FILES_PATH), $(call rwildcard,$(src_path),*.*) )
MY_ALL_FILES += $(foreach src_path,$(M4RI_SOURCE_FILES_PATH), $(call rwildcard,$(src_path),*.*) )
#$(warning $(MY_ALL_FILES))
MY_ALL_FILES := $(MY_ALL_FILES:$(MY_CPP_PATH)/./%=$(MY_CPP_PATH)%)
MY_SRC_LIST  := $(filter $(MY_FILES_SUFFIX),$(MY_ALL_FILES))
MY_SRC_LIST  := $(MY_SRC_LIST:$(LOCAL_PATH)/%=%)

LOCAL_MODULE := wbc2
LOCAL_SRC_FILES := $(MY_SRC_LIST)
# LOCAL_CFLAGS += -DANDROID_VER -DANDROID_MK_VER
LOCAL_CFLAGS += -D__ANDROID__
LOCAL_SHARED_LIBRARIES := AisinoSSL
LOCAL_SHARED_LIBRARIES += MatrixLib

LOCAL_LDLIBS += -llog # When Debug

include $(BUILD_SHARED_LIBRARY)