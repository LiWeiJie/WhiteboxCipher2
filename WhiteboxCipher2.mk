LOCAL_PATH := $(call my-dir)
 
$(warning  ****LOCAL_PATH**** )
$(warning  $(LOCAL_PATH))
 
include $(CLEAR_VARS)

LOCAL_MODULE := AisinoSSL    
LOCAL_SRC_FILES := lib/android/armeabi-v7a/libaisinossl.so		
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/AisinoSSL
include $(PREBUILT_SHARED_LIBRARY)    
 
include $(CLEAR_VARS)


LOCAL_MODULE := MatrixLib    
LOCAL_SRC_FILES := lib/android/armeabi-v7a/libMatrixLib.so		
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/matrixLib
include $(PREBUILT_SHARED_LIBRARY)    
 
include $(CLEAR_VARS)

LOCAL_MODULE    := ShitAdd-test
LOCAL_SRC_FILES := WMNetSdkTest.cpp
 
LOCAL_SHARED_LIBRARIES  := libShitAdd 
LOCAL_LDLIBS    := -llog -lz -lm 
include $(BUILD_SHARED_LIBRARY)

#
# WhiteboxCipher2.main.mk
# For Android WhiteboxCipher2 Library
#
# Only compile WhiteboxCipher2 (Base modules, except SM4 White box)
#
# ONLY SUPPORT 32bits OS
#

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
APP_BUILD_SCRIPT := WhiteboxCipher2.mk
NDK_APP_DST_DIR := ./android-lib/$(TARGET_ARCH_ABI)

# Target filename
LOCAL_MODULE := wbc2
APP_ABI := armeabi-v7a x86
# NOT SUPPORT armeabi
# PARTICULAR SUPPORT x64

APP_PLATFORM := android-14 # >= 4.0

# APP_STL := c++_static # OLLVM
APP_CPPFLAGS += -frtti -fexceptions -fvisibility=hidden

# Required Modules
LOCAL_CFLAGS += -DANDROID_VER -DANDROID_MK_VER
LOCAL_CFLAGS += -D__ANDROID__

MY_HEADER_FILES_PATH := $(LOCAL_PATH)/include/

MY_SOURCE_FILES_PATH := $(LOCAL_PATH)/library

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

# Include source files
LOCAL_SRC_FILES := $(wildcard $(MY_SOURCE_FILES_PATH)/feistalBox/*.c)
LOCAL_SRC_FILES += $(wildcard $(MY_SOURCE_FILES_PATH)/wbc2/*.c)

LOCAL_SHARED_LIBRARIES  :=  libAisinoSSL
LOCAL_SHARED_LIBRARIES  +=  libMatrixLib

LOCAL_LDLIBS += -landroid
LOCAL_LDLIBS += -llog # When Debug

include $(BUILD_SHARED_LIBRARY)
