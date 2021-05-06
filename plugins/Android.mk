LOCAL_PATH := $(call my-dir)

###################### optee-plugins ######################
include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += -Wall

LOCAL_SRC_FILES += host/main.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/ta/include

LOCAL_SHARED_LIBRARIES := libteec
LOCAL_MODULE := optee_example_plugins
LOCAL_VENDOR_MODULE := true
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

###################### optee-plugins libs #################
include $(CLEAR_VARS)

PLUGIN_UUID = 96bcf744-4f72-4866-bf1d-8634fd9c65e5

PLUGIN                  = $(PLUGIN_UUID).plugin
PLUGIN_INCLUDES_DIR     = $(LOCAL_PATH)/syslog

LOCAL_MODULE := $(PLUGIN)
LOCAL_MODULE_RELATIVE_PATH := tee-supplicant/plugins
LOCAL_VENDOR_MODULE := true
# below is needed to locate optee_client exported headers
LOCAL_SHARED_LIBRARIES := libteec

LOCAL_SRC_FILES += syslog/syslog_plugin.c
LOCAL_C_INCLUDES += $(PLUGIN_INCLUDES_DIR)

LOCAL_MODULE_TAGS := optional

# Build the 32-bit and 64-bit versions.
LOCAL_MULTILIB := both
LOCAL_MODULE_TARGET_ARCH := arm arm64

include $(BUILD_SHARED_LIBRARY)

###################### TA #################################
include $(LOCAL_PATH)/ta/Android.mk
