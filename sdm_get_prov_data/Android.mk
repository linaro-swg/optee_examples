###################### optee-sdm-get-prov-data ######################
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += -Wall

LOCAL_SRC_FILES += host/main.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/ta/include

LOCAL_SHARED_LIBRARIES := libteec
LOCAL_MODULE := sdm_get_prov_data
LOCAL_VENDOR_MODULE := true
LOCAL_MODULE_TAGS := optional
include $(LOCAL_PATH)/ta/Android.mk
