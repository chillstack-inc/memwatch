LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := memwatch

LOCAL_SRC_FILES := memwatch.cpp

LOCAL_CFLAGS := -std=c++17
LOCAL_LDFLAGS := -llog
include $(BUILD_EXECUTABLE)