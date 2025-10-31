#ifndef WHATSZAP_NATIVE_LIB_H
#define WHATSZAP_NATIVE_LIB_H

#include <jni.h>
#include <string>
#include <android/log.h>

// Logging macros
#define LOG_TAG "WhatsZapNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

#endif // WHATSZAP_NATIVE_LIB_H

