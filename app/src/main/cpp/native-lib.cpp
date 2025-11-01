#include <jni.h>
#include <string>
#include <android/log.h>
#include "file_monitor.h"
#include "malware_scanner.h"

#define LOG_TAG "WhatsZapNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// Global file monitor instance
static FileMonitor* g_fileMonitor = nullptr;

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_whatszap_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    LOGI("Native library loaded successfully");
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_example_whatszap_FileMonitorService_nativeCreateFileMonitor(
        JNIEnv* env,
        jobject /* this */) {
    LOGI("Creating file monitor");
    FileMonitor* monitor = new FileMonitor();
    return reinterpret_cast<jlong>(monitor);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_whatszap_FileMonitorService_nativeStartMonitoring(
        JNIEnv* env,
        jobject /* this */,
        jlong nativeHandle,
        jstring directory,
        jobject callback) {
    if (nativeHandle == 0) {
        LOGE("Invalid native handle");
        return JNI_FALSE;
    }
    
    if (directory == nullptr || callback == nullptr) {
        LOGE("Invalid parameters: directory or callback is null");
        return JNI_FALSE;
    }
    
    try {
        FileMonitor* monitor = reinterpret_cast<FileMonitor*>(nativeHandle);
        const char* dirStr = env->GetStringUTFChars(directory, nullptr);
        if (dirStr == nullptr) {
            LOGE("Failed to get directory string");
            return JNI_FALSE;
        }
        
        std::string dir(dirStr);
        env->ReleaseStringUTFChars(directory, dirStr);
        
        bool result = monitor->startMonitoring(dir, env, callback);
        
        if (env->ExceptionCheck()) {
            LOGE("Exception occurred in startMonitoring");
            env->ExceptionDescribe();
            env->ExceptionClear();
            return JNI_FALSE;
        }
        
        return result ? JNI_TRUE : JNI_FALSE;
    } catch (const std::exception& e) {
        LOGE("Exception in nativeStartMonitoring: %s", e.what());
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_whatszap_FileMonitorService_nativeStopMonitoring(
        JNIEnv* env,
        jobject /* this */,
        jlong nativeHandle) {
    if (nativeHandle == 0) {
        return;
    }
    
    FileMonitor* monitor = reinterpret_cast<FileMonitor*>(nativeHandle);
    monitor->stopMonitoring();
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_whatszap_FileMonitorService_nativeDestroyFileMonitor(
        JNIEnv* env,
        jobject /* this */,
        jlong nativeHandle) {
    if (nativeHandle == 0) {
        return;
    }
    
    FileMonitor* monitor = reinterpret_cast<FileMonitor*>(nativeHandle);
    delete monitor;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_example_whatszap_FileMonitorService_nativeCreateMalwareScanner(
        JNIEnv* env,
        jobject /* this */) {
    LOGI("Creating malware scanner");
    MalwareScanner* scanner = new MalwareScanner();
    return reinterpret_cast<jlong>(scanner);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_example_whatszap_FileMonitorService_nativeScanApk(
        JNIEnv* env,
        jobject /* this */,
        jlong nativeHandle,
        jstring apkPath) {
    if (nativeHandle == 0) {
        LOGE("Invalid native handle");
        return nullptr;
    }
    
    if (apkPath == nullptr) {
        LOGE("Invalid apkPath parameter");
        return nullptr;
    }
    
    try {
        MalwareScanner* scanner = reinterpret_cast<MalwareScanner*>(nativeHandle);
        const char* pathStr = env->GetStringUTFChars(apkPath, nullptr);
        if (pathStr == nullptr) {
            LOGE("Failed to get apkPath string");
            return nullptr;
        }
        
        std::string path(pathStr);
        env->ReleaseStringUTFChars(apkPath, pathStr);
        
        ScanResult result = scanner->scanApk(path);
        
        // Create Java ScanResult object
        jclass resultClass = env->FindClass("com/example/whatszap/ScanResult");
        if (!resultClass) {
            LOGE("Could not find ScanResult class");
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            return nullptr;
        }
        
        jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZILjava/util/List;J)V");
        if (!constructor) {
            LOGE("Could not find ScanResult constructor");
            env->DeleteLocalRef(resultClass);
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            return nullptr;
        }
        
        // Create ArrayList for threats
        jclass arrayListClass = env->FindClass("java/util/ArrayList");
        if (!arrayListClass) {
            LOGE("Could not find ArrayList class");
            env->DeleteLocalRef(resultClass);
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            return nullptr;
        }
        
        jmethodID arrayListConstructor = env->GetMethodID(arrayListClass, "<init>", "(I)V");
        jmethodID arrayListAdd = env->GetMethodID(arrayListClass, "add", "(Ljava/lang/Object;)Z");
        
        if (!arrayListConstructor || !arrayListAdd) {
            LOGE("Could not find ArrayList methods");
            env->DeleteLocalRef(resultClass);
            env->DeleteLocalRef(arrayListClass);
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            return nullptr;
        }
        
        jobject threatsList = env->NewObject(arrayListClass, arrayListConstructor, result.threats.size());
        if (!threatsList) {
            LOGE("Failed to create ArrayList");
            env->DeleteLocalRef(resultClass);
            env->DeleteLocalRef(arrayListClass);
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            return nullptr;
        }
        
        for (const auto& threat : result.threats) {
            jstring threatStr = env->NewStringUTF(threat.c_str());
            if (threatStr) {
                env->CallBooleanMethod(threatsList, arrayListAdd, threatStr);
                if (env->ExceptionCheck()) {
                    LOGE("Exception adding threat to list");
                    env->ExceptionDescribe();
                    env->ExceptionClear();
                }
                env->DeleteLocalRef(threatStr);
            }
        }
        
        jobject javaResult = env->NewObject(resultClass, constructor,
            result.isMalicious ? JNI_TRUE : JNI_FALSE,
            result.confidence,
            threatsList,
            result.scanDuration);
        
        env->DeleteLocalRef(threatsList);
        env->DeleteLocalRef(resultClass);
        env->DeleteLocalRef(arrayListClass);
        
        if (env->ExceptionCheck()) {
            LOGE("Exception creating ScanResult object");
            env->ExceptionDescribe();
            env->ExceptionClear();
            return nullptr;
        }
        
        return javaResult;
    } catch (const std::exception& e) {
        LOGE("Exception in nativeScanApk: %s", e.what());
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return nullptr;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_whatszap_FileMonitorService_nativeDestroyMalwareScanner(
        JNIEnv* env,
        jobject /* this */,
        jlong nativeHandle) {
    if (nativeHandle == 0) {
        return;
    }
    
    MalwareScanner* scanner = reinterpret_cast<MalwareScanner*>(nativeHandle);
    delete scanner;
}

