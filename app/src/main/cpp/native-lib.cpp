#include "file_monitor.h"
#include "malware_scanner.h"
#include <android/log.h>
#include <jni.h>
#include <string>

#define LOG_TAG "WhatsZapNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// Global file monitor instance
static FileMonitor *g_fileMonitor = nullptr;

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_whatszap_MainActivity_stringFromJNI(JNIEnv *env,
                                                     jobject /* this */) {
  std::string hello = "Hello from C++";
  LOGI("Native library loaded successfully");
  return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_example_whatszap_FileMonitorService_nativeCreateFileMonitor(
    JNIEnv *env, jobject /* this */) {
  LOGI("Creating file monitor");
  FileMonitor *monitor = new FileMonitor();
  return reinterpret_cast<jlong>(monitor);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_whatszap_FileMonitorService_nativeStartMonitoring(
    JNIEnv *env, jobject /* this */, jlong nativeHandle, jstring directory,
    jobject callback) {
  if (nativeHandle == 0) {
    LOGE("Invalid native handle");
    return JNI_FALSE;
  }

  FileMonitor *monitor = reinterpret_cast<FileMonitor *>(nativeHandle);
  const char *dirStr = env->GetStringUTFChars(directory, nullptr);
  std::string dir(dirStr);
  env->ReleaseStringUTFChars(directory, dirStr);

  bool result = monitor->startMonitoring(dir, env, callback);
  return result ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_whatszap_FileMonitorService_nativeStopMonitoring(
    JNIEnv *env, jobject /* this */, jlong nativeHandle) {
  if (nativeHandle == 0) {
    return;
  }

  FileMonitor *monitor = reinterpret_cast<FileMonitor *>(nativeHandle);
  monitor->stopMonitoring();
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_whatszap_FileMonitorService_nativeDestroyFileMonitor(
    JNIEnv *env, jobject /* this */, jlong nativeHandle) {
  if (nativeHandle == 0) {
    return;
  }

  FileMonitor *monitor = reinterpret_cast<FileMonitor *>(nativeHandle);
  delete monitor;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_example_whatszap_FileMonitorService_nativeCreateMalwareScanner(
    JNIEnv *env, jobject /* this */) {
  LOGI("Creating malware scanner");
  MalwareScanner *scanner = new MalwareScanner();
  return reinterpret_cast<jlong>(scanner);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_example_whatszap_FileMonitorService_nativeScanApk(JNIEnv *env,
                                                           jobject /* this */,
                                                           jlong nativeHandle,
                                                           jstring apkPath) {
  if (nativeHandle == 0) {
    LOGE("Invalid native handle");
    return nullptr;
  }

  MalwareScanner *scanner = reinterpret_cast<MalwareScanner *>(nativeHandle);
  const char *pathStr = env->GetStringUTFChars(apkPath, nullptr);
  std::string path(pathStr);
  env->ReleaseStringUTFChars(apkPath, pathStr);

  ScanResult result = scanner->scanApk(path);

  // Create Java ScanResult object using the companion object factory method
  jclass resultClass = env->FindClass("com/example/whatszap/ScanResult");
  if (!resultClass) {
    LOGE("Could not find ScanResult class");
    return nullptr;
  }

  // Find the companion object
  jclass companionClass =
      env->FindClass("com/example/whatszap/ScanResult$Companion");
  if (!companionClass) {
    LOGE("Could not find ScanResult$Companion class");
    env->DeleteLocalRef(resultClass);
    return nullptr;
  }

  // Get the companion instance field
  jfieldID companionField = env->GetStaticFieldID(
      resultClass, "Companion", "Lcom/example/whatszap/ScanResult$Companion;");
  if (!companionField) {
    LOGE("Could not find Companion field");
    env->DeleteLocalRef(resultClass);
    env->DeleteLocalRef(companionClass);
    return nullptr;
  }

  jobject companion = env->GetStaticObjectField(resultClass, companionField);
  if (!companion) {
    LOGE("Could not get Companion instance");
    env->DeleteLocalRef(resultClass);
    env->DeleteLocalRef(companionClass);
    return nullptr;
  }

  // Find the factory method on the companion
  jmethodID factoryMethod = env->GetMethodID(
      companionClass, "createFromNative",
      "(ZILjava/util/List;J)Lcom/example/whatszap/ScanResult;");
  if (!factoryMethod) {
    LOGE("Could not find createFromNative method");
    env->DeleteLocalRef(resultClass);
    env->DeleteLocalRef(companionClass);
    env->DeleteLocalRef(companion);
    return nullptr;
  }

  // Create ArrayList for threats
  jclass arrayListClass = env->FindClass("java/util/ArrayList");
  jmethodID arrayListConstructor =
      env->GetMethodID(arrayListClass, "<init>", "(I)V");
  jmethodID arrayListAdd =
      env->GetMethodID(arrayListClass, "add", "(Ljava/lang/Object;)Z");

  jobject threatsList = env->NewObject(arrayListClass, arrayListConstructor,
                                       (jint)result.threats.size());

  for (const auto &threat : result.threats) {
    jstring threatStr = env->NewStringUTF(threat.c_str());
    env->CallBooleanMethod(threatsList, arrayListAdd, threatStr);
    env->DeleteLocalRef(threatStr);
  }

  // Call the factory method
  jobject javaResult = env->CallObjectMethod(
      companion, factoryMethod, result.isMalicious ? JNI_TRUE : JNI_FALSE,
      result.confidence, threatsList, (jlong)result.scanDuration);

  // Cleanup local references
  env->DeleteLocalRef(threatsList);
  env->DeleteLocalRef(resultClass);
  env->DeleteLocalRef(companionClass);
  env->DeleteLocalRef(companion);
  env->DeleteLocalRef(arrayListClass);

  return javaResult;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_whatszap_FileMonitorService_nativeDestroyMalwareScanner(
    JNIEnv *env, jobject /* this */, jlong nativeHandle) {
  if (nativeHandle == 0) {
    return;
  }

  MalwareScanner *scanner = reinterpret_cast<MalwareScanner *>(nativeHandle);
  delete scanner;
}
