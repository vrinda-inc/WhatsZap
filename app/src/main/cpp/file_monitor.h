#ifndef WHATSZAP_FILE_MONITOR_H
#define WHATSZAP_FILE_MONITOR_H

#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <jni.h>

class FileMonitor {
public:
    FileMonitor();
    ~FileMonitor();
    
    // Start monitoring directory
    bool startMonitoring(const std::string& directory, JNIEnv* env, jobject callback);
    void stopMonitoring();
    
    bool isMonitoring() const { return monitoring_; }

private:
    // Pass JavaVM* instead of JNIEnv* to the thread
    void monitorThread(const std::string& directory, JavaVM* jvm, jobject callback);
    
    std::atomic<bool> monitoring_;
    std::atomic<bool> shouldStop_;
    std::thread monitorThread_;
    
    static bool isApkFile(const std::string& filename);
};

#endif // WHATSZAP_FILE_MONITOR_H
