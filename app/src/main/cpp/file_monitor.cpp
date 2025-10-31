#include "file_monitor.h"
#include "native-lib.h"
#include <sys/inotify.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <algorithm>
#include <sys/select.h>
#include <jni.h>

FileMonitor::FileMonitor() : monitoring_(false), shouldStop_(false) {
}

FileMonitor::~FileMonitor() {
    stopMonitoring();
}

bool FileMonitor::startMonitoring(const std::string& directory, JNIEnv* env, jobject callback) {
    if (monitoring_) {
        LOGW("Already monitoring");
        return false;
    }
    
    // Check if directory exists
    struct stat dirStat;
    if (stat(directory.c_str(), &dirStat) != 0 || !S_ISDIR(dirStat.st_mode)) {
        LOGE("Directory does not exist: %s", directory.c_str());
        return false;
    }
    
    // Create global reference to callback
    jobject globalCallback = env->NewGlobalRef(callback);
    
    shouldStop_ = false;
    monitoring_ = true;
    
    // Start monitoring thread
    monitorThread_ = std::thread(&FileMonitor::monitorThread, this, directory, env, globalCallback);
    
    LOGI("Started monitoring directory: %s", directory.c_str());
    return true;
}

void FileMonitor::stopMonitoring() {
    if (!monitoring_) {
        return;
    }
    
    shouldStop_ = true;
    monitoring_ = false;
    
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
    
    LOGI("Stopped monitoring");
}

void FileMonitor::monitorThread(const std::string& directory, JNIEnv* env, jobject callback) {
    // Attach thread to JVM
    JavaVM* jvm;
    env->GetJavaVM(&jvm);
    JNIEnv* threadEnv;
    jvm->AttachCurrentThread(&threadEnv, nullptr);
    
    // Create inotify instance
    int inotifyFd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (inotifyFd < 0) {
        LOGE("Failed to initialize inotify: %s", strerror(errno));
        monitoring_ = false;
        jvm->DetachCurrentThread();
        return;
    }
    
    // Add watch for directory
    int wd = inotify_add_watch(inotifyFd, directory.c_str(), 
        IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE);
    if (wd < 0) {
        LOGE("Failed to add watch for %s: %s", directory.c_str(), strerror(errno));
        close(inotifyFd);
        monitoring_ = false;
        jvm->DetachCurrentThread();
        return;
    }
    
    LOGI("Added watch for: %s (wd=%d)", directory.c_str(), wd);
    
    char buffer[1024 * 1024]; // 1MB buffer
    
    while (!shouldStop_ && monitoring_) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(inotifyFd, &readfds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int ret = select(inotifyFd + 1, &readfds, nullptr, nullptr, &timeout);
        
        if (ret < 0) {
            if (errno != EINTR) {
                LOGE("select error: %s", strerror(errno));
                break;
            }
            continue;
        }
        
        if (ret == 0) {
            // Timeout - continue monitoring
            continue;
        }
        
        if (FD_ISSET(inotifyFd, &readfds)) {
            ssize_t length = read(inotifyFd, buffer, sizeof(buffer));
            
            if (length < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOGE("read error: %s", strerror(errno));
                }
                continue;
            }
            
            int i = 0;
            while (i < length) {
                struct inotify_event* event = (struct inotify_event*)&buffer[i];
                
                if (event->len > 0) {
                    std::string filename(event->name);
                    
                    // Check if it's an APK file
                    if (isApkFile(filename)) {
                        std::string fullPath = directory + "/" + filename;
                        
                        // Wait a bit to ensure file is fully written
                        usleep(500000); // 500ms
                        
                        // Verify file exists
                        struct stat fileStat;
                        if (stat(fullPath.c_str(), &fileStat) == 0 && 
                            S_ISREG(fileStat.st_mode)) {
                            LOGI("APK file detected: %s", fullPath.c_str());
                            
                            // Call Java callback
                            jclass callbackClass = threadEnv->GetObjectClass(callback);
                            jmethodID methodId = threadEnv->GetMethodID(callbackClass, "onApkDetected", "(Ljava/lang/String;)V");
                            
                            if (methodId) {
                                jstring jPath = threadEnv->NewStringUTF(fullPath.c_str());
                                threadEnv->CallVoidMethod(callback, methodId, jPath);
                                threadEnv->DeleteLocalRef(jPath);
                            }
                            threadEnv->DeleteLocalRef(callbackClass);
                        }
                    }
                }
                
                i += sizeof(struct inotify_event) + event->len;
            }
        }
    }
    
    // Cleanup
    inotify_rm_watch(inotifyFd, wd);
    close(inotifyFd);
    monitoring_ = false;
    
    // Cleanup global reference
    threadEnv->DeleteGlobalRef(callback);
    
    LOGI("Monitor thread exiting");
    jvm->DetachCurrentThread();
}

bool FileMonitor::isApkFile(const std::string& filename) {
    if (filename.length() < 4) {
        return false;
    }
    
    std::string lower = filename;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    return lower.substr(lower.length() - 4) == ".apk";
}

