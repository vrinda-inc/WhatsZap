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
    
    // Get JavaVM before creating thread (JNIEnv is thread-local)
    JavaVM* jvm;
    if (env->GetJavaVM(&jvm) != JNI_OK) {
        LOGE("Failed to get JavaVM");
        return false;
    }
    
    // Create global reference to callback
    jobject globalCallback = env->NewGlobalRef(callback);
    if (!globalCallback) {
        LOGE("Failed to create global reference to callback");
        return false;
    }
    
    shouldStop_ = false;
    monitoring_ = true;
    
    // Start monitoring thread with JavaVM instead of JNIEnv
    // Use a lambda to safely capture all parameters
    monitorThread_ = std::thread([this, directory, jvm, globalCallback]() {
        this->monitorThread(directory, jvm, globalCallback);
    });
    
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

void FileMonitor::monitorThread(std::string directory, JavaVM* jvm, jobject callback) {
    LOGI("Monitor thread started for directory: %s", directory.c_str());
    
    // Validate parameters
    if (!jvm) {
        LOGE("Invalid JavaVM pointer");
        return;
    }
    
    if (!callback) {
        LOGE("Invalid callback object");
        return;
    }
    
    // Attach thread to JVM
    JNIEnv* threadEnv = nullptr;
    jint result = jvm->AttachCurrentThread(&threadEnv, nullptr);
    if (result != JNI_OK || !threadEnv) {
        LOGE("Failed to attach thread to JVM, result=%d", result);
        // Note: Cannot cleanup global ref here as we don't have valid JNIEnv
        // It will be cleaned up when FileMonitor is destroyed
        return;
    }
    
    LOGI("Thread attached to JVM successfully");
    
    // Create inotify instance
    int inotifyFd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (inotifyFd < 0) {
        LOGE("Failed to initialize inotify: %s", strerror(errno));
        monitoring_ = false;
        threadEnv->DeleteGlobalRef(callback);
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
        threadEnv->DeleteGlobalRef(callback);
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
                // Check if we have enough data for the event structure
                if (i + static_cast<int>(sizeof(struct inotify_event)) > length) {
                    LOGE("Incomplete inotify event structure");
                    break;
                }
                
                struct inotify_event* event = (struct inotify_event*)&buffer[i];
                
                // Check if we have enough data for the full event (including name)
                int eventSize = sizeof(struct inotify_event) + event->len;
                if (i + eventSize > length) {
                    LOGE("Incomplete inotify event data");
                    break;
                }
                
                if (event->len > 0 && event->name != nullptr) {
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
                            
                            // Call Java callback with exception handling
                            jclass callbackClass = threadEnv->GetObjectClass(callback);
                            if (!callbackClass) {
                                LOGE("Failed to get callback class");
                                i += eventSize;
                                continue;
                            }
                            
                            jmethodID methodId = threadEnv->GetMethodID(callbackClass, "onApkDetected", "(Ljava/lang/String;)V");
                            
                            if (methodId) {
                                jstring jPath = threadEnv->NewStringUTF(fullPath.c_str());
                                if (jPath) {
                                    threadEnv->CallVoidMethod(callback, methodId, jPath);
                                    
                                    // Check for exceptions after JNI call
                                    if (threadEnv->ExceptionCheck()) {
                                        LOGE("Exception occurred in Java callback");
                                        threadEnv->ExceptionDescribe();
                                        threadEnv->ExceptionClear();
                                    }
                                    
                                    threadEnv->DeleteLocalRef(jPath);
                                } else {
                                    LOGE("Failed to create jstring for path: %s", fullPath.c_str());
                                }
                            } else {
                                LOGE("Failed to find onApkDetected method");
                            }
                            threadEnv->DeleteLocalRef(callbackClass);
                        }
                    }
                }
                
                i += eventSize;
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
    if (filename.empty() || filename.length() < 4) {
        return false;
    }
    
    std::string lower = filename;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    return lower.substr(lower.length() - 4) == ".apk";
}

