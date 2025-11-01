package com.example.whatszap

import android.app.*
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.File

class FileMonitorService : Service(), ApkDetectionCallback {
    private val nativeFileMonitors = mutableListOf<Long>()
    private var nativeScannerHandle: Long = 0
    
    companion object {
        private const val TAG = "FileMonitorService"
        private const val CHANNEL_ID = "FileMonitorChannel"
        private const val NOTIFICATION_ID = 1
        
        private var libraryLoaded = false
        
        init {
            try {
                System.loadLibrary("whatszap-native")
                libraryLoaded = true
                Log.i(TAG, "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library", e)
                libraryLoaded = false
            } catch (e: Exception) {
                Log.e(TAG, "Exception loading native library", e)
                libraryLoaded = false
            }
        }
    }
    
    // Native methods
    private external fun nativeCreateFileMonitor(): Long
    private external fun nativeStartMonitoring(
        nativeHandle: Long,
        directory: String,
        callback: ApkDetectionCallback
    ): Boolean
    private external fun nativeStopMonitoring(nativeHandle: Long)
    private external fun nativeDestroyFileMonitor(nativeHandle: Long)
    
    private external fun nativeCreateMalwareScanner(): Long
    private external fun nativeScanApk(nativeHandle: Long, apkPath: String): ScanResult?
    private external fun nativeDestroyMalwareScanner(nativeHandle: Long)

    override fun onCreate() {
        super.onCreate()
        
        if (!libraryLoaded) {
            Log.e(TAG, "Native library not loaded, cannot start service")
            stopSelf()
            return
        }
        
        try {
            createNotificationChannel()
            val notification = createNotification()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, 
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            
            // Initialize native scanner
            try {
                if (libraryLoaded) {
                    nativeScannerHandle = nativeCreateMalwareScanner()
                    if (nativeScannerHandle == 0L) {
                        Log.e(TAG, "Failed to create native scanner")
                        stopSelf()
                        return
                    }
                } else {
                    Log.e(TAG, "Library not loaded, cannot create scanner")
                    stopSelf()
                    return
                }
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Native method not found for scanner creation", e)
                libraryLoaded = false
                stopSelf()
                return
            } catch (e: Exception) {
                Log.e(TAG, "Error creating native scanner", e)
                stopSelf()
                return
            }
            
            // Start monitoring WhatsApp directories
            val whatsappPath = File(
                android.os.Environment.getExternalStorageDirectory(),
                "WhatsApp/Media/WhatsApp Documents"
            ).absolutePath
            
            val downloadsPath = android.os.Environment.getExternalStoragePublicDirectory(
                android.os.Environment.DIRECTORY_DOWNLOADS
            ).absolutePath
            
            // Create separate monitors for each directory
            try {
                if (libraryLoaded) {
                    val whatsappMonitor = nativeCreateFileMonitor()
                    if (whatsappMonitor != 0L && nativeStartMonitoring(whatsappMonitor, whatsappPath, this)) {
                        nativeFileMonitors.add(whatsappMonitor)
                        Log.i(TAG, "Started monitoring WhatsApp directory: $whatsappPath")
                    } else {
                        Log.w(TAG, "Failed to start monitoring WhatsApp directory: $whatsappPath")
                    }
                }
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Native method not found while setting up WhatsApp monitor", e)
                libraryLoaded = false
            } catch (e: Exception) {
                Log.e(TAG, "Error setting up WhatsApp monitor", e)
            }
            
            try {
                if (libraryLoaded) {
                    val downloadsMonitor = nativeCreateFileMonitor()
                    if (downloadsMonitor != 0L && nativeStartMonitoring(downloadsMonitor, downloadsPath, this)) {
                        nativeFileMonitors.add(downloadsMonitor)
                        Log.i(TAG, "Started monitoring downloads directory: $downloadsPath")
                    } else {
                        Log.w(TAG, "Failed to start monitoring downloads directory: $downloadsPath")
                    }
                }
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Native method not found while setting up downloads monitor", e)
                libraryLoaded = false
            } catch (e: Exception) {
                Log.e(TAG, "Error setting up downloads monitor", e)
            }
            
            Log.i(TAG, "Service started with ${nativeFileMonitors.size} active monitors")
        } catch (e: Exception) {
            Log.e(TAG, "Error in onCreate", e)
            stopSelf()
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "APK Guardian Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitors WhatsApp downloads for APK files"
            }
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("APK Guardian Active")
            .setContentText("Monitoring WhatsApp downloads...")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .build()
    }

    override fun onApkDetected(apkPath: String) {
        Log.i(TAG, "APK detected via native callback: $apkPath")
        
        try {
            // Show alert activity
            val intent = Intent(this, AlertActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("apk_path", apkPath)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error starting AlertActivity", e)
        }
        
        // Start malware scanning in background thread
        Thread {
            try {
                if (!libraryLoaded) {
                    Log.e(TAG, "Native library not loaded, cannot scan APK")
                    return@Thread
                }
                
                if (nativeScannerHandle == 0L) {
                    Log.e(TAG, "Native scanner handle is invalid")
                    return@Thread
                }
                
                val result = nativeScanApk(nativeScannerHandle, apkPath)
                result?.let {
                    Log.i(TAG, "Scan complete: isMalicious=${it.isMalicious}, confidence=${it.confidence}")
                    
                    // Send broadcast when scan completes
                    try {
                        val scanIntent = Intent("com.example.whatszap.SCAN_COMPLETE").apply {
                            putExtra("apk_path", apkPath)
                            putExtra("is_malicious", it.isMalicious)
                            putExtra("confidence", it.confidence)
                            putExtra("threats", it.threats.toTypedArray())
                        }
                        sendBroadcast(scanIntent)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error sending scan complete broadcast", e)
                    }
                } ?: run {
                    Log.w(TAG, "Scan returned null result for: $apkPath")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error during APK scan", e)
            }
        }.start()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        
        if (!libraryLoaded) {
            Log.w(TAG, "Library not loaded, skipping cleanup")
            return
        }
        
        try {
            // Stop and destroy all file monitors
            nativeFileMonitors.forEach { handle ->
                try {
                    if (handle != 0L) {
                        nativeStopMonitoring(handle)
                        nativeDestroyFileMonitor(handle)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error destroying file monitor", e)
                }
            }
            nativeFileMonitors.clear()
            
            if (nativeScannerHandle != 0L) {
                try {
                    nativeDestroyMalwareScanner(nativeScannerHandle)
                } catch (e: Exception) {
                    Log.e(TAG, "Error destroying malware scanner", e)
                }
                nativeScannerHandle = 0
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in onDestroy", e)
        }
        
        Log.i(TAG, "Service destroyed")
    }
}

