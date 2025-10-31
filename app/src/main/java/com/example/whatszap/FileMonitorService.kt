package com.example.whatszap

import android.app.*
import android.content.Intent
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
        
        init {
            System.loadLibrary("whatszap-native")
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
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())
        
        // Initialize native scanner
        nativeScannerHandle = nativeCreateMalwareScanner()
        
        // Start monitoring WhatsApp directories
        val whatsappPath = File(
            android.os.Environment.getExternalStorageDirectory(),
            "WhatsApp/Media/WhatsApp Documents"
        ).absolutePath
        
        val downloadsPath = android.os.Environment.getExternalStoragePublicDirectory(
            android.os.Environment.DIRECTORY_DOWNLOADS
        ).absolutePath
        
        // Create separate monitors for each directory
        val whatsappMonitor = nativeCreateFileMonitor()
        if (nativeStartMonitoring(whatsappMonitor, whatsappPath, this)) {
            nativeFileMonitors.add(whatsappMonitor)
        }
        
        val downloadsMonitor = nativeCreateFileMonitor()
        if (nativeStartMonitoring(downloadsMonitor, downloadsPath, this)) {
            nativeFileMonitors.add(downloadsMonitor)
        }
        
        Log.i(TAG, "Service started with native monitoring")
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
        
        // Show alert activity
        val intent = Intent(this, AlertActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("apk_path", apkPath)
        }
        startActivity(intent)
        
        // Start malware scanning in background thread
        Thread {
            val result = nativeScanApk(nativeScannerHandle, apkPath)
            result?.let {
                Log.i(TAG, "Scan complete: isMalicious=${it.isMalicious}, confidence=${it.confidence}")
                
                // Send broadcast when scan completes
                val scanIntent = Intent("com.example.whatszap.SCAN_COMPLETE").apply {
                    putExtra("apk_path", apkPath)
                    putExtra("is_malicious", it.isMalicious)
                    putExtra("confidence", it.confidence)
                    putExtra("threats", it.threats.toTypedArray())
                }
                sendBroadcast(scanIntent)
            }
        }.start()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        
        // Stop and destroy all file monitors
        nativeFileMonitors.forEach { handle ->
            nativeStopMonitoring(handle)
            nativeDestroyFileMonitor(handle)
        }
        nativeFileMonitors.clear()
        
        if (nativeScannerHandle != 0L) {
            nativeDestroyMalwareScanner(nativeScannerHandle)
            nativeScannerHandle = 0
        }
        
        Log.i(TAG, "Service destroyed")
    }
}

