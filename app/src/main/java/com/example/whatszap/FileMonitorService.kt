package com.example.whatszap

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.whatszap.data.*
import com.example.whatszap.network.VirusTotalRepository
import com.example.whatszap.utils.ApkAnalyzer
import com.example.whatszap.utils.ApkQuarantine
import com.example.whatszap.utils.BehaviorAnalyzer
import com.example.whatszap.utils.HashUtils
import com.example.whatszap.utils.ScreenshotCapture
import kotlinx.coroutines.*
import java.io.File

class FileMonitorService : Service(), ApkDetectionCallback {
    private val nativeFileMonitors = mutableListOf<Long>()
    private var nativeScannerHandle: Long = 0
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var virusTotalRepository: VirusTotalRepository
    private lateinit var apkQuarantine: ApkQuarantine
    private lateinit var behaviorAnalyzer: BehaviorAnalyzer
    private lateinit var screenshotCapture: ScreenshotCapture
    
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
        
        // Initialize VirusTotal repository FIRST (used by createNotification)
        virusTotalRepository = VirusTotalRepository.getInstance()
        
        // Initialize behavioral analysis components
        apkQuarantine = ApkQuarantine.getInstance(this)
        behaviorAnalyzer = BehaviorAnalyzer.getInstance(this)
        screenshotCapture = ScreenshotCapture.getInstance(this)
        
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
        
        // Also monitor Android/media path for newer WhatsApp versions
        val whatsappMediaPath = File(
            android.os.Environment.getExternalStorageDirectory(),
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents"
        ).absolutePath
        
        // Create separate monitors for each directory
        startMonitoringDirectory(whatsappPath)
        startMonitoringDirectory(downloadsPath)
        startMonitoringDirectory(whatsappMediaPath)
        
        Log.i(TAG, "Service started with native monitoring and VirusTotal integration")
        Log.i(TAG, "VirusTotal API configured: ${virusTotalRepository.isApiKeyConfigured()}")
    }
    
    private fun startMonitoringDirectory(path: String) {
        val dir = File(path)
        if (dir.exists() && dir.isDirectory) {
            val monitor = nativeCreateFileMonitor()
            if (nativeStartMonitoring(monitor, path, this)) {
                nativeFileMonitors.add(monitor)
                Log.i(TAG, "Started monitoring: $path")
            } else {
                Log.w(TAG, "Failed to start monitoring: $path")
                nativeDestroyFileMonitor(monitor)
            }
        } else {
            Log.w(TAG, "Directory does not exist: $path")
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
        val vtStatus = if (virusTotalRepository.isApiKeyConfigured()) {
            "VirusTotal: Active"
        } else {
            "VirusTotal: Not configured"
        }
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("APK Guardian Active")
            .setContentText("Monitoring WhatsApp downloads... | $vtStatus")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .build()
    }

    override fun onApkDetected(apkPath: String) {
        Log.i(TAG, "APK detected via native callback: $apkPath")
        
        // STEP 1: Quarantine the APK immediately to prevent installation
        val quarantinePath = apkQuarantine.quarantineApk(apkPath)
        if (quarantinePath != null) {
            Log.i(TAG, "APK quarantined: $quarantinePath")
        } else {
            Log.w(TAG, "Failed to quarantine APK, continuing with analysis")
        }
        
        // STEP 2: Capture screenshot (if permission granted)
        // Note: Screenshot capture requires MediaProjection permission which must be
        // granted via user interaction. For now, we'll skip automatic capture.
        // This can be enabled later when permission flow is implemented.
        
        // STEP 3: Show alert activity immediately
        val intent = Intent(this, AlertActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("apk_path", apkPath)
            putExtra("quarantine_path", quarantinePath)
        }
        startActivity(intent)
        
        // STEP 4: Start comprehensive scanning in background
        serviceScope.launch {
            performComprehensiveScan(apkPath, quarantinePath)
        }
    }
    
    private suspend fun performComprehensiveScan(apkPath: String, quarantinePath: String?) {
        val startTime = System.currentTimeMillis()
        
        Log.i(TAG, "Starting comprehensive scan for: $apkPath")
        
        // Step 1: Extract message context
        val messageContext = behaviorAnalyzer.extractMessageContext(apkPath)
        Log.i(TAG, "Message context: sender=${messageContext.senderInfo}, type=${messageContext.senderType}")
        
        // Step 2: Perform behavioral analysis
        val behaviorAnalysis = behaviorAnalyzer.analyzeApk(apkPath, messageContext)
        Log.i(TAG, "Behavioral analysis complete. Risk score: ${behaviorAnalysis.riskScore}")
        Log.i(TAG, "Patterns detected: ${behaviorAnalysis.patternsDetected.size}")
        
        // Step 3: Calculate SHA-256 hash
        val sha256 = HashUtils.calculateSha256(apkPath)
        Log.i(TAG, "SHA-256: $sha256")
        
        // Step 4: Perform static analysis
        val staticAnalysis = ApkAnalyzer.analyzeApk(this@FileMonitorService, apkPath)
        Log.i(TAG, "Static analysis complete. Risk score: ${staticAnalysis.riskScore}")
        
        // Step 5: Get sender context (legacy, now using messageContext)
        val senderContext = messageContext.senderInfo ?: ApkAnalyzer.getSenderContext(apkPath)
        
        // Step 4: Perform native scan (in parallel)
        val nativeScanDeferred = serviceScope.async {
            nativeScanApk(nativeScannerHandle, apkPath)
        }
        
        // Step 5: Check VirusTotal (if configured)
        var vtResult = virusTotalRepository.checkFileHash(sha256 ?: "")
        
        // If not found in VT database and API key is configured, try uploading
        if (!vtResult.isFound && virusTotalRepository.isApiKeyConfigured() && sha256 != null) {
            Log.i(TAG, "Hash not found in VirusTotal, uploading file...")
            // For now, we'll skip upload to avoid long wait times
            // vtResult = virusTotalRepository.uploadFile(apkPath)
        }
        
        // Wait for native scan
        val nativeResult = nativeScanDeferred.await()
        
        val scanDuration = System.currentTimeMillis() - startTime
        
        // Combine results including behavioral analysis
        val isMalicious = vtResult.isMalicious || 
                         (staticAnalysis.riskScore >= 50) ||
                         (behaviorAnalysis.riskScore >= 60) ||
                         (nativeResult?.isMalicious == true)
        
        val combinedThreats = mutableListOf<String>()
        
        // Add VT threats
        combinedThreats.addAll(vtResult.threatNames)
        
        // Add static analysis threats
        combinedThreats.addAll(staticAnalysis.getSummaryThreats())
        
        // Add behavioral analysis threats
        combinedThreats.addAll(behaviorAnalysis.riskFactors)
        
        // Add native scan threats
        nativeResult?.threats?.let { threats ->
            combinedThreats.addAll(threats.filter { it != "No threats detected" })
        }
        
        // Calculate overall confidence
        val confidence = calculateOverallConfidence(vtResult, staticAnalysis, behaviorAnalysis, nativeResult)
        
        Log.i(TAG, "Comprehensive scan complete:")
        Log.i(TAG, "  - Malicious: $isMalicious")
        Log.i(TAG, "  - Confidence: $confidence")
        Log.i(TAG, "  - VT Detections: ${vtResult.detectionRatio}")
        Log.i(TAG, "  - Static Risk Score: ${staticAnalysis.riskScore}")
        Log.i(TAG, "  - Behavioral Risk Score: ${behaviorAnalysis.riskScore}")
        Log.i(TAG, "  - Duration: ${scanDuration}ms")
        
        // Send broadcast with comprehensive results
        val scanIntent = Intent("com.example.whatszap.SCAN_COMPLETE").apply {
            // Set package so broadcast is received by our app's receiver (required for RECEIVER_NOT_EXPORTED)
            setPackage(packageName)
            
            putExtra("apk_path", apkPath)
            putExtra("is_malicious", isMalicious)
            putExtra("confidence", confidence)
            putExtra("threats", combinedThreats.distinct().toTypedArray())
            
            // VirusTotal data
            putExtra("sha256_hash", sha256 ?: "")
            putExtra("vt_detections", vtResult.maliciousCount)
            putExtra("vt_engines", vtResult.totalEngines)
            putExtra("vt_link", vtResult.virusTotalLink)
            putExtra("vt_scanned", vtResult.isFound)
            putExtra("vt_threats", vtResult.threatNames.toTypedArray())
            
            // Static analysis data
            putExtra("package_name", staticAnalysis.packageName)
            putExtra("app_label", staticAnalysis.appLabel)
            putExtra("risk_score", staticAnalysis.riskScore)
            putExtra("dangerous_permissions", staticAnalysis.dangerousPermissions.toTypedArray())
            putExtra("suspicious_permissions", staticAnalysis.highlySuspiciousPermissions.toTypedArray())
            
            // Context
            putExtra("sender_context", senderContext)
            putExtra("file_size", staticAnalysis.fileSizeBytes)
            putExtra("scan_duration", scanDuration)
            
            // Behavioral analysis data
            putExtra("behavior_risk_score", behaviorAnalysis.riskScore)
            putExtra("behavior_risk_level", behaviorAnalysis.getRiskLevel())
            putExtra("behavior_patterns", behaviorAnalysis.patternsDetected.map { it.description }.toTypedArray())
            putExtra("is_unknown_sender", messageContext.isFromUnknownSender())
            putExtra("sender_type", messageContext.senderType.name)
            
            // Quarantine data
            putExtra("is_quarantined", quarantinePath != null)
            putExtra("quarantine_path", quarantinePath)
        }
        sendBroadcast(scanIntent)
        Log.i(TAG, "Broadcast sent to AlertActivity")
    }
    
    private fun calculateOverallConfidence(
        vtResult: com.example.whatszap.network.VirusTotalScanResult,
        staticAnalysis: com.example.whatszap.utils.ApkAnalysisResult,
        behaviorAnalysis: BehaviorAnalysisResult,
        nativeResult: ScanResult?
    ): Int {
        var confidence = 0
        
        // VT detection confidence (max 50)
        if (vtResult.isFound) {
            val vtConfidence = when {
                vtResult.maliciousCount >= 10 -> 50
                vtResult.maliciousCount >= 5 -> 40
                vtResult.maliciousCount >= 1 -> 30
                else -> 10 // Found but clean
            }
            confidence += vtConfidence
        }
        
        // Static analysis confidence (max 25)
        confidence += (staticAnalysis.riskScore * 0.25).toInt()
        
        // Behavioral analysis confidence (max 15)
        confidence += (behaviorAnalysis.riskScore * 0.15).toInt()
        
        // Native scan confidence (max 10)
        nativeResult?.let {
            confidence += (it.confidence * 0.1).toInt()
        }
        
        return minOf(confidence, 100)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        
        // Cancel all coroutines
        serviceScope.cancel()
        
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
