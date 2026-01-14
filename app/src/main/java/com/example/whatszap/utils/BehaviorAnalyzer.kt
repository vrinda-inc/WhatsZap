package com.example.whatszap.utils

import android.content.Context
import android.util.Log
import com.example.whatszap.data.*
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Analyzes behavioral patterns related to APK file detections
 * NOW WITH OCR-BASED SOCIAL ENGINEERING DETECTION
 */
class BehaviorAnalyzer(private val context: Context) {
    
    companion object {
        private const val TAG = "BehaviorAnalyzer"
        
        // Timing thresholds
        private const val RAPID_SUCCESSION_MINUTES = 30L
        private const val UNUSUAL_HOUR_START = 23 // 11 PM
        private const val UNUSUAL_HOUR_END = 6     // 6 AM
        
        // Risk score weights
        private const val UNKNOWN_SENDER_WEIGHT = 25
        private const val REPEAT_SENDER_WEIGHT = 20
        private const val RAPID_SUCCESSION_WEIGHT = 15
        private const val UNUSUAL_TIME_WEIGHT = 10
        private const val SUSPICIOUS_FILENAME_WEIGHT = 15
        
        @Volatile
        private var instance: BehaviorAnalyzer? = null
        
        fun getInstance(context: Context): BehaviorAnalyzer {
            return instance ?: synchronized(this) {
                instance ?: BehaviorAnalyzer(context.applicationContext).also { instance = it }
            }
        }
    }
    
    /**
     * Analyze behavioral patterns for a detected APK
     * Includes OCR-based social engineering detection
     */
    fun analyzeApk(
        apkPath: String,
        messageContext: MessageContext
    ): BehaviorAnalysisResult {
        val patterns = mutableListOf<BehaviorPattern>()
        var riskScore = 0
        val riskFactors = mutableListOf<String>()
        
        // Get sender profile from history
        val senderProfile = getSenderProfile(messageContext.senderInfo)
        
        // Check for unknown sender
        if (messageContext.isFromUnknownSender()) {
            patterns.add(
                BehaviorPattern(
                    type = BehaviorPattern.PatternType.UNKNOWN_SENDER_APK,
                    description = "APK received from unknown/unsaved number",
                    severity = BehaviorPattern.Severity.HIGH,
                    confidence = 0.95f
                )
            )
            riskScore += UNKNOWN_SENDER_WEIGHT
            riskFactors.add("Unknown sender")
        }
        
        // Check for repeat sender
        val isRepeatSender = senderProfile != null && senderProfile.totalApksReceived > 0
        if (isRepeatSender && senderProfile != null) {
            if (senderProfile.maliciousCount > 0) {
                patterns.add(
                    BehaviorPattern(
                        type = BehaviorPattern.PatternType.REPEATED_APK_SENDING,
                        description = "Sender has previously sent malicious APKs (${senderProfile.maliciousCount})",
                        severity = BehaviorPattern.Severity.CRITICAL,
                        confidence = 1.0f
                    )
                )
                riskScore += REPEAT_SENDER_WEIGHT * 2
                riskFactors.add("Known malicious sender")
            } else if (senderProfile.totalApksReceived >= 2) {
                patterns.add(
                    BehaviorPattern(
                        type = BehaviorPattern.PatternType.REPEATED_APK_SENDING,
                        description = "Sender has sent ${senderProfile.totalApksReceived} APKs previously",
                        severity = BehaviorPattern.Severity.MEDIUM,
                        confidence = 0.8f
                    )
                )
                riskScore += REPEAT_SENDER_WEIGHT
                riskFactors.add("Repeat APK sender")
            }
        }
        
        // Check timing patterns
        val timingRisk = analyzeTimingPatterns(messageContext, senderProfile)
        
        if (timingRisk.isRapidSuccession) {
            patterns.add(
                BehaviorPattern(
                    type = BehaviorPattern.PatternType.RAPID_SUCCESSION,
                    description = "Multiple APKs in short time period",
                    severity = BehaviorPattern.Severity.HIGH,
                    confidence = 0.9f
                )
            )
            riskScore += RAPID_SUCCESSION_WEIGHT
            riskFactors.add("Rapid succession")
        }
        
        if (timingRisk.isUnusualTime) {
            patterns.add(
                BehaviorPattern(
                    type = BehaviorPattern.PatternType.UNUSUAL_TIMING,
                    description = "Received during unusual hours (late night/early morning)",
                    severity = BehaviorPattern.Severity.MEDIUM,
                    confidence = 0.7f
                )
            )
            riskScore += UNUSUAL_TIME_WEIGHT
            riskFactors.add("Unusual timing")
        }
        
        // Check filename patterns
        if (hasSuspiciousFilename(apkPath)) {
            patterns.add(
                BehaviorPattern(
                    type = BehaviorPattern.PatternType.SUSPICIOUS_FILENAME,
                    description = "Filename suggests malicious intent",
                    severity = BehaviorPattern.Severity.HIGH,
                    confidence = 0.85f
                )
            )
            riskScore += SUSPICIOUS_FILENAME_WEIGHT
            riskFactors.add("Suspicious filename")
        }
        
        // Check file size
        val fileSize = File(apkPath).length()
        if (fileSize > 100 * 1024 * 1024) { // > 100MB
            patterns.add(
                BehaviorPattern(
                    type = BehaviorPattern.PatternType.LARGE_FILE_SIZE,
                    description = "Unusually large APK file (${fileSize / 1024 / 1024}MB)",
                    severity = BehaviorPattern.Severity.LOW,
                    confidence = 0.6f
                )
            )
            riskScore += 5
            riskFactors.add("Large file size")
        }
        
        // >>> NEW: Analyze social engineering from extracted message text (if available)
        var socialEngRisk = 0
        var socialEngAnalysis: String? = null
        
        if (!messageContext.extractedMessageText.isNullOrBlank()) {
            val seAnalysis = SocialEngineeringDetector.analyzeMessage(
                messageContext.extractedMessageText,
                messageContext.senderInfo
            )
            
            socialEngRisk = seAnalysis.riskScore
            socialEngAnalysis = seAnalysis.analysis
            
            // Add social engineering patterns
            if (seAnalysis.hasApkMismatch) {
                patterns.add(
                    BehaviorPattern(
                        type = BehaviorPattern.PatternType.APK_MESSAGE_MISMATCH,
                        description = "Message describes media/document but file is APK",
                        severity = BehaviorPattern.Severity.CRITICAL,
                        confidence = 0.95f
                    )
                )
                riskScore += 30
                riskFactors.add("APK-message mismatch (social engineering)")
            }
            
            if (seAnalysis.suspiciousKeywords.isNotEmpty()) {
                patterns.add(
                    BehaviorPattern(
                        type = BehaviorPattern.PatternType.SOCIAL_ENGINEERING,
                        description = "Social engineering detected: ${seAnalysis.suspiciousKeywords.take(3).joinToString(", ")}",
                        severity = BehaviorPattern.Severity.HIGH,
                        confidence = 0.9f
                    )
                )
                riskScore += socialEngRisk / 2 // Add half of SE risk to main score
                riskFactors.add("Social engineering tactics")
            }
            
            Log.i(TAG, "Social engineering risk: $socialEngRisk, patterns: ${seAnalysis.detectedPatterns.size}")
        }
        
        return BehaviorAnalysisResult(
            riskScore = riskScore.coerceIn(0, 100),
            patternsDetected = patterns,
            senderProfile = senderProfile,
            riskFactors = riskFactors,
            isRepeatSender = isRepeatSender,
            similarFilesCount = senderProfile?.totalApksReceived ?: 0,
            timingRisk = timingRisk,
            socialEngineeringRisk = socialEngRisk,
            socialEngineeringAnalysis = socialEngAnalysis
        )
    }
    
    /**
     * Analyze timing patterns
     */
    private fun analyzeTimingPatterns(
        messageContext: MessageContext,
        senderProfile: SenderProfile?
    ): BehaviorAnalysisResult.TimingRisk {
        val currentTime = System.currentTimeMillis()
        val hourOfDay = java.util.Calendar.getInstance().apply {
            timeInMillis = currentTime
        }.get(java.util.Calendar.HOUR_OF_DAY)
        
        // Check if received during unusual hours
        val isUnusualTime = hourOfDay >= UNUSUAL_HOUR_START || hourOfDay < UNUSUAL_HOUR_END
        
        // Check for rapid succession
        val isRapidSuccession = senderProfile?.let {
            val timeSinceLastSeen = currentTime - it.lastSeen
            timeSinceLastSeen < TimeUnit.MINUTES.toMillis(RAPID_SUCCESSION_MINUTES)
        } ?: false
        
        // Calculate frequency score
        val frequencyScore = senderProfile?.let {
            val daysSinceFirstSeen = TimeUnit.MILLISECONDS.toDays(currentTime - it.firstSeen)
            if (daysSinceFirstSeen > 0) {
                ((it.totalApksReceived.toFloat() / daysSinceFirstSeen) * 100).toInt()
            } else {
                it.totalApksReceived * 50 // If same day, high score
            }
        } ?: 0
        
        return BehaviorAnalysisResult.TimingRisk(
            isRapidSuccession = isRapidSuccession,
            isUnusualTime = isUnusualTime,
            frequencyScore = frequencyScore.coerceIn(0, 100)
        )
    }
    
    /**
     * Check if filename is suspicious
     */
    private fun hasSuspiciousFilename(apkPath: String): Boolean {
        val filename = File(apkPath).name.lowercase()
        
        val suspiciousKeywords = listOf(
            "hack", "crack", "mod", "cheat", "free", "premium",
            "spy", "monitor", "keylog", "rat", "trojan",
            "virus", "malware", "exploit", "payload"
        )
        
        return suspiciousKeywords.any { keyword ->
            filename.contains(keyword)
        }
    }
    
    /**
     * Get sender profile from stored history
     * TODO: Implement database storage for persistent history
     */
    private fun getSenderProfile(senderInfo: String?): SenderProfile? {
        // For now, return null as we don't have database yet
        // This will be implemented with Room database
        return null
    }
    
    /**
     * Extract message context from file path and metadata
     */
    fun extractMessageContext(apkPath: String): MessageContext {
        val file = File(apkPath)
        val timestamp = System.currentTimeMillis()
        val fileTimestamp = file.lastModified()
        
        // Determine sender type from path
        val (senderType, senderInfo, groupName) = when {
            apkPath.contains("/WhatsApp/") -> {
                // Try to extract from WhatsApp path structure
                extractWhatsAppInfo(apkPath)
            }
            apkPath.contains("/Download") -> {
                Triple(MessageContext.SenderType.UNKNOWN, "Downloads folder", null)
            }
            else -> {
                Triple(MessageContext.SenderType.UNKNOWN, "Unknown source", null)
            }
        }
        
        return MessageContext(
            senderInfo = senderInfo,
            senderType = senderType,
            timestamp = timestamp,
            fileTimestamp = fileTimestamp,
            filePath = apkPath,
            whatsappGroupName = groupName,
            messageSnippet = null // Cannot extract without WhatsApp database access
        )
    }
    
    /**
     * Extract WhatsApp sender info from file path
     */
    private fun extractWhatsAppInfo(path: String): Triple<MessageContext.SenderType, String, String?> {
        // WhatsApp typically saves media in paths like:
        // /WhatsApp/Media/WhatsApp Documents/
        // Without database access, we can only infer it came from WhatsApp
        
        return if (path.contains("group", ignoreCase = true)) {
            Triple(MessageContext.SenderType.GROUP_CHAT, "WhatsApp Group", null)
        } else {
            // Default to unknown number since we can't determine contact
            Triple(MessageContext.SenderType.UNKNOWN_NUMBER, "WhatsApp Contact (Unknown)", null)
        }
    }
    
    /**
     * Extract message context with OCR from screenshot
     * Call this when screenshot is available for OCR analysis
     */
    suspend fun extractMessageContextWithOCR(
        apkPath: String,
        screenshotPath: String?
    ): MessageContext {
        // Start with basic context
        var messageContext = extractMessageContext(apkPath)
        
        // If screenshot is available, perform OCR to extract message text
        if (!screenshotPath.isNullOrBlank()) {
            try {
                val messageOCR = MessageOCR.getInstance(context)
                
                // Initialize OCR if not already done
                messageOCR.initialize()
                
                // Extract WhatsApp message from screenshot
                val whatsappMessage = messageOCR.extractWhatsAppMessage(screenshotPath)
                
                if (whatsappMessage.messageText != null) {
                    Log.i(TAG, "OCR extracted message (${whatsappMessage.confidence}% confidence): ${whatsappMessage.messageText.take(50)}...")
                    
                    // Update context with OCR data
                    messageContext = messageContext.copy(
                        extractedMessageText = whatsappMessage.messageText,
                        ocrConfidence = whatsappMessage.confidence,
                        senderInfo = whatsappMessage.senderName ?: messageContext.senderInfo,
                        messageSnippet = whatsappMessage.messageText.take(200)
                    )
                } else {
                    Log.w(TAG, "OCR completed but no text extracted")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to perform OCR on screenshot", e)
            }
        }
        
        return messageContext
    }
}
