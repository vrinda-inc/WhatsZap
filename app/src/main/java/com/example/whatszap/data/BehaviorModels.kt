package com.example.whatszap.data

import java.io.File

/**
 * Data models for behavioral analysis system
 */

/**
 * Represents context information about a message/file received via WhatsApp
 */
data class MessageContext(
    val senderInfo: String?,          // Sender identifier (phone number, contact name)
    val senderType: SenderType,       // Type of sender
    val timestamp: Long,              // When the file was detected
    val fileTimestamp: Long,          // File modification timestamp
    val filePath: String,             // Original file path
    val whatsappGroupName: String? = null, // Group name if from group
    val messageSnippet: String? = null,    // Any extractable message content
    val extractedMessageText: String? = null, // OCR extracted message text
    val ocrConfidence: Float = 0f     // OCR confidence score
) {
    enum class SenderType {
        UNKNOWN_NUMBER,    // From unknown/unsaved number
        KNOWN_CONTACT,     // From saved contact
        GROUP_CHAT,        // From WhatsApp group
        BROADCAST,         // From broadcast list
        UNKNOWN            // Cannot determine
    }
    
    fun isFromUnknownSender(): Boolean {
        return senderType == SenderType.UNKNOWN_NUMBER || senderType == SenderType.UNKNOWN
    }
}

/**
 * Results from behavioral analysis
 */
data class BehaviorAnalysisResult(
    val riskScore: Int,               // 0-100 behavioral risk score
    val patternsDetected: List<BehaviorPattern>,
    val senderProfile: SenderProfile?,
    val riskFactors: List<String>,
    val isRepeatSender: Boolean,
    val similarFilesCount: Int,       // Files from same sender
    val timingRisk: TimingRisk,
    val socialEngineeringRisk: Int = 0, // 0-100 social engineering risk
    val socialEngineeringAnalysis: String? = null // Human-readable analysis
) {
    data class TimingRisk(
        val isRapidSuccession: Boolean,   // Multiple files in short time
        val isUnusualTime: Boolean,       // Sent at odd hours
        val frequencyScore: Int           // How often sender sends files
    )
    
    fun getRiskLevel(): String = when {
        riskScore >= 70 -> "HIGH RISK"
        riskScore >= 40 -> "MEDIUM RISK"
        riskScore >= 20 -> "LOW RISK"
        else -> "MINIMAL RISK"
    }
}

/**
 * Behavioral pattern detected
 */
data class BehaviorPattern(
    val type: PatternType,
    val description: String,
    val severity: Severity,
    val confidence: Float  // 0.0 to 1.0
) {
    enum class PatternType {
        REPEATED_APK_SENDING,     // Same sender sending multiple APKs
        RAPID_SUCCESSION,          // Multiple APKs in short time
        UNKNOWN_SENDER_APK,        // APK from unknown number
        UNUSUAL_TIMING,            // Sent at odd hours
        SUSPICIOUS_FILENAME,       // Filename suggests malware
        LARGE_FILE_SIZE,          // Unusually large APK
        MULTIPLE_SENDERS,         // Multiple unknowns sending APKs
        SOCIAL_ENGINEERING,       // Social engineering detected in message
        APK_MESSAGE_MISMATCH      // Message describes media but file is APK
    }
    
    enum class Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW
    }
}

/**
 * Profile of a sender based on historical data
 */
data class SenderProfile(
    val senderIdentifier: String,     // Phone number or contact ID
    val firstSeen: Long,              // First detection timestamp
    val lastSeen: Long,               // Most recent detection
    val totalApksReceived: Int,       // Total APKs from this sender
    val maliciousCount: Int,          // How many were flagged malicious
    val suspiciousCount: Int,         // How many were suspicious
    val cleanCount: Int,              // How many were clean
    val trustScore: Int               // 0-100, based on history
) {
    fun isSuspiciousSender(): Boolean {
        return totalApksReceived > 1 || maliciousCount > 0 || trustScore < 30
    }
}

/**
 * Information about a captured screenshot
 */
data class ScreenshotInfo(
    val screenshotPath: String,       // Path to full screenshot
    val thumbnailPath: String?,       // Path to thumbnail
    val captureTimestamp: Long,       // When screenshot was taken
    val captureSuccess: Boolean,      // Whether capture succeeded
    val errorMessage: String? = null, // Error if capture failed
    val fileSize: Long = 0            // Screenshot file size
) {
    fun exists(): Boolean {
        return captureSuccess && File(screenshotPath).exists()
    }
}

/**
 * Extended scan result with behavioral data
 */
data class ComprehensiveScanResult(
    // Original scan data
    val apkPath: String,
    val isMalicious: Boolean,
    val confidence: Int,
    val threats: List<String>,
    
    // VirusTotal data
    val sha256Hash: String?,
    val vtDetections: Int,
    val vtEngines: Int,
    val vtLink: String?,
    
    // Static analysis
    val packageName: String?,
    val appLabel: String?,
    val riskScore: Int,
    
    // Behavioral data
    val messageContext: MessageContext?,
    val behaviorAnalysis: BehaviorAnalysisResult?,
    val screenshotInfo: ScreenshotInfo?,
    val quarantineStatus: QuarantineStatus,
    
    val scanDuration: Long,
    val scanTimestamp: Long = System.currentTimeMillis()
)

/**
 * Quarantine status of an APK file
 */
data class QuarantineStatus(
    val isQuarantined: Boolean,
    val quarantinePath: String?,
    val originalPath: String,
    val quarantineTimestamp: Long = 0,
    val canRestore: Boolean = true
)
