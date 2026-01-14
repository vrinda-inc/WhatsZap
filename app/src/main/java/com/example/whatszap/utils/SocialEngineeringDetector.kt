package com.example.whatszap.utils

import android.util.Log

/**
 * Analyzes message text extracted from WhatsApp screenshots
 * to detect social engineering and phishing attempts
 */
object SocialEngineeringDetector {
    
    private const val TAG = "SocialEngDetector"
    
    /**
     * Suspicious keywords that often accompany malicious APKs
     */
    private val SOCIAL_ENGINEERING_KEYWORDS = mapOf(
        // Emotional manipulation
        "urgent" to 15,
        "immediately" to 12,
        "hurry" to 10,
        "limited time" to 15,
        "act now" to 12,
        "expire" to 10,
        "last chance" to 15,
        
        // Trust exploitation
        "wedding" to 20,
        "invitation" to 18,
        "birthday" to 15,
        "party" to 12,
        "celebration" to 12,
        "family" to 10,
        "photos" to 15,
        "pictures" to 15,
        "album" to 12,
        
        // Financial lures
        "prize" to 20,
        "won" to 18,
        "winner" to 18,
        "lottery" to 25,
        "reward" to 15,
        "cash" to 15,
        "money" to 15,
        "refund" to 20,
        "claim" to 15,
        "payment" to 12,
        
        // Authority impersonation
        "bank" to 20,
        "account" to 15,
        "verify" to 18,
        "confirm" to 15,
        "update" to 12,
        "security" to 15,
        "suspended" to 20,
        "blocked" to 18,
        "locked" to 18,
        
        // Job/opportunity scams
        "job offer" to 20,
        "hiring" to 15,
        "work from home" to 18,
        "earn money" to 20,
        "easy money" to 25,
        "part time" to 12,
        
        // Document lures
        "document" to 15,
        "form" to 12,
        "application" to 12,
        "resume" to 10,
        "cv" to 10,
        "certificate" to 12,
        
        // Action prompts
        "click here" to 15,
        "download" to 18,
        "install" to 20,
        "open" to 10,
        "view" to 10,
        "see" to 8
    )
    
    /**
     * APK-message mismatch patterns
     * These indicate the message doesn't match typical APK distribution
     */
    private val APK_MISMATCH_PATTERNS = listOf(
        "photo", "image", "picture", "video", "pdf", "document",
        "wedding", "birthday", "invitation", "album"
    )
    
    /**
     * Analyze message text for social engineering indicators
     */
    fun analyzeMessage(messageText: String?, senderName: String?): SocialEngineeringAnalysis {
        if (messageText.isNullOrBlank()) {
            return SocialEngineeringAnalysis(
                riskScore = 0,
                detectedPatterns = emptyList(),
                suspiciousKeywords = emptyList(),
                hasApkMismatch = false,
                analysis = "No message text available"
            )
        }
        
        val lowercaseMessage = messageText.lowercase()
        val detectedPatterns = mutableListOf<String>()
        val suspiciousKeywords = mutableListOf<String>()
        var riskScore = 0
        
        // Check for social engineering keywords
        SOCIAL_ENGINEERING_KEYWORDS.forEach { (keyword, score) ->
            if (lowercaseMessage.contains(keyword)) {
                suspiciousKeywords.add(keyword)
                riskScore += score
                Log.d(TAG, "Found keyword: '$keyword' (+$score points)")
            }
        }
        
        // Check for APK-message mismatch
        val hasApkMismatch = APK_MISMATCH_PATTERNS.any { pattern ->
            lowercaseMessage.contains(pattern) && !lowercaseMessage.contains("apk")
        }
        
        if (hasApkMismatch) {
            detectedPatterns.add("Message mentions media/document but file is APK")
            riskScore += 30
            Log.d(TAG, "APK-message mismatch detected (+30 points)")
        }
        
        // Check for urgency indicators
        val urgencyCount = listOf("urgent", "now", "immediately", "asap", "hurry").count {
            lowercaseMessage.contains(it)
        }
        if (urgencyCount >= 2) {
            detectedPatterns.add("Multiple urgency indicators")
            riskScore += 15
        }
        
        // Check for suspicious patterns
        if (lowercaseMessage.contains("click") && lowercaseMessage.contains("link")) {
            detectedPatterns.add("Link clicking prompt with APK")
            riskScore += 20
        }
        
        // Check message length - very short messages with APKs are suspicious
        if (messageText.trim().split("\\s+".toRegex()).size <= 3) {
            detectedPatterns.add("Suspiciously brief message")
            riskScore += 10
        }
        
        // Build analysis summary
        val analysis = buildAnalysisSummary(
            messageText,
            senderName,
            suspiciousKeywords,
            hasApkMismatch,
            riskScore
        )
        
        return SocialEngineeringAnalysis(
            riskScore = riskScore.coerceIn(0, 100),
            detectedPatterns = detectedPatterns,
            suspiciousKeywords = suspiciousKeywords,
            hasApkMismatch = hasApkMismatch,
            analysis = analysis
        )
    }
    
    /**
     * Build human-readable analysis summary
     */
    private fun buildAnalysisSummary(
        messageText: String,
        senderName: String?,
        keywords: List<String>,
        hasMismatch: Boolean,
        score: Int
    ): String {
        val parts = mutableListOf<String>()
        
        senderName?.let {
            parts.add("Sender: $it")
        }
        
        parts.add("Message: \"${messageText.take(100)}${if (messageText.length > 100) "..." else ""}\"")
        
        if (keywords.isNotEmpty()) {
            parts.add("Suspicious keywords: ${keywords.take(5).joinToString(", ")}")
        }
        
        if (hasMismatch) {
            parts.add("⚠️ Message describes media/document but file is APK (classic social engineering)")
        }
        
        return parts.joinToString("\n")
    }
}

/**
 * Result of social engineering analysis
 */
data class SocialEngineeringAnalysis(
    val riskScore: Int,                    // 0-100 risk score
    val detectedPatterns: List<String>,    // Detected social engineering patterns
    val suspiciousKeywords: List<String>,  // Suspicious keywords found
    val hasApkMismatch: Boolean,           // Message/file type mismatch
    val analysis: String                   // Human-readable summary
) {
    fun getRiskLevel(): String = when {
        riskScore >= 70 -> "CRITICAL"
        riskScore >= 50 -> "HIGH"
        riskScore >= 30 -> "MEDIUM"
        else -> "LOW"
    }
}
