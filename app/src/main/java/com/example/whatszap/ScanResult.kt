package com.example.whatszap

/**
 * Comprehensive scan result containing both static analysis and VirusTotal results
 */
data class ScanResult(
    val isMalicious: Boolean,
    val confidence: Int,
    val threats: List<String>,
    val scanDuration: Long,
    
    // VirusTotal results
    val sha256Hash: String = "",
    val virusTotalDetections: Int = 0,
    val virusTotalEngines: Int = 0,
    val virusTotalLink: String? = null,
    val virusTotalThreats: List<String> = emptyList(),
    val isVirusTotalScanned: Boolean = false,
    
    // Static analysis results
    val packageName: String? = null,
    val appLabel: String? = null,
    val riskScore: Int = 0,
    val dangerousPermissions: List<String> = emptyList(),
    val highlySuspiciousPermissions: List<String> = emptyList(),
    
    // Context
    val senderContext: String? = null,
    val filePath: String = "",
    val fileSizeBytes: Long = 0
) {
    companion object {
        /**
         * Factory method for JNI - creates ScanResult with basic fields
         * Native code calls this via reflection
         */
        @JvmStatic
        fun createFromNative(
            isMalicious: Boolean,
            confidence: Int,
            threats: List<String>,
            scanDuration: Long
        ): ScanResult {
            return ScanResult(
                isMalicious = isMalicious,
                confidence = confidence,
                threats = threats,
                scanDuration = scanDuration
            )
        }
    }
    
    /**
     * Get detection ratio string for display
     */
    fun getVirusTotalRatio(): String {
        return if (isVirusTotalScanned) {
            "$virusTotalDetections/$virusTotalEngines"
        } else {
            "Not scanned"
        }
    }
    
    /**
     * Get overall risk level
     */
    fun getRiskLevel(): String {
        return when {
            isMalicious && virusTotalDetections > 5 -> "CRITICAL"
            isMalicious || virusTotalDetections > 0 -> "HIGH RISK"
            riskScore >= 50 -> "MEDIUM RISK"
            riskScore >= 20 -> "LOW RISK"
            else -> "SAFE"
        }
    }
    
    /**
     * Combine all threats into a single list
     */
    fun getAllThreats(): List<String> {
        val allThreats = mutableListOf<String>()
        
        // Add VT detections first
        if (virusTotalThreats.isNotEmpty()) {
            allThreats.addAll(virusTotalThreats.take(5))
        }
        
        // Add static analysis threats
        allThreats.addAll(threats.filter { it != "No threats detected" })
        
        // Add permission warnings
        if (highlySuspiciousPermissions.isNotEmpty()) {
            allThreats.add("High-risk permissions: ${highlySuspiciousPermissions.size}")
        }
        
        return allThreats.distinct()
    }
    
    /**
     * Check if VT scan had any detections
     */
    fun hasVirusTotalDetections(): Boolean = virusTotalDetections > 0
}
