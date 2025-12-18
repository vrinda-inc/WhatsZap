package com.example.whatszap.utils

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.util.zip.ZipInputStream

/**
 * Utility class for analyzing APK files
 * Performs static analysis to extract metadata and detect suspicious patterns
 */
object ApkAnalyzer {
    private const val TAG = "ApkAnalyzer"
    
    /**
     * High-risk permissions that are commonly abused by malware
     */
    private val DANGEROUS_PERMISSIONS = setOf(
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.WRITE_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE"
    )
    
    /**
     * Very suspicious permissions that are rarely needed legitimately
     */
    private val HIGHLY_SUSPICIOUS_PERMISSIONS = setOf(
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES"
    )
    
    /**
     * Suspicious package name patterns often used by malware
     */
    private val SUSPICIOUS_PACKAGE_PATTERNS = listOf(
        Regex("^com\\.android\\..*", RegexOption.IGNORE_CASE), // Impersonating system apps
        Regex("^com\\.google\\.android\\..*", RegexOption.IGNORE_CASE), // Impersonating Google apps
        Regex("^com\\.samsung\\..*", RegexOption.IGNORE_CASE), // Impersonating Samsung
        Regex(".*\\.free\\..*", RegexOption.IGNORE_CASE),
        Regex(".*\\.hack.*", RegexOption.IGNORE_CASE),
        Regex(".*\\.crack.*", RegexOption.IGNORE_CASE),
        Regex(".*\\.mod\\..*", RegexOption.IGNORE_CASE)
    )
    
    /**
     * Analyze an APK file and return analysis results
     */
    fun analyzeApk(context: Context, apkPath: String): ApkAnalysisResult {
        val file = File(apkPath)
        if (!file.exists()) {
            return ApkAnalysisResult(
                isValid = false,
                errorMessage = "File not found"
            )
        }
        
        val result = ApkAnalysisResult(isValid = true)
        
        try {
            // Get package info from APK
            val packageInfo = getPackageInfo(context, apkPath)
            
            if (packageInfo != null) {
                result.packageName = packageInfo.packageName
                result.versionName = packageInfo.versionName
                result.versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    packageInfo.longVersionCode
                } else {
                    @Suppress("DEPRECATION")
                    packageInfo.versionCode.toLong()
                }
                
                // Extract permissions
                val permissions = packageInfo.requestedPermissions?.toList() ?: emptyList()
                result.requestedPermissions = permissions
                
                // Identify dangerous permissions
                result.dangerousPermissions = permissions.filter { it in DANGEROUS_PERMISSIONS }
                result.highlySuspiciousPermissions = permissions.filter { it in HIGHLY_SUSPICIOUS_PERMISSIONS }
                
                // Check for suspicious package name
                result.hasSuspiciousPackageName = SUSPICIOUS_PACKAGE_PATTERNS.any { 
                    it.matches(packageInfo.packageName ?: "") 
                }
                
                // Calculate risk score
                result.riskScore = calculateRiskScore(result)
                
                // Get app label if possible
                packageInfo.applicationInfo?.let { appInfo ->
                    try {
                        result.appLabel = context.packageManager.getApplicationLabel(appInfo).toString()
                    } catch (e: Exception) {
                        Log.w(TAG, "Could not get app label", e)
                    }
                }
            }
            
            // Analyze APK structure
            analyzeApkStructure(apkPath, result)
            
            // Get file size
            result.fileSizeBytes = file.length()
            
        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing APK", e)
            result.errorMessage = e.message
        }
        
        return result
    }
    
    /**
     * Get PackageInfo from APK file
     */
    private fun getPackageInfo(context: Context, apkPath: String): PackageInfo? {
        return try {
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES
            }
            
            context.packageManager.getPackageArchiveInfo(apkPath, flags)?.also {
                it.applicationInfo?.apply {
                    sourceDir = apkPath
                    publicSourceDir = apkPath
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting package info", e)
            null
        }
    }
    
    /**
     * Analyze APK structure for suspicious patterns
     */
    private fun analyzeApkStructure(apkPath: String, result: ApkAnalysisResult) {
        try {
            FileInputStream(apkPath).use { fis ->
                ZipInputStream(fis).use { zis ->
                    var hasDex = false
                    var hasManifest = false
                    var hasNativeLibs = false
                    var dexCount = 0
                    val suspiciousFiles = mutableListOf<String>()
                    
                    var entry = zis.nextEntry
                    while (entry != null) {
                        val name = entry.name
                        
                        when {
                            name.endsWith(".dex") -> {
                                hasDex = true
                                dexCount++
                            }
                            name == "AndroidManifest.xml" -> hasManifest = true
                            name.startsWith("lib/") && name.endsWith(".so") -> hasNativeLibs = true
                            name.endsWith(".apk") -> suspiciousFiles.add("Embedded APK: $name")
                            name.endsWith(".jar") -> suspiciousFiles.add("Embedded JAR: $name")
                            name.endsWith(".dex") && !name.startsWith("classes") -> {
                                suspiciousFiles.add("Hidden DEX: $name")
                            }
                        }
                        
                        zis.closeEntry()
                        entry = zis.nextEntry
                    }
                    
                    result.hasDexFiles = hasDex
                    result.hasManifest = hasManifest
                    result.hasNativeLibraries = hasNativeLibs
                    result.dexFileCount = dexCount
                    result.suspiciousFiles = suspiciousFiles
                    
                    // Mark as suspicious if structure is invalid
                    if (!hasDex || !hasManifest) {
                        result.hasInvalidStructure = true
                    }
                    
                    // Multiple DEX files might indicate obfuscation
                    if (dexCount > 5) {
                        result.hasExcessiveDexFiles = true
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing APK structure", e)
        }
    }
    
    /**
     * Calculate overall risk score (0-100)
     */
    private fun calculateRiskScore(result: ApkAnalysisResult): Int {
        var score = 0
        
        // Highly suspicious permissions (15 points each, max 45)
        score += minOf(result.highlySuspiciousPermissions.size * 15, 45)
        
        // Dangerous permissions (5 points each, max 25)
        score += minOf(result.dangerousPermissions.size * 5, 25)
        
        // Suspicious package name (15 points)
        if (result.hasSuspiciousPackageName) score += 15
        
        // Invalid structure (20 points)
        if (result.hasInvalidStructure) score += 20
        
        // Excessive DEX files (10 points)
        if (result.hasExcessiveDexFiles) score += 10
        
        // Suspicious embedded files (5 points each, max 15)
        score += minOf(result.suspiciousFiles.size * 5, 15)
        
        return minOf(score, 100)
    }
    
    /**
     * Get sender context from file path
     * Extracts information about who sent the file based on WhatsApp folder structure
     */
    fun getSenderContext(apkPath: String): String? {
        return try {
            val file = File(apkPath)
            val parentDir = file.parentFile?.name
            
            when {
                apkPath.contains("WhatsApp") -> {
                    "Received via WhatsApp"
                }
                parentDir?.equals("Downloads", ignoreCase = true) == true -> {
                    "Downloaded file"
                }
                else -> {
                    "Source: $parentDir"
                }
            }
        } catch (e: Exception) {
            null
        }
    }
}

/**
 * Data class holding APK analysis results
 */
data class ApkAnalysisResult(
    var isValid: Boolean = true,
    var errorMessage: String? = null,
    var packageName: String? = null,
    var appLabel: String? = null,
    var versionName: String? = null,
    var versionCode: Long = 0,
    var fileSizeBytes: Long = 0,
    var requestedPermissions: List<String> = emptyList(),
    var dangerousPermissions: List<String> = emptyList(),
    var highlySuspiciousPermissions: List<String> = emptyList(),
    var hasSuspiciousPackageName: Boolean = false,
    var hasDexFiles: Boolean = false,
    var hasManifest: Boolean = false,
    var hasNativeLibraries: Boolean = false,
    var hasInvalidStructure: Boolean = false,
    var hasExcessiveDexFiles: Boolean = false,
    var dexFileCount: Int = 0,
    var suspiciousFiles: List<String> = emptyList(),
    var riskScore: Int = 0
) {
    fun getRiskLevel(): String = when {
        riskScore >= 70 -> "HIGH RISK"
        riskScore >= 40 -> "MEDIUM RISK"
        riskScore >= 20 -> "LOW RISK"
        else -> "SAFE"
    }
    
    fun getSummaryThreats(): List<String> {
        val threats = mutableListOf<String>()
        
        if (hasInvalidStructure) threats.add("Invalid APK structure")
        if (hasSuspiciousPackageName) threats.add("Suspicious package name")
        if (hasExcessiveDexFiles) threats.add("Excessive DEX files ($dexFileCount)")
        if (highlySuspiciousPermissions.isNotEmpty()) {
            threats.add("High-risk permissions (${highlySuspiciousPermissions.size})")
        }
        if (suspiciousFiles.isNotEmpty()) {
            threats.add("Suspicious embedded files")
        }
        
        return threats
    }
}
