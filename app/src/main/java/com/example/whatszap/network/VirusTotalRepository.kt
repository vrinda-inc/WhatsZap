package com.example.whatszap.network

import android.util.Log
import com.example.whatszap.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Repository for VirusTotal API operations
 * Handles all network calls and response parsing
 */
class VirusTotalRepository private constructor() {
    
    companion object {
        private const val TAG = "VirusTotalRepository"
        private const val BASE_URL = "https://www.virustotal.com/api/v3/"
        private const val VT_GUI_URL = "https://www.virustotal.com/gui/file/"
        private const val MAX_POLL_ATTEMPTS = 30
        private const val POLL_DELAY_MS = 2000L
        
        @Volatile
        private var instance: VirusTotalRepository? = null
        
        fun getInstance(): VirusTotalRepository {
            return instance ?: synchronized(this) {
                instance ?: VirusTotalRepository().also { instance = it }
            }
        }
    }
    
    private val apiKey: String = BuildConfig.VIRUSTOTAL_API_KEY
    
    private val loggingInterceptor = HttpLoggingInterceptor().apply {
        level = if (BuildConfig.DEBUG) {
            HttpLoggingInterceptor.Level.BODY
        } else {
            HttpLoggingInterceptor.Level.NONE
        }
    }
    
    private val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(loggingInterceptor)
        .connectTimeout(60, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(120, TimeUnit.SECONDS)
        .build()
    
    private val retrofit = Retrofit.Builder()
        .baseUrl(BASE_URL)
        .client(okHttpClient)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
    
    private val service: VirusTotalService = retrofit.create(VirusTotalService::class.java)
    
    /**
     * Check if API key is configured
     */
    fun isApiKeyConfigured(): Boolean {
        return apiKey.isNotBlank() && apiKey != "YOUR_API_KEY_HERE"
    }
    
    /**
     * Check file hash against VirusTotal database
     */
    suspend fun checkFileHash(sha256: String): VirusTotalScanResult = withContext(Dispatchers.IO) {
        if (!isApiKeyConfigured()) {
            Log.w(TAG, "VirusTotal API key not configured")
            return@withContext VirusTotalScanResult.error(sha256, "API key not configured")
        }
        
        try {
            Log.i(TAG, "Checking hash: $sha256")
            val response = service.getFileReport(apiKey, sha256)
            
            if (response.isSuccessful) {
                val fileResponse = response.body()
                val attributes = fileResponse?.data?.attributes
                val stats = attributes?.lastAnalysisStats
                
                if (stats != null) {
                    val threatNames = extractThreatNames(attributes.lastAnalysisResults)
                    
                    Log.i(TAG, "Hash found. Detections: ${stats.malicious}/${stats.totalEngines}")
                    
                    return@withContext VirusTotalScanResult(
                        isFound = true,
                        isMalicious = stats.malicious > 0 || stats.suspicious > 0,
                        maliciousCount = stats.malicious + stats.suspicious,
                        totalEngines = stats.totalEngines,
                        detectionRatio = "${stats.malicious + stats.suspicious}/${stats.totalEngines}",
                        threatNames = threatNames,
                        sha256 = sha256,
                        virusTotalLink = "$VT_GUI_URL$sha256",
                        errorMessage = null
                    )
                }
            } else if (response.code() == 404) {
                Log.i(TAG, "Hash not found in VirusTotal database")
                return@withContext VirusTotalScanResult.notFound(sha256)
            } else {
                Log.e(TAG, "API error: ${response.code()} - ${response.message()}")
                return@withContext VirusTotalScanResult.error(sha256, "API error: ${response.code()}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception checking hash", e)
            return@withContext VirusTotalScanResult.error(sha256, e.message ?: "Unknown error")
        }
        
        return@withContext VirusTotalScanResult.notFound(sha256)
    }
    
    /**
     * Upload file to VirusTotal for scanning
     */
    suspend fun uploadFile(filePath: String): VirusTotalScanResult = withContext(Dispatchers.IO) {
        if (!isApiKeyConfigured()) {
            Log.w(TAG, "VirusTotal API key not configured")
            return@withContext VirusTotalScanResult.error("", "API key not configured")
        }
        
        val file = File(filePath)
        if (!file.exists()) {
            return@withContext VirusTotalScanResult.error("", "File not found: $filePath")
        }
        
        try {
            Log.i(TAG, "Uploading file: ${file.name}")
            
            val requestBody = file.asRequestBody("application/vnd.android.package-archive".toMediaTypeOrNull())
            val multipartBody = MultipartBody.Part.createFormData("file", file.name, requestBody)
            
            val response = service.uploadFile(apiKey, multipartBody)
            
            if (response.isSuccessful) {
                val uploadData = response.body()?.data
                val analysisId = uploadData?.id
                
                if (analysisId != null) {
                    Log.i(TAG, "File uploaded. Analysis ID: $analysisId")
                    return@withContext pollAnalysisResult(analysisId)
                }
            } else {
                Log.e(TAG, "Upload failed: ${response.code()} - ${response.message()}")
                return@withContext VirusTotalScanResult.error("", "Upload failed: ${response.code()}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception uploading file", e)
            return@withContext VirusTotalScanResult.error("", e.message ?: "Upload failed")
        }
        
        return@withContext VirusTotalScanResult.error("", "Upload failed")
    }
    
    /**
     * Poll for analysis results after file upload
     */
    private suspend fun pollAnalysisResult(analysisId: String): VirusTotalScanResult = withContext(Dispatchers.IO) {
        var attempts = 0
        
        while (attempts < MAX_POLL_ATTEMPTS) {
            try {
                delay(POLL_DELAY_MS)
                
                val response = service.getAnalysis(apiKey, analysisId)
                
                if (response.isSuccessful) {
                    val analysisData = response.body()?.data?.attributes
                    val status = analysisData?.status
                    
                    Log.d(TAG, "Analysis status: $status (attempt ${attempts + 1})")
                    
                    if (status == "completed") {
                        val stats = analysisData.stats
                        val threatNames = extractThreatNames(analysisData.results)
                        
                        val sha256 = analysisId.split("-").firstOrNull() ?: ""
                        
                        return@withContext VirusTotalScanResult(
                            isFound = true,
                            isMalicious = (stats?.malicious ?: 0) > 0 || (stats?.suspicious ?: 0) > 0,
                            maliciousCount = (stats?.malicious ?: 0) + (stats?.suspicious ?: 0),
                            totalEngines = stats?.totalEngines ?: 0,
                            detectionRatio = "${(stats?.malicious ?: 0) + (stats?.suspicious ?: 0)}/${stats?.totalEngines ?: 0}",
                            threatNames = threatNames,
                            sha256 = sha256,
                            virusTotalLink = if (sha256.isNotEmpty()) "$VT_GUI_URL$sha256" else null,
                            errorMessage = null
                        )
                    }
                }
                
                attempts++
            } catch (e: Exception) {
                Log.e(TAG, "Exception polling analysis", e)
                attempts++
            }
        }
        
        Log.w(TAG, "Analysis polling timed out after $MAX_POLL_ATTEMPTS attempts")
        return@withContext VirusTotalScanResult.error("", "Analysis timed out")
    }
    
    /**
     * Extract threat names from engine results
     */
    private fun extractThreatNames(results: Map<String, EngineResult>?): List<String> {
        if (results == null) return emptyList()
        
        return results.values
            .filter { it.category == "malicious" || it.category == "suspicious" }
            .mapNotNull { result ->
                val engineName = result.engineName ?: "Unknown"
                val threatName = result.result ?: "Detected"
                "$engineName: $threatName"
            }
            .take(10) // Limit to top 10 detections
    }
}
