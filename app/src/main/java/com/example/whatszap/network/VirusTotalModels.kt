package com.example.whatszap.network

import com.google.gson.annotations.SerializedName

/**
 * VirusTotal API response models
 */

data class VirusTotalFileResponse(
    @SerializedName("data")
    val data: FileData?
)

data class FileData(
    @SerializedName("id")
    val id: String,
    @SerializedName("type")
    val type: String,
    @SerializedName("attributes")
    val attributes: FileAttributes?
)

data class FileAttributes(
    @SerializedName("last_analysis_stats")
    val lastAnalysisStats: AnalysisStats?,
    @SerializedName("last_analysis_results")
    val lastAnalysisResults: Map<String, EngineResult>?,
    @SerializedName("meaningful_name")
    val meaningfulName: String?,
    @SerializedName("sha256")
    val sha256: String?,
    @SerializedName("md5")
    val md5: String?,
    @SerializedName("sha1")
    val sha1: String?,
    @SerializedName("size")
    val size: Long?,
    @SerializedName("type_description")
    val typeDescription: String?,
    @SerializedName("reputation")
    val reputation: Int?
)

data class AnalysisStats(
    @SerializedName("malicious")
    val malicious: Int = 0,
    @SerializedName("suspicious")
    val suspicious: Int = 0,
    @SerializedName("undetected")
    val undetected: Int = 0,
    @SerializedName("harmless")
    val harmless: Int = 0,
    @SerializedName("timeout")
    val timeout: Int = 0,
    @SerializedName("confirmed-timeout")
    val confirmedTimeout: Int = 0,
    @SerializedName("failure")
    val failure: Int = 0,
    @SerializedName("type-unsupported")
    val typeUnsupported: Int = 0
) {
    val totalEngines: Int
        get() = malicious + suspicious + undetected + harmless + timeout + confirmedTimeout + failure + typeUnsupported
    
    val detectionRatio: String
        get() = "$malicious/$totalEngines"
}

data class EngineResult(
    @SerializedName("category")
    val category: String?,
    @SerializedName("engine_name")
    val engineName: String?,
    @SerializedName("engine_version")
    val engineVersion: String?,
    @SerializedName("result")
    val result: String?,
    @SerializedName("method")
    val method: String?,
    @SerializedName("engine_update")
    val engineUpdate: String?
)

// Upload response
data class VirusTotalUploadResponse(
    @SerializedName("data")
    val data: UploadData?
)

data class UploadData(
    @SerializedName("id")
    val id: String,
    @SerializedName("type")
    val type: String
)

// Analysis response
data class VirusTotalAnalysisResponse(
    @SerializedName("data")
    val data: AnalysisData?
)

data class AnalysisData(
    @SerializedName("id")
    val id: String,
    @SerializedName("type")
    val type: String,
    @SerializedName("attributes")
    val attributes: AnalysisAttributes?
)

data class AnalysisAttributes(
    @SerializedName("status")
    val status: String?,
    @SerializedName("stats")
    val stats: AnalysisStats?,
    @SerializedName("results")
    val results: Map<String, EngineResult>?
)

/**
 * Wrapper result for VT scanning
 */
data class VirusTotalScanResult(
    val isFound: Boolean,
    val isMalicious: Boolean,
    val maliciousCount: Int,
    val totalEngines: Int,
    val detectionRatio: String,
    val threatNames: List<String>,
    val sha256: String,
    val virusTotalLink: String?,
    val errorMessage: String?
) {
    companion object {
        fun notFound(sha256: String): VirusTotalScanResult = VirusTotalScanResult(
            isFound = false,
            isMalicious = false,
            maliciousCount = 0,
            totalEngines = 0,
            detectionRatio = "0/0",
            threatNames = emptyList(),
            sha256 = sha256,
            virusTotalLink = null,
            errorMessage = null
        )
        
        fun error(sha256: String, message: String): VirusTotalScanResult = VirusTotalScanResult(
            isFound = false,
            isMalicious = false,
            maliciousCount = 0,
            totalEngines = 0,
            detectionRatio = "0/0",
            threatNames = emptyList(),
            sha256 = sha256,
            virusTotalLink = null,
            errorMessage = message
        )
    }
}
