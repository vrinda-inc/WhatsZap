package com.example.whatszap.network

import okhttp3.MultipartBody
import okhttp3.RequestBody
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Path

/**
 * Retrofit service interface for VirusTotal API v3
 * 
 * API Documentation: https://developers.virustotal.com/reference/overview
 */
interface VirusTotalService {
    
    /**
     * Get file report by hash (SHA-256, SHA-1, or MD5)
     * Returns information about the file if it has been previously analyzed
     */
    @GET("files/{hash}")
    suspend fun getFileReport(
        @Header("x-apikey") apiKey: String,
        @Path("hash") hash: String
    ): Response<VirusTotalFileResponse>
    
    /**
     * Upload a file for scanning
     * Use this when the file hash is not found in the database
     */
    @Multipart
    @POST("files")
    suspend fun uploadFile(
        @Header("x-apikey") apiKey: String,
        @Part file: MultipartBody.Part
    ): Response<VirusTotalUploadResponse>
    
    /**
     * Get analysis results for a previously uploaded file
     */
    @GET("analyses/{id}")
    suspend fun getAnalysis(
        @Header("x-apikey") apiKey: String,
        @Path("id") analysisId: String
    ): Response<VirusTotalAnalysisResponse>
}
