package com.example.whatszap.utils

import android.content.Context
import android.util.Log
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Manages APK quarantine to prevent installation during analysis
 */
class ApkQuarantine(private val context: Context) {
    
    companion object {
        private const val TAG = "ApkQuarantine"
        private const val QUARANTINE_DIR_NAME = "quarantine"
        
        @Volatile
        private var instance: ApkQuarantine? = null
        
        fun getInstance(context: Context): ApkQuarantine {
            return instance ?: synchronized(this) {
                instance ?: ApkQuarantine(context.applicationContext).also { instance = it }
            }
        }
    }
    
    private val quarantineDir: File by lazy {
        File(context.filesDir, QUARANTINE_DIR_NAME).apply {
            if (!exists()) {
                mkdirs()
            }
        }
    }
    
    /**
     * Move an APK file to quarantine
     * Returns the new quarantine path or null if failed
     */
    fun quarantineApk(apkPath: String): String? {
        return try {
            val sourceFile = File(apkPath)
            if (!sourceFile.exists()) {
                Log.e(TAG, "Source file does not exist: $apkPath")
                return null
            }
            
            // Create unique filename in quarantine
            val timestamp = System.currentTimeMillis()
            val quarantinedFile = File(quarantineDir, "${timestamp}_${sourceFile.name}")
            
            // Copy file to quarantine (keep original for now)
            sourceFile.copyTo(quarantinedFile, overwrite = true)
            
            // Make original read-only to prevent installation
            if (!makeReadOnly(sourceFile)) {
                Log.w(TAG, "Could not make original file read-only")
            }
            
            Log.i(TAG, "Quarantined APK: $apkPath -> ${quarantinedFile.absolutePath}")
            quarantinedFile.absolutePath
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to quarantine APK: $apkPath", e)
            null
        }
    }
    
    /**
     * Make a file read-only to prevent installation
     */
    private fun makeReadOnly(file: File): Boolean {
        return try {
            file.setReadOnly()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set read-only: ${file.absolutePath}", e)
            false
        }
    }
    
    /**
     * Restore a file from quarantine to its original location
     */
    fun restoreFromQuarantine(quarantinePath: String, originalPath: String): Boolean {
        return try {
            val quarantinedFile = File(quarantinePath)
            val originalFile = File(originalPath)
            
            if (!quarantinedFile.exists()) {
                Log.e(TAG, "Quarantined file not found: $quarantinePath")
                return false
            }
            
            // Restore file
            quarantinedFile.copyTo(originalFile, overwrite = true)
            
            // Make writable
            originalFile.setWritable(true)
            originalFile.setReadable(true)
            
            // Delete from quarantine
            quarantinedFile.delete()
            
            Log.i(TAG, "Restored from quarantine: $quarantinePath -> $originalPath")
            true
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to restore from quarantine", e)
            false
        }
    }
    
    /**
     * Permanently delete a quarantined file
     */
    fun deleteQuarantined(quarantinePath: String): Boolean {
        return try {
            val file = File(quarantinePath)
            val deleted = file.delete()
            
            if (deleted) {
                Log.i(TAG, "Permanently deleted quarantined file: $quarantinePath")
            } else {
                Log.w(TAG, "Failed to delete quarantined file: $quarantinePath")
            }
            
            deleted
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting quarantined file", e)
            false
        }
    }
    
    /**
     * Delete the original APK after successful quarantine
     */
    fun deleteOriginal(originalPath: String): Boolean {
        return try {
            val file = File(originalPath)
            
            // First restore write permissions
            file.setWritable(true)
            
            val deleted = file.delete()
            if (deleted) {
                Log.i(TAG, "Deleted original file: $originalPath")
            } else {
                Log.w(TAG, "Failed to delete original file: $originalPath")
            }
            
            deleted
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting original file", e)
            false
        }
    }
    
    /**
     * List all quarantined files
     */
    fun listQuarantinedFiles(): List<File> {
        return quarantineDir.listFiles()?.toList() ?: emptyList()
    }
    
    /**
     * Get size of quarantine directory in bytes
     */
    fun getQuarantineSize(): Long {
        return listQuarantinedFiles().sumOf { it.length() }
    }
    
    /**
     * Clean up old quarantined files (older than specified days)
     */
    fun cleanupOldFiles(olderThanDays: Int = 7): Int {
        val cutoffTime = System.currentTimeMillis() - (olderThanDays * 24 * 60 * 60 * 1000L)
        var deletedCount = 0
        
        listQuarantinedFiles().forEach { file ->
            if (file.lastModified() < cutoffTime) {
                if (file.delete()) {
                    deletedCount++
                    Log.i(TAG, "Cleaned up old quarantine file: ${file.name}")
                }
            }
        }
        
        return deletedCount
    }
    
    /**
     * Check if a file is currently quarantined
     */
    fun isQuarantined(originalPath: String): Boolean {
        val fileName = File(originalPath).name
        return listQuarantinedFiles().any { it.name.endsWith(fileName) }
    }
    
    /**
     * Find quarantine path for an original file
     */
    fun findQuarantinePath(originalPath: String): String? {
        val fileName = File(originalPath).name
        return listQuarantinedFiles()
            .firstOrNull { it.name.endsWith(fileName) }
            ?.absolutePath
    }
}
