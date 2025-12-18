package com.example.whatszap.utils

import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * Utility class for calculating file hashes
 */
object HashUtils {
    private const val TAG = "HashUtils"
    private const val BUFFER_SIZE = 8192
    
    /**
     * Calculate SHA-256 hash of a file
     * @param filePath Absolute path to the file
     * @return SHA-256 hash as lowercase hex string, or null if failed
     */
    fun calculateSha256(filePath: String): String? {
        return try {
            val file = File(filePath)
            if (!file.exists()) {
                Log.e(TAG, "File not found: $filePath")
                return null
            }
            
            val digest = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { fis ->
                val buffer = ByteArray(BUFFER_SIZE)
                var bytesRead: Int
                while (fis.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            
            val hashBytes = digest.digest()
            bytesToHex(hashBytes)
        } catch (e: Exception) {
            Log.e(TAG, "Error calculating SHA-256", e)
            null
        }
    }
    
    /**
     * Calculate MD5 hash of a file
     * @param filePath Absolute path to the file
     * @return MD5 hash as lowercase hex string, or null if failed
     */
    fun calculateMd5(filePath: String): String? {
        return try {
            val file = File(filePath)
            if (!file.exists()) {
                Log.e(TAG, "File not found: $filePath")
                return null
            }
            
            val digest = MessageDigest.getInstance("MD5")
            FileInputStream(file).use { fis ->
                val buffer = ByteArray(BUFFER_SIZE)
                var bytesRead: Int
                while (fis.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            
            val hashBytes = digest.digest()
            bytesToHex(hashBytes)
        } catch (e: Exception) {
            Log.e(TAG, "Error calculating MD5", e)
            null
        }
    }
    
    /**
     * Convert byte array to hexadecimal string
     */
    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = HEX_CHARS[v ushr 4]
            hexChars[i * 2 + 1] = HEX_CHARS[v and 0x0F]
        }
        return String(hexChars).lowercase()
    }
    
    private val HEX_CHARS = "0123456789ABCDEF".toCharArray()
}
