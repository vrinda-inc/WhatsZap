package com.example.whatszap.utils

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Log
import com.googlecode.tesseract.android.TessBaseAPI
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

/**
 * OCR utility for extracting text from WhatsApp screenshots
 * Uses Tesseract to read message content for behavioral analysis
 */
class MessageOCR(private val context: Context) {
    
    companion object {
        private const val TAG = "MessageOCR"
        private const val TESSDATA_DIR = "tessdata"
        private const val LANGUAGE = "eng" // English language data
        
        @Volatile
        private var instance: MessageOCR? = null
        
        fun getInstance(context: Context): MessageOCR {
            return instance ?: synchronized(this) {
                instance ?: MessageOCR(context.applicationContext).also { instance = it }
            }
        }
    }
    
    private var tessBaseAPI: TessBaseAPI? = null
    private var isInitialized = false
    
    /**
     * Initialize Tesseract OCR engine
     * Must be called before performing OCR
     */
    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        if (isInitialized) return@withContext true
        
        try {
            // Create tessdata directory
            val dataPath = context.filesDir.absolutePath
            val tessDataDir = File(dataPath, TESSDATA_DIR)
            
            if (!tessDataDir.exists()) {
                tessDataDir.mkdirs()
            }
            
            // Copy trained data file if not exists
            val trainedDataFile = File(tessDataDir, "$LANGUAGE.traineddata")
            
            if (!trainedDataFile.exists()) {
                Log.i(TAG, "Copying Tesseract trained data...")
                
                // Note: eng.traineddata should be in assets/tessdata/
                // For production, package this file in assets
                context.assets.open("tessdata/$LANGUAGE.traineddata").use { input ->
                    FileOutputStream(trainedDataFile).use { output ->
                        input.copyTo(output)
                    }
                }
            }
            
            // Initialize TessBaseAPI
            tessBaseAPI = TessBaseAPI().apply {
                if (!init(dataPath, LANGUAGE)) {
                    Log.e(TAG, "Failed to initialize Tesseract")
                    return@withContext false
                }
                
                // Set page segmentation mode for better accuracy
                // PSM_AUTO_ONLY: Automatic page segmentation
                pageSegMode = TessBaseAPI.PageSegMode.PSM_AUTO_ONLY
            }
            
            isInitialized = true
            Log.i(TAG, "Tesseract initialized successfully")
            true
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Tesseract", e)
            isInitialized = false
            false
        }
    }
    
    /**
     * Extract text from screenshot image file
     */
    suspend fun extractTextFromImage(imagePath: String): OCRResult = withContext(Dispatchers.IO) {
        if (!isInitialized) {
            if (!initialize()) {
                return@withContext OCRResult(
                    success = false,
                    extractedText = "",
                    confidence = 0f,
                    errorMessage = "OCR engine not initialized"
                )
            }
        }
        
        try {
            val bitmap = BitmapFactory.decodeFile(imagePath)
            
            if (bitmap == null) {
                return@withContext OCRResult(
                    success = false,
                    extractedText = "",
                    confidence = 0f,
                    errorMessage = "Failed to load image"
                )
            }
            
            val result = extractTextFromBitmap(bitmap)
            bitmap.recycle()
            
            result
            
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting text from image", e)
            OCRResult(
                success = false,
                extractedText = "",
                confidence = 0f,
                errorMessage = e.message
            )
        }
    }
    
    /**
     * Extract text from bitmap
     */
    private fun extractTextFromBitmap(bitmap: Bitmap): OCRResult {
        return try {
            tessBaseAPI?.setImage(bitmap)
            val extractedText = tessBaseAPI?.utF8Text ?: ""
            val confidence = tessBaseAPI?.meanConfidence() ?: 0
            
            Log.i(TAG, "OCR completed: ${extractedText.length} chars, confidence: $confidence%")
            
            OCRResult(
                success = true,
                extractedText = extractedText.trim(),
                confidence = confidence.toFloat(),
                errorMessage = null
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error during OCR", e)
            OCRResult(
                success = false,
                extractedText = "",
                confidence = 0f,
                errorMessage = e.message
            )
        }
    }
    
    /**
     * Extract specific sections from WhatsApp screenshot
     * Attempts to identify sender name and message content
     */
    suspend fun extractWhatsAppMessage(imagePath: String): WhatsAppMessage {
        val ocrResult = extractTextFromImage(imagePath)
        
        if (!ocrResult.success || ocrResult.extractedText.isEmpty()) {
            return WhatsAppMessage(
                senderName = null,
                messageText = null,
                confidence = 0f,
                rawText = ""
            )
        }
        
        // Parse WhatsApp message structure
        return parseWhatsAppText(ocrResult.extractedText, ocrResult.confidence)
    }
    
    /**
     * Parse extracted text to identify WhatsApp components
     */
    private fun parseWhatsAppText(text: String, confidence: Float): WhatsAppMessage {
        val lines = text.lines().filter { it.isNotBlank() }
        
        if (lines.isEmpty()) {
            return WhatsAppMessage(null, null, confidence, text)
        }
        
        // WhatsApp typically shows sender at top in group chats
        // or contact name in 1-1 chats
        val senderName = lines.firstOrNull()?.trim()
        
        // Message content is usually the remaining lines
        val messageText = lines.drop(1).joinToString("\n").trim()
        
        return WhatsAppMessage(
            senderName = senderName?.takeIf { it.isNotEmpty() },
            messageText = messageText.takeIf { it.isNotEmpty() },
            confidence = confidence,
            rawText = text
        )
    }
    
    /**
     * Release OCR resources
     */
    fun release() {
        tessBaseAPI?.end()
        tessBaseAPI = null
        isInitialized = false
        Log.i(TAG, "Tesseract released")
    }
}

/**
 * Result from OCR operation
 */
data class OCRResult(
    val success: Boolean,
    val extractedText: String,
    val confidence: Float,
    val errorMessage: String? = null
)

/**
 * Parsed WhatsApp message from screenshot
 */
data class WhatsAppMessage(
    val senderName: String?,
    val messageText: String?,
    val confidence: Float,
    val rawText: String
)
