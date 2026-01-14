package com.example.whatszap.utils

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Handler
import android.os.Looper
import android.util.DisplayMetrics
import android.util.Log
import android.view.WindowManager
import com.example.whatszap.data.ScreenshotInfo
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * Utility class for capturing screenshots using MediaProjection API
 */
class ScreenshotCapture(private val context: Context) {
    
    companion object {
        private const val TAG = "ScreenshotCapture"
        const val REQUEST_CODE_SCREEN_CAPTURE = 1001
        
        private const val SCREENSHOT_DIR_NAME = "screenshots"
        private const val THUMBNAIL_DIR_NAME = "thumbnails"
        
        @Volatile
        private var instance: ScreenshotCapture? = null
        
        fun getInstance(context: Context): ScreenshotCapture {
            return instance ?: synchronized(this) {
                instance ?: ScreenshotCapture(context.applicationContext).also { instance = it }
            }
        }
    }
    
    private var mediaProjection: MediaProjection? = null
    private var captureCallback: ((ScreenshotInfo) -> Unit)? = null
    
    private val screenshotDir: File by lazy {
        File(context.filesDir, SCREENSHOT_DIR_NAME).apply {
            if (!exists()) {
                mkdirs()
            }
        }
    }
    
    private val thumbnailDir: File by lazy {
        File(context.filesDir, THUMBNAIL_DIR_NAME).apply {
            if (!exists()) {
                mkdirs()
            }
        }
    }
    
    /**
     * Request screen capture permission
     * Call this from an Activity, it will launch the permission dialog
     */
    fun requestScreenCapturePermission(activity: Activity) {
        val mediaProjectionManager = context.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val captureIntent = mediaProjectionManager.createScreenCaptureIntent()
        activity.startActivityForResult(captureIntent, REQUEST_CODE_SCREEN_CAPTURE)
    }
    
    /**
     * Handle the permission result
     * Call this from Activity's onActivityResult
     */
    fun handlePermissionResult(resultCode: Int, data: Intent?, callback: (Boolean) -> Unit) {
        if (resultCode == Activity.RESULT_OK && data != null) {
            val mediaProjectionManager = context.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
            mediaProjection = mediaProjectionManager.getMediaProjection(resultCode, data)
            callback(true)
        } else {
            Log.e(TAG, "Screen capture permission denied")
            callback(false)
        }
    }
    
    /**
     * Initialize with an existing MediaProjection
     */
    fun initializeWithProjection(projection: MediaProjection) {
        mediaProjection = projection
    }
    
    /**
     * Capture a screenshot
     * Requires MediaProjection to be already initialized
     */
    fun captureScreenshot(callback: (ScreenshotInfo) -> Unit) {
        this.captureCallback = callback
        
        val projection = mediaProjection
        if (projection == null) {
            Log.e(TAG, "MediaProjection not initialized")
            callback(
                ScreenshotInfo(
                    screenshotPath = "",
                    thumbnailPath = null,
                    captureTimestamp = System.currentTimeMillis(),
                    captureSuccess = false,
                    errorMessage = "MediaProjection not initialized"
                )
            )
            return
        }
        
        try {
            val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val metrics = DisplayMetrics()
            windowManager.defaultDisplay.getMetrics(metrics)
            
            val width = metrics.widthPixels
            val height = metrics.heightPixels
            val density = metrics.densityDpi
            
            val imageReader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)
            
            val virtualDisplay = projection.createVirtualDisplay(
                "ScreenCapture",
                width, height, density,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                imageReader.surface,
                null, null
            )
            
            // Delay to ensure display is ready
            Handler(Looper.getMainLooper()).postDelayed({
                val image = imageReader.acquireLatestImage()
                
                if (image != null) {
                    val bitmap = imageToBitmap(image)
                    image.close()
                    
                    if (bitmap != null) {
                        saveScreenshot(bitmap)
                    } else {
                        callback(
                            ScreenshotInfo(
                                screenshotPath = "",
                                thumbnailPath = null,
                                captureTimestamp = System.currentTimeMillis(),
                                captureSuccess = false,
                                errorMessage = "Failed to convert image to bitmap"
                            )
                        )
                    }
                } else {
                    Log.e(TAG, "Failed to acquire image")
                    callback(
                        ScreenshotInfo(
                            screenshotPath = "",
                            thumbnailPath = null,
                            captureTimestamp = System.currentTimeMillis(),
                            captureSuccess = false,
                            errorMessage = "Failed to acquire image"
                        )
                    )
                }
                
                virtualDisplay?.release()
                imageReader.close()
            }, 300) // Wait 300ms for screen to be captured
            
        } catch (e: Exception) {
            Log.e(TAG, "Error capturing screenshot", e)
            callback(
                ScreenshotInfo(
                    screenshotPath = "",
                    thumbnailPath = null,
                    captureTimestamp = System.currentTimeMillis(),
                    captureSuccess = false,
                    errorMessage = e.message
                )
            )
        }
    }
    
    /**
     * Convert Image to Bitmap
     */
    private fun imageToBitmap(image: Image): Bitmap? {
        return try {
            val planes = image.planes
            val buffer = planes[0].buffer
            val pixelStride = planes[0].pixelStride
            val rowStride = planes[0].rowStride
            val rowPadding = rowStride - pixelStride * image.width
            
            val bitmap = Bitmap.createBitmap(
                image.width + rowPadding / pixelStride,
                image.height,
                Bitmap.Config.ARGB_8888
            )
            bitmap.copyPixelsFromBuffer(buffer)
            
            // Crop to actual size if there's padding
            if (rowPadding > 0) {
                Bitmap.createBitmap(bitmap, 0, 0, image.width, image.height)
            } else {
                bitmap
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error converting image to bitmap", e)
            null
        }
    }
    
    /**
     * Save screenshot to file and create thumbnail
     */
    private fun saveScreenshot(bitmap: Bitmap) {
        try {
            val timestamp = System.currentTimeMillis()
            val screenshotFile = File(screenshotDir, "screenshot_$timestamp.png")
            val thumbnailFile = File(thumbnailDir, "thumb_$timestamp.png")
            
            // Save full screenshot
            FileOutputStream(screenshotFile).use { out ->
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
            }
            Log.i(TAG, "Screenshot saved: ${screenshotFile.absolutePath}")
            
            // Create and save thumbnail (reduced size)
            val thumbnailWidth = 300
            val thumbnailHeight = (bitmap.height * (thumbnailWidth.toFloat() / bitmap.width)).toInt()
            val thumbnail = Bitmap.createScaledBitmap(bitmap, thumbnailWidth, thumbnailHeight, true)
            
            FileOutputStream(thumbnailFile).use { out ->
                thumbnail.compress(Bitmap.CompressFormat.JPEG, 80, out)
            }
            Log.i(TAG, "Thumbnail saved: ${thumbnailFile.absolutePath}")
            
            // Clean up
            thumbnail.recycle()
            bitmap.recycle()
            
            captureCallback?.invoke(
                ScreenshotInfo(
                    screenshotPath = screenshotFile.absolutePath,
                    thumbnailPath = thumbnailFile.absolutePath,
                    captureTimestamp = timestamp,
                    captureSuccess = true,
                    fileSize = screenshotFile.length()
                )
            )
            
        } catch (e: IOException) {
            Log.e(TAG, "Error saving screenshot", e)
            captureCallback?.invoke(
                ScreenshotInfo(
                    screenshotPath = "",
                    thumbnailPath = null,
                    captureTimestamp = System.currentTimeMillis(),
                    captureSuccess = false,
                    errorMessage = e.message
                )
            )
        }
    }
    
    /**
     * Release resources
     */
    fun release() {
        mediaProjection?.stop()
        mediaProjection = null
    }
    
    /**
     * Get list of all saved screenshots
     */
    fun listScreenshots(): List<File> {
        return screenshotDir.listFiles()?.sortedByDescending { it.lastModified() }?.toList() ?: emptyList()
    }
    
    /**
     * Delete a screenshot and its thumbnail
     */
    fun deleteScreenshot(screenshotPath: String): Boolean {
        return try {
            val screenshotFile = File(screenshotPath)
            val thumbnailFile = File(thumbnailDir, screenshotFile.name.replace("screenshot_", "thumb_").replace(".png", ".png"))
            
            val deleted = screenshotFile.delete()
            thumbnailFile.delete() // Also delete thumbnail
            
            deleted
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting screenshot", e)
            false
        }
    }
    
    /**
     * Clean up old screenshots
     */
    fun cleanupOldScreenshots(olderThanDays: Int = 7): Int {
        val cutoffTime = System.currentTimeMillis() - (olderThanDays * 24 * 60 * 60 * 1000L)
        var deletedCount = 0
        
        listScreenshots().forEach { file ->
            if (file.lastModified() < cutoffTime) {
                if (deleteScreenshot(file.absolutePath)) {
                    deletedCount++
                }
            }
        }
        
        return deletedCount
    }
}
