package com.example.whatszap

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

/**
 * Monitors APK installation events to warn about analyzed packages
 */
class InstallationMonitor : BroadcastReceiver() {
    
    companion object {
        private const val TAG = "InstallationMonitor"
        private const val CHANNEL_ID = "InstallationWarning"
        private const val NOTIFICATION_ID_BASE = 2000
    }
    
    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        
        when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                handlePackageAdded(context, intent)
            }
            Intent.ACTION_PACKAGE_INSTALL -> {
                handlePackageInstall(context, intent)
            }
        }
    }
    
    /**
     * Handle package added event (installation completed)
     */
    private fun handlePackageAdded(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart
        
        if (packageName != null && !intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
            Log.i(TAG, "Package installed: $packageName")
            
            // Check if this was a recently analyzed package
            // TODO: Check against database of analyzed APKs
            
            // For now, just log it
            Log.i(TAG, "New package installation detected: $packageName")
        }
    }
    
    /**
     * Handle package install event (installation starting)
     */
    private fun handlePackageInstall(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart
        
        if (packageName != null) {
            Log.i(TAG, "Package installation starting: $packageName")
            
            // Show warning if this is a flagged package
            // TODO: Check against database
        }
    }
    
    /**
     * Show warning notification about suspicious installation
     */
    private fun showInstallationWarning(
        context: Context,
        packageName: String,
        isMalicious: Boolean
    ) {
        try {
            val title = if (isMalicious) {
                "⚠️ MALICIOUS APP INSTALLED"
            } else {
                "⚠️ Suspicious App Installed"
            }
            
            val message = "Package: $packageName\nThis app was flagged during analysis. Proceed with caution!"
            
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(message)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setStyle(NotificationCompat.BigTextStyle().bigText(message))
                .build()
            
            NotificationManagerCompat.from(context).notify(
                NOTIFICATION_ID_BASE + packageName.hashCode(),
                notification
            )
            
            Log.i(TAG, "Installation warning shown for: $packageName")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error showing installation warning", e)
        }
    }
}
