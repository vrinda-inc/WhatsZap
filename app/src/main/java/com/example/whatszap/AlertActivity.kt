package com.example.whatszap

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.OnBackPressedCallback
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.whatszap.ui.theme.WhatsZapTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class AlertActivity : ComponentActivity() {
    private var scanComplete = false
    private val minDisplayTime = 10000L // 10 seconds minimum
    private val startTime = System.currentTimeMillis()
    private val handler = Handler(Looper.getMainLooper())
    
    private val scanCompleteReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.example.whatszap.SCAN_COMPLETE") {
                scanComplete = true
                checkCanDismiss()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Make window non-dismissible and always on top
        window.setFlags(
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
            WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH or
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
            WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
            WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD or
            WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
            WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH or
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
            WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
            WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD or
            WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
        )
        
        // Set window to be always on top
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        }
        
        // Prevent back button
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                // Do nothing - prevent back button
            }
        })
        
        enableEdgeToEdge()
        
        val apkPath = intent.getStringExtra("apk_path") ?: "Unknown"
        
        setContent {
            WhatsZapTheme {
                AlertScreen(apkPath = apkPath)
            }
        }
        
        // Register receiver for scan completion
        try {
            registerReceiver(scanCompleteReceiver, IntentFilter("com.example.whatszap.SCAN_COMPLETE"))
        } catch (e: Exception) {
            android.util.Log.e("AlertActivity", "Error registering receiver", e)
        }
        
        // Set auto-dismiss after minimum time if scan completes
        handler.postDelayed({
            checkCanDismiss()
        }, minDisplayTime)
    }
    
    private fun checkCanDismiss() {
        val elapsed = System.currentTimeMillis() - startTime
        if (scanComplete && elapsed >= minDisplayTime) {
            finish()
        } else if (!scanComplete) {
            // Reschedule check
            handler.postDelayed({
                checkCanDismiss()
            }, 1000)
        } else {
            // Scan complete but need to wait for minimum time
            handler.postDelayed({
                finish()
            }, minDisplayTime - elapsed)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            if (scanCompleteReceiver != null) {
                unregisterReceiver(scanCompleteReceiver)
            }
        } catch (e: IllegalArgumentException) {
            // Receiver was not registered, ignore
        } catch (e: Exception) {
            android.util.Log.e("AlertActivity", "Error unregistering receiver", e)
        }
    }
}

@Composable
fun AlertScreen(apkPath: String) {
    var scanStatus by remember { mutableStateOf("Scanning in progress...") }
    var scanProgress by remember { mutableStateOf(0) }
    var scanComplete by remember { mutableStateOf(false) }
    var isMalicious by remember { mutableStateOf(false) }
    var threats by remember { mutableStateOf<List<String>>(emptyList()) }
    
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    
    // Listen for scan completion broadcast
    DisposableEffect(Unit) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == "com.example.whatszap.SCAN_COMPLETE") {
                    scanComplete = true
                    isMalicious = intent.getBooleanExtra("is_malicious", false)
                    threats = intent.getStringArrayExtra("threats")?.toList() ?: emptyList()
                    scanProgress = 100
                    scanStatus = if (isMalicious) {
                        "⚠️ Potential threats detected!"
                    } else {
                        "✓ Scan complete - No threats found"
                    }
                }
            }
        }
        context.registerReceiver(receiver, IntentFilter("com.example.whatszap.SCAN_COMPLETE"))
        
        // Simulate progress update while scanning
        val progressJob = coroutineScope.launch {
            while (!scanComplete && scanProgress < 90) {
                delay(500)
                scanProgress += 10
            }
        }
        
        onDispose {
            try {
                context.unregisterReceiver(receiver)
            } catch (e: Exception) {
                // Receiver might not be registered
            }
            progressJob.cancel()
        }
    }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.8f))
            .padding(16.dp),
        contentAlignment = Alignment.Center
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
        ) {
            Column(
                modifier = Modifier
                    .padding(24.dp)
                    .fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = "⚠️ SECURITY ALERT",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
                
                Text(
                    text = "APK File Detected",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
                
                Text(
                    text = apkPath.split("/").lastOrNull() ?: "Unknown file",
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.padding(horizontal = 8.dp)
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                LinearProgressIndicator(
                    progress = { scanProgress / 100f },
                    modifier = Modifier.fillMaxWidth(),
                    color = MaterialTheme.colorScheme.error
                )
                
                Text(
                    text = scanStatus,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
                
                if (scanComplete && threats.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Scan Results:",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                    threats.forEach { threat ->
                        Text(
                            text = "• $threat",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.9f),
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                } else {
                    Text(
                        text = "Please wait while we analyze this file for potential threats...",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.8f),
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
                
                Text(
                    text = "This window cannot be closed until analysis is complete.",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.7f),
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }
    }
}

