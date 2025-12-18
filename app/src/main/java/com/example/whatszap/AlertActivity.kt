package com.example.whatszap

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.OnBackPressedCallback
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
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
                AlertScreen(apkPath = apkPath, onDismiss = { finish() })
            }
        }
        
        // Register receiver for scan completion
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(
                scanCompleteReceiver, 
                IntentFilter("com.example.whatszap.SCAN_COMPLETE"),
                RECEIVER_NOT_EXPORTED
            )
        } else {
            registerReceiver(scanCompleteReceiver, IntentFilter("com.example.whatszap.SCAN_COMPLETE"))
        }
        
        // Set auto-dismiss after minimum time if scan completes
        handler.postDelayed({
            checkCanDismiss()
        }, minDisplayTime)
    }
    
    private fun checkCanDismiss() {
        val elapsed = System.currentTimeMillis() - startTime
        if (scanComplete && elapsed >= minDisplayTime) {
            // Don't auto-dismiss, let user review results
        } else if (!scanComplete) {
            // Reschedule check
            handler.postDelayed({
                checkCanDismiss()
            }, 1000)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(scanCompleteReceiver)
        } catch (e: Exception) {
            // Receiver might not be registered
        }
    }
}

@Composable
fun AlertScreen(apkPath: String, onDismiss: () -> Unit) {
    var scanStatus by remember { mutableStateOf("Initializing scan...") }
    var scanProgress by remember { mutableStateOf(0f) }
    var scanComplete by remember { mutableStateOf(false) }
    var isMalicious by remember { mutableStateOf(false) }
    var threats by remember { mutableStateOf<List<String>>(emptyList()) }
    var confidence by remember { mutableStateOf(0) }
    
    // VirusTotal state
    var vtScanned by remember { mutableStateOf(false) }
    var vtDetections by remember { mutableStateOf(0) }
    var vtEngines by remember { mutableStateOf(0) }
    var vtLink by remember { mutableStateOf<String?>(null) }
    var vtThreats by remember { mutableStateOf<List<String>>(emptyList()) }
    var sha256Hash by remember { mutableStateOf("") }
    
    // Static analysis state
    var packageName by remember { mutableStateOf<String?>(null) }
    var appLabel by remember { mutableStateOf<String?>(null) }
    var riskScore by remember { mutableStateOf(0) }
    var dangerousPermissions by remember { mutableStateOf<List<String>>(emptyList()) }
    var suspiciousPermissions by remember { mutableStateOf<List<String>>(emptyList()) }
    
    // Context
    var senderContext by remember { mutableStateOf<String?>(null) }
    var fileSize by remember { mutableStateOf(0L) }
    
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    
    // Animation for scanning indicator
    val infiniteTransition = rememberInfiniteTransition(label = "scan")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse"
    )
    
    // Listen for scan completion broadcast
    DisposableEffect(Unit) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == "com.example.whatszap.SCAN_COMPLETE") {
                    scanComplete = true
                    isMalicious = intent.getBooleanExtra("is_malicious", false)
                    confidence = intent.getIntExtra("confidence", 0)
                    threats = intent.getStringArrayExtra("threats")?.toList() ?: emptyList()
                    
                    // VirusTotal data
                    vtScanned = intent.getBooleanExtra("vt_scanned", false)
                    vtDetections = intent.getIntExtra("vt_detections", 0)
                    vtEngines = intent.getIntExtra("vt_engines", 0)
                    vtLink = intent.getStringExtra("vt_link")
                    vtThreats = intent.getStringArrayExtra("vt_threats")?.toList() ?: emptyList()
                    sha256Hash = intent.getStringExtra("sha256_hash") ?: ""
                    
                    // Static analysis data
                    packageName = intent.getStringExtra("package_name")
                    appLabel = intent.getStringExtra("app_label")
                    riskScore = intent.getIntExtra("risk_score", 0)
                    dangerousPermissions = intent.getStringArrayExtra("dangerous_permissions")?.toList() ?: emptyList()
                    suspiciousPermissions = intent.getStringArrayExtra("suspicious_permissions")?.toList() ?: emptyList()
                    
                    // Context
                    senderContext = intent.getStringExtra("sender_context")
                    fileSize = intent.getLongExtra("file_size", 0)
                    
                    scanProgress = 1f
                    scanStatus = if (isMalicious) {
                        "⚠️ Threats Detected!"
                    } else if (vtDetections > 0) {
                        "⚠️ Suspicious Activity"
                    } else {
                        "✓ Scan Complete"
                    }
                }
            }
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(
                receiver, 
                IntentFilter("com.example.whatszap.SCAN_COMPLETE"),
                Context.RECEIVER_NOT_EXPORTED
            )
        } else {
            context.registerReceiver(receiver, IntentFilter("com.example.whatszap.SCAN_COMPLETE"))
        }
        
        // Simulate progress update while scanning
        val progressJob = coroutineScope.launch {
            val stages = listOf(
                "Calculating file hash..." to 0.15f,
                "Performing static analysis..." to 0.30f,
                "Checking VirusTotal database..." to 0.50f,
                "Analyzing permissions..." to 0.70f,
                "Running behavioral analysis..." to 0.85f,
                "Finalizing scan..." to 0.95f
            )
            
            for ((status, progress) in stages) {
                if (scanComplete) break
                scanStatus = status
                scanProgress = progress
                delay(1500)
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
    
    val backgroundColor = when {
        scanComplete && isMalicious -> Color(0xFFB71C1C) // Dark red
        scanComplete && vtDetections > 0 -> Color(0xFFE65100) // Dark orange
        scanComplete -> Color(0xFF1B5E20) // Dark green
        else -> Color(0xFF1A237E) // Dark blue
    }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color.Black.copy(alpha = 0.95f),
                        backgroundColor.copy(alpha = 0.9f)
                    )
                )
            )
            .padding(16.dp),
        contentAlignment = Alignment.Center
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.95f)
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 12.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier
                    .padding(24.dp)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Animated Icon
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .scale(if (!scanComplete) pulseScale else 1f)
                        .clip(CircleShape)
                        .background(
                            when {
                                scanComplete && isMalicious -> Color(0xFFFFCDD2)
                                scanComplete && vtDetections > 0 -> Color(0xFFFFE0B2)
                                scanComplete -> Color(0xFFC8E6C9)
                                else -> Color(0xFFBBDEFB)
                            }
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = when {
                            scanComplete && (isMalicious || vtDetections > 0) -> Icons.Default.Warning
                            scanComplete -> Icons.Default.CheckCircle
                            else -> Icons.Default.Info
                        },
                        contentDescription = null,
                        modifier = Modifier.size(48.dp),
                        tint = when {
                            scanComplete && isMalicious -> Color(0xFFB71C1C)
                            scanComplete && vtDetections > 0 -> Color(0xFFE65100)
                            scanComplete -> Color(0xFF1B5E20)
                            else -> Color(0xFF1565C0)
                        }
                    )
                }
                
                // Title
                Text(
                    text = when {
                        scanComplete && isMalicious -> "🚨 MALWARE DETECTED"
                        scanComplete && vtDetections > 0 -> "⚠️ SUSPICIOUS FILE"
                        scanComplete -> "✅ FILE APPEARS SAFE"
                        else -> "🔍 SECURITY SCAN"
                    },
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = when {
                        scanComplete && isMalicious -> Color(0xFFB71C1C)
                        scanComplete && vtDetections > 0 -> Color(0xFFE65100)
                        scanComplete -> Color(0xFF1B5E20)
                        else -> MaterialTheme.colorScheme.primary
                    },
                    textAlign = TextAlign.Center
                )
                
                // File name
                Text(
                    text = apkPath.split("/").lastOrNull() ?: "Unknown file",
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    textAlign = TextAlign.Center
                )
                
                // Sender context
                senderContext?.let {
                    Text(
                        text = it,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                    )
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                // Progress indicator
                if (!scanComplete) {
                    LinearProgressIndicator(
                        progress = { scanProgress },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(8.dp)
                            .clip(RoundedCornerShape(4.dp)),
                        color = MaterialTheme.colorScheme.primary
                    )
                    
                    Text(
                        text = scanStatus,
                        fontSize = 14.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                
                // Scan complete results
                AnimatedVisibility(visible = scanComplete) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Divider()
                        
                        // VirusTotal Section
                        if (vtScanned) {
                            ResultSection(
                                title = "VirusTotal Analysis",
                                content = {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column {
                                            Text(
                                                text = "Detection Ratio",
                                                fontSize = 12.sp,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                            Text(
                                                text = "$vtDetections / $vtEngines engines",
                                                fontSize = 18.sp,
                                                fontWeight = FontWeight.Bold,
                                                color = if (vtDetections > 0) Color(0xFFB71C1C) else Color(0xFF1B5E20)
                                            )
                                        }
                                        
                                        vtLink?.let { link ->
                                            TextButton(onClick = {
                                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(link))
                                                context.startActivity(intent)
                                            }) {
                                                Text("View Report →")
                                            }
                                        }
                                    }
                                    
                                    if (vtThreats.isNotEmpty()) {
                                        Spacer(modifier = Modifier.height(8.dp))
                                        vtThreats.take(3).forEach { threat ->
                                            Text(
                                                text = "• $threat",
                                                fontSize = 11.sp,
                                                color = Color(0xFFB71C1C)
                                            )
                                        }
                                    }
                                }
                            )
                        } else {
                            ResultSection(
                                title = "VirusTotal Analysis",
                                content = {
                                    Text(
                                        text = "API key not configured",
                                        fontSize = 14.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            )
                        }
                        
                        // Static Analysis Section
                        ResultSection(
                            title = "Static Analysis",
                            content = {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Column {
                                        Text(
                                            text = "Risk Score",
                                            fontSize = 12.sp,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                        Text(
                                            text = "$riskScore / 100",
                                            fontSize = 18.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = when {
                                                riskScore >= 70 -> Color(0xFFB71C1C)
                                                riskScore >= 40 -> Color(0xFFE65100)
                                                else -> Color(0xFF1B5E20)
                                            }
                                        )
                                    }
                                    
                                    Column(horizontalAlignment = Alignment.End) {
                                        Text(
                                            text = "Package",
                                            fontSize = 12.sp,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                        Text(
                                            text = packageName?.take(25) ?: "Unknown",
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Medium
                                        )
                                    }
                                }
                                
                                if (suspiciousPermissions.isNotEmpty()) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(
                                        text = "⚠️ High-Risk Permissions (${suspiciousPermissions.size}):",
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = Color(0xFFE65100)
                                    )
                                    suspiciousPermissions.take(3).forEach { perm ->
                                        val shortPerm = perm.replace("android.permission.", "")
                                        Text(
                                            text = "• $shortPerm",
                                            fontSize = 11.sp,
                                            color = Color(0xFFE65100)
                                        )
                                    }
                                }
                            }
                        )
                        
                        // SHA-256 Hash (collapsed)
                        if (sha256Hash.isNotEmpty()) {
                            ResultSection(
                                title = "File Hash (SHA-256)",
                                content = {
                                    Text(
                                        text = sha256Hash.take(32) + "...",
                                        fontSize = 10.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                                    )
                                }
                            )
                        }
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        // Action button
                        Button(
                            onClick = onDismiss,
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = when {
                                    isMalicious -> Color(0xFFB71C1C)
                                    vtDetections > 0 -> Color(0xFFE65100)
                                    else -> Color(0xFF1B5E20)
                                }
                            ),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text(
                                text = when {
                                    isMalicious -> "⚠️ Understood - Delete Recommended"
                                    vtDetections > 0 -> "Proceed with Caution"
                                    else -> "Continue"
                                },
                                modifier = Modifier.padding(vertical = 8.dp),
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
                
                // Waiting message
                if (!scanComplete) {
                    Text(
                        text = "Please wait while we analyze this file for potential threats.\nThis window cannot be closed.",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun ResultSection(
    title: String,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
        ) {
            Text(
                text = title,
                fontSize = 14.sp,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(bottom = 8.dp)
            )
            content()
        }
    }
}
