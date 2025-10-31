package com.example.whatszap

data class ScanResult(
    val isMalicious: Boolean,
    val confidence: Int,
    val threats: List<String>,
    val scanDuration: Long
)

