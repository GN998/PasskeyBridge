package com.yourcompany.passkeybridge.core.hybrid

// Data class representing extracted FIDO URI parameters
data class HybridQrData(
    val version: Int,
    val publicKey: ByteArray,
    val secret: ByteArray,
    val tunnelServerId: Int
)