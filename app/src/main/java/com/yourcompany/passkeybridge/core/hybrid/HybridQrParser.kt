package com.yourcompany.passkeybridge.core.hybrid

import com.yourcompany.passkeybridge.BuildConfig
import java.math.BigInteger

// Parser object for handling FIDO URI and QR code data parsing
object HybridQrParser {

    // Parses a FIDO URI string into a HybridQrData instance
    fun parse(uriString: String): HybridQrData? {
        try {
            // 1. Validate and strip the FIDO URI prefix
            val prefix = "fido:/"
            if (!uriString.startsWith(prefix, ignoreCase = true)) {
                return null
            }
            
            val numberStr = uriString.substring(prefix.length)
            
            // 2. Decode the Base10 string into a byte array
            var bytes = BigInteger(numberStr, 10).toByteArray()
            
            // BigInteger may add a leading 0x00 sign byte to keep the value positive; remove it if present
            if (bytes.size > 1 && bytes[0] == 0.toByte()) {
                bytes = bytes.copyOfRange(1, bytes.size)
            }
            
            if (bytes.isEmpty()) {
                return null
            }
            
            // 3. Extract components based on standard CTAP Hybrid QR byte layout
            // Byte 0: Version
            // Bytes 1 to 16: QR Secret (16 bytes)
            // Bytes 17 to end: Public Key (Typically 32 or 33 bytes)
            val version = bytes[0].toInt()
            
            val secretLength = 16
            if (bytes.size <= 1 + secretLength) {
                return null // Payload too short
            }
            
            val secret = bytes.copyOfRange(1, 1 + secretLength)
            val publicKey = bytes.copyOfRange(1 + secretLength, bytes.size)
            
            return HybridQrData(
                version = version,
                publicKey = publicKey,
                secret = secret,
                // Assign the tunnelServerId dynamically from the injected build configuration
                tunnelServerId = BuildConfig.TUNNEL_ID
            )
        } catch (e: Exception) {
            // Return null if parsing fails (e.g., NumberFormatException)
            return null
        }
    }
}