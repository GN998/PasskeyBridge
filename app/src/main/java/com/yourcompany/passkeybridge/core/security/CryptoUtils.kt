package com.yourcompany.passkeybridge.core.security

import android.util.Base64
import android.util.Log
import java.security.MessageDigest

/**
 * Utility functions for cryptographic hashing, Base64URL encoding/decoding.
 */
object CryptoUtils {
    fun encodeBase64UrlNoPadding(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    fun decodeBase64Url(base64Str: String): ByteArray {
        // Diagnostic Log: Track input string passed into decodeBase64Url
        Log.d("FIDO_DIAG", "[CryptoUtils] decodeBase64Url input length: ${base64Str.length}, content: '$base64Str'")

        // Normalize Base64URL string by replacing URL-safe characters and restoring proper padding
        var cleanStr = base64Str.trim().replace('-', '+').replace('_', '/')
        val pad = cleanStr.length % 4
        if (pad > 0) {
            cleanStr += "=".repeat(4 - pad)
        }
        val decodedBytes = Base64.decode(cleanStr, Base64.DEFAULT or Base64.NO_WRAP)

        // Diagnostic Log: Track decoded output byte array size
        Log.d("FIDO_DIAG", "[CryptoUtils] decodeBase64Url decoded size: ${decodedBytes.size} bytes")
        return decodedBytes
    }

    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }
}
