package com.dev.fido.bridge.core.security

import android.util.Base64
import java.security.MessageDigest

object CryptoUtils {
    fun encodeBase64UrlNoPadding(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    fun decodeBase64Url(base64Str: String): ByteArray {
        // Normalize Base64URL string by replacing URL-safe characters and restoring proper padding
        var cleanStr = base64Str.trim().replace('-', '+').replace('_', '/')
        val pad = cleanStr.length % 4
        if (pad > 0) {
            cleanStr += "=".repeat(4 - pad)
        }
        return Base64.decode(cleanStr, Base64.DEFAULT or Base64.NO_WRAP)
    }

    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }
}
