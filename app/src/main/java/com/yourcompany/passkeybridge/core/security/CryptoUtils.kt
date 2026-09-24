package com.yourcompany.passkeybridge.core.security

import android.util.Base64
import java.security.MessageDigest

object CryptoUtils {
    fun encodeBase64UrlNoPadding(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    fun decodeBase64Url(base64Str: String): ByteArray {
        return Base64.decode(base64Str, Base64.NO_WRAP or Base64.URL_SAFE)
    }

    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }
}