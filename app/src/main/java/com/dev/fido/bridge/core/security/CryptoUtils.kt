package com.dev.fido.bridge.core.security

import android.util.Base64
import java.security.MessageDigest

/**
 * Provide low-level cryptographic utilities for encoding and hashing across CTAP and caBLE protocol layers.
 */
object CryptoUtils {

    /**
     * Encode binary data into Base64URL string without trailing padding characters.
     * Ensure compatibility with WebAuthn/caBLE URL-safe parameters.
     */
    fun encodeBase64UrlNoPadding(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    /**
     * Decode a Base64URL string into raw bytes, handling unpadded or normalized input formats.
     * Normalize custom URL-safe replacements ('-') and ('_') and re-introduce padding before decoding to prevent format exceptions.
     */
    fun decodeBase64Url(base64Str: String): ByteArray {
        var cleanStr = base64Str.trim().replace('-', '+').replace('_', '/')
        val pad = cleanStr.length % 4
        if (pad > 0) {
            cleanStr += "=".repeat(4 - pad)
        }
        return Base64.decode(cleanStr, Base64.DEFAULT or Base64.NO_WRAP)
    }

    /**
     * Compute SHA-256 digest of input byte sequence.
     * Use standard MessageDigest provider for hashing authentication data and domain seeds.
     */
    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }
}
