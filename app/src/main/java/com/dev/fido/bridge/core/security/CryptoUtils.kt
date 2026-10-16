package com.dev.fido.bridge.core.security

import android.util.Base64
import java.math.BigInteger
import java.security.MessageDigest

object CryptoUtils {
    fun encodeBase64UrlNoPadding(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    fun decodeBase64Url(base64Str: String): ByteArray {
        // Delegate URL-safe alphabet and missing padding handling directly to Android's native Base64 decoder
        return Base64.decode(base64Str.trim(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }
}

/**
 * Format byte array into hexadecimal string for logging and tunnel URL construction.
 */
fun ByteArray.toHex(uppercase: Boolean = false): String {
    val format = if (uppercase) "%02X" else "%02x"
    return joinToString("") { format.format(it) }
}

/**
 * Decode hexadecimal string into raw bytes for routing ID and protocol parameter extraction.
 */
fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0) { "Hex string must have an even length" }
    return ByteArray(length / 2) { i ->
        substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

/**
 * Convert BigInteger to fixed-width unsigned big-endian byte array.
 * Strip leading sign byte or pad with leading zeros to satisfy P-256 32-byte coordinate encoding.
 */
fun BigInteger.toFixedLengthBytes(length: Int = 32): ByteArray {
    val bytes = toByteArray()
    return when {
        bytes.size == length -> bytes
        bytes.size > length -> bytes.copyOfRange(bytes.size - length, bytes.size)
        else -> ByteArray(length).also {
            System.arraycopy(bytes, 0, it, length - bytes.size, bytes.size)
        }
    }
}