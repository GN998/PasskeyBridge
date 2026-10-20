package com.dev.fido.bridge.core.security

import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import javax.crypto.Cipher

/**
 * Hold client-side WebPush subscription keys required by RFC 8291.
 */
data class WebPushKeyMaterial(
    val p256dhPublicKeyB64: String,
    val p256dhPrivateKeyScalar: ByteArray,
    val authSecretB64: String
)

/**
 * Implement RFC 8291 (Web Push Message Encryption) and RFC 8188 (aes128gcm) decryption.
 * Enable zero-dependency edge wakeup payload decryption matching cable-tunnel-server's push.ts encoder.
 */
object WebPushCrypto {
    private const val SALT_LENGTH = 16
    private const val KEY_ID_OFFSET = 21
    private const val P256_UNCOMPRESSED_LENGTH = 65
    private const val HEADER_LENGTH = 86 // 16 (salt) + 4 (rs) + 1 (idlen=65) + 65 (server pubkey)
    private const val PADDING_DELIMITER: Byte = 0x02

    private val secureRandom = SecureRandom()

    /**
     * Generate a fresh P-256 ECDH key pair and 16-byte authentication secret for WebPush subscription registration.
     */
    fun generateSubscriptionKeys(): WebPushKeyMaterial {
        val (pub, priv) = CryptoHelper.generateEcKeyPair()
        val pubUncompressed = CryptoHelper.uncompressECKey(pub)
        val privScalar = priv.s.toFixedLengthBytes(32)

        val authSecret = ByteArray(16).also { secureRandom.nextBytes(it) }

        return WebPushKeyMaterial(
            p256dhPublicKeyB64 = CryptoUtils.encodeBase64UrlNoPadding(pubUncompressed),
            p256dhPrivateKeyScalar = privScalar,
            authSecretB64 = CryptoUtils.encodeBase64UrlNoPadding(authSecret)
        )
    }

    /**
     * Decrypt an incoming WebPush payload or extract plaintext hex if already decrypted by the UnifiedPush distributor.
     */
    fun decryptWakeupPayload(
        rawPushBytes: ByteArray,
        recipientPrivateKey: ECPrivateKey,
        recipientPublicKeyUncompressed: ByteArray,
        authSecretBytes: ByteArray
    ): String? {
        if (rawPushBytes.isEmpty()) return null

        // Fast-path: check if the UnifiedPush distributor (e.g., Sunup) already unwrapped aes128gcm into ASCII hex.
        if (looksLikePlaintextHex(rawPushBytes)) {
            return String(rawPushBytes, Charsets.US_ASCII).trim()
        }

        return try {
            val plaintextBytes = decryptAes128Gcm(
                ciphertextWithHeader = rawPushBytes,
                uaPrivate = recipientPrivateKey,
                uaPublic = recipientPublicKeyUncompressed,
                authSecret = authSecretBytes
            )
            String(plaintextBytes, Charsets.UTF_8).trim()
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Decrypt an RFC 8188 / RFC 8291 aes128gcm binary frame into raw plaintext bytes.
     */
    fun decryptAes128Gcm(
        ciphertextWithHeader: ByteArray,
        uaPrivate: ECPrivateKey,
        uaPublic: ByteArray,
        authSecret: ByteArray
    ): ByteArray {
        require(ciphertextWithHeader.size > HEADER_LENGTH + 16) {
            "WebPush payload too short for RFC 8188 header and GCM tag"
        }

        val salt = ciphertextWithHeader.copyOfRange(0, SALT_LENGTH)
        val recordSize = ByteBuffer.wrap(ciphertextWithHeader, SALT_LENGTH, 4)
            .order(ByteOrder.BIG_ENDIAN)
            .int
        require(recordSize >= 18) { "Invalid RFC 8188 record size: $recordSize" }

        val idLen = ciphertextWithHeader[20].toInt() and 0xFF
        require(idLen == P256_UNCOMPRESSED_LENGTH) {
            "Expected 65-byte uncompressed P-256 keyid in RFC 8291 header, got $idLen"
        }

        val asPublic = ciphertextWithHeader.copyOfRange(KEY_ID_OFFSET, HEADER_LENGTH)
        val encryptedRecord = ciphertextWithHeader.copyOfRange(HEADER_LENGTH, ciphertextWithHeader.size)

        // Step 1: Compute ECDH shared secret between user agent private key and application server ephemeral public key.
        val ecdhSecret = CryptoHelper.recd(uaPrivate, asPublic)

        // Step 2: Combine ECDH shared secret and auth secret into 32-byte IKM per RFC 8291 §3.3.
        val keyInfo = buildHkdfInfo("WebPush: info", uaPublic, asPublic)
        val ikm = CryptoHelper.endif(
            ikm = ecdhSecret,
            salt = authSecret,
            info = keyInfo,
            length = 32
        )

        // Step 3: Derive 16-byte AES-128-GCM Content Encryption Key (CEK) and 12-byte Nonce per RFC 8188 §2.2 / §2.3.
        val cekInfo = buildHkdfInfo("Content-Encoding: aes128gcm")
        val cek = CryptoHelper.endif(
            ikm = ikm,
            salt = salt,
            info = cekInfo,
            length = 16
        )

        val nonceInfo = buildHkdfInfo("Content-Encoding: nonce")
        val nonce = CryptoHelper.endif(
            ikm = ikm,
            salt = salt,
            info = nonceInfo,
            length = 12
        )

        // Step 4: Authenticate and decrypt using AES-128-GCM (CryptoHelper.aesGcm natively supports 16-byte keys).
        val paddedPlaintext = CryptoHelper.aesGcm(
            mode = Cipher.DECRYPT_MODE,
            key = cek,
            nonce = nonce,
            input = encryptedRecord
        )

        // Step 5: Strip trailing zero padding and the 0x02 final record delimiter per RFC 8188 §2.
        var delimiterIndex = paddedPlaintext.lastIndex
        while (delimiterIndex >= 0 && paddedPlaintext[delimiterIndex] == 0x00.toByte()) {
            delimiterIndex--
        }
        if (delimiterIndex < 0 || paddedPlaintext[delimiterIndex] != PADDING_DELIMITER) {
            throw GeneralSecurityException("Missing RFC 8188 0x02 record padding delimiter")
        }

        return paddedPlaintext.copyOfRange(0, delimiterIndex)
    }

    private fun buildHkdfInfo(label: String, vararg context: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(label.toByteArray(Charsets.US_ASCII))
        out.write(0x00)
        for (chunk in context) {
            out.write(chunk)
        }
        return out.toByteArray()
    }

    private fun looksLikePlaintextHex(bytes: ByteArray): Boolean {
        if (bytes.size < 56 || bytes.size > 512 || bytes.size % 2 != 0) return false
        // Major type 5 CBOR map starts with 'a' or 'b' in ASCII hex (0xA0..0xBF).
        val firstChar = bytes[0].toInt().toChar().lowercaseChar()
        if (firstChar != 'a' && firstChar != 'b') return false
        return bytes.all { b ->
            val c = b.toInt().toChar()
            c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
        }
    }
}