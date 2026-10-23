package com.dev.fido.bridge.client.qr

import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.security.DomainDerivation
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

/**
 * Holds the ephemeral cryptographic credentials and encoded FIDO:/ URI for a single client QR session.
 */
data class ClientQrSessionData(
    val identityPublicKey: ECPublicKey,
    val identityPrivateKey: ECPrivateKey,
    val uncompressedIdentityPublicKey: ByteArray,
    val qrSecret: ByteArray,
    val fidoUri: String
)

object HybridQrGenerator {
    private val secureRandom = SecureRandom()

    // Number of base-10 digits required to encode 0..6 trailing bytes per PXP §5.1
    private val PARTIAL_CHUNK_DIGITS = intArrayOf(0, 3, 5, 8, 10, 13, 15)

    /**
     * Generate a fresh P-256 identity keypair, 16-byte QR secret, and digit-encoded FIDO:/ URI
     * per CTAP 2.3 §11.5.1.1.
     *
     * @param operationHint "ga" for getAssertion or "mc" for makeCredential.
     */
    fun generateQrSession(operationHint: String = "ga"): ClientQrSessionData {
        val (pubKey, privKey) = CryptoHelper.generateEcKeyPair()
        val compressedPubKey = CryptoHelper.compressECKey(pubKey)
        val uncompressedPubKey = CryptoHelper.uncompressECKey(pubKey)

        val qrSecret = ByteArray(16).also { secureRandom.nextBytes(it) }
        val epochSeconds = System.currentTimeMillis() / 1000L
        val normalizedHint = if (operationHint == "mc") "mc" else "ga"

        // Construct canonical CBOR map for QR code payload per CTAP 2.3 §11.5.1.1
        val qrCborMap = mapOf<Long, Any>(
            0L to compressedPubKey,
            1L to qrSecret,
            2L to DomainDerivation.NUM_ASSIGNED_DOMAINS,
            3L to epochSeconds,
            4L to false, // State-assisted linking disabled; enforce stateless QR flow
            5L to normalizedHint
        )

        val cborBytes = CtapCodec.SimpleCbor.write(qrCborMap)
        val fidoUri = "FIDO:/" + encodeDigitPayload(cborBytes)

        return ClientQrSessionData(
            identityPublicKey = pubKey,
            identityPrivateKey = privKey,
            uncompressedIdentityPublicKey = uncompressedPubKey,
            qrSecret = qrSecret,
            fidoUri = fidoUri
        )
    }

    /**
     * Encode raw CBOR bytes into 17-digit base-10 chunks (7 bytes per chunk, little-endian)
     * per PXP §5.1 digitEncode specification.
     */
    internal fun encodeDigitPayload(data: ByteArray): String {
        val sb = StringBuilder((data.size / 7 + 1) * 17)
        val buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)

        val fullChunks = data.size / 7
        for (i in 0 until fullChunks) {
            buffer.clear()
            buffer.put(data, i * 7, 7)
            buffer.put(0.toByte())
            buffer.flip()
            val unsignedStr = java.lang.Long.toUnsignedString(buffer.long)
            repeat(17 - unsignedStr.length) { sb.append('0') }
            sb.append(unsignedStr)
        }

        val remainder = data.size % 7
        if (remainder > 0) {
            val digits = PARTIAL_CHUNK_DIGITS[remainder]
            buffer.clear()
            buffer.put(data, fullChunks * 7, remainder)
            while (buffer.hasRemaining()) {
                buffer.put(0.toByte())
            }
            buffer.flip()
            val unsignedStr = java.lang.Long.toUnsignedString(buffer.long)
            repeat(digits - unsignedStr.length) { sb.append('0') }
            sb.append(unsignedStr)
        }

        return sb.toString()
    }
}