package com.dev.fido.bridge.core.hybrid

import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.security.hexToByteArray

/**
 * Represent the parsed X-caBLE-Client-Payload sent by a linked client platform during state-assisted transactions.
 * Decouple link identification and BLE EID key diversification nonce per PXP §5.3.2.
 */
data class ClientPayload(
    val linkId: ByteArray,
    val clientNonce: ByteArray,
    val operationHint: String = "ga"
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ClientPayload) return false
        return linkId.contentEquals(other.linkId) &&
            clientNonce.contentEquals(other.clientNonce) &&
            operationHint == other.operationHint
    }

    override fun hashCode(): Int {
        var result = linkId.contentHashCode()
        result = 31 * result + clientNonce.contentHashCode()
        result = 31 * result + operationHint.hashCode()
        return result
    }
}

/**
 * Represent persistent pairing state shared between this authenticator and a linked desktop client platform.
 */
data class LinkRecord(
    val linkId: ByteArray,
    val linkSecret: ByteArray,
    val createdAtEpochMs: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LinkRecord) return false
        return linkId.contentEquals(other.linkId) &&
            linkSecret.contentEquals(other.linkSecret) &&
            createdAtEpochMs == other.createdAtEpochMs
    }

    override fun hashCode(): Int {
        var result = linkId.contentHashCode()
        result = 31 * result + linkSecret.contentHashCode()
        result = 31 * result + createdAtEpochMs.hashCode()
        return result
    }
}

/**
 * Parse and serialize state-assisted caBLE v2 CBOR structures per CTAP 2.3 §11.5.2 and PXP §5.3.2 / §6.2.
 */
object StateAssistedCodec {

    private val KNOWN_HINTS = setOf("ga", "mc", "dcp", "dci")

    /**
     * Decode hex-encoded X-caBLE-Client-Payload into a validated ClientPayload instance.
     * Ignore unknown or GREASE CBOR keys to preserve forward compatibility with future PXP extensions.
     */
    fun parseClientPayloadHex(hexPayload: String): ClientPayload? {
        return try {
            val cleanHex = hexPayload.trim()
            if (cleanHex.length < 56 || cleanHex.length > 512 || cleanHex.length % 2 != 0) {
                return null
            }
            val rawBytes = cleanHex.hexToByteArray()
            val map = CtapCodec.SimpleCbor.read(rawBytes) as? Map<*, *> ?: return null

            // Enforce exact 8-byte link ID (Key 1) and 16-byte client nonce (Key 2) per PXP §5.3.2.
            val linkId = (map[1L] as? ByteArray)?.takeIf { it.size == 8 } ?: return null
            val clientNonce = (map[2L] as? ByteArray)?.takeIf { it.size == 16 } ?: return null

            // Normalize unknown operation hints (Key 3) to "ga" per PXP §5.3.1 / §5.3.2.
            val rawHint = when (val h = map[3L]) {
                is String -> h
                is ByteArray -> String(h, Charsets.UTF_8)
                else -> null
            }
            val operationHint = if (rawHint != null && rawHint in KNOWN_HINTS) rawHint else "ga"

            ClientPayload(
                linkId = linkId,
                clientNonce = clientNonce,
                operationHint = operationHint
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Encode authenticator linking metadata into a typeUpdate (0x02) transport frame per PXP §6.2.
     * Prepend frame type byte 0x02 so the desktop client persists the Contact ID and link keys for future QR-less logins.
     */
    fun encodeUpdateMessageFrame(
        contactIdRawBytes: ByteArray,
        linkId: ByteArray,
        linkSecret: ByteArray,
        authenticatorPublicKey: ByteArray,
        authenticatorName: String,
        handshakeSignature: ByteArray
    ): ByteArray {
        require(linkId.size == 8) { "Link ID must be 8 bytes" }
        require(linkSecret.size == 32) { "Link secret must be 32 bytes" }
        require(authenticatorPublicKey.size == 65 && authenticatorPublicKey[0] == 0x04.toByte()) {
            "Authenticator public key must be a 65-byte uncompressed P-256 point"
        }
        require(handshakeSignature.size == 32) { "Handshake signature must be 32 bytes" }

        val linkingDataMap = mapOf<Long, Any>(
            1L to contactIdRawBytes,
            2L to linkId,
            3L to linkSecret,
            4L to authenticatorPublicKey,
            5L to authenticatorName,
            6L to handshakeSignature
        )

        val updateMap = mapOf<Long, Any>(
            1L to linkingDataMap
        )

        return byteArrayOf(0x02) + CtapCodec.SimpleCbor.write(updateMap)
    }
}