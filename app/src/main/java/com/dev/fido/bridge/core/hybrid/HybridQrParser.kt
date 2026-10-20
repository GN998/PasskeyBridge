package com.dev.fido.bridge.core.hybrid

import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.security.TunnelConfigManager
import java.nio.ByteBuffer
import java.nio.ByteOrder

// Parser object for handling FIDO caBLE v2 (CTAP 2.3) URI and QR code data parsing
object HybridQrParser {

    private val PADDING_TABLE = intArrayOf(0, 3, 5, 8, 10, 13, 15)

    // Parses a FIDO URI string (FIDO:/...) into a HybridQrData instance
    fun parse(uriString: String): HybridQrData? {
        try {
            val prefix = "fido:/"
            if (!uriString.startsWith(prefix, ignoreCase = true)) {
                return null
            }

            val encoded = uriString.substring(prefix.length)
            val cborBytes = decodeGmsBase34(encoded) ?: return null

            val cborMap = CtapCodec.SimpleCbor.read(cborBytes) as? Map<*, *> ?: return null

            // Query Long keys directly since SimpleCbor always deserializes unsigned integers as Long.
            // Enforce exact 16-byte QR secret length per CTAP 2.3 §11.5.1.1 (publicKey is validated during SEC1 decompression).
            val publicKey = cborMap[0L] as? ByteArray ?: return null
            val secret = (cborMap[1L] as? ByteArray)?.takeIf { it.size == 16 } ?: return null

            // Extract optional epoch seconds (Key 3), state-assisted capability flag (Key 4), and flow hint (Key 5) per CTAP 2.3 §11.5.1.1
            val timestampSeconds = (cborMap[3L] as? Long)?.takeIf { it > 0L }
            // Always enable state-assisted linking frame dispatch so desktop platforms receive 0x02 linking metadata regardless of QR Key 4 hint
            val supportsStateAssisted = true
            val operationHint = when (val rawHint = cborMap[5L]) {
                is String -> rawHint
                is ByteArray -> String(rawHint, Charsets.UTF_8)
                else -> null
            }?.let { if (it == "mc") "mc" else "ga" } ?: "ga"

            // In CTAP 2.3 §11.5.1.1, QR CBOR Key 2 is numAssignedDomains, NOT the tunnel server ID.
            // Resolve tunnel server ID dynamically to support user runtime overrides alongside build-time defaults.
            val tunnelServerId = TunnelConfigManager.getEffectiveTunnelId()

            return HybridQrData(
                publicKey = publicKey,
                secret = secret,
                tunnelServerId = tunnelServerId,
                timestampSeconds = timestampSeconds,
                operationHint = operationHint,
                supportsStateAssisted = supportsStateAssisted
            )
        } catch (e: Exception) {
            return null
        }
    }

    // Decodes GMS Base34 (17-digit decimal groups) encoded string into CBOR byte array
    private fun decodeGmsBase34(encoded: String): ByteArray? {
        val length = encoded.length
        val fullBlocks = length / 17
        val remainder = length % 17

        val remainingBytes = PADDING_TABLE.indexOfFirst { remainder == it }
        if (remainingBytes == -1) return null

        val totalBytes = fullBlocks * 7 + remainingBytes
        val result = ByteArray(totalBytes)
        val buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)

        // Decode full 17-digit blocks into 7 bytes each
        for (i in 0 until fullBlocks) {
            val digitGroup = encoded.substring(i * 17, (i + 1) * 17)
            val longValue = digitGroup.toLongOrNull() ?: return null

            buffer.rewind()
            buffer.putLong(longValue)
            buffer.rewind()
            buffer.get(result, i * 7, 7)

            if (buffer.get() != 0.toByte()) return null
        }

        // Decode trailing partial block
        if (remainder > 0) {
            val remainingDigits = encoded.substring(fullBlocks * 17)
            val longValue = remainingDigits.toLongOrNull() ?: return null

            buffer.rewind()
            buffer.putLong(longValue)
            buffer.rewind()
            buffer.get(result, totalBytes - remainingBytes, remainingBytes)

            while (buffer.hasRemaining()) {
                if (buffer.get() != 0.toByte()) return null
            }
        }

        return result
    }
}