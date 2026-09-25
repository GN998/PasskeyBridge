package com.yourcompany.passkeybridge.core.hybrid

import com.yourcompany.passkeybridge.BuildConfig
import com.yourcompany.passkeybridge.core.ctap.codec.CtapCodec
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

            // Key 0: 33-byte compressed P-256 public key
            val publicKey = (cborMap[0L] ?: cborMap[0]) as? ByteArray ?: return null

            // Key 1: 16-byte random QR secret
            val secret = (cborMap[1L] ?: cborMap[1]) as? ByteArray ?: return null

            // Key 2: Tunnel Server ID (assigned domain index or hashed domain ID)
            val tunnelServerIdRaw = (cborMap[2L] ?: cborMap[2]) as? Number
            val tunnelServerId = tunnelServerIdRaw?.toInt() ?: BuildConfig.TUNNEL_ID

            return HybridQrData(
                version = 2,
                publicKey = publicKey,
                secret = secret,
                tunnelServerId = tunnelServerId
            )
        } catch (e: Exception) {
            return null
        }
    }

    // Decodes GMS Base34 (17-digit decimal groups) encoded string into CBOR byte array
    private fun decodeGmsBase34(encoded: String): ByteArray? {
        try {
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
        } catch (e: Exception) {
            return null
        }
    }
}
