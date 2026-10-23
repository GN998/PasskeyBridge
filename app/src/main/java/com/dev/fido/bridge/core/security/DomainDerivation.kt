package com.dev.fido.bridge.core.security

import java.nio.ByteBuffer
import java.nio.ByteOrder

object DomainDerivation {
    private val ASSIGNED_DOMAINS = listOf("cable.ua5v.com", "cable.auth.com")

    // Expose known assigned domain count for CTAP 2.3 §11.5.1.1 QR code CBOR Key 2
    const val NUM_ASSIGNED_DOMAINS: Long = 2L

    // Cache the last derived tunnel domain as an atomic pair to avoid redundant SHA-256 and Base32 computations
    @Volatile
    private var cachedDerivation: Pair<Int, String>? = null

    fun deriveDomainForTunnelId(tunnelId: Int): String {
        return resolveDomainOrNull(tunnelId) ?: ASSIGNED_DOMAINS[0]
    }

    /**
     * Resolve tunnel server domain per CTAP 2.3 §11.5.1.1.1, returning null if an assigned domain ID (<256)
     * is outside the known ASSIGNED_DOMAINS table or if tunnelId exceeds uint16 bounds.
     */
    fun resolveDomainOrNull(tunnelId: Int): String? {
        if (tunnelId !in 0..65535) return null

        cachedDerivation?.let { (id, domain) ->
            if (id == tunnelId) return domain
        }

        // IDs below 256 are reserved directly assigned domains
        if (tunnelId < 256) {
            return ASSIGNED_DOMAINS.getOrNull(tunnelId)
        }

        // CTAP 2.3 Hybrid Routing ID derivation algorithm (Little-Endian & specific prefix)
        val prefix = "caBLEv2 tunnel server domain".toByteArray(Charsets.US_ASCII)
        val buffer = ByteBuffer.allocate(prefix.size + 3).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(prefix)
        buffer.put((tunnelId and 0xFF).toByte())
        buffer.put(((tunnelId shr 8) and 0xFF).toByte())
        buffer.put(0.toByte())

        val digest = CryptoUtils.sha256(buffer.array())
        var v = ByteBuffer.wrap(digest, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long

        val tldIndex = (v and 3L).toInt()
        v = v ushr 2

        val base32Chars = "abcdefghijklmnopqrstuvwxyz234567"
        var ret = "cable."
        while (v != 0L) {
            ret += base32Chars[(v and 31L).toInt()]
            v = v ushr 5
        }

        val tlds = arrayOf(".com", ".org", ".net", ".info")
        ret += tlds[tldIndex]

        cachedDerivation = tunnelId to ret
        return ret
    }
}