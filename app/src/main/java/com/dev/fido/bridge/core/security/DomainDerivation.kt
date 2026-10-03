package com.dev.fido.bridge.core.security

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/**
 * Derive caBLE v2 tunnel server domains based on routing IDs and assigned domain mapping per CTAP 2.3 specification.
 */
object DomainDerivation {

    private val ASSIGNED_DOMAINS = listOf("cable.ua5v.com", "cable.auth.com")

    /**
     * Compute tunnel domain corresponding to given 16-bit tunnel ID.
     * Route IDs below 256 to assigned static domains, and use SHA-256 base32 encoding algorithm for larger IDs.
     */
    fun deriveDomainForTunnelId(tunnelId: Int): String {
        if (tunnelId < 256) {
            return if (tunnelId in ASSIGNED_DOMAINS.indices) ASSIGNED_DOMAINS[tunnelId] else ASSIGNED_DOMAINS[0]
        }

        val prefix = "caBLEv2 tunnel server domain".toByteArray(Charsets.US_ASCII)
        val buffer = ByteBuffer.allocate(prefix.size + 3).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(prefix)
        buffer.put((tunnelId and 0xFF).toByte())
        buffer.put(((tunnelId shr 8) and 0xFF).toByte())
        buffer.put(0.toByte())

        val digest = MessageDigest.getInstance("SHA-256").digest(buffer.array())
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
        ret += tlds[tldIndex and 3]

        return ret
    }
}
