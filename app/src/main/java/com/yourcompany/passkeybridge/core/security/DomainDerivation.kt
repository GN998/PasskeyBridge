package com.yourcompany.passkeybridge.core.security

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

object DomainDerivation {
    private val ASSIGNED_DOMAINS = listOf("cable.ua5v.com", "cable.auth.com")

    fun deriveDomainForTunnelId(tunnelId: Int): String {
        // IDs below 256 are reserved directly assigned domains
        if (tunnelId < 256) {
            return if (tunnelId < ASSIGNED_DOMAINS.size) ASSIGNED_DOMAINS[tunnelId] else ""
        }

        // Fix: Follow CTAP 2.3 Hybrid Routing ID derivation algorithm (Little-Endian & specific prefix)
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