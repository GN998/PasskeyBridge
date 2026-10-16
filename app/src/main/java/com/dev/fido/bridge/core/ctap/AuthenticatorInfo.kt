package com.dev.fido.bridge.core.ctap

import com.dev.fido.bridge.core.ctap.model.Ctap2Response

object AuthenticatorInfo {
    fun getInfo(): Ctap2Response.GetInfoResponse {
        return Ctap2Response.GetInfoResponse(
            // Advertise FIDO_2_0 exclusively to delegate user verification to Android CredentialManager without triggering CTAP 2.1+ pinUvAuthToken (0x06) handshakes
            versions = listOf("FIDO_2_0"),
            extensions = emptyList(),
            aaguid = ByteArray(16),
            options = mapOf(
                "plat" to false,
                "rk" to true,
                // Use standard CTAP option key "uv" instead of WebAuthn parameter name "userVerification" per CTAP 2.3 §6.4
                "uv" to true,
                "up" to true
            ),
            maxMsgSize = 2048,
            pinUvAuthProtocols = emptyList()
        )
    }

    /**
     * Serialize GetInfoResponse into its canonical CTAP2 CBOR map representation.
     * Share across pre-flight caBLE post-handshake messages and 0x04 GetInfo commands to prevent capability drift.
     */
    fun toCborMap(info: Ctap2Response.GetInfoResponse = getInfo()): Map<Long, Any> {
        // Omit optional empty collections (extensions, pinUvAuthProtocols) to satisfy CTAP 2.3 §6.4 non-empty array constraints
        return buildMap {
            put(1L, info.versions)
            if (info.extensions.isNotEmpty()) {
                put(2L, info.extensions)
            }
            put(3L, info.aaguid)
            put(4L, info.options)
            put(5L, info.maxMsgSize.toLong())
            if (info.pinUvAuthProtocols.isNotEmpty()) {
                put(6L, info.pinUvAuthProtocols.map { it.toLong() })
            }
            put(9L, listOf("internal", "hybrid"))
        }
    }
}