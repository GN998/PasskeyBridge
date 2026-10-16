package com.dev.fido.bridge.core.ctap

import com.dev.fido.bridge.core.ctap.model.Ctap2Response

object AuthenticatorInfo {
    fun getInfo(): Ctap2Response.GetInfoResponse {
        return Ctap2Response.GetInfoResponse(
            versions = listOf("FIDO_2_0", "FIDO_2_1", "FIDO_2_3"),
            extensions = listOf("credProtect", "hmac-secret"),
            aaguid = ByteArray(16),
            options = mapOf(
                "plat" to false,
                "rk" to true,
                // Use standard CTAP option key "uv" instead of WebAuthn parameter name "userVerification" per CTAP 2.3 §6.4
                "uv" to true,
                "up" to true
            ),
            maxMsgSize = 2048,
            pinUvAuthProtocols = listOf(1)
        )
    }

    /**
     * Serialize GetInfoResponse into its canonical CTAP2 CBOR map representation.
     * Share across pre-flight caBLE post-handshake messages and 0x04 GetInfo commands to prevent capability drift.
     */
    fun toCborMap(info: Ctap2Response.GetInfoResponse = getInfo()): Map<Long, Any> {
        return mapOf(
            1L to info.versions,
            2L to info.extensions,
            3L to info.aaguid,
            4L to info.options,
            5L to info.maxMsgSize.toLong(),
            6L to info.pinUvAuthProtocols.map { it.toLong() },
            9L to listOf("internal", "hybrid")
        )
    }
}