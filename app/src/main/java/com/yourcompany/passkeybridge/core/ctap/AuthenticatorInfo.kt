package com.yourcompany.passkeybridge.core.ctap

import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response

object AuthenticatorInfo {
    fun getInfo(): Ctap2Response.GetInfoResponse {
        return Ctap2Response.GetInfoResponse(
            versions = listOf("FIDO_2_0", "FIDO_2_1", "FIDO_2_3"),
            extensions = listOf("credProtect", "hmac-secret"),
            aaguid = ByteArray(16),
            options = mapOf(
                "plat" to false,
                "rk" to true,
                // Fixed: Use standard CTAP option key "uv" instead of WebAuthn parameter name "userVerification" per CTAP 2.3 §6.4
                "uv" to true,
                "up" to true
            ),
            maxMsgSize = 2048,
            pinUvAuthProtocols = listOf(1)
        )
    }
}
