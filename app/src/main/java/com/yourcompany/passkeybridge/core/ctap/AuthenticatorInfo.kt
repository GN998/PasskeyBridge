package com.yourcompany.passkeybridge.core.ctap

import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response

object AuthenticatorInfo {
    fun getInfo(): Ctap2Response.GetInfoResponse {
        return Ctap2Response.GetInfoResponse(
            // Fix for Bug 3: Include "FIDO_2_3" in supported versions list per CTAP 2.3 §6.4
            versions = listOf("FIDO_2_0", "FIDO_2_1", "FIDO_2_3"),
            extensions = listOf("credProtect", "hmac-secret"),
            aaguid = ByteArray(16),
            options = mapOf(
                "plat" to false,
                "rk" to true,
                "userVerification" to true,
                "up" to true
            ),
            maxMsgSize = 2048,
            pinUvAuthProtocols = listOf(1)
        )
    }
}
