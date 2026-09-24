package com.yourcompany.passkeybridge.core.ctap

import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response

object AuthenticatorInfo {
    fun getInfo(): Ctap2Response.GetInfoResponse {
        return Ctap2Response.GetInfoResponse(
            versions = listOf("FIDO_2_0", "FIDO_2_1"),
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