package com.yourcompany.passkeybridge.core.ctap.model

sealed class Ctap2Request {
    data class GetInfo(val dummy: Boolean = true) : Ctap2Request()
    
    data class GetAssertion(
        val rpId: String,
        val clientDataHash: ByteArray,
        val allowList: List<CredentialDescriptor>? = null,
        val userVerification: String? = null
    ) : Ctap2Request()

    data class MakeCredential(
        val clientDataHash: ByteArray,
        val rpId: String,
        val rpName: String,
        val userId: ByteArray,
        val userName: String,
        val userDisplayName: String,
        val pubKeyCredParams: List<Map<String, Int>> = emptyList()
    ) : Ctap2Request()
}

data class CredentialDescriptor(
    val type: String = "public-key",
    val id: ByteArray
)

sealed class Ctap2Response {
    data class GetInfoResponse(
        val versions: List<String>,
        val extensions: List<String>,
        val aaguid: ByteArray,
        val options: Map<String, Boolean>,
        val maxMsgSize: Int = 1024,
        val pinUvAuthProtocols: List<Int> = listOf(1)
    ) : Ctap2Response()

    data class GetAssertionResponse(
        val credentialId: ByteArray,
        val authenticatorData: ByteArray,
        val signature: ByteArray,
        val userHandle: ByteArray? = null
    ) : Ctap2Response()

    data class MakeCredentialResponse(
        val fmt: String = "none",
        val authData: ByteArray,
        val attStmt: Map<String, String> = emptyMap()
    ) : Ctap2Response()

    data class ErrorResponse(val errorCode: Byte) : Ctap2Response()
}