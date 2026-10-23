package com.dev.fido.bridge.client.ctap

import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.codec.CtapCodec.requireField
import com.dev.fido.bridge.core.ctap.codec.CtapCodecException
import com.dev.fido.bridge.core.ctap.model.CredentialDescriptor
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.ctap.model.CtapStatus

/**
 * Client-side CTAP2 encoder (for outbound commands) and decoder (for inbound authenticator responses)
 * per CTAP 2.3 §6 & §8.
 */
object ClientCtapCodec {

    fun encodeRequest(request: Ctap2Request): ByteArray {
        return when (request) {
            is Ctap2Request.GetInfo -> byteArrayOf(0x04)
            is Ctap2Request.MakeCredential -> {
                val map = buildMap<Long, Any> {
                    put(1L, request.clientDataHash)
                    put(2L, buildMap<String, Any> {
                        put("id", request.rpId)
                        if (request.rpName.isNotEmpty()) put("name", request.rpName)
                    })
                    put(3L, buildMap<String, Any> {
                        put("id", request.userId)
                        if (request.userName.isNotEmpty()) put("name", request.userName)
                        if (request.userDisplayName.isNotEmpty()) put("displayName", request.userDisplayName)
                    })
                    put(4L, request.pubKeyCredParams)
                    request.excludeList?.takeIf { it.isNotEmpty() }?.let { list ->
                        put(5L, list.map { it.toCborMap() })
                    }
                    request.options?.takeIf { it.isNotEmpty() }?.let { opts ->
                        put(7L, opts)
                    }
                }
                byteArrayOf(0x01) + CtapCodec.SimpleCbor.write(map)
            }
            is Ctap2Request.GetAssertion -> {
                val map = buildMap<Long, Any> {
                    put(1L, request.rpId)
                    put(2L, request.clientDataHash)
                    request.allowList?.takeIf { it.isNotEmpty() }?.let { list ->
                        put(3L, list.map { it.toCborMap() })
                    }
                    val optionsMap = buildMap<String, Boolean> {
                        if (!request.userPresence) put("up", false)
                        if (request.userVerification == "required" || request.userVerification == "preferred") {
                            put("uv", true)
                        }
                    }
                    if (optionsMap.isNotEmpty()) {
                        put(5L, optionsMap)
                    }
                }
                byteArrayOf(0x02) + CtapCodec.SimpleCbor.write(map)
            }
        }
    }

    private fun CredentialDescriptor.toCborMap(): Map<String, Any> = buildMap {
        put("type", type)
        put("id", id)
        transports?.takeIf { it.isNotEmpty() }?.let { put("transports", it) }
    }

    /**
     * Decode a raw CTAP2 response payload (1-byte status code followed by optional CBOR map)
     * given the originating [commandByte] (0x01 MakeCredential or 0x02 GetAssertion).
     */
    fun decodeResponse(commandByte: Byte, rawResponse: ByteArray): Ctap2Response {
        if (rawResponse.isEmpty()) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Empty CTAP response payload")
        }
        val status = rawResponse[0]
        if (status != CtapStatus.SUCCESS) {
            return Ctap2Response.ErrorResponse(status)
        }

        val cborBytes = if (rawResponse.size > 1) rawResponse.copyOfRange(1, rawResponse.size) else ByteArray(0)
        // Use non-strict CBOR decoding for responses so authenticators with X.509 attestation certificates
        // or deeper extension structures do not fail the 4-level request depth check.
        val map = CtapCodec.SimpleCbor.read(cborBytes, strict = false) as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CTAP response must be a CBOR map")

        return when (commandByte) {
            0x01.toByte() -> {
                val fmt = map.requireField<String>(1L, "MakeCredential.fmt")
                val authData = map.requireField<ByteArray>(2L, "MakeCredential.authData")
                val attStmt = map.requireField<Map<*, *>>(3L, "MakeCredential.attStmt")
                Ctap2Response.MakeCredentialResponse(fmt = fmt, authData = authData, attStmt = attStmt)
            }
            0x02.toByte() -> {
                val credMap = map[1L] as? Map<*, *>
                val credentialId = (credMap?.get("id") as? ByteArray) ?: ByteArray(0)
                val authData = map.requireField<ByteArray>(2L, "GetAssertion.authData")
                val signature = map.requireField<ByteArray>(3L, "GetAssertion.signature")
                val userMap = map[4L] as? Map<*, *>
                val userHandle = userMap?.get("id") as? ByteArray
                Ctap2Response.GetAssertionResponse(
                    credentialId = credentialId,
                    authenticatorData = authData,
                    signature = signature,
                    userHandle = userHandle
                )
            }
            else -> throw CtapCodecException(CtapStatus.ERR_INVALID_COMMAND, "Unsupported response command context: $commandByte")
        }
    }
}