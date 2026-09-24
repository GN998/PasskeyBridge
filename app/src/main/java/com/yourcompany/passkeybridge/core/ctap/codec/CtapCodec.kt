package com.yourcompany.passkeybridge.core.ctap.codec

import android.util.Log
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Request
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response
import com.yourcompany.passkeybridge.core.ctap.model.CtapStatus
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.cbor.Cbor

@OptIn(ExperimentalSerializationApi::class)
object CtapCodec {
    private val cbor = Cbor { ignoreUnknownKeys = true }

    fun decodeRequest(rawPayload: ByteArray): Ctap2Request {
        if (rawPayload.isEmpty()) throw IllegalArgumentException("Empty CTAP payload")
        
        val commandByte = rawPayload[0]
        val cborBytes = if (rawPayload.size > 1) rawPayload.copyOfRange(1, rawPayload.size) else ByteArray(0)

        return try {
            when (commandByte) {
                0x04.toByte() -> Ctap2Request.GetInfo()
                0x01.toByte() -> {
                    // TODO: Use cbor.decodeFromByteArray to map CTAP MakeCredential CBOR with integer keys
                    Log.d("CtapCodec", "Decoded MakeCredential (0x01)")
                    // Temporary dummy implementation, to be replaced after full Model mapping
                    Ctap2Request.MakeCredential(ByteArray(32), "", "", ByteArray(0), "", "")
                }
                0x02.toByte() -> {
                    Log.d("CtapCodec", "Decoded GetAssertion (0x02)")
                    // Temporary dummy implementation
                    Ctap2Request.GetAssertion("", ByteArray(32))
                }
                else -> throw IllegalArgumentException("Unsupported command byte: $commandByte")
            }
        } catch (e: Exception) {
            Log.e("CtapCodec", "CBOR Decode Error", e)
            throw IllegalArgumentException("Invalid CBOR payload")
        }
    }

    fun encodeResponse(response: Ctap2Response): ByteArray {
        // First byte is status code, followed by CBOR encoded data
        return when (response) {
            is Ctap2Response.ErrorResponse -> byteArrayOf(response.errorCode)
            is Ctap2Response.GetInfoResponse -> {
                // TODO: Serialize actual GetInfo Map
                byteArrayOf(CtapStatus.SUCCESS)
            }
            is Ctap2Response.MakeCredentialResponse -> {
                // Spec requires MakeCredential response to be a Map arranged by integer keys
                // 0x01: fmt, 0x02: authData, 0x03: attStmt
                // Simplified handling, complete CBOR Map pending
                byteArrayOf(CtapStatus.SUCCESS) + response.authData 
            }
            is Ctap2Response.GetAssertionResponse -> {
                byteArrayOf(CtapStatus.SUCCESS) + response.authenticatorData
            }
        }
    }
}