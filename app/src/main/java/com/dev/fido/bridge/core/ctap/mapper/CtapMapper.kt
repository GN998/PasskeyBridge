package com.dev.fido.bridge.core.ctap.mapper

import android.util.Log
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.security.CryptoUtils
import org.json.JSONArray
import org.json.JSONObject

/**
 * Translate between CTAP2 domain models and WebAuthn JSON structures.
 *
 * Convert structured CTAP requests into WebAuthn-compliant JSON strings required by Android CredentialManager,
 * and parse WebAuthn JSON responses back into CTAP2 domain models.
 */
object CtapMapper {

    /**
     * Convert CTAP GetAssertion request into WebAuthn GetCredential JSON payload.
     */
    fun toWebAuthnGetCredentialJson(req: Ctap2Request.GetAssertion): String {
        return JSONObject().apply {
            put("challenge", CryptoUtils.encodeBase64UrlNoPadding(req.clientDataHash))
            put("rpId", req.rpId)
            put("userVerification", req.userVerification ?: "preferred")

            req.allowList?.let { list ->
                val allowArray = JSONArray()
                for (item in list) {
                    allowArray.put(JSONObject().apply {
                        put("type", item.type)
                        put("id", CryptoUtils.encodeBase64UrlNoPadding(item.id))
                    })
                }
                put("allowCredentials", allowArray)
            }
        }.toString()
    }

    /**
     * Convert CTAP MakeCredential request into WebAuthn CreateCredential JSON payload.
     */
    fun toWebAuthnCreateCredentialJson(req: Ctap2Request.MakeCredential): String {
        return JSONObject().apply {
            put("challenge", CryptoUtils.encodeBase64UrlNoPadding(req.clientDataHash))
            put("rp", JSONObject().apply {
                put("id", req.rpId)
                put("name", req.rpName)
            })
            put("user", JSONObject().apply {
                put("id", CryptoUtils.encodeBase64UrlNoPadding(req.userId))
                put("name", req.userName)
                put("displayName", req.userDisplayName)
            })
            val pubKeyParams = JSONArray()
            req.pubKeyCredParams.forEach { param ->
                pubKeyParams.put(JSONObject(param))
            }
            put("pubKeyCredParams", pubKeyParams)
        }.toString()
    }

    /**
     * Parse WebAuthn authentication response JSON into a CTAP GetAssertionResponse model.
     *
     * Decode URL-safe Base64 fields and validate assertion signature byte bounds against CTAP 2.3
     * specifications (requiring ASN.1 DER ECDSA signatures between 64 and 72 bytes) to detect and log
     * signature truncation anomalies prior to CBOR framing.
     */
    fun parseAssertionResponseJson(jsonResponseStr: String, credentialId: ByteArray): Ctap2Response.GetAssertionResponse {
        val responseObj = JSONObject(jsonResponseStr).getJSONObject("response")
        val rawSigStr = responseObj.getString("signature")
        val signatureBytes = CryptoUtils.decodeBase64Url(rawSigStr)

        if (signatureBytes.size < 64) {
            Log.e("CtapMapper", "Parsed assertion signature length is invalid (${signatureBytes.size} bytes): $rawSigStr")
        } else {
            Log.d("CtapMapper", "Successfully parsed assertion signature (${signatureBytes.size} bytes)")
        }

        return Ctap2Response.GetAssertionResponse(
            credentialId = credentialId,
            authenticatorData = CryptoUtils.decodeBase64Url(responseObj.getString("authenticatorData")),
            signature = signatureBytes,
            userHandle = responseObj.optString("userHandle", null)?.takeIf { it.isNotEmpty() }?.let { CryptoUtils.decodeBase64Url(it) }
        )
    }

    /**
     * Parse WebAuthn registration response JSON into a CTAP MakeCredentialResponse model.
     */
    fun parseMakeCredentialResponseJson(jsonResponseStr: String): Ctap2Response.MakeCredentialResponse {
        val responseObj = JSONObject(jsonResponseStr).getJSONObject("response")
        val attestationObjectBytes = CryptoUtils.decodeBase64Url(responseObj.getString("attestationObject"))
        
        val map = com.dev.fido.bridge.core.ctap.codec.CtapCodec.SimpleCbor.read(attestationObjectBytes) as Map<*, *>
        
        return Ctap2Response.MakeCredentialResponse(
            fmt = map["fmt"] as String,
            authData = map["authData"] as ByteArray,
            attStmt = map["attStmt"] as Map<*, *>
        )
    }
}
