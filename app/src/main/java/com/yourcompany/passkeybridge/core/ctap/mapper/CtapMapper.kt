package com.yourcompany.passkeybridge.core.ctap.mapper

import android.util.Log
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Request
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response
import com.yourcompany.passkeybridge.core.security.CryptoUtils
import org.json.JSONArray
import org.json.JSONObject

/**
 * Mapper for converting between CTAP2 data models and WebAuthn JSON representations.
 */
object CtapMapper {

    fun toWebAuthnGetCredentialJson(req: Ctap2Request.GetAssertion): String {
        return JSONObject().apply {
            // Set challenge to Base64URL-encoded clientDataHash required by Android CredentialManager WebAuthn API
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

    fun toWebAuthnCreateCredentialJson(req: Ctap2Request.MakeCredential): String {
        return JSONObject().apply {
            // Set challenge to Base64URL-encoded clientDataHash required by Android CredentialManager WebAuthn API
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

    fun parseAssertionResponseJson(jsonResponseStr: String, credentialId: ByteArray): Ctap2Response.GetAssertionResponse {
        val responseObj = JSONObject(jsonResponseStr).getJSONObject("response")
        val rawSigStr = responseObj.getString("signature")
        val rawAuthDataStr = responseObj.getString("authenticatorData")

        // Diagnostic Log Node 2: Log signature string extracted from response JSON
        Log.d("FIDO_DIAG", "================ [2. JSON EXTRACTED SIGNATURE STRING] ================")
        Log.d("FIDO_DIAG", "rawSigStr: '$rawSigStr'")
        Log.d("FIDO_DIAG", "rawSigStr length: ${rawSigStr.length}")

        val sigBytes = CryptoUtils.decodeBase64Url(rawSigStr)

        // Diagnostic Log Node 3: Log Base64 decoded signature bytes
        Log.d("FIDO_DIAG", "================ [3. BASE64 DECODED SIGNATURE BYTES] ================")
        Log.d("FIDO_DIAG", "sigBytes size: ${sigBytes.size}")
        Log.d("FIDO_DIAG", "sigBytes hex: ${sigBytes.joinToString("") { "%02X".format(it) }}")

        return Ctap2Response.GetAssertionResponse(
            credentialId = credentialId,
            authenticatorData = CryptoUtils.decodeBase64Url(rawAuthDataStr),
            signature = sigBytes,
            userHandle = responseObj.optString("userHandle", null)?.takeIf { it.isNotEmpty() }?.let { CryptoUtils.decodeBase64Url(it) }
        )
    }

    fun parseMakeCredentialResponseJson(jsonResponseStr: String): Ctap2Response.MakeCredentialResponse {
        val responseObj = JSONObject(jsonResponseStr).getJSONObject("response")
        val attestationObjectBytes = CryptoUtils.decodeBase64Url(responseObj.getString("attestationObject"))
        
        // Decode the CBOR attestationObject into fmt, authData, and attStmt
        val map = com.yourcompany.passkeybridge.core.ctap.codec.CtapCodec.SimpleCbor.read(attestationObjectBytes) as Map<*, *>
        
        return Ctap2Response.MakeCredentialResponse(
            fmt = map["fmt"] as String,
            authData = map["authData"] as ByteArray,
            attStmt = map["attStmt"] as Map<*, *>
        )
    }
}
