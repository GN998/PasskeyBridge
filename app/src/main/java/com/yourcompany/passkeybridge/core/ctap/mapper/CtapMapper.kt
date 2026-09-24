package com.yourcompany.passkeybridge.core.ctap.mapper

import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Request
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response
import com.yourcompany.passkeybridge.core.security.CryptoUtils
import org.json.JSONArray
import org.json.JSONObject

object CtapMapper {

    fun toWebAuthnGetCredentialJson(req: Ctap2Request.GetAssertion): String {
        return JSONObject().apply {
            // Fix: challenge and origin are handled via privileged API's clientDataHash instead; set to empty to maintain structure
            put("challenge", "")
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
            // Fix: Same as above, no need to incorrectly disguise challenge using base64(hash)
            put("challenge", "")
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
        return Ctap2Response.GetAssertionResponse(
            credentialId = credentialId,
            authenticatorData = CryptoUtils.decodeBase64Url(responseObj.getString("authenticatorData")),
            signature = CryptoUtils.decodeBase64Url(responseObj.getString("signature")),
            userHandle = responseObj.optString("userHandle", null)?.takeIf { it.isNotEmpty() }?.let { CryptoUtils.decodeBase64Url(it) }
        )
    }

    fun parseMakeCredentialResponseJson(jsonResponseStr: String): Ctap2Response.MakeCredentialResponse {
        val responseObj = JSONObject(jsonResponseStr).getJSONObject("response")
        val attestationObjectBytes = CryptoUtils.decodeBase64Url(responseObj.getString("attestationObject"))
        
        // Fix: Decode the CBOR attestationObject into fmt, authData, and attStmt
        val map = com.yourcompany.passkeybridge.core.ctap.codec.CtapCodec.SimpleCbor.read(attestationObjectBytes) as Map<*, *>
        
        return Ctap2Response.MakeCredentialResponse(
            fmt = map["fmt"] as String,
            authData = map["authData"] as ByteArray,
            attStmt = map["attStmt"] as Map<*, *>
        )
    }
}