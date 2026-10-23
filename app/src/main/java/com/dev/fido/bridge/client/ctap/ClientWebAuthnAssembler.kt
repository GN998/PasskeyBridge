package com.dev.fido.bridge.client.ctap

import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.CredentialDescriptor
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.security.CryptoUtils
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer

/**
 * Holds the prepared CTAP2 request alongside the synthesized clientDataJSON (when not overridden by a browser's raw clientDataHash).
 */
data class PreparedClientCeremony(
    val ctapRequest: Ctap2Request,
    val clientDataJsonBytes: ByteArray,
    val operationHint: String
)

object ClientWebAuthnAssembler {

    /**
     * Convert Android CredentialProvider GetPublicKeyCredentialOption JSON into a CTAP2 GetAssertion request.
     * If the privileged caller (e.g., Edge) supplies [providedClientDataHash], forward it directly per Android CredentialProvider spec.
     */
    fun prepareGetAssertion(
        requestJson: String,
        origin: String,
        providedClientDataHash: ByteArray?,
        packageName: String? = null
    ): PreparedClientCeremony {
        val json = JSONObject(requestJson)
        val rpId = json.getString("rpId")
        val challengeB64 = json.getString("challenge")
        val uv = json.optString("userVerification", "preferred")

        val clientDataBytes = buildClientDataJson(
            type = "webauthn.get",
            challengeBase64Url = challengeB64,
            origin = origin,
            packageName = packageName
        )
        val effectiveHash = providedClientDataHash?.takeIf { it.size == 32 }
            ?: CryptoUtils.sha256(clientDataBytes)

        val allowList = json.optJSONArray("allowCredentials")?.toDescriptorList()

        val ctapReq = Ctap2Request.GetAssertion(
            rpId = rpId,
            clientDataHash = effectiveHash,
            allowList = allowList,
            userVerification = uv,
            userPresence = true
        )
        return PreparedClientCeremony(
            ctapRequest = ctapReq,
            clientDataJsonBytes = clientDataBytes,
            operationHint = "ga"
        )
    }

    /**
     * Convert Android CredentialProvider CreatePublicKeyCredentialRequest JSON into a CTAP2 MakeCredential request.
     */
    fun prepareMakeCredential(
        requestJson: String,
        origin: String,
        providedClientDataHash: ByteArray?,
        packageName: String? = null
    ): PreparedClientCeremony {
        val json = JSONObject(requestJson)
        val challengeB64 = json.getString("challenge")

        val rpObj = json.getJSONObject("rp")
        val rpId = rpObj.getString("id")
        val rpName = rpObj.optString("name", rpId)

        val userObj = json.getJSONObject("user")
        val userId = CryptoUtils.decodeBase64Url(userObj.getString("id"))
        val userName = userObj.optString("name", "")
        val userDisplayName = userObj.optString("displayName", userName)

        val paramsArray = json.getJSONArray("pubKeyCredParams")
        val pubKeyCredParams = mutableListOf<Map<String, Any>>()
        for (i in 0 until paramsArray.length()) {
            val item = paramsArray.getJSONObject(i)
            pubKeyCredParams.add(
                mapOf(
                    "type" to item.getString("type"),
                    "alg" to item.getLong("alg")
                )
            )
        }

        val excludeList = json.optJSONArray("excludeCredentials")?.toDescriptorList()

        val authSel = json.optJSONObject("authenticatorSelection")
        val residentKeyStr = authSel?.optString("residentKey", "") ?: ""
        val requireRk = authSel?.optBoolean("requireResidentKey", false) ?: false
        val rk = requireRk || residentKeyStr == "required" || residentKeyStr == "preferred"
        val uvStr = authSel?.optString("userVerification", "preferred") ?: "preferred"

        val options = buildMap<String, Boolean> {
            if (rk) put("rk", true)
            if (uvStr == "required" || uvStr == "preferred") put("uv", true)
        }

        val clientDataBytes = buildClientDataJson(
            type = "webauthn.create",
            challengeBase64Url = challengeB64,
            origin = origin,
            packageName = packageName
        )
        val effectiveHash = providedClientDataHash?.takeIf { it.size == 32 }
            ?: CryptoUtils.sha256(clientDataBytes)

        val ctapReq = Ctap2Request.MakeCredential(
            clientDataHash = effectiveHash,
            rpId = rpId,
            rpName = rpName,
            userId = userId,
            userName = userName,
            userDisplayName = userDisplayName,
            pubKeyCredParams = pubKeyCredParams,
            excludeList = excludeList,
            options = options
        )
        return PreparedClientCeremony(
            ctapRequest = ctapReq,
            clientDataJsonBytes = clientDataBytes,
            operationHint = "mc"
        )
    }

/**
     * Assemble WebAuthn AuthenticationResponseJSON string from a CTAP2 GetAssertionResponse per WebAuthn §5.1.
     */
    fun buildGetAssertionResponseJson(
        response: Ctap2Response.GetAssertionResponse,
        clientDataJsonBytes: ByteArray,
        fallbackAllowList: List<CredentialDescriptor>? = null
    ): String {
        val effectiveCredId = response.credentialId.takeIf { it.isNotEmpty() }
            ?: fallbackAllowList?.firstOrNull()?.id
            ?: ByteArray(0)
        val credIdB64 = CryptoUtils.encodeBase64UrlNoPadding(effectiveCredId)

        return JSONObject().apply {
            put("id", credIdB64)
            put("rawId", credIdB64)
            put("type", "public-key")
            put("authenticatorAttachment", "cross-platform")
            put("response", JSONObject().apply {
                put("clientDataJSON", CryptoUtils.encodeBase64UrlNoPadding(clientDataJsonBytes))
                put("authenticatorData", CryptoUtils.encodeBase64UrlNoPadding(response.authenticatorData))
                put("signature", CryptoUtils.encodeBase64UrlNoPadding(response.signature))
                response.userHandle?.takeIf { it.isNotEmpty() }?.let { uh ->
                    put("userHandle", CryptoUtils.encodeBase64UrlNoPadding(uh))
                }
            })
            put("clientExtensionResults", JSONObject())
        }.toString()
    }

    /**
     * Assemble WebAuthn RegistrationResponseJSON string from a CTAP2 MakeCredentialResponse per WebAuthn §5.1.
     * Extract the newly generated credentialId from authData's attestedCredentialData (offset 53..55 + L).
     */
    fun buildMakeCredentialResponseJson(
        response: Ctap2Response.MakeCredentialResponse,
        clientDataJsonBytes: ByteArray
    ): String {
        val credentialId = extractCredentialIdFromAuthData(response.authData)
        val credIdB64 = CryptoUtils.encodeBase64UrlNoPadding(credentialId)

        val attestationObjectMap = mapOf(
            "fmt" to response.fmt,
            "authData" to response.authData,
            "attStmt" to response.attStmt
        )
        val attestationObjectBytes = CtapCodec.SimpleCbor.write(attestationObjectMap)

        return JSONObject().apply {
            put("id", credIdB64)
            put("rawId", credIdB64)
            put("type", "public-key")
            put("authenticatorAttachment", "cross-platform")
            put("response", JSONObject().apply {
                put("clientDataJSON", CryptoUtils.encodeBase64UrlNoPadding(clientDataJsonBytes))
                put("attestationObject", CryptoUtils.encodeBase64UrlNoPadding(attestationObjectBytes))
                put("transports", JSONArray(listOf("hybrid", "internal")))
            })
            put("clientExtensionResults", JSONObject())
        }.toString()
    }

    /**
     * Extract credentialId from authenticatorData per WebAuthn §6.1 & §6.5.1:
     * rpIdHash (32) + flags (1) + signCount (4) + aaguid (16) + credIdLen (2, big-endian) + credentialId (L).
     */
    private fun extractCredentialIdFromAuthData(authData: ByteArray): ByteArray {
        if (authData.size < 55) return ByteArray(0)
        val flags = authData[32].toInt() and 0xFF
        val hasAttestedCredData = (flags and 0x40) != 0
        if (!hasAttestedCredData) return ByteArray(0)

        val credIdLen = ByteBuffer.wrap(authData, 53, 2).short.toInt() and 0xFFFF
        if (authData.size < 55 + credIdLen) return ByteArray(0)
        return authData.copyOfRange(55, 55 + credIdLen)
    }

    private fun buildClientDataJson(
        type: String,
        challengeBase64Url: String,
        origin: String,
        packageName: String?
    ): ByteArray {
        val obj = JSONObject().apply {
            put("type", type)
            put("challenge", challengeBase64Url)
            put("origin", origin)
            put("crossOrigin", false)
            if (!packageName.isNullOrEmpty()) {
                put("androidPackageName", packageName)
            }
        }
        return obj.toString().toByteArray(Charsets.UTF_8)
    }

    private fun JSONArray.toDescriptorList(): List<CredentialDescriptor> {
        val list = mutableListOf<CredentialDescriptor>()
        for (i in 0 until length()) {
            val item = getJSONObject(i)
            val idBytes = CryptoUtils.decodeBase64Url(item.getString("id"))
            val typeStr = item.optString("type", "public-key")
            val transports = item.optJSONArray("transports")?.let { tArr ->
                List(tArr.length()) { idx -> tArr.getString(idx) }
            }
            list.add(CredentialDescriptor(type = typeStr, id = idBytes, transports = transports))
        }
        return list
    }
}