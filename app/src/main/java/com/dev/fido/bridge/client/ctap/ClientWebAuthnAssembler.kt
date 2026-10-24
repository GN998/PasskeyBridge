package com.dev.fido.bridge.client.ctap

import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.CredentialDescriptor
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.security.CryptoUtils
import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec

/**
 * Holds the prepared CTAP2 request alongside the synthesized clientDataJSON (when not overridden by a browser's raw clientDataHash).
 */
data class PreparedClientCeremony(
    val ctapRequest: Ctap2Request,
    val clientDataJsonBytes: ByteArray,
    val operationHint: String,
    val attestationPreference: String = "none"
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
        val attestationPref = json.optString("attestation", "none")

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
            operationHint = "mc",
            attestationPreference = attestationPref
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
     * Strip attestation statement and zero out AAGUID when [attestationPreference] is "none" per WebAuthn §5.1.3,
     * and populate authenticatorData, publicKeyAlgorithm, and SPKI publicKey required by Chromium's MojoClassFromJSON parser.
     */
    fun buildMakeCredentialResponseJson(
        response: Ctap2Response.MakeCredentialResponse,
        clientDataJsonBytes: ByteArray,
        attestationPreference: String = "none"
    ): String {
        val stripAttestation = attestationPreference == "none"
        val effectiveAuthData = if (stripAttestation && response.authData.size >= 53) {
            response.authData.copyOf().apply {
                // Zero out the 16-byte AAGUID (bytes 37..52) when attestation conveyance is "none" per WebAuthn §5.1.3
                java.util.Arrays.fill(this, 37, 53, 0.toByte())
            }
        } else {
            response.authData
        }

        val parsedAuthData = parseAttestedAuthData(effectiveAuthData)
        val credIdB64 = CryptoUtils.encodeBase64UrlNoPadding(parsedAuthData.credentialId)

        val attestationObjectMap = mapOf(
            "fmt" to if (stripAttestation) "none" else response.fmt,
            "authData" to effectiveAuthData,
            "attStmt" to if (stripAttestation) emptyMap<Any, Any>() else response.attStmt
        )
        val attestationObjectBytes = CtapCodec.SimpleCbor.write(attestationObjectMap)

        return JSONObject().apply {
            put("id", credIdB64)
            put("rawId", credIdB64)
            put("type", "public-key")
            put("authenticatorAttachment", "cross-platform")
            put("response", JSONObject().apply {
                put("clientDataJSON", CryptoUtils.encodeBase64UrlNoPadding(clientDataJsonBytes))
                put("authenticatorData", CryptoUtils.encodeBase64UrlNoPadding(effectiveAuthData))
                put("attestationObject", CryptoUtils.encodeBase64UrlNoPadding(attestationObjectBytes))
                put("transports", JSONArray(listOf("hybrid", "internal")))
                put("publicKeyAlgorithm", parsedAuthData.coseAlgorithm)
                parsedAuthData.spkiPublicKeyBytes?.let { spki ->
                    put("publicKey", CryptoUtils.encodeBase64UrlNoPadding(spki))
                }
            })
            put("clientExtensionResults", JSONObject())
        }.toString()
    }

    private data class ParsedAttestedAuthData(
        val credentialId: ByteArray,
        val coseAlgorithm: Long,
        val spkiPublicKeyBytes: ByteArray?
    )

    /**
     * Extract credentialId, COSEAlgorithmIdentifier (key 3), and DER SubjectPublicKeyInfo from authenticatorData
     * per WebAuthn §6.1 & §6.5.1:
     * rpIdHash (32) + flags (1) + signCount (4) + aaguid (16) + credIdLen (2, big-endian) + credentialId (L) + credentialPublicKey (CBOR).
     */
    private fun parseAttestedAuthData(authData: ByteArray): ParsedAttestedAuthData {
        if (authData.size < 55) {
            return ParsedAttestedAuthData(ByteArray(0), -7L, null)
        }
        val flags = authData[32].toInt() and 0xFF
        val hasAttestedCredData = (flags and 0x40) != 0
        if (!hasAttestedCredData) {
            return ParsedAttestedAuthData(ByteArray(0), -7L, null)
        }

        val credIdLen = ByteBuffer.wrap(authData, 53, 2).short.toInt() and 0xFFFF
        val coseKeyOffset = 55 + credIdLen
        if (authData.size < coseKeyOffset) {
            return ParsedAttestedAuthData(ByteArray(0), -7L, null)
        }

        val credentialId = authData.copyOfRange(55, coseKeyOffset)
        if (authData.size == coseKeyOffset) {
            return ParsedAttestedAuthData(credentialId, -7L, null)
        }

        val coseSlice = authData.copyOfRange(coseKeyOffset, authData.size)
        val coseMap = runCatching {
            CtapCodec.SimpleCbor.read(coseSlice, strict = false, allowTrailingBytes = true) as? Map<*, *>
        }.getOrNull()

        val alg = (coseMap?.get(3L) as? Number)?.toLong() ?: -7L
        val spkiBytes = runCatching { coseMap?.let(::convertCoseKeyToSpki) }.getOrNull()

        return ParsedAttestedAuthData(
            credentialId = credentialId,
            coseAlgorithm = alg,
            spkiPublicKeyBytes = spkiBytes
        )
    }

    /**
     * Convert COSE_Key map into DER-encoded SubjectPublicKeyInfo (SPKI) bytes per WebAuthn §5.2.1.1.
     */
    private fun convertCoseKeyToSpki(coseMap: Map<*, *>): ByteArray? {
        val kty = (coseMap[1L] as? Number)?.toInt() ?: return null
        return when (kty) {
            2 -> {
                // EC2 (P-256 / ES256: crv = 1, x = -2, y = -3)
                val crv = (coseMap[-1L] as? Number)?.toInt()
                val xBytes = coseMap[-2L] as? ByteArray ?: return null
                val yBytes = coseMap[-3L] as? ByteArray ?: return null
                if (crv != 1 || xBytes.size != 32 || yBytes.size != 32) return null

                val params = AlgorithmParameters.getInstance("EC").apply {
                    init(ECGenParameterSpec("secp256r1"))
                }.getParameterSpec(ECParameterSpec::class.java)
                val point = ECPoint(BigInteger(1, xBytes), BigInteger(1, yBytes))
                KeyFactory.getInstance("EC")
                    .generatePublic(ECPublicKeySpec(point, params))
                    .encoded
            }
            1 -> {
                // OKP (Ed25519 / EdDSA: crv = 6, x = -2) -> RFC 8410 12-byte SPKI header + 32-byte raw key
                val crv = (coseMap[-1L] as? Number)?.toInt()
                val xBytes = coseMap[-2L] as? ByteArray ?: return null
                if (crv != 6 || xBytes.size != 32) return null
                byteArrayOf(0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00) + xBytes
            }
            3 -> {
                // RSA (RS256: n = -1, e = -2)
                val nBytes = coseMap[-1L] as? ByteArray ?: return null
                val eBytes = coseMap[-2L] as? ByteArray ?: return null
                val spec = RSAPublicKeySpec(BigInteger(1, nBytes), BigInteger(1, eBytes))
                KeyFactory.getInstance("RSA").generatePublic(spec).encoded
            }
            else -> null
        }
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