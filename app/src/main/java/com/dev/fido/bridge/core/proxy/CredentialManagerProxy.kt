package com.dev.fido.bridge.core.proxy

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.PublicKeyCredential
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.mapper.CtapMapper
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.security.CryptoUtils
import org.json.JSONObject

/**
 * Delegate FIDO CTAP2 requests to Android CredentialManager system services.
 *
 * Map CTAP2 GetAssertion and MakeCredential requests into native WebAuthn JSON payloads,
 * invoking Android CredentialManager to perform biometric/PIN user verification and retrieve
 * public-key credentials.
 */
class CredentialManagerProxy(private val context: Context) {
    private val credentialManager = CredentialManager.create(context)

    /**
     * Dispatch incoming CTAP2 requests to corresponding CredentialManager handlers.
     */
    suspend fun handleCtapRequest(request: Ctap2Request): Ctap2Response {
        return when (request) {
            is Ctap2Request.GetInfo -> AuthenticatorInfo.getInfo()
            is Ctap2Request.GetAssertion -> handleGetAssertion(request)
            is Ctap2Request.MakeCredential -> handleMakeCredential(request)
        }
    }

    /**
     * Execute WebAuthn assertion retrieval via Android CredentialManager.
     *
     * Dynamically resolve the actual credential ID selected during user authentication from the
     * response JSON payload before falling back to the request allowList. This prevents credential ID
     * mismatches in multi-account environments where the user chooses a non-first credential.
     */
    private suspend fun handleGetAssertion(req: Ctap2Request.GetAssertion): Ctap2Response {
        val jsonRequest = CtapMapper.toWebAuthnGetCredentialJson(req)
        val trustedOrigin = "https://${req.rpId}"

        val option = GetPublicKeyCredentialOption(
            requestJson = jsonRequest,
            clientDataHash = req.clientDataHash
        )
        val getReq = GetCredentialRequest.Builder()
            .addCredentialOption(option)
            .setOrigin(trustedOrigin)
            .build()

        val result = credentialManager.getCredential(context, getReq)
        if (result.credential is PublicKeyCredential) {
            val pubKeyCredential = result.credential as PublicKeyCredential
            val responseJson = pubKeyCredential.authenticationResponseJson

            // Dynamically resolve actual chosen credential ID from response JSON before falling back to allowList
            val credId = try {
                val responseObj = JSONObject(responseJson)
                val idStr = responseObj.optString("id", "").ifEmpty { responseObj.optString("rawId", "") }
                if (idStr.isNotEmpty()) {
                    CryptoUtils.decodeBase64Url(idStr)
                } else {
                    req.allowList?.firstOrNull()?.id ?: ByteArray(0)
                }
            } catch (_: Exception) {
                req.allowList?.firstOrNull()?.id ?: ByteArray(0)
            }

            return CtapMapper.parseAssertionResponseJson(responseJson, credId)
        } else {
            return Ctap2Response.ErrorResponse(0x31)
        }
    }

    /**
     * Execute WebAuthn credential registration via Android CredentialManager.
     */
    private suspend fun handleMakeCredential(req: Ctap2Request.MakeCredential): Ctap2Response {
        val jsonRequest = CtapMapper.toWebAuthnCreateCredentialJson(req)
        val trustedOrigin = "https://${req.rpId}"

        val createReq = CreatePublicKeyCredentialRequest(
            requestJson = jsonRequest,
            clientDataHash = req.clientDataHash,
            origin = trustedOrigin,
            preferImmediatelyAvailableCredentials = false
        )

        val result = credentialManager.createCredential(context, createReq)
        if (result is CreatePublicKeyCredentialResponse) {
            val responseJson = result.registrationResponseJson
            return CtapMapper.parseMakeCredentialResponseJson(responseJson)
        } else {
            return Ctap2Response.ErrorResponse(0x31)
        }
    }
}
