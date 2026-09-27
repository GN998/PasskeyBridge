package com.yourcompany.passkeybridge.core.proxy

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.PublicKeyCredential
import com.yourcompany.passkeybridge.core.ctap.AuthenticatorInfo
import com.yourcompany.passkeybridge.core.ctap.mapper.CtapMapper
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Request
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response
import com.yourcompany.passkeybridge.core.security.CryptoUtils
import org.json.JSONObject

class CredentialManagerProxy(private val context: Context) {
    private val credentialManager = CredentialManager.create(context)

    suspend fun handleCtapRequest(request: Ctap2Request): Ctap2Response {
        return when (request) {
            is Ctap2Request.GetInfo -> AuthenticatorInfo.getInfo()
            is Ctap2Request.GetAssertion -> handleGetAssertion(request)
            is Ctap2Request.MakeCredential -> handleMakeCredential(request)
        }
    }

    private suspend fun handleGetAssertion(req: Ctap2Request.GetAssertion): Ctap2Response {
        val jsonRequest = CtapMapper.toWebAuthnGetCredentialJson(req)
        val trustedOrigin = "https://${req.rpId}"

        val option = GetPublicKeyCredentialOption(
            requestJson = jsonRequest,
            clientDataHash = req.clientDataHash
        )
        // Call setOrigin on GetCredentialRequest.Builder
        val getReq = GetCredentialRequest.Builder()
            .addCredentialOption(option)
            .setOrigin(trustedOrigin)
            .build()

        val result = credentialManager.getCredential(context, getReq)
        if (result.credential is PublicKeyCredential) {
            val pubKeyCredential = result.credential as PublicKeyCredential
            val responseJson = pubKeyCredential.authenticationResponseJson
            // Fix for Bug 5: Extract credential ID from allowList or parse authenticationResponseJson (Passkey / discoverable credentials)
            val credId = req.allowList?.firstOrNull()?.id?.takeIf { it.isNotEmpty() }
                ?: try {
                    val responseObj = JSONObject(responseJson)
                    val idStr = responseObj.optString("id", "").ifEmpty { responseObj.optString("rawId", "") }
                    if (idStr.isNotEmpty()) CryptoUtils.decodeBase64Url(idStr) else ByteArray(0)
                } catch (e: Exception) {
                    ByteArray(0)
                }
            return CtapMapper.parseAssertionResponseJson(responseJson, credId)
        } else {
            return Ctap2Response.ErrorResponse(0x31)
        }
    }

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
