package com.dev.fido.bridge.core.proxy

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.PublicKeyCredential
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.mapper.AssertionResponseResolver
import com.dev.fido.bridge.core.ctap.mapper.CtapMapper
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response

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
     * Delegate credential ID extraction to [AssertionResponseResolver] to bind the signature
     * directly to the credential chosen by the user in the system UI sheet.
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

            // Resolve the actual selected credential ID from response JSON to prevent public key mismatches
            val credId = AssertionResponseResolver.resolveCredentialId(responseJson, req.allowList)

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