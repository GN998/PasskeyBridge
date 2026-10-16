package com.dev.fido.bridge.core.proxy

import android.content.Context
import android.util.Log
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.mapper.CtapMapper
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.security.toHex

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
        val clientDataHashHex = req.clientDataHash.toHex(uppercase = true)

        Log.d("CredentialManagerProxy", "GetAssertion Request JSON: $jsonRequest")
        Log.d("CredentialManagerProxy", "GetAssertion PC clientDataHash: $clientDataHashHex, origin: $trustedOrigin")

        // Enforce strict privileged request with both setOrigin and PC's raw clientDataHash.
        // Never fall back to an unprivileged request without setOrigin, as doing so causes
        // providers to hash an Android-generated clientDataJSON and invalidates the signature.
        val option = GetPublicKeyCredentialOption(
            requestJson = jsonRequest,
            clientDataHash = req.clientDataHash
        )
        val getReq = GetCredentialRequest.Builder()
            .addCredentialOption(option)
            .setOrigin(trustedOrigin)
            .build()

        return executePrivilegedRequest("GetCredential") {
            val result = credentialManager.getCredential(context, getReq)
            val pubKeyCredential = result.credential as? PublicKeyCredential
                ?: return@executePrivilegedRequest Ctap2Response.ErrorResponse(CtapStatus.ERR_OPERATION_DENIED)

            val responseJson = pubKeyCredential.authenticationResponseJson
            Log.d("CredentialManagerProxy", "Raw authenticationResponseJson: $responseJson")
            CtapMapper.parseAssertionResponseJson(responseJson, req.allowList)
        }
    }

    private suspend fun handleMakeCredential(req: Ctap2Request.MakeCredential): Ctap2Response {
        val jsonRequest = CtapMapper.toWebAuthnCreateCredentialJson(req)
        val trustedOrigin = "https://${req.rpId}"

        Log.d("CredentialManagerProxy", "MakeCredential Request JSON: $jsonRequest")

        // Enforce strict privileged request with explicit origin and PC's raw clientDataHash.
        val createReq = CreatePublicKeyCredentialRequest(
            requestJson = jsonRequest,
            clientDataHash = req.clientDataHash,
            origin = trustedOrigin,
            preferImmediatelyAvailableCredentials = false
        )

        return executePrivilegedRequest("CreateCredential") {
            val result = credentialManager.createCredential(context, createReq)
            val pubKeyResponse = result as? CreatePublicKeyCredentialResponse
                ?: return@executePrivilegedRequest Ctap2Response.ErrorResponse(CtapStatus.ERR_OPERATION_DENIED)

            val responseJson = pubKeyResponse.registrationResponseJson
            Log.d("CredentialManagerProxy", "Raw registrationResponseJson: $responseJson")
            CtapMapper.parseMakeCredentialResponseJson(responseJson)
        }
    }

    /**
     * Execute privileged CredentialManager calls and translate DOM or security exceptions into standard CTAP2 error responses.
     */
    private suspend inline fun executePrivilegedRequest(
        operationName: String,
        block: () -> Ctap2Response
    ): Ctap2Response = try {
        block()
    } catch (e: SecurityException) {
        Log.e("CredentialManagerProxy", "SecurityException during $operationName: check provider allowlist or CREDENTIAL_MANAGER_SET_ORIGIN", e)
        Ctap2Response.ErrorResponse(CtapStatus.ERR_OPERATION_DENIED)
    } catch (e: Exception) {
        Log.e("CredentialManagerProxy", "$operationName failed: ${e.message}", e)
        Ctap2Response.ErrorResponse(mapExceptionToCtapStatus(e))
    }

    // Map Android CredentialManager exceptions to accurate CTAP2 status codes
    private fun mapExceptionToCtapStatus(e: Exception): Byte = when (e) {
        is NoCredentialException -> CtapStatus.ERR_NO_CREDENTIALS
        is CreatePublicKeyCredentialDomException -> when (e.domError) {
            is InvalidStateError -> CtapStatus.ERR_CREDENTIAL_EXCLUDED
            is NotSupportedError -> CtapStatus.ERR_UNSUPPORTED_ALGORITHM
            else -> CtapStatus.ERR_OPERATION_DENIED
        }
        else -> CtapStatus.ERR_OPERATION_DENIED
    }
}