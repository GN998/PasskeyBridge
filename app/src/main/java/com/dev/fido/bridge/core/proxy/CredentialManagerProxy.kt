package com.dev.fido.bridge.core.proxy

import android.content.Context
import android.util.Log
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.mapper.CtapMapper
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.security.CryptoUtils
import com.dev.fido.bridge.core.security.toHex
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

        return try {
            val result = credentialManager.getCredential(context, getReq)
            val pubKeyCredential = result.credential as? PublicKeyCredential
                ?: return Ctap2Response.ErrorResponse(CtapStatus.ERR_OPERATION_DENIED)

            val responseJson = pubKeyCredential.authenticationResponseJson
            Log.d("CredentialManagerProxy", "Raw authenticationResponseJson: $responseJson")

            // Extract the actual selected credential ID from authenticationResponseJson first
            // so multi-credential allowLists do not return the wrong descriptor ID.
            val credId = runCatching {
                val responseObj = JSONObject(responseJson)
                val idStr = responseObj.optString("rawId", "").ifEmpty { responseObj.optString("id", "") }
                if (idStr.isNotEmpty()) CryptoUtils.decodeBase64Url(idStr) else null
            }.getOrNull() ?: req.allowList?.firstOrNull()?.id ?: ByteArray(0)

            CtapMapper.parseAssertionResponseJson(responseJson, credId)
        } catch (e: GetCredentialException) {
            Log.e("CredentialManagerProxy", "GetCredential failed: ${e.type} - ${e.message}", e)
            Ctap2Response.ErrorResponse(mapGetExceptionToCtapStatus(e))
        } catch (e: SecurityException) {
            Log.e("CredentialManagerProxy", "SecurityException during GetCredential: check provider allowlist or CREDENTIAL_MANAGER_SET_ORIGIN", e)
            Ctap2Response.ErrorResponse(CtapStatus.ERR_OPERATION_DENIED)
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

        return try {
            val result = credentialManager.createCredential(context, createReq)
            val pubKeyResponse = result as? CreatePublicKeyCredentialResponse
                ?: return Ctap2Response.ErrorResponse(CtapStatus.ERR_OPERATION_DENIED)

            val responseJson = pubKeyResponse.registrationResponseJson
            Log.d("CredentialManagerProxy", "Raw registrationResponseJson: $responseJson")
            CtapMapper.parseMakeCredentialResponseJson(responseJson)
        } catch (e: CreateCredentialException) {
            Log.e("CredentialManagerProxy", "CreateCredential failed: ${e.type} - ${e.message}", e)
            Ctap2Response.ErrorResponse(mapCreateExceptionToCtapStatus(e))
        } catch (e: SecurityException) {
            Log.e("CredentialManagerProxy", "SecurityException during CreateCredential: check provider allowlist or CREDENTIAL_MANAGER_SET_ORIGIN", e)
            Ctap2Response.ErrorResponse(CtapStatus.ERR_OPERATION_DENIED)
        }
    }

    // Map Android CredentialManager exceptions to accurate CTAP2 status codes instead of hardcoding 0x31 (PIN_INVALID)
    private fun mapGetExceptionToCtapStatus(e: GetCredentialException): Byte = when (e) {
        is GetCredentialCancellationException -> CtapStatus.ERR_OPERATION_DENIED
        is NoCredentialException -> CtapStatus.ERR_NO_CREDENTIALS
        is GetPublicKeyCredentialDomException -> when (e.domError) {
            is NotAllowedError -> CtapStatus.ERR_OPERATION_DENIED
            else -> CtapStatus.ERR_OPERATION_DENIED
        }
        else -> CtapStatus.ERR_OPERATION_DENIED
    }

    private fun mapCreateExceptionToCtapStatus(e: CreateCredentialException): Byte = when (e) {
        is CreateCredentialCancellationException -> CtapStatus.ERR_OPERATION_DENIED
        is CreatePublicKeyCredentialDomException -> when (e.domError) {
            is InvalidStateError -> CtapStatus.ERR_CREDENTIAL_EXCLUDED
            is NotSupportedError -> CtapStatus.ERR_UNSUPPORTED_ALGORITHM
            is NotAllowedError -> CtapStatus.ERR_OPERATION_DENIED
            else -> CtapStatus.ERR_OPERATION_DENIED
        }
        else -> CtapStatus.ERR_OPERATION_DENIED
    }
}