package com.yourcompany.passkeybridge.feature.session

import android.content.Context
import android.util.Log
import com.yourcompany.passkeybridge.core.proxy.CredentialManagerProxy
import com.yourcompany.passkeybridge.core.transport.TransportManager
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Request
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

class BridgeSessionController(
    private val context: Context,
    private val transportManager: TransportManager? = null
) {
    private val proxy = CredentialManagerProxy(context)
    private val scope = CoroutineScope(Dispatchers.Main)

    fun onQrCodeScanned(eid: ByteArray, psk: ByteArray) {
        transportManager?.startSession(eid, psk) { rawCtapRequest ->
            var responseBytes = ByteArray(0)
            try {
                val parsedRequest = parseRawCtapToRequest(rawCtapRequest)
                val response = runBlocking(Dispatchers.Main) {
                    proxy.handleCtapRequest(parsedRequest)
                }
                responseBytes = encodeResponseToRawCtap(response)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            responseBytes
        }
    }
    
    // Step 2: Hardcoded hash verification spike to validate Privileged API behavior
    suspend fun runStep2HashVerificationSpike(): String {
        Log.d("Step2Spike", "Starting Privileged API hash verification spike (MakeCredential)...")
        
        // Hardcode a 32-byte fixed clientDataHash to test provider signature logic
        val fixedHash = ByteArray(32) { 0x5A } 
        
        // Fix: Pass emptyList() for pubKeyCredParams to match List<Map<String, Int>> model type
        val req = Ctap2Request.MakeCredential(
            clientDataHash = fixedHash,
            rpId = "example.com",
            rpName = "Example RP",
            userId = byteArrayOf(1, 2, 3, 4),
            userName = "testuser",
            userDisplayName = "Test User",
            pubKeyCredParams = listOf(
                mapOf("type" to "public-key", "alg" to -7),
                mapOf("type" to "public-key", "alg" to -257)
            )
        )
        
        Log.d("Step2Spike", "Dispatching MakeCredential with fixed clientDataHash...")
        val response = proxy.handleCtapRequest(req)
        
        return if (response is Ctap2Response.MakeCredentialResponse) {
            "SUCCESS!\nCredential Created.\nAuthData length: ${response.authData.size} bytes.\n\nAction Required: Verify signature against the 0x5A hash in Provider."
        } else {
            "FAILED!\nResponse: $response"
        }
    }

    private fun parseRawCtapToRequest(raw: ByteArray): Ctap2Request {
        return Ctap2Request.GetInfo(true)
    }
    
    private fun encodeResponseToRawCtap(response: Ctap2Response): ByteArray {
        return byteArrayOf(0x00)
    }
}