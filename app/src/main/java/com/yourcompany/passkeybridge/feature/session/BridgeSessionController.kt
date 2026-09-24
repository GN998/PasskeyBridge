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
    suspend fun runStep2HashVerificationSpike() {
        Log.d("Step2Spike", "Starting Privileged API hash verification spike...")
        
        // Hardcode a 32-byte fixed clientDataHash to test provider signature logic
        val fixedHash = ByteArray(32) { 0x5A } 
        
        val req = Ctap2Request.GetAssertion(
            rpId = "example.com",
            clientDataHash = fixedHash,
            allowList = null
        )
        
        Log.d("Step2Spike", "Dispatching GetAssertion with fixed clientDataHash...")
        val response = proxy.handleCtapRequest(req)
        
        if (response is Ctap2Response.GetAssertionResponse) {
            Log.d("Step2Spike", "Assertion received successfully.")
            Log.d("Step2Spike", "Signature length: ${response.signature.size} bytes.")
            Log.d("Step2Spike", "Proceeding to cryptographic verification against fixedHash.")
            // Note: Independent cryptographic verification logic will assert this signature here.
        } else {
            Log.e("Step2Spike", "Failed to get assertion. Response: $response")
        }
    }

    private fun parseRawCtapToRequest(raw: ByteArray): Ctap2Request {
        return Ctap2Request.GetInfo(true)
    }
    
    private fun encodeResponseToRawCtap(response: Ctap2Response): ByteArray {
        return byteArrayOf(0x00)
    }
}