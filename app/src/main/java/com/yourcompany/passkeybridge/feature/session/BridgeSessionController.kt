package com.yourcompany.passkeybridge.feature.session

import android.content.Context
import android.util.Log
import com.yourcompany.passkeybridge.core.proxy.CredentialManagerProxy
import com.yourcompany.passkeybridge.core.transport.TransportManager
import com.yourcompany.passkeybridge.core.ctap.model.CtapStatus
import com.yourcompany.passkeybridge.core.ctap.codec.CtapCodec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking

class BridgeSessionController(
    private val context: Context,
    private val transportManager: TransportManager? = null
) {
    private val proxy = CredentialManagerProxy(context)
    // Introduce SupervisorJob to control coroutine lifecycle
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    fun onQrCodeScanned(eid: ByteArray, psk: ByteArray) {
        transportManager?.startSession(eid, psk) { rawCtapRequest ->
            var responseBytes = byteArrayOf(CtapStatus.ERR_OPERATION_DENIED)
            
            try {
                // 1. Decode the binary CTAP command frame
                val parsedRequest = CtapCodec.decodeRequest(rawCtapRequest)
                
                // 2. Transport layer callback is synchronous; use runBlocking temporarily
                // Note: For future iterations, consider migrating to a fully asynchronous data flow
                val response = runBlocking(Dispatchers.Main) {
                    proxy.handleCtapRequest(parsedRequest)
                }
                
                // 3. Encode status code and CBOR response body
                responseBytes = CtapCodec.encodeResponse(response)
            } catch (e: IllegalArgumentException) {
                Log.e("SessionController", "Invalid request format", e)
                responseBytes = byteArrayOf(CtapStatus.ERR_INVALID_CBOR)
            } catch (e: Exception) {
                Log.e("SessionController", "Unhandled exception during CTAP processing", e)
                responseBytes = byteArrayOf(CtapStatus.ERR_OPERATION_DENIED)
            }
            
            responseBytes
        }
    }
}