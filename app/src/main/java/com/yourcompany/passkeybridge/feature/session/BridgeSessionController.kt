package com.yourcompany.passkeybridge.feature.session

import android.content.Context
import android.util.Log
import com.yourcompany.passkeybridge.BuildConfig
import com.yourcompany.passkeybridge.core.proxy.CredentialManagerProxy
import com.yourcompany.passkeybridge.core.transport.TransportManager
import com.yourcompany.passkeybridge.core.ctap.model.CtapStatus
import com.yourcompany.passkeybridge.core.ctap.codec.CtapCodec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class BridgeSessionController(
    private val context: Context,
    private val transportManager: TransportManager? = null
) {
    private val proxy = CredentialManagerProxy(context)
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    
    var onStatusUpdate: ((String) -> Unit)? = null

    // Default value provided for domainId to ensure backwards compatibility
    fun onQrCodeScanned(peerPublicKey: ByteArray, psk: ByteArray, domainId: Int = BuildConfig.TUNNEL_ID) {
        transportManager?.onStatusUpdate = { status ->
            scope.launch { onStatusUpdate?.invoke(status) }
        }

        transportManager?.startSession(peerPublicKey, psk, domainId) { rawCtapRequest ->
            var responseBytes = byteArrayOf(CtapStatus.ERR_OPERATION_DENIED)
            
            try {
                val parsedRequest = CtapCodec.decodeRequest(rawCtapRequest)
                
                val response = runBlocking(Dispatchers.Main) {
                    proxy.handleCtapRequest(parsedRequest)
                }
                
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