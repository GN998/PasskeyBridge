package com.dev.fido.bridge.feature.session

import android.content.Context
import android.util.Log
import com.dev.fido.bridge.BuildConfig
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.proxy.CredentialManagerProxy
import com.dev.fido.bridge.core.transport.TransportManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Coordinate FIDO bridge authentication sessions between transport components and Android Credential Manager.
 */
class BridgeSessionController(
    private val context: Context,
    private val proxy: CredentialManagerProxy = CredentialManagerProxy(context),
    private val transportManager: TransportManager? = null
) {
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    
    var onStatusUpdate: ((String) -> Unit)? = null

    /**
     * Initialize transport session upon scanning peer QR code parameters.
     *
     * Delegate CTAP parsing and Credential Manager invocation to non-blocking coroutine dispatchers,
     * removing thread blocking while supporting constructor dependency injection for testing.
     */
    fun onQrCodeScanned(peerPublicKey: ByteArray, psk: ByteArray, domainId: Int = BuildConfig.TUNNEL_ID) {
        transportManager?.onStatusUpdate = { status ->
            scope.launch { onStatusUpdate?.invoke(status) }
        }

        transportManager?.startSession(
            peerPublicKey = peerPublicKey,
            psk = psk,
            domainId = domainId,
            onPostHandshakePayloadProvider = {
                // Supply CTAP2 post-handshake metadata directly from CTAP codec
                CtapCodec.buildPostHandshakePayload()
            },
            onRequestReceived = { rawCtapRequest ->
                // Switch off the calling thread to process request decoding and response encoding on background workers
                withContext(Dispatchers.Default) {
                    var responseBytes = byteArrayOf(CtapStatus.ERR_OPERATION_DENIED)
                    
                    try {
                        val parsedRequest = CtapCodec.decodeRequest(rawCtapRequest)
                        
                        // Invoke CredentialManager proxy as a suspending function to avoid blocking main thread UI loop
                        val response = proxy.handleCtapRequest(parsedRequest)
                        
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
        )
    }

    /**
     * Stop active transport sessions and release underlying network and Bluetooth resources.
     */
    fun stopSession() {
        transportManager?.stopSession()
    }
}
