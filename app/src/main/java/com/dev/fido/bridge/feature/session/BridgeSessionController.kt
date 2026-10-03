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
import kotlinx.coroutines.runBlocking

/**
 * Coordinate FIDO bridge authentication sessions between transport components and Android Credential Manager.
 */
class BridgeSessionController(
    private val context: Context,
    private val transportManager: TransportManager? = null
) {
    private val proxy = CredentialManagerProxy(context)
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    
    var onStatusUpdate: ((String) -> Unit)? = null

    /**
     * Initialize transport session upon scanning peer QR code parameters.
     *
     * Supply protocol payload provider callback to [TransportManager] so protocol construction
     * remains contained within the CTAP feature layer.
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
        )
    }
}
