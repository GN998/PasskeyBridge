package com.dev.fido.bridge.feature.session

import android.content.Context
import android.util.Log
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.codec.CtapCodecException
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.proxy.CredentialManagerProxy
import com.dev.fido.bridge.core.transport.TransportManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class BridgeSessionController(
    context: Context,
    // Require non-null TransportManager to eliminate redundant safe-call operators
    private val transportManager: TransportManager
) {
    private val proxy = CredentialManagerProxy(context)
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    var onStatusUpdate: ((String) -> Unit)? = null
    var onSessionTerminated: (() -> Unit)? = null

    fun onQrCodeScanned(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int
    ) {
        transportManager.onStatusUpdate = { status ->
            scope.launch { onStatusUpdate?.invoke(status) }
        }
        transportManager.onSessionTerminated = {
            scope.launch { onSessionTerminated?.invoke() }
        }

        transportManager.startSession(peerPublicKey, psk, domainId) { rawCtapRequest ->
            try {
                val parsedRequest = CtapCodec.decodeRequest(rawCtapRequest)

                // Switch to Main dispatcher non-blockingly for Android CredentialManager UI interaction
                val response = withContext(Dispatchers.Main) {
                    proxy.handleCtapRequest(parsedRequest)
                }

                CtapCodec.encodeResponse(response)
            } catch (e: CancellationException) {
                // Rethrow cancellation exceptions to respect structured concurrency lifecycles
                throw e
            } catch (e: CtapCodecException) {
                // Preserve specific CTAP status code (e.g., ERR_INVALID_COMMAND vs ERR_INVALID_CBOR)
                Log.e("SessionController", "CTAP codec exception: 0x${"%02X".format(e.statusCode)}", e)
                byteArrayOf(e.statusCode)
            } catch (e: Exception) {
                Log.e("SessionController", "Unhandled exception during CTAP processing", e)
                byteArrayOf(CtapStatus.ERR_OPERATION_DENIED)
            }
        }
    }

    // Release BLE advertising, WebSocket tunnel, and child coroutine jobs while keeping scope reusable
    fun stopSession() {
        transportManager.stopSession()
        scope.coroutineContext.cancelChildren()
    }
}