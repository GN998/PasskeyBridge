package com.dev.fido.bridge.client.transport.websocket

import android.util.Log
import com.dev.fido.bridge.core.security.DomainDerivation
import com.dev.fido.bridge.core.security.toHex
import com.dev.fido.bridge.core.transport.websocket.TunnelWebsocket
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * WebSocket client for the caBLE v2 / PXP §6.1.1 client platform endpoint (/cable/connect/<routingId>/<tunnelId>).
 */
class ClientTunnelWebsocket(
    private val domain: String,
    private val routingId: ByteArray,
    private val tunnelId: ByteArray,
    private val onConnected: () -> Unit,
    private val onMessageReceived: (ByteArray) -> Unit,
    private val onStatusUpdate: ((String) -> Unit)? = null,
    private val onDisconnected: (() -> Unit)? = null
) {
    private var webSocket: WebSocket? = null

    @Volatile
    private var isClientClosed = false

    fun connect() {
        val routingIdHex = routingId.toHex(uppercase = false)
        val tunnelIdHex = tunnelId.toHex(uppercase = false)
        val url = "wss://$domain/cable/connect/$routingIdHex/$tunnelIdHex"

        val request = Request.Builder()
            .url(url)
            .header("Sec-WebSocket-Protocol", "fido.cable")
            .build()

        webSocket = TunnelWebsocket.sharedClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                val negotiatedSubprotocol = response.header("Sec-WebSocket-Protocol")
                if (negotiatedSubprotocol != null && !negotiatedSubprotocol.equals("fido.cable", ignoreCase = true)) {
                    Log.w("ClientTunnelWs", "Unexpected WebSocket subprotocol: $negotiatedSubprotocol")
                }
                Log.d("ClientTunnelWs", "Client WebSocket Tunnel Connected!")
                onStatusUpdate?.invoke("Tunnel connected, performing Noise handshake...")
                onConnected()
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                onMessageReceived(bytes.toByteArray())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                Log.w("ClientTunnelWs", "Received unsupported text frame, closing connection.")
                webSocket.close(1003, "Binary frames required")
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(code, reason)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d("ClientTunnelWs", "Client WebSocket Closed ($code)")
                onDisconnected?.invoke()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (isClientClosed) {
                    onDisconnected?.invoke()
                    return
                }
                val sanitizedError = t.message?.replace(domain, "***", ignoreCase = true) ?: "Connection failed"
                val msg = "WebSocket Error: $sanitizedError"
                Log.e("ClientTunnelWs", msg)
                onStatusUpdate?.invoke(msg)
                onDisconnected?.invoke()
            }
        })
    }

    fun sendFrame(data: ByteArray) {
        webSocket?.send(data.toByteString())
    }

    fun close() {
        isClientClosed = true
        webSocket?.close(1000, "Closed by client")
    }

    fun cancel() {
        isClientClosed = true
        webSocket?.cancel()
    }
}