package com.yourcompany.passkeybridge.core.transport.websocket

import android.util.Log
import com.yourcompany.passkeybridge.core.security.DomainDerivation
import okhttp3.*
import okio.ByteString

class TunnelWebsocket(
    private val domainId: Int,
    private val ephemeralTunnelId: ByteArray,
    private val onConnected: (ByteArray) -> Unit, // Fix: Added connection callback to receive Routing ID
    private val onMessageReceived: (ByteArray) -> Unit,
    private val onStatusUpdate: ((String) -> Unit)? = null
) {
    private val client = OkHttpClient()
    private var webSocket: WebSocket? = null

    fun connect() {
        val domain = DomainDerivation.deriveDomainForTunnelId(domainId)
        val tunnelIdHex = ephemeralTunnelId.joinToString("") { "%02x".format(it) }
        
        val url = "wss://$domain/cable/new/$tunnelIdHex"

        val request = Request.Builder()
            .url(url)
            .header("Sec-WebSocket-Protocol", "fido.cable")
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                val msg = "WebSocket Tunnel Connected to $domain!"
                Log.d("TunnelWebsocket", msg)
                onStatusUpdate?.invoke(msg)
                
                // Fix: Extract Routing ID from headers
                val routingIdHex = response.header("X-Cable-Routing-Id")
                val routingId = try {
                    if (routingIdHex != null) {
                        val bytes = ByteArray(routingIdHex.length / 2)
                        for (i in bytes.indices) {
                            bytes[i] = routingIdHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                        }
                        bytes
                    } else {
                        ByteArray(3) // Fallback
                    }
                } catch (e: Exception) {
                    ByteArray(3)
                }
                onConnected(routingId)
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                onMessageReceived(bytes.toByteArray())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                Log.w("TunnelWebsocket", "Received unsupported text frame, dropping.")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                val msg = "WebSocket Error: ${t.message}"
                Log.e("TunnelWebsocket", msg)
                onStatusUpdate?.invoke(msg)
            }
        })
    }

    fun sendFrame(data: ByteArray) {
        webSocket?.send(ByteString.of(*data))
    }

    fun close() {
        webSocket?.close(1000, "Closed by client")
    }
}