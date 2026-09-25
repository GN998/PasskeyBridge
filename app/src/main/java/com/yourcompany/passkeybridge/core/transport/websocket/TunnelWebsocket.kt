package com.yourcompany.passkeybridge.core.transport.websocket

import android.util.Log
import com.yourcompany.passkeybridge.core.security.DomainDerivation
import okhttp3.*
import okio.ByteString
import java.util.concurrent.TimeUnit

class TunnelWebsocket(
    private val domainId: Int,
    private val ephemeralTunnelId: ByteArray,
    private val onConnected: (ByteArray) -> Unit,
    private val onMessageReceived: (ByteArray) -> Unit,
    private val onStatusUpdate: ((String) -> Unit)? = null
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

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
                
                // Extract 3-byte Routing ID from HTTP response header "X-Cable-Routing-Id"
                val routingIdHeader = response.header("X-Cable-Routing-Id") ?: response.header("x-cable-routing-id")
                val routingId = try {
                    if (!routingIdHeader.isNullOrEmpty()) {
                        val routingIdHex = routingIdHeader.trim()
                        if (routingIdHex.length == 6) {
                            val bytes = ByteArray(3)
                            for (i in 0 until 3) {
                                bytes[i] = routingIdHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                            }
                            bytes
                        } else {
                            routingIdHex.toByteArray(Charsets.ISO_8859_1).copyOf(3)
                        }
                    } else {
                        ByteArray(3) // Fallback empty routing ID
                    }
                } catch (e: Exception) {
                    Log.w("TunnelWebsocket", "Failed to parse X-Cable-Routing-Id header: $routingIdHeader", e)
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
                Log.e("TunnelWebsocket", msg, t)
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
