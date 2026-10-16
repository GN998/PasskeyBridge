package com.dev.fido.bridge.core.transport.websocket

import android.util.Log
import com.dev.fido.bridge.core.security.DomainDerivation
import com.dev.fido.bridge.core.security.hexToByteArray
import com.dev.fido.bridge.core.security.toHex
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.util.concurrent.TimeUnit

class TunnelWebsocket(
    private val domainId: Int,
    private val ephemeralTunnelId: ByteArray,
    private val onConnected: (ByteArray) -> Unit,
    private val onMessageReceived: (ByteArray) -> Unit,
    private val onStatusUpdate: ((String) -> Unit)? = null
) {
    companion object {
        // Share a single OkHttpClient instance across sessions to reuse connection pools and thread dispatchers.
        // Enable 15-second ping interval to prevent idle tunnel drops while user interacts with biometric/PIN prompts.
        private val sharedClient: OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .pingInterval(15, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }

    private var webSocket: WebSocket? = null

    fun connect() {
        val domain = DomainDerivation.deriveDomainForTunnelId(domainId)
        val tunnelIdHex = ephemeralTunnelId.toHex()

        val url = "wss://$domain/cable/new/$tunnelIdHex"

        val request = Request.Builder()
            .url(url)
            .header("Sec-WebSocket-Protocol", "fido.cable")
            .build()

        webSocket = sharedClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                // Verify the negotiated WebSocket subprotocol matches "fido.cable" per CTAP 2.3 §11.5.1.1.1
                val negotiatedSubprotocol = response.header("Sec-WebSocket-Protocol")
                if (negotiatedSubprotocol != null && !negotiatedSubprotocol.equals("fido.cable", ignoreCase = true)) {
                    Log.w("TunnelWebsocket", "Unexpected WebSocket subprotocol: $negotiatedSubprotocol")
                }

                val msg = "WebSocket Tunnel Connected to $domain!"
                Log.d("TunnelWebsocket", msg)
                onStatusUpdate?.invoke(msg)

                // Extract 3-byte Routing ID from HTTP response header "X-Cable-Routing-Id"
                val routingIdHeader = response.header("X-Cable-Routing-Id")
                val routingId = try {
                    val trimmed = routingIdHeader?.trim()
                    when {
                        trimmed.isNullOrEmpty() -> ByteArray(3)
                        trimmed.length == 6 -> trimmed.hexToByteArray()
                        else -> trimmed.toByteArray(Charsets.ISO_8859_1).copyOf(3)
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