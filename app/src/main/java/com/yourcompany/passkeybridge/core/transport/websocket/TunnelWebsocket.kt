package com.yourcompany.passkeybridge.core.transport.websocket

import com.yourcompany.passkeybridge.BuildConfig
import android.util.Log
import com.yourcompany.passkeybridge.core.security.DomainDerivation
import okhttp3.*
import okio.ByteString

class TunnelWebsocket(
    private val tunnelId: Int = BuildConfig.TUNNEL_ID,
    private val onMessageReceived: (ByteArray) -> Unit
) {
    private val client = OkHttpClient()
    private var webSocket: WebSocket? = null

    fun connect() {
        val domain = DomainDerivation.deriveDomainForTunnelId(tunnelId)
        val url = "wss://$domain/cable/connect"

        val request = Request.Builder().url(url).build()
        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.d("TunnelWebsocket", "WebSocket Tunnel Connected to $domain")
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                onMessageReceived(bytes.toByteArray())
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e("TunnelWebsocket", "WebSocket Error: ${t.message}")
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