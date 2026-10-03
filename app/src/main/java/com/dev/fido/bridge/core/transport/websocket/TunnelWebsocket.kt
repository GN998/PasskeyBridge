package com.dev.fido.bridge.core.transport.websocket

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.util.concurrent.TimeUnit

/**
 * Manage asynchronous WebSocket connection to caBLE v2 tunnel servers.
 *
 * Transport binary Noise frames between client platforms and authenticators via intermediate
 * relay servers, handling `X-Cable-Routing-Id` header extraction during handshake.
 */
class TunnelWebsocket(
    private val endpoint: CableTunnelEndpoint,
    private val onConnected: (routingId: ByteArray) -> Unit,
    private val onMessageReceived: (ByteArray) -> Unit,
    private val onStatusUpdate: ((String) -> Unit)? = null
) {
    companion object {
        private const val TAG = "TunnelWebsocket"
    }

    /**
     * Legacy constructor for backwards compatibility with QR-initiated workflows.
     */
    constructor(
        domainId: Int,
        ephemeralTunnelId: ByteArray,
        onConnected: (routingId: ByteArray) -> Unit,
        onMessageReceived: (ByteArray) -> Unit,
        onStatusUpdate: ((String) -> Unit)? = null
    ) : this(
        endpoint = CableTunnelEndpoint.NewTunnel(domainId, ephemeralTunnelId),
        onConnected = onConnected,
        onMessageReceived = onMessageReceived,
        onStatusUpdate = onStatusUpdate
    )

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    private var webSocket: WebSocket? = null

    /**
     * Initiate WebSocket handshake with the configured [CableTunnelEndpoint].
     */
    fun connect() {
        val url = endpoint.buildUrl()
        val headers = endpoint.buildHeaders()

        val requestBuilder = Request.Builder().url(url)
        headers.forEach { (key, value) ->
            requestBuilder.header(key, value)
        }

        Log.d(TAG, "Connecting to caBLE WebSocket URL: $url")

        webSocket = client.newWebSocket(requestBuilder.build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                val statusMsg = "WebSocket Tunnel Connected ($url)"
                Log.d(TAG, statusMsg)
                onStatusUpdate?.invoke(statusMsg)

                // Extract 3-byte Routing ID from HTTP response header "X-Cable-Routing-Id"
                val routingIdHeader = response.header("X-Cable-Routing-Id") ?: response.header("x-cable-routing-id")
                val routingId = parseRoutingIdHeader(routingIdHeader)
                onConnected(routingId)
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                onMessageReceived(bytes.toByteArray())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                Log.w(TAG, "Received unsupported text frame from tunnel server, dropping payload.")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                val errorMsg = "WebSocket failure: ${t.message}"
                Log.e(TAG, errorMsg, t)
                onStatusUpdate?.invoke(errorMsg)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WebSocket connection closed cleanly: $code / $reason")
                onStatusUpdate?.invoke("WebSocket Closed ($code)")
            }
        })
    }

    /**
     * Send binary frame over active WebSocket connection.
     *
     * @param data Raw byte array frame payload.
     */
    fun sendFrame(data: ByteArray) {
        webSocket?.send(ByteString.of(*data))
    }

    /**
     * Close WebSocket connection gracefully.
     */
    fun close() {
        webSocket?.close(1000, "Client initiated closure")
        webSocket = null
    }

    /**
     * Parse 3-byte routing identifier from response header string.
     */
    private fun parseRoutingIdHeader(routingIdHeader: String?): ByteArray {
        if (routingIdHeader.isNullOrEmpty()) {
            return ByteArray(3)
        }
        return try {
            val cleanHex = routingIdHeader.trim()
            if (cleanHex.length == 6) {
                val result = ByteArray(3)
                for (i in 0 until 3) {
                    result[i] = cleanHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                }
                result
            } else {
                cleanHex.toByteArray(Charsets.ISO_8859_1).copyOf(3)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse X-Cable-Routing-Id header: '$routingIdHeader'", e)
            ByteArray(3)
        }
    }
}
