package com.dev.fido.bridge.core.transport.websocket

import android.util.Log
import com.dev.fido.bridge.core.security.DomainDerivation
import com.dev.fido.bridge.core.security.hexToByteArray
import com.dev.fido.bridge.core.security.toHex
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.util.concurrent.TimeUnit

class TunnelWebsocket(
    private val domainId: Int,
    private val ephemeralTunnelId: ByteArray,
    private val onConnected: (ByteArray) -> Unit,
    private val onMessageReceived: (ByteArray) -> Unit,
    private val onStatusUpdate: ((String) -> Unit)? = null,
    private val onDisconnected: (() -> Unit)? = null
) {
    companion object {
        // Initialize OkHttpClient lazily so referencing the companion object in Application.onCreate()
        // does not synchronously load the system X509TrustManager and SSLContext on the main thread.
        // Tighten connectTimeout to 10s so OkHttp 4.x route fallback recovers faster when a dual-stack
        // IPv6 route is unreachable, while keeping readTimeout(0) and 5s pings for background survival.
        internal val sharedClient: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .pingInterval(5, TimeUnit.SECONDS)
                .build()
        }

        /**
         * Pre-initialize the OkHttp TLS engine and JCA P-256 curve parameters on a background IO thread
         * during cold start to eliminate classloading and trust-store overhead without blocking the main thread.
         */
        fun warmupLocalCryptoAndTls() {
            CoroutineScope(Dispatchers.IO).launch {
                sharedClient
                CryptoHelper.warmup()
            }
        }
    }

    private var webSocket: WebSocket? = null

    // Track intentional client close so peer TCP resets after receiving the final CTAP response do not trigger false error logs
    @Volatile
    private var isClientClosed = false

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

                // Omit derived tunnel hostname from UI and logs to prevent exposing custom relay infrastructure
                val msg = "WebSocket Tunnel Connected!"
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
                // Reject non-binary WebSocket frames per CTAP 2.3 §11.5.1.1.1; lifecycle callbacks handle cleanup
                Log.w("TunnelWebsocket", "Received unsupported text frame, closing connection.")
                webSocket.close(1003, "Binary frames required")
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                // Acknowledge peer close handshake so the socket transitions to onClosed cleanly
                webSocket.close(code, reason)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                // Notify upper layer when the peer or relay closes the WebSocket without a 0x00 frame
                val msg = "WebSocket Closed ($code)"
                Log.d("TunnelWebsocket", msg)
                onStatusUpdate?.invoke(msg)
                onDisconnected?.invoke()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (isClientClosed) {
                    Log.d("TunnelWebsocket", "WebSocket closed after client-initiated shutdown.")
                    onDisconnected?.invoke()
                    return
                }
                // Redact derived hostname from network exception messages (e.g., DNS resolution failures)
                val sanitizedError = t.message?.replace(domain, "***", ignoreCase = true) ?: "Connection failed"
                val msg = "WebSocket Error: $sanitizedError"
                Log.e("TunnelWebsocket", msg)
                onStatusUpdate?.invoke(msg)
                onDisconnected?.invoke()
            }
        })
    }

    fun sendFrame(data: ByteArray) {
        // Convert ByteArray via Okio extension to avoid redundant array cloning from Kotlin's vararg spread operator
        webSocket?.send(data.toByteString())
    }

    fun close() {
        isClientClosed = true
        webSocket?.close(1000, "Closed by client")
    }

    /**
     * Immediately abort the underlying TCP/TLS call and release socket resources when tearing down
     * an incomplete or superseded session where flushing outbound frames is not required.
     */
    fun cancel() {
        isClientClosed = true
        webSocket?.cancel()
    }
}