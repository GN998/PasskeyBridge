package com.dev.fido.bridge.core.transport

import android.util.Log
import com.dev.fido.bridge.BuildConfig
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import com.dev.fido.bridge.core.transport.noise.NoiseSession
import com.dev.fido.bridge.core.transport.websocket.TunnelWebsocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

/**
 * Manage transport-layer lifecycle across BLE advertising and WebSocket tunneling.
 *
 * Decouple transport orchestration from upper-level application protocols (e.g., CTAP) by operating
 * purely on encrypted byte streams and delegating protocol-specific payload construction to callbacks.
 */
class TransportManager(
    private val bleAdvertiser: HybridBleAdvertiser
) {
    private val noiseSession = NoiseSession()
    private var tunnelWebsocket: TunnelWebsocket? = null
    private val transportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var frameChannel: Channel<ByteArray>? = null
    
    var onStatusUpdate: ((String) -> Unit)? = null

    /**
     * Start a hybrid transport session using ephemeral routing IDs and Noise KNpsk0 handshake parameters.
     *
     * Accept suspending callbacks for request processing to ensure network message processing thread
     * remains unblocked while asynchronous security operations execute.
     */
    fun startSession(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int = BuildConfig.TUNNEL_ID,
        onPostHandshakePayloadProvider: () -> ByteArray,
        onRequestReceived: suspend (ByteArray) -> ByteArray
    ) {
        val uncompressedPeerKey = CryptoHelper.decompressECKey(peerPublicKey)
        noiseSession.setPeerPublicKey(uncompressedPeerKey)

        val ephemeralTunnelId = CryptoHelper.endif(
            ikm = psk,
            salt = ByteArray(0),
            info = byteArrayOf(2, 0, 0, 0),
            length = 16
        )

        // Close any existing channel before initiating a new session to prevent stale frame consumption.
        frameChannel?.close()

        // Create an unbounded channel to buffer incoming WebSocket frame payloads.
        // Enforce strict FIFO processing order to satisfy CTAP 2.3 §11.5.1.2 requirements
        // for monotonically increasing AES-GCM nonces and prevent decryption failures.
        val channel = Channel<ByteArray>(Channel.UNLIMITED)
        frameChannel = channel

        // Spawn a dedicated consumer coroutine to process frames sequentially on the channel,
        // isolating cipher state mutation from concurrent network socket callbacks.
        transportScope.launch {
            for (encryptedFrame in channel) {
                try {
                    if (!noiseSession.isHandshakeComplete) {
                        Log.d("TransportManager", "Received ClientHello, processing Noise KNpsk0 handshake...")
                        val serverHello = noiseSession.processClientHelloAndGenerateServerHello(encryptedFrame)
                        tunnelWebsocket?.sendFrame(serverHello)
                        
                        val msg = "Noise KNpsk0 Handshake Success!\nSent Post-Handshake Message."
                        Log.d("TransportManager", msg)

                        onStatusUpdate?.invoke(msg)
                        
                        // Obtain upper-layer protocol payload via callback to maintain transport decoupling
                        val postHandshakeMsg = onPostHandshakePayloadProvider()
                        tunnelWebsocket?.sendFrame(noiseSession.encrypt(postHandshakeMsg))
                    } else {
                        val decrypted = noiseSession.decrypt(encryptedFrame)
                        if (decrypted.isEmpty()) continue
                        
                        val frameType = decrypted[0].toInt() and 0xFF
                        when (frameType) {
                            0x01 -> {
                                val logMsg = "Received CTAP Request!"
                                Log.d("TransportManager", logMsg)
                                onStatusUpdate?.invoke(logMsg)
                                
                                val ctapReq = decrypted.copyOfRange(1, decrypted.size)
                                // Await asynchronous request handler without blocking background threads
                                val response = onRequestReceived(ctapReq)
                                val framedResponse = byteArrayOf(0x01) + response
                                tunnelWebsocket?.sendFrame(noiseSession.encrypt(framedResponse))
                            }
                            0x00 -> Log.d("TransportManager", "Received Control/ACK message")
                            else -> Log.d("TransportManager", "Received Unknown Frame Type: 0x${frameType.toString(16)}")
                        }
                    }
                } catch (e: Exception) {
                    val msg = "Frame Error: ${e.message}"
                    Log.e("TransportManager", msg, e)
                    onStatusUpdate?.invoke(msg)
                }
            }
        }

        tunnelWebsocket = TunnelWebsocket(
            domainId = domainId,
            ephemeralTunnelId = ephemeralTunnelId,
            onConnected = { routingId ->
                // Derive advertisement seed and Noise PSK using CTAP2 hybrid specifications
                val advertPlaintext = CryptoHelper.generateSeed(routingId, domainId)

                val eidKey = CryptoHelper.endif(
                    ikm = psk,
                    salt = ByteArray(0),
                    info = byteArrayOf(1, 0, 0, 0),
                    length = 64
                )

                val finalEid = CryptoHelper.generateEid(eidKey, advertPlaintext)

                val noisePsk = CryptoHelper.endif(
                    ikm = psk,
                    salt = advertPlaintext,
                    info = byteArrayOf(3, 0, 0, 0),
                    length = 32
                )

                // Initialize Noise state machine and initiate BLE advertisement for proximity binding
                noiseSession.initializeHandshake(noisePsk)

                bleAdvertiser.startAdvertising(finalEid)
                onStatusUpdate?.invoke("BLE Advertising Started with 20-byte EID...")
            },
            onMessageReceived = { encryptedFrame ->
                // Pass raw frame into the sequential processing pipeline immediately upon WebSocket receipt.
                frameChannel?.trySend(encryptedFrame)
            },
            onStatusUpdate = { status ->
                onStatusUpdate?.invoke(status)
            }
        )
        tunnelWebsocket?.connect()
    }

    /**
     * Terminate active transport operations including BLE advertising and WebSocket socket connections.
     */
    fun stopSession() {
        frameChannel?.close()
        frameChannel = null
        bleAdvertiser.stopAdvertising()
        tunnelWebsocket?.close()
    }
}
