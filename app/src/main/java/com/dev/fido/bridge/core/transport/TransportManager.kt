package com.dev.fido.bridge.core.transport

import android.util.Log
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import com.dev.fido.bridge.core.transport.noise.NoiseSession
import com.dev.fido.bridge.core.transport.websocket.TunnelWebsocket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class TransportManager(
    private val bleAdvertiser: HybridBleAdvertiser
) {
    companion object {
        // Pre-serialize immutable post-handshake CBOR payload once to eliminate encoding overhead during handshake
        private val CACHED_POST_HANDSHAKE_MSG: ByteArray by lazy {
            // Share canonical AuthenticatorInfo CBOR map to prevent capability drift between pre-flight and 0x04 GetInfo
            val getInfoBytes = CtapCodec.SimpleCbor.write(AuthenticatorInfo.toCborMap())
            // Advertise only "ctap" support in Key 3 so clients do not send unimplemented typeJSON (0x03) Digital Credentials frames per CTAP 2.3 §11.5
            val postHandshakeMap = mapOf(
                1L to getInfoBytes,
                3L to listOf("ctap")
            )
            CtapCodec.SimpleCbor.write(postHandshakeMap)
        }
    }

    @Volatile
    private var tunnelWebsocket: TunnelWebsocket? = null
    private val transportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    @Volatile
    private var handshakeTimeoutJob: Job? = null

    @Volatile
    var onStatusUpdate: ((String) -> Unit)? = null
    // Notify controller when a transaction finishes or the tunnel closes to decouple control flow from log strings
    @Volatile
    var onSessionTerminated: (() -> Unit)? = null

    /**
     * Atomically clear active session references if owned by [sessionWs] so concurrent
     * callbacks and stopSession() never double-close or leak watchdog jobs.
     */
    private fun clearActiveSession(sessionWs: TunnelWebsocket): Boolean = synchronized(this) {
        if (tunnelWebsocket === sessionWs) {
            handshakeTimeoutJob?.cancel()
            handshakeTimeoutJob = null
            tunnelWebsocket = null
            true
        } else {
            false
        }
    }

    // Synchronize session startup with stopSession() so rapid consecutive scans cancel prior setup coroutines before launching new ones
    @Synchronized
    fun startSession(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int,
        onRequestReceived: suspend (ByteArray) -> ByteArray
    ) {
        // Terminate any lingering WebSocket connection, BLE advertisement, or coroutine job
        // from a prior scan before starting a new hybrid transport session.
        stopSession()

        // Offload session setup from the UI thread while validating and setting the peer public key
        // prior to opening the WebSocket to prevent race conditions with onConnected and avoid socket leaks.
        transportScope.launch {
            // Instantiate a dedicated NoiseSession and busy guard per transport session to prevent cross-session state races
            val sessionNoise = NoiseSession()
            val isProcessingCtap = AtomicBoolean(false)
            try {
                val uncompressedPeerKey = CryptoHelper.decompressECKey(peerPublicKey)
                sessionNoise.prepareSession(uncompressedPeerKey)
            } catch (e: Exception) {
                Log.e("TransportManager", "Invalid peer public key", e)
                onStatusUpdate?.invoke("Error: ${e.message}")
                onSessionTerminated?.invoke()
                return@launch
            }

            val ephemeralTunnelId = CryptoHelper.endif(
                ikm = psk,
                salt = ByteArray(0),
                info = byteArrayOf(2, 0, 0, 0),
                length = 16
            )

            // Pre-derive the 64-byte EID key before connecting so BLE advertising can start immediately upon receiving the routing ID
            val eidKey = CryptoHelper.endif(
                ikm = psk,
                salt = ByteArray(0),
                info = byteArrayOf(1, 0, 0, 0),
                length = 64
            )

            lateinit var sessionWs: TunnelWebsocket

            // Synchronize frame encryption and WebSocket enqueueing under sessionNoise monitor to prevent
            // out-of-order AES-GCM write nonces when reader-thread 0x06 busy replies race with IO-thread CTAP responses.
            fun sendEncryptedFrame(plaintext: ByteArray) {
                synchronized(sessionNoise) {
                    sessionWs.sendFrame(sessionNoise.encrypt(plaintext))
                }
            }

            sessionWs = TunnelWebsocket(
                domainId = domainId,
                ephemeralTunnelId = ephemeralTunnelId,
                onConnected = { routingId ->
                    if (tunnelWebsocket !== sessionWs) return@TunnelWebsocket

                    // 1. Generate the single 16-byte advertPlaintext seed (containing nonce, routingId, domainId)
                    val advertPlaintext = CryptoHelper.generateSeed(routingId, domainId)

                    // 2. Encrypt the EXACT advertPlaintext seed to 20-byte BLE EID using pre-derived eidKey
                    val finalEid = CryptoHelper.generateEid(eidKey, advertPlaintext)

                    // 3. Start BLE advertising immediately before deriving Noise keys or generating P-256 keypairs, and abort the tunnel if the radio is unavailable
                    val bleDispatched = bleAdvertiser.startAdvertising(finalEid) { errorCode ->
                        // Handle asynchronous BLE start failures (e.g., ADVERTISE_FAILED_TOO_MANY_ADVERTISERS)
                        // delivered on the main looper so the tunnel does not hang until the 60s watchdog expires.
                        if (clearActiveSession(sessionWs)) {
                            sessionWs.cancel()
                            onStatusUpdate?.invoke("BLE advertising failed ($errorCode)")
                            onSessionTerminated?.invoke()
                        }
                    }
                    if (!bleDispatched) {
                        if (clearActiveSession(sessionWs)) {
                            onStatusUpdate?.invoke("Failed to start BLE advertising")
                            sessionWs.cancel()
                            onSessionTerminated?.invoke()
                        }
                        return@TunnelWebsocket
                    }
                    onStatusUpdate?.invoke("Connecting...")

                    // 4. Derive 32-byte Noise PSK using the EXACT same advertPlaintext while BLE radio is already broadcasting
                    val noisePsk = CryptoHelper.endif(
                        ikm = psk,
                        salt = advertPlaintext,
                        info = byteArrayOf(3, 0, 0, 0),
                        length = 32
                    )

                    // 5. Initialize Noise KNpsk0 state machine with derived noisePsk
                    sessionNoise.initializeHandshake(noisePsk)

                    // Enforce a 60-second handshake deadline under monitor lock so stopSession() cannot race with watchdog creation
                    synchronized(this@TransportManager) {
                        if (tunnelWebsocket === sessionWs) {
                            handshakeTimeoutJob?.cancel()
                            handshakeTimeoutJob = transportScope.launch {
                                delay(60_000)
                                if (!sessionNoise.isHandshakeComplete && clearActiveSession(sessionWs)) {
                                    Log.w("TransportManager", "Handshake timed out waiting for ClientHello; closing session.")
                                    onStatusUpdate?.invoke("Connection timed out")
                                    bleAdvertiser.stopAdvertising()
                                    sessionWs.cancel()
                                    onSessionTerminated?.invoke()
                                }
                            }
                        }
                    }
                },
                onMessageReceived = { encryptedFrame ->
                    if (tunnelWebsocket !== sessionWs) return@TunnelWebsocket
                    try {
                        if (!sessionNoise.isHandshakeComplete) {
                            Log.d("TransportManager", "Received ClientHello, processing Noise KNpsk0 handshake...")
                            val serverHello = sessionNoise.processClientHelloAndGenerateServerHello(encryptedFrame)

                            // Cancel the handshake watchdog and stop BLE proximity advertising after ClientHello is authenticated
                            synchronized(this@TransportManager) {
                                handshakeTimeoutJob?.cancel()
                                handshakeTimeoutJob = null
                            }
                            bleAdvertiser.stopAdvertising()

                            // Enqueue ServerHello and Post-Handshake frames back-to-back before UI dispatch to minimize round-trip latency
                            sessionWs.sendFrame(serverHello)
                            sendEncryptedFrame(CACHED_POST_HANDSHAKE_MSG)

                            Log.d("TransportManager", "Noise KNpsk0 Handshake Success! Sent Post-Handshake Message.")
                            onStatusUpdate?.invoke("Connected")
                        } else {
                            val decrypted = sessionNoise.decrypt(encryptedFrame)
                            // Treat empty post-handshake frames as a protocol error per CTAP 2.3 §11.5.1.2
                            require(decrypted.isNotEmpty()) { "Empty transport frame is a protocol error" }

                            val frameType = decrypted[0].toInt() and 0xFF
                            when (frameType) {
                                0x01 -> {
                                    // Reject overlapping CTAP commands with ERR_CHANNEL_BUSY (0x06) per CTAP 2.3 §6 to prevent concurrent UI prompts
                                    if (!isProcessingCtap.compareAndSet(false, true)) {
                                        Log.w("TransportManager", "Channel busy; rejecting concurrent CTAP request with 0x06")
                                        sendEncryptedFrame(byteArrayOf(0x01, CtapStatus.ERR_CHANNEL_BUSY))
                                        return@TunnelWebsocket
                                    }

                                    val ctapReq = decrypted.copyOfRange(1, decrypted.size)
                                    // Avoid coercing empty CTAP payloads into a fake 0x00 command byte so logs reflect actual wire data
                                    val commandByte = ctapReq.firstOrNull()
                                    val cmdLabel = commandByte?.let { "0x%02X".format(it) } ?: "EMPTY"
                                    Log.d("TransportManager", "Received CTAP Request ($cmdLabel)!")
                                    onStatusUpdate?.invoke("Verifying...")

                                    // Dispatch CTAP request asynchronously so WebSocket reader thread remains responsive
                                    transportScope.launch {
                                        try {
                                            val response = onRequestReceived(ctapReq)
                                            // Ensure coroutine was not cancelled and session was not replaced while awaiting UI prompt
                                            ensureActive()
                                            if (tunnelWebsocket !== sessionWs) return@launch

                                            val framedResponse = byteArrayOf(0x01) + response
                                            sendEncryptedFrame(framedResponse)

                                            // Close the tunnel cleanly after a MakeCredential (0x01) or GetAssertion (0x02) ceremony
                                            // unless it was a silent pre-flight probe (up=false), where the client expects the tunnel
                                            // to remain open for a subsequent interactive request per CTAP 2.3 §6.2.2.
                                            if (commandByte == 0x01.toByte() || commandByte == 0x02.toByte()) {
                                                val statusByte = response[0]
                                                val isSilentPreFlight = commandByte == 0x02.toByte() &&
                                                    statusByte == CtapStatus.ERR_NO_CREDENTIALS &&
                                                    runCatching {
                                                        val req = CtapCodec.decodeRequest(ctapReq)
                                                        req is com.dev.fido.bridge.core.ctap.model.Ctap2Request.GetAssertion && !req.userPresence
                                                    }.getOrDefault(false)

                                                if (!isSilentPreFlight && clearActiveSession(sessionWs)) {
                                                    val msg = if (statusByte == CtapStatus.SUCCESS) {
                                                        "Completed"
                                                    } else {
                                                        "Cancelled (0x${"%02X".format(statusByte)})"
                                                    }
                                                    onStatusUpdate?.invoke(msg)
                                                    sessionWs.close()
                                                    onSessionTerminated?.invoke()
                                                } else if (statusByte != CtapStatus.SUCCESS) {
                                                    onStatusUpdate?.invoke("Cancelled (0x${"%02X".format(statusByte)})")
                                                }
                                            }
                                        } catch (e: CancellationException) {
                                            throw e
                                        } catch (e: Exception) {
                                            Log.e("TransportManager", "Error processing CTAP request", e)
                                            onStatusUpdate?.invoke("Error: ${e.message}")
                                            // Cancel the underlying WebSocket on fatal CTAP dispatch errors to prevent orphaned keep-alive pings
                                            if (clearActiveSession(sessionWs)) {
                                                sessionWs.cancel()
                                                onSessionTerminated?.invoke()
                                            }
                                        } finally {
                                            isProcessingCtap.set(false)
                                        }
                                    }
                                }
                                0x00 -> {
                                    // Close session cleanly upon receiving client shutdown message (typeShutdown = 0) per CTAP 2.3 §11.5
                                    Log.d("TransportManager", "Received Shutdown message (0x00), closing tunnel.")
                                    bleAdvertiser.stopAdvertising()
                                    if (clearActiveSession(sessionWs)) {
                                        onStatusUpdate?.invoke("Completed")
                                        sessionWs.close()
                                        onSessionTerminated?.invoke()
                                    }
                                }
                                else -> Log.d("TransportManager", "Received Unknown Frame Type: 0x${frameType.toString(16)}")
                            }
                        }
                    } catch (e: Exception) {
                        val msg = "Error: ${e.message}"
                        Log.e("TransportManager", msg, e)
                        bleAdvertiser.stopAdvertising()
                        // Cancel the WebSocket when handshake or frame decryption fails so the tunnel does not remain open indefinitely
                        if (clearActiveSession(sessionWs)) {
                            sessionWs.cancel()
                            onStatusUpdate?.invoke(msg)
                            onSessionTerminated?.invoke()
                        }
                    }
                },
                onStatusUpdate = null,
                onDisconnected = {
                    // Stop BLE advertising and reset session guard via explicit disconnect callback instead of log string matching
                    if (clearActiveSession(sessionWs)) {
                        bleAdvertiser.stopAdvertising()
                        onSessionTerminated?.invoke()
                    }
                }
            )
            // Guard WebSocket assignment and connection against concurrent stopSession() calls on the main thread
            // so a cancelled setup coroutine cannot escape teardown and leak a background socket.
            synchronized(this@TransportManager) {
                ensureActive()
                tunnelWebsocket = sessionWs
                sessionWs.connect()
            }
        }
    }

    @Synchronized
    fun stopSession() {
        handshakeTimeoutJob?.cancel()
        handshakeTimeoutJob = null
        transportScope.coroutineContext.cancelChildren()
        bleAdvertiser.stopAdvertising()
        tunnelWebsocket?.cancel()
        tunnelWebsocket = null
    }
}