package com.dev.fido.bridge.core.transport

import android.util.Log
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.hybrid.StateAssistedCodec
import com.dev.fido.bridge.core.security.LinkStore
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

    private val noiseSession = NoiseSession()
    @Volatile
    private var tunnelWebsocket: TunnelWebsocket? = null
    private val transportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var handshakeTimeoutJob: Job? = null

    var onStatusUpdate: ((String) -> Unit)? = null
    // Notify controller when a transaction finishes or the tunnel closes to decouple control flow from log strings
    var onSessionTerminated: (() -> Unit)? = null

    // Support suspending callback to prevent blocking OkHttp reader thread during UI credential prompts
    fun startSession(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int,
        supportsStateAssisted: Boolean = false,
        onRequestReceived: suspend (ByteArray) -> ByteArray
    ) {
        // Terminate any lingering WebSocket connection, BLE advertisement, or coroutine job
        // from a prior scan before starting a new hybrid transport session.
        stopSession()

        val uncompressedPeerKey = CryptoHelper.decompressECKey(peerPublicKey)
        noiseSession.setPeerPublicKey(uncompressedPeerKey)

        val ephemeralTunnelId = CryptoHelper.endif(
            ikm = psk,
            salt = ByteArray(0),
            info = byteArrayOf(2, 0, 0, 0),
            length = 16
        )

        lateinit var sessionWs: TunnelWebsocket
        sessionWs = TunnelWebsocket(
            domainId = domainId,
            ephemeralTunnelId = ephemeralTunnelId,
            onConnected = { routingId ->
                if (tunnelWebsocket !== sessionWs) return@TunnelWebsocket

                // 1. Generate the single 16-byte advertPlaintext seed (containing nonce, routingId, domainId)
                val advertPlaintext = CryptoHelper.generateSeed(routingId, domainId)

                // 2. Derive 64-byte eidKey from qrSecret (psk)
                val eidKey = CryptoHelper.endif(
                    ikm = psk,
                    salt = ByteArray(0),
                    info = byteArrayOf(1, 0, 0, 0),
                    length = 64
                )

                // 3. Encrypt the EXACT advertPlaintext seed to 20-byte BLE EID
                val finalEid = CryptoHelper.generateEid(eidKey, advertPlaintext)

                // 4. Derive 32-byte Noise PSK using the EXACT same advertPlaintext
                val noisePsk = CryptoHelper.endif(
                    ikm = psk,
                    salt = advertPlaintext,
                    info = byteArrayOf(3, 0, 0, 0),
                    length = 32
                )

                // 5. Initialize Noise KNpsk0 state machine with derived noisePsk
                noiseSession.initializeHandshake(noisePsk)

                // 6. Start BLE advertising with finalEid
                bleAdvertiser.startAdvertising(finalEid)
                onStatusUpdate?.invoke("BLE Advertising Started with 20-byte EID...")

                // Enforce a 60-second handshake deadline to reclaim the WebSocket and URI guard if a scanned QR code is stale
                scheduleHandshakeWatchdog(sessionWs)
            },
            onMessageReceived = { encryptedFrame ->
                handleIncomingTunnelFrame(
                    sessionWs = sessionWs,
                    encryptedFrame = encryptedFrame,
                    handshakeLabel = "KNpsk0",
                    uncompressedQrPeerKey = if (supportsStateAssisted) uncompressedPeerKey else null,
                    onRequestReceived = onRequestReceived
                )
            },
            onStatusUpdate = { status ->
                if (tunnelWebsocket === sessionWs) {
                    onStatusUpdate?.invoke(status)
                }
            },
            onDisconnected = {
                // Stop BLE advertising and reset session guard via explicit disconnect callback instead of log string matching
                if (tunnelWebsocket === sessionWs) {
                    handshakeTimeoutJob?.cancel()
                    bleAdvertiser.stopAdvertising()
                    tunnelWebsocket = null
                    onSessionTerminated?.invoke()
                }
            }
        )
        tunnelWebsocket = sessionWs
        sessionWs.connect()
    }

    /**
     * Start a state-assisted (QR-less) hybrid session over `/cable/contact/<contact_id>` per CTAP 2.3 §11.5.2 and PXP §5.3.2.
     */
    fun startStateAssistedSession(
        contactId: String,
        initialClientPayloadHex: String?,
        domainId: Int,
        onRequestReceived: suspend (ByteArray) -> ByteArray
    ) {
        stopSession()

        var handshakeInitialized = false

        fun initializeProximityAndNoise(payloadHex: String): Boolean {
            if (handshakeInitialized) return true
            val parsed = StateAssistedCodec.parseClientPayloadHex(payloadHex)
            if (parsed == null) {
                onStatusUpdate?.invoke("Error: Invalid X-caBLE-Client-Payload CBOR.")
                return false
            }
            val linkSecret = LinkStore.findLinkSecret(parsed.linkId)
            if (linkSecret == null) {
                onStatusUpdate?.invoke("Error: Unrecognized Link ID in client payload.")
                return false
            }

            // 1. Derive 64-byte EID key from linkSecret and 16-byte clientNonce per PXP §5.3.2
            val eidKey = CryptoHelper.endif(
                ikm = linkSecret,
                salt = parsed.clientNonce,
                info = byteArrayOf(1, 0, 0, 0),
                length = 64
            )

            // 2. Generate 16-byte state-assisted advertisement plaintext (zero flags byte + 15-byte random nonce)
            val advertPlaintext = CryptoHelper.generateStateAssistedSeed()

            // 3. Encrypt advertisement plaintext into 20-byte BLE EID
            val finalEid = CryptoHelper.generateEid(eidKey, advertPlaintext)

            // 4. Derive 32-byte Noise PSK from linkSecret and advertPlaintext per PXP §5.3.2
            val noisePsk = CryptoHelper.endif(
                ikm = linkSecret,
                salt = advertPlaintext,
                info = byteArrayOf(3, 0, 0, 0),
                length = 32
            )

            // 5. Initialize Noise NKpsk0 responder state machine and start BLE proximity advertising
            noiseSession.initializeStateAssistedHandshake(
                psk = noisePsk,
                localStaticPubKeyBytes = LinkStore.getAuthenticatorPublicKeyBytes(),
                localStaticPrivateKey = LinkStore.getAuthenticatorPrivateKey()
            )
            handshakeInitialized = true

            bleAdvertiser.startAdvertising(finalEid)
            val flowHint = if (parsed.operationHint == "mc") "MakeCredential" else "GetAssertion"
            onStatusUpdate?.invoke("State-assisted ($flowHint): BLE Advertising Started...")
            return true
        }

        // Start BLE proximity advertising immediately if the WebPush wakeup already provided the decrypted client payload
        if (!initialClientPayloadHex.isNullOrBlank()) {
            if (!initializeProximityAndNoise(initialClientPayloadHex)) {
                onSessionTerminated?.invoke()
                return
            }
        }

        lateinit var sessionWs: TunnelWebsocket
        sessionWs = TunnelWebsocket(
            domainId = domainId,
            ephemeralTunnelId = ByteArray(16),
            contactId = contactId,
            onClientPayloadReceived = { headerPayloadHex ->
                if (tunnelWebsocket !== sessionWs) return@TunnelWebsocket
                if (!handshakeInitialized) {
                    if (headerPayloadHex.isNullOrBlank() || !initializeProximityAndNoise(headerPayloadHex)) {
                        Log.e("TransportManager", "Missing or invalid X-caBLE-Client-Payload on contact tunnel")
                        sessionWs.close()
                        tunnelWebsocket = null
                        onSessionTerminated?.invoke()
                    }
                }
            },
            onConnected = {
                if (tunnelWebsocket !== sessionWs) return@TunnelWebsocket
                scheduleHandshakeWatchdog(sessionWs)
            },
            onMessageReceived = { encryptedFrame ->
                handleIncomingTunnelFrame(
                    sessionWs = sessionWs,
                    encryptedFrame = encryptedFrame,
                    handshakeLabel = "NKpsk0",
                    uncompressedQrPeerKey = null,
                    onRequestReceived = onRequestReceived
                )
            },
            onStatusUpdate = { status ->
                if (tunnelWebsocket === sessionWs) {
                    onStatusUpdate?.invoke(status)
                }
            },
            onDisconnected = {
                if (tunnelWebsocket === sessionWs) {
                    handshakeTimeoutJob?.cancel()
                    bleAdvertiser.stopAdvertising()
                    tunnelWebsocket = null
                    onSessionTerminated?.invoke()
                }
            }
        )
        tunnelWebsocket = sessionWs
        sessionWs.connect()
    }

    private fun scheduleHandshakeWatchdog(sessionWs: TunnelWebsocket) {
        handshakeTimeoutJob?.cancel()
        handshakeTimeoutJob = transportScope.launch {
            delay(60_000)
            if (tunnelWebsocket === sessionWs && !noiseSession.isHandshakeComplete) {
                Log.w("TransportManager", "Handshake timed out waiting for ClientHello; closing session.")
                onStatusUpdate?.invoke("Handshake timed out. Please try again.")
                bleAdvertiser.stopAdvertising()
                sessionWs.close()
                tunnelWebsocket = null
                onSessionTerminated?.invoke()
            }
        }
    }

    private fun handleIncomingTunnelFrame(
        sessionWs: TunnelWebsocket,
        encryptedFrame: ByteArray,
        handshakeLabel: String,
        uncompressedQrPeerKey: ByteArray?,
        onRequestReceived: suspend (ByteArray) -> ByteArray
    ) {
        if (tunnelWebsocket !== sessionWs) return
        try {
            if (!noiseSession.isHandshakeComplete) {
                Log.d("TransportManager", "Received ClientHello, processing Noise $handshakeLabel handshake...")
                // Cancel the handshake watchdog and stop BLE proximity advertising once the peer responds
                handshakeTimeoutJob?.cancel()
                bleAdvertiser.stopAdvertising()

                val serverHello = noiseSession.processClientHelloAndGenerateServerHello(encryptedFrame)
                val encryptedPostHandshake = noiseSession.encrypt(CACHED_POST_HANDSHAKE_MSG)

                // Enqueue ServerHello and Post-Handshake frames back-to-back before UI dispatch to minimize round-trip latency
                sessionWs.sendFrame(serverHello)
                sessionWs.sendFrame(encryptedPostHandshake)

                val msg = "Noise $handshakeLabel Handshake Success!\nSent Post-Handshake Message."
                Log.d("TransportManager", msg)
                onStatusUpdate?.invoke(msg)

                // Send typeUpdate (0x02) linking frame after post-handshake whenever the QR peer supports state-assisted transactions.
                // Decouple desktop linking from current push registration state so the client platform always persists the Contact ID.
                if (uncompressedQrPeerKey != null) {
                    try {
                        val updateFrame = LinkStore.createLinkAndBuildUpdateFrame(
                            qrPeerUncompressedPubKey = uncompressedQrPeerKey,
                            handshakeHash = noiseSession.handshakeHash
                        )
                        sessionWs.sendFrame(noiseSession.encrypt(updateFrame))
                        Log.d("TransportManager", "Sent 0x02 UpdateMessage with state-assisted linking data")
                        onStatusUpdate?.invoke("Sent QR-less Linking Data (0x02) to desktop.")
                    } catch (e: Exception) {
                        Log.w("TransportManager", "Failed to send state-assisted UpdateMessage", e)
                    }
                }
            } else {
                val decrypted = noiseSession.decrypt(encryptedFrame)
                // Treat empty post-handshake frames as a protocol error per CTAP 2.3 §11.5.1.2
                require(decrypted.isNotEmpty()) { "Empty transport frame is a protocol error" }

                val frameType = decrypted[0].toInt() and 0xFF
                when (frameType) {
                    0x01 -> {
                        val ctapReq = decrypted.copyOfRange(1, decrypted.size)
                        val commandByte = if (ctapReq.isNotEmpty()) ctapReq[0] else 0x00.toByte()
                        val logMsg = "Received CTAP Request (0x${"%02X".format(commandByte)})!"
                        Log.d("TransportManager", logMsg)
                        onStatusUpdate?.invoke(logMsg)

                        // Dispatch CTAP request asynchronously so WebSocket reader thread remains responsive
                        transportScope.launch {
                            try {
                                val response = onRequestReceived(ctapReq)
                                // Ensure coroutine was not cancelled and session was not replaced while awaiting UI prompt
                                ensureActive()
                                if (tunnelWebsocket !== sessionWs) return@launch

                                val framedResponse = byteArrayOf(0x01) + response
                                sessionWs.sendFrame(noiseSession.encrypt(framedResponse))

                                // Notify UI when MakeCredential (0x01) or GetAssertion (0x02) transaction completes.
                                // Defer onSessionTerminated until peer sends 0x00 Shutdown or closes WebSocket
                                // so activeFidoUri remains guarded while the tunnel is still open.
                                if (commandByte == 0x01.toByte() || commandByte == 0x02.toByte()) {
                                    val statusByte = response[0]
                                    if (statusByte == CtapStatus.SUCCESS) {
                                        onStatusUpdate?.invoke("CTAP Transaction Complete.")
                                    } else {
                                        onStatusUpdate?.invoke("CTAP Rejected (Status: 0x${"%02X".format(statusByte)}).")
                                    }
                                }
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                Log.e("TransportManager", "Error processing CTAP request", e)
                                onStatusUpdate?.invoke("CTAP Error: ${e.message}")
                                // Close the underlying WebSocket on fatal CTAP dispatch errors to prevent orphaned keep-alive pings
                                sessionWs.close()
                                if (tunnelWebsocket === sessionWs) {
                                    tunnelWebsocket = null
                                }
                                onSessionTerminated?.invoke()
                            }
                        }
                    }
                    0x00 -> {
                        // Close session cleanly upon receiving client shutdown message (typeShutdown = 0) per CTAP 2.3 §11.5
                        Log.d("TransportManager", "Received Shutdown message (0x00), closing tunnel.")
                        onStatusUpdate?.invoke("Peer closed connection. Session complete.")
                        bleAdvertiser.stopAdvertising()
                        sessionWs.close()
                        if (tunnelWebsocket === sessionWs) {
                            tunnelWebsocket = null
                        }
                        onSessionTerminated?.invoke()
                    }
                    else -> Log.d("TransportManager", "Received Unknown Frame Type: 0x${frameType.toString(16)}")
                }
            }
        } catch (e: Exception) {
            val msg = "Frame Error: ${e.message}"
            Log.e("TransportManager", msg, e)
            handshakeTimeoutJob?.cancel()
            bleAdvertiser.stopAdvertising()
            // Close the WebSocket when handshake or frame decryption fails so the tunnel does not remain open indefinitely
            sessionWs.close()
            if (tunnelWebsocket === sessionWs) {
                tunnelWebsocket = null
            }
            onStatusUpdate?.invoke(msg)
            onSessionTerminated?.invoke()
        }
    }

    fun stopSession() {
        handshakeTimeoutJob?.cancel()
        handshakeTimeoutJob = null
        transportScope.coroutineContext.cancelChildren()
        bleAdvertiser.stopAdvertising()
        tunnelWebsocket?.close()
        tunnelWebsocket = null
    }
}