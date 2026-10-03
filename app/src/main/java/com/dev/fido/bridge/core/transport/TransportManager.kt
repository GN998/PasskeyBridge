package com.dev.fido.bridge.core.transport

import android.util.Log
import com.dev.fido.bridge.BuildConfig
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.security.CryptoHelper
import com.dev.fido.bridge.core.storage.model.IdentityKeyPair
import com.dev.fido.bridge.core.storage.model.LinkingRecord
import com.dev.fido.bridge.core.transport.ble.BleAdvertisingMode
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.core.transport.noise.NoiseHandshakeMode
import com.dev.fido.bridge.core.transport.noise.NoiseSession
import com.dev.fido.bridge.core.transport.websocket.CableTunnelEndpoint
import com.dev.fido.bridge.core.transport.websocket.TunnelWebsocket

/**
 * Coordinate caBLE v2 transport layers including WebSocket tunnels, BLE advertisements, and Noise sessions.
 *
 * Support both QR-initiated ad-hoc sessions (KNpsk0 handshake + 20-byte EID) and State-assisted paired
 * reconnect sessions (NKpsk0 handshake + 15-byte EID) per CTAP 2.3 §11.5 specifications.
 */
class TransportManager(
    private val bleAdvertiser: HybridBleAdvertiser
) {
    companion object {
        private const val TAG = "TransportManager"
    }

    private val noiseSession = NoiseSession()
    private var tunnelWebsocket: TunnelWebsocket? = null

    /**
     * Status callback listener invoked when connection state transitions occur.
     */
    var onStatusUpdate: ((String) -> Unit)? = null

    /**
     * Start a QR-initiated ad-hoc caBLE session (KNpsk0 handshake mode).
     *
     * Derive ephemeral tunnel identifier, connect to WebSocket tunnel, initiate 20-byte BLE EID broadcast,
     * and handle incoming CTAP requests once handshake completes.
     *
     * @param peerPublicKey Uncompressed EC P-256 public key scanned from QR code.
     * @param psk Pre-shared secret (qrSecret) scanned from QR code.
     * @param domainId 16-bit domain identifier parsed from QR data.
     * @param onRequestReceived Callback invoked when a decrypted CTAP request frame is received.
     */
    fun startQrSession(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int = BuildConfig.TUNNEL_ID,
        onRequestReceived: (ByteArray) -> ByteArray
    ) {
        stopSession()

        val uncompressedPeerKey = CryptoHelper.decompressECKey(peerPublicKey)
        noiseSession.setPeerPublicKey(uncompressedPeerKey)

        val ephemeralTunnelId = CryptoHelper.hkdf(
            ikm = psk,
            salt = ByteArray(0),
            info = byteArrayOf(2, 0, 0, 0),
            length = 16
        )

        val endpoint = CableTunnelEndpoint.NewTunnel(
            domainId = domainId,
            ephemeralTunnelId = ephemeralTunnelId
        )

        tunnelWebsocket = TunnelWebsocket(
            endpoint = endpoint,
            onConnected = { routingId ->
                // 1. Generate 16-byte advertPlaintext seed bound to routingId, domainId, and timestamp
                val advertPlaintext = CryptoHelper.generateSeed(routingId, domainId)

                // 2. Derive 64-byte eidKey from qrSecret (psk)
                val eidKey = CryptoHelper.hkdf(
                    ikm = psk,
                    salt = ByteArray(0),
                    info = byteArrayOf(1, 0, 0, 0),
                    length = 64
                )

                // 3. Encrypt seed into 20-byte BLE EID
                val finalEid = CryptoHelper.generateEid(eidKey, advertPlaintext)

                // 4. Derive 32-byte Noise PSK
                val noisePsk = CryptoHelper.hkdf(
                    ikm = psk,
                    salt = advertPlaintext,
                    info = byteArrayOf(3, 0, 0, 0),
                    length = 32
                )

                // 5. Initialize Noise KNpsk0 state machine
                noiseSession.initializeHandshake(
                    mode = NoiseHandshakeMode.KNpsk0,
                    psk = noisePsk
                )

                // 6. Broadcast 20-byte BLE EID
                bleAdvertiser.startAdvertising(BleAdvertisingMode.AdHoc(finalEid))
                onStatusUpdate?.invoke("BLE Advertising Started with 20-byte EID...")
            },
            onMessageReceived = { encryptedFrame ->
                handleIncomingFrame(encryptedFrame, onRequestReceived)
            },
            onStatusUpdate = { status ->
                onStatusUpdate?.invoke(status)
            }
        )
        tunnelWebsocket?.connect()
    }

    /**
     * Backward-compatible alias for [startQrSession].
     */
    fun startSession(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int = BuildConfig.TUNNEL_ID,
        onRequestReceived: (ByteArray) -> ByteArray
    ) {
        startQrSession(peerPublicKey, psk, domainId, onRequestReceived)
    }

    /**
     * Start a State-assisted caBLE reconnection session (NKpsk0 handshake mode).
     *
     * Connect to paired Contact Tunnel, broadcast 15-byte BLE Nonce/EID, perform NKpsk0 handshake using
     * persistent `linkSecret` and authenticator [IdentityKeyPair].
     *
     * @param record Persistent pairing metadata record containing `contactId`, `linkSecret`, and client public key.
     * @param identityKey Device persistent P-256 identity key pair.
     * @param onRequestReceived Callback invoked when a decrypted CTAP request frame is received.
     */
    fun startStateAssistedSession(
        record: LinkingRecord,
        identityKey: IdentityKeyPair,
        onRequestReceived: (ByteArray) -> ByteArray
    ) {
        stopSession()

        noiseSession.setPeerPublicKey(record.authenticatorPublicKey)

        val endpoint = CableTunnelEndpoint.ContactTunnel(
            domain = record.tunnelServerDomain,
            contactId = record.contactId,
            clientPayload = ByteArray(0)
        )

        tunnelWebsocket = TunnelWebsocket(
            endpoint = endpoint,
            onConnected = { routingId ->
                // Derive 15-byte State-assisted BLE Nonce / EID
                val stateAssistedNonce = CryptoHelper.hkdf(
                    ikm = record.linkSecret,
                    salt = routingId,
                    info = byteArrayOf(4, 0, 0, 0),
                    length = 15
                )

                // Initialize Noise NKpsk0 state machine
                noiseSession.initializeHandshake(
                    mode = NoiseHandshakeMode.NKpsk0,
                    psk = record.linkSecret
                )

                // Broadcast 15-byte BLE Nonce
                bleAdvertiser.startAdvertising(BleAdvertisingMode.StateAssisted(stateAssistedNonce))
                onStatusUpdate?.invoke("State-assisted BLE Advertising Started (15-byte)...")
            },
            onMessageReceived = { encryptedFrame ->
                handleIncomingFrame(encryptedFrame, onRequestReceived)
            },
            onStatusUpdate = { status ->
                onStatusUpdate?.invoke(status)
            }
        )
        tunnelWebsocket?.connect()
    }

    /**
     * Stop all active BLE advertising and close WebSocket tunnel connections.
     */
    fun stopSession() {
        bleAdvertiser.stopAdvertising()
        tunnelWebsocket?.close()
        tunnelWebsocket = null
    }

    /**
     * Process incoming raw frames received over WebSocket tunnel.
     */
    private fun handleIncomingFrame(
        encryptedFrame: ByteArray,
        onRequestReceived: (ByteArray) -> ByteArray
    ) {
        try {
            if (!noiseSession.isHandshakeComplete) {
                Log.d(TAG, "Received ClientHello, processing Noise handshake...")
                val serverHello = noiseSession.processClientHelloAndGenerateServerHello(encryptedFrame)
                tunnelWebsocket?.sendFrame(serverHello)

                val msg = "Noise Handshake Success! Sent ServerHello & Post-Handshake Message."
                Log.d(TAG, msg)
                onStatusUpdate?.invoke(msg)

                val postHandshakeMsg = buildPostHandshakeMessage()
                tunnelWebsocket?.sendFrame(noiseSession.encrypt(postHandshakeMsg))
            } else {
                val decrypted = noiseSession.decrypt(encryptedFrame)
                if (decrypted.isEmpty()) return

                val frameType = decrypted[0].toInt() and 0xFF
                when (frameType) {
                    0x01 -> {
                        val logMsg = "Received CTAP Request!"
                        Log.d(TAG, logMsg)
                        onStatusUpdate?.invoke(logMsg)

                        val ctapReq = decrypted.copyOfRange(1, decrypted.size)
                        val response = onRequestReceived(ctapReq)
                        val framedResponse = byteArrayOf(0x01) + response
                        tunnelWebsocket?.sendFrame(noiseSession.encrypt(framedResponse))
                    }
                    0x00 -> Log.d(TAG, "Received Control/ACK frame")
                    else -> Log.d(TAG, "Received unknown frame type: 0x${frameType.toString(16)}")
                }
            }
        } catch (e: Exception) {
            val errorMsg = "Frame processing error: ${e.message}"
            Log.e(TAG, errorMsg, e)
            onStatusUpdate?.invoke(errorMsg)
        }
    }

    /**
     * Build post-handshake authenticator capabilities map frame per CTAP 2.3 §11.5.
     */
    private fun buildPostHandshakeMessage(): ByteArray {
        val getInfoMap = mapOf(
            1L to listOf("FIDO_2_0", "FIDO_2_1", "FIDO_2_3"),
            3L to ByteArray(16),
            4L to mapOf("rk" to true, "up" to true, "uv" to true, "plat" to false),
            9L to listOf("internal", "hybrid")
        )
        val getInfoBytes = CtapCodec.SimpleCbor.write(getInfoMap)
        val postHandshakeMap = mapOf(
            1L to getInfoBytes,
            3L to listOf("dc", "ctap")
        )
        return CtapCodec.SimpleCbor.write(postHandshakeMap)
    }
}
