package com.dev.fido.bridge.core.transport

import android.util.Log
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.security.TunnelConfigManager
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import com.dev.fido.bridge.core.transport.noise.NoiseSession
import com.dev.fido.bridge.core.transport.websocket.TunnelWebsocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.launch

class TransportManager(
    private val bleAdvertiser: HybridBleAdvertiser
) {
    private val noiseSession = NoiseSession()
    private var tunnelWebsocket: TunnelWebsocket? = null
    private val transportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    var onStatusUpdate: ((String) -> Unit)? = null
    // Notify controller when a transaction finishes or the tunnel closes to decouple control flow from log strings
    var onSessionTerminated: (() -> Unit)? = null

    // Support suspending callback to prevent blocking OkHttp reader thread during UI credential prompts
    fun startSession(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int = TunnelConfigManager.getEffectiveTunnelId(),
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

        tunnelWebsocket = TunnelWebsocket(
            domainId = domainId,
            ephemeralTunnelId = ephemeralTunnelId,
            onConnected = { routingId ->
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
            },
            onMessageReceived = { encryptedFrame ->
                try {
                    if (!noiseSession.isHandshakeComplete) {
                        Log.d("TransportManager", "Received ClientHello, processing Noise KNpsk0 handshake...")
                        // Stop BLE proximity advertising immediately once peer proves possession of EID via ClientHello
                        bleAdvertiser.stopAdvertising()

                        val serverHello = noiseSession.processClientHelloAndGenerateServerHello(encryptedFrame)
                        tunnelWebsocket?.sendFrame(serverHello)

                        val msg = "Noise KNpsk0 Handshake Success!\nSent Post-Handshake Message."
                        Log.d("TransportManager", msg)
                        onStatusUpdate?.invoke(msg)

                        val postHandshakeMsg = buildPostHandshakeMessage()
                        tunnelWebsocket?.sendFrame(noiseSession.encrypt(postHandshakeMsg))
                    } else {
                        val decrypted = noiseSession.decrypt(encryptedFrame)
                        if (decrypted.isEmpty()) return@TunnelWebsocket

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
                                        val framedResponse = byteArrayOf(0x01) + response
                                        tunnelWebsocket?.sendFrame(noiseSession.encrypt(framedResponse))

                                        // Notify UI when MakeCredential (0x01) or GetAssertion (0x02) transaction completes
                                        if (commandByte == 0x01.toByte() || commandByte == 0x02.toByte()) {
                                            val statusByte = if (response.isNotEmpty()) response[0] else CtapStatus.ERR_OPERATION_DENIED
                                            if (statusByte == CtapStatus.SUCCESS) {
                                                onStatusUpdate?.invoke("CTAP Transaction Complete.")
                                            } else {
                                                onStatusUpdate?.invoke("CTAP Rejected (Status: 0x${"%02X".format(statusByte)}).")
                                            }
                                            onSessionTerminated?.invoke()
                                        }
                                    } catch (e: Exception) {
                                        Log.e("TransportManager", "Error processing CTAP request", e)
                                        onStatusUpdate?.invoke("CTAP Error: ${e.message}")
                                        onSessionTerminated?.invoke()
                                    }
                                }
                            }
                            0x00 -> {
                                // Close session cleanly upon receiving client shutdown message (typeShutdown = 0) per CTAP 2.3 §11.5
                                Log.d("TransportManager", "Received Shutdown message (0x00), closing tunnel.")
                                onStatusUpdate?.invoke("Peer closed connection. Session complete.")
                                bleAdvertiser.stopAdvertising()
                                tunnelWebsocket?.close()
                                tunnelWebsocket = null
                                onSessionTerminated?.invoke()
                            }
                            else -> Log.d("TransportManager", "Received Unknown Frame Type: 0x${frameType.toString(16)}")
                        }
                    }
                } catch (e: Exception) {
                    val msg = "Frame Error: ${e.message}"
                    Log.e("TransportManager", msg, e)
                    onStatusUpdate?.invoke(msg)
                    onSessionTerminated?.invoke()
                }
            },
            onStatusUpdate = { status ->
                onStatusUpdate?.invoke(status)
                if (status.startsWith("WebSocket Error")) {
                    onSessionTerminated?.invoke()
                }
            }
        )
        tunnelWebsocket?.connect()
    }

    fun stopSession() {
        transportScope.coroutineContext.cancelChildren()
        bleAdvertiser.stopAdvertising()
        tunnelWebsocket?.close()
        tunnelWebsocket = null
    }

    private fun buildPostHandshakeMessage(): ByteArray {
        // Share canonical AuthenticatorInfo CBOR map to prevent capability drift between pre-flight and 0x04 GetInfo
        val getInfoBytes = CtapCodec.SimpleCbor.write(AuthenticatorInfo.toCborMap())
        // Advertise only "ctap" support in Key 3 so clients do not send unimplemented typeJSON (0x03) Digital Credentials frames per CTAP 2.3 §11.5
        val postHandshakeMap = mapOf(
            1L to getInfoBytes,
            3L to listOf("ctap")
        )
        return CtapCodec.SimpleCbor.write(postHandshakeMap)
    }
}