package com.dev.fido.bridge.client.transport

import android.util.Log
import com.dev.fido.bridge.client.ctap.ClientCtapCodec
import com.dev.fido.bridge.client.qr.ClientQrSessionData
import com.dev.fido.bridge.client.transport.ble.HybridBleScanner
import com.dev.fido.bridge.client.transport.noise.ClientNoiseSession
import com.dev.fido.bridge.client.transport.websocket.ClientTunnelWebsocket
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.security.DomainDerivation
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class ClientTransportManager(
    private val bleScanner: HybridBleScanner
) {
    private val transportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Volatile
    private var activeWebsocket: ClientTunnelWebsocket? = null

    @Volatile
    private var sessionTimeoutJob: Job? = null

    @Volatile
    var onStatusUpdate: ((String) -> Unit)? = null

    private fun clearActiveSession(ws: ClientTunnelWebsocket?): Boolean = synchronized(this) {
        if (ws == null || activeWebsocket === ws) {
            sessionTimeoutJob?.cancel()
            sessionTimeoutJob = null
            activeWebsocket = null
            true
        } else {
            false
        }
    }

    /**
     * Start a QR-initiated client transaction: scan for the authenticator's BLE EID advertisement,
     * connect to the authenticator-selected tunnel domain, complete the Noise KNpsk0 initiator handshake,
     * exchange the CTAP2 command/response, and send a 0x00 shutdown frame per PXP §6.2.
     */
    @Synchronized
    fun startClientSession(
        qrSession: ClientQrSessionData,
        ctapRequest: Ctap2Request,
        onSuccess: (Ctap2Response) -> Unit,
        onError: (String) -> Unit
    ) {
        stopSession()

        val encodedCtapPayload = ClientCtapCodec.encodeRequest(ctapRequest)
        val commandByte = encodedCtapPayload[0]

        // Pre-derive the 64-byte EID key (purpose = 1) and 16-byte tunnel ID (purpose = 2) from qrSecret
        val eidKey = CryptoHelper.endif(
            ikm = qrSession.qrSecret,
            salt = ByteArray(0),
            info = byteArrayOf(1, 0, 0, 0),
            length = 64
        )
        val tunnelId = CryptoHelper.endif(
            ikm = qrSession.qrSecret,
            salt = ByteArray(0),
            info = byteArrayOf(2, 0, 0, 0),
            length = 16
        )

        val scanStarted = bleScanner.startScanning(
            eidKey = eidKey,
            onAdvertMatched = { advert ->
                transportScope.launch {
                    connectTunnelAndExecuteCeremony(
                        qrSession = qrSession,
                        tunnelId = tunnelId,
                        advert = advert,
                        commandByte = commandByte,
                        encodedCtapPayload = encodedCtapPayload,
                        onSuccess = onSuccess,
                        onError = onError
                    )
                }
            },
            onFailure = { errorCode ->
                stopSession()
                onError("BLE scan failed (code $errorCode).")
            }
        )

        if (!scanStarted) {
            onError("Failed to start BLE scanner. Check Bluetooth state and permissions.")
            return
        }

        onStatusUpdate?.invoke("Waiting for other device to scan QR code...")

        // Enforce a 90-second overall ceremony timeout while waiting for QR scan and user verification
        sessionTimeoutJob = transportScope.launch {
            delay(90_000)
            stopSession()
            onError("Transaction timed out.")
        }
    }

    private fun connectTunnelAndExecuteCeremony(
        qrSession: ClientQrSessionData,
        tunnelId: ByteArray,
        advert: com.dev.fido.bridge.core.transport.noise.DecryptedBleAdvert,
        commandByte: Byte,
        encodedCtapPayload: ByteArray,
        onSuccess: (Ctap2Response) -> Unit,
        onError: (String) -> Unit
    ) {
        val domain = DomainDerivation.resolveDomainOrNull(advert.encodedTunnelServerDomain)
        if (domain == null) {
            stopSession()
            onError("Authenticator requested unsupported tunnel domain ID: ${advert.encodedTunnelServerDomain}")
            return
        }

        // Derive 32-byte Noise PSK (purpose = 3) using the decrypted 16-byte BLE advert plaintext as salt
        val psk = CryptoHelper.endif(
            ikm = qrSession.qrSecret,
            salt = advert.plaintext,
            info = byteArrayOf(3, 0, 0, 0),
            length = 32
        )

        val noiseSession = ClientNoiseSession(
            identityPrivateKey = qrSession.identityPrivateKey,
            uncompressedIdentityPubKey = qrSession.uncompressedIdentityPublicKey
        )
        // Pre-compute the 81-byte ClientHello before the WebSocket finishes TCP/TLS setup
        val clientHello = noiseSession.startHandshakeAndBuildClientHello(psk)
        val awaitingPostHandshake = AtomicBoolean(true)
        val completed = AtomicBoolean(false)

        lateinit var ws: ClientTunnelWebsocket

        fun sendEncryptedFrame(plaintext: ByteArray) {
            synchronized(noiseSession) {
                ws.sendFrame(noiseSession.encrypt(plaintext))
            }
        }

        ws = ClientTunnelWebsocket(
            domain = domain,
            routingId = advert.routingId,
            tunnelId = tunnelId,
            onConnected = {
                if (activeWebsocket !== ws) return@ClientTunnelWebsocket
                // Initiator speaks first in KNpsk0 to prove possession of the decrypted BLE advert
                ws.sendFrame(clientHello)
            },
            onMessageReceived = { frame ->
                if (activeWebsocket !== ws) return@ClientTunnelWebsocket
                try {
                    if (!noiseSession.isHandshakeComplete) {
                        noiseSession.processServerHello(frame)
                        onStatusUpdate?.invoke("Encrypted channel established. Waiting for authenticator info...")
                    } else if (awaitingPostHandshake.compareAndSet(true, false)) {
                        val postHandshakeBytes = noiseSession.decrypt(frame)
                        val postMap = CtapCodec.SimpleCbor.read(postHandshakeBytes, strict = false) as? Map<*, *>
                            ?: throw IllegalArgumentException("Invalid post-handshake CBOR map")
                        if (postMap[1L] !is ByteArray) {
                            throw IllegalArgumentException("Post-handshake message missing getInfo (key 1)")
                        }

                        onStatusUpdate?.invoke("Verify identity on the other device...")
                        // Send framed CTAP command (0x01 = typeCTAP || commandByte || CBOR)
                        sendEncryptedFrame(byteArrayOf(0x01) + encodedCtapPayload)
                    } else {
                        val decrypted = noiseSession.decrypt(frame)
                        require(decrypted.isNotEmpty()) { "Empty transport frame is a protocol error" }

                        when (val msgType = decrypted[0].toInt() and 0xFF) {
                            0x01 -> {
                                // typeCTAP response from authenticator
                                val rawCtapResp = decrypted.copyOfRange(1, decrypted.size)
                                val parsedResp = ClientCtapCodec.decodeResponse(commandByte, rawCtapResp)

                                // Send typeShutdown (0x00) to close the hybrid transaction cleanly per PXP §6.2
                                runCatching { sendEncryptedFrame(byteArrayOf(0x00)) }

                                if (completed.compareAndSet(false, true) && clearActiveSession(ws)) {
                                    ws.close()
                                    onSuccess(parsedResp)
                                }
                            }
                            0x02 -> {
                                // typeUpdate (linking metadata from authenticator); ignore in stateless QR mode per PXP §6.2
                                Log.d("ClientTransport", "Ignored optional typeUpdate (0x02) frame")
                            }
                            else -> {
                                throw IllegalArgumentException("Unexpected hybrid frame type: 0x${"%02X".format(msgType)}")
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e("ClientTransport", "Client transport error", e)
                    if (completed.compareAndSet(false, true) && clearActiveSession(ws)) {
                        ws.cancel()
                        onError("Protocol error: ${e.message}")
                    }
                }
            },
            onStatusUpdate = { status ->
                if (activeWebsocket === ws) onStatusUpdate?.invoke(status)
            },
            onDisconnected = {
                if (!completed.get() && clearActiveSession(ws)) {
                    onError("Connection closed before authentication completed.")
                }
            }
        )

        synchronized(this) {
            activeWebsocket = ws
            ws.connect()
        }
    }

    @Synchronized
    fun stopSession() {
        sessionTimeoutJob?.cancel()
        sessionTimeoutJob = null
        transportScope.coroutineContext.cancelChildren()
        bleScanner.stopScanning()
        activeWebsocket?.cancel()
        activeWebsocket = null
    }
}