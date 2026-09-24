package com.yourcompany.passkeybridge.core.transport

import android.util.Log
import com.yourcompany.passkeybridge.BuildConfig
import com.yourcompany.passkeybridge.core.ctap.codec.CtapCodec
import com.yourcompany.passkeybridge.core.transport.ble.HybridBleAdvertiser
import com.yourcompany.passkeybridge.core.transport.noise.CryptoHelper
import com.yourcompany.passkeybridge.core.transport.noise.NoiseSession
import com.yourcompany.passkeybridge.core.transport.websocket.TunnelWebsocket

class TransportManager(
    private val bleAdvertiser: HybridBleAdvertiser
) {
    private val noiseSession = NoiseSession()
    private var tunnelWebsocket: TunnelWebsocket? = null
    
    var onStatusUpdate: ((String) -> Unit)? = null

    // Default value provided for domainId to ensure backwards compatibility
    fun startSession(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int = BuildConfig.TUNNEL_ID,
        onRequestReceived: (ByteArray) -> ByteArray
    ) {
        val uncompressedPeerKey = CryptoHelper.decompressECKey(peerPublicKey)
        noiseSession.setPeerPublicKey(uncompressedPeerKey)
        noiseSession.initializeHandshake(psk)

        val ephemeralTunnelId = CryptoHelper.endif(
            ikm = psk,
            salt = ByteArray(0),
            info = byteArrayOf(2, 0, 0, 0),
            length = 16
        )

        tunnelWebsocket = TunnelWebsocket(domainId, ephemeralTunnelId, onConnected = { routingId ->
            val finalEid = CryptoHelper.generateEid(qrSecret = psk, routingId = routingId, domainId = domainId)
            bleAdvertiser.startAdvertising(finalEid)
            onStatusUpdate?.invoke("BLE Advertising Started with 20-byte EID...")
            
        }, onMessageReceived = { encryptedFrame ->
            try {
                if (!noiseSession.isHandshakeComplete) {
                    Log.d("TransportManager", "Received ClientHello, processing handshake...")
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
                            val logMsg = "Received CTAP Request!"
                            Log.d("TransportManager", logMsg)
                            onStatusUpdate?.invoke(logMsg)
                            
                            val ctapReq = decrypted.copyOfRange(1, decrypted.size)
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
        }, onStatusUpdate = { status ->
            onStatusUpdate?.invoke(status)
        })
        tunnelWebsocket?.connect()
    }

    fun stopSession() {
        tunnelWebsocket?.close()
    }

    private fun buildPostHandshakeMessage(): ByteArray {
        val getInfoMap = mapOf(
            1L to listOf("FIDO_2_0", "FIDO_2_1"),
            3L to ByteArray(16), 
            4L to mapOf("rk" to true, "up" to true, "uv" to true, "plat" to false),
            9L to listOf("internal", "cable")
        )
        val getInfoBytes = CtapCodec.SimpleCbor.write(getInfoMap)
        val postHandshakeMap = mapOf(
            1L to getInfoBytes,
            3L to listOf("dc", "ctap")
        )
        return CtapCodec.SimpleCbor.write(postHandshakeMap)
    }
}