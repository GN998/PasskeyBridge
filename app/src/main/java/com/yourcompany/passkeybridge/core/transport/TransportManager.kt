package com.yourcompany.passkeybridge.core.transport

import com.yourcompany.passkeybridge.BuildConfig
import com.yourcompany.passkeybridge.core.transport.ble.HybridBleAdvertiser
import com.yourcompany.passkeybridge.core.transport.noise.NoiseSession
import com.yourcompany.passkeybridge.core.transport.websocket.TunnelWebsocket

class TransportManager(
    private val bleAdvertiser: HybridBleAdvertiser,
    private val tunnelId: Int = BuildConfig.TUNNEL_ID
) {
    private val noiseSession = NoiseSession()
    private var tunnelWebsocket: TunnelWebsocket? = null

    fun startSession(
        eid: ByteArray,
        psk: ByteArray,
        onRequestReceived: (ByteArray) -> ByteArray
    ) {
        bleAdvertiser.startAdvertising(eid)
        noiseSession.performHandshake(psk)

        tunnelWebsocket = TunnelWebsocket(tunnelId) { encryptedFrame ->
            val decrypted = noiseSession.decrypt(encryptedFrame)
            val response = onRequestReceived(decrypted)
            val encryptedResponse = noiseSession.encrypt(response)
            tunnelWebsocket?.sendFrame(encryptedResponse)
        }
        tunnelWebsocket?.connect()
    }

    fun stopSession() {
        tunnelWebsocket?.close()
    }
}