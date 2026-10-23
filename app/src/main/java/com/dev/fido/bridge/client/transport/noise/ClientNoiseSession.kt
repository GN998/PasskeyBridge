package com.dev.fido.bridge.client.transport.noise

import android.util.Log
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import com.dev.fido.bridge.core.transport.noise.NoiseCrypter
import com.dev.fido.bridge.core.transport.noise.NoiseHandshakeState
import java.security.interfaces.ECPrivateKey

/**
 * Noise KNpsk0 initiator state machine for QR-initiated client transactions per CTAP 2.3 §11.5.1.2 / PXP §6.2.
 */
class ClientNoiseSession(
    private val identityPrivateKey: ECPrivateKey,
    private val uncompressedIdentityPubKey: ByteArray
) {
    @Volatile
    var isHandshakeComplete = false
        private set

    private var noiseState: NoiseHandshakeState? = null
    private var crypter: NoiseCrypter? = null
    private lateinit var ephPriv: ECPrivateKey

    /**
     * Initialize Noise KNpsk0 initiator state with the derived 32-byte PSK and construct the 81-byte ClientHello
     * (65-byte uncompressed ephemeral P-256 point + 16-byte AES-GCM tag over empty plaintext) per PXP §6.2.
     */
    @Synchronized
    fun startHandshakeAndBuildClientHello(psk: ByteArray): ByteArray {
        isHandshakeComplete = false
        crypter = null

        val nh = NoiseHandshakeState()
        noiseState = nh

        // KNpsk0 initiator prologue: mixHash(0x01) -> mixHash(static identity pubkey) -> mixKeyAndHash(psk)
        nh.mixHash(byteArrayOf(1))
        nh.mixHash(uncompressedIdentityPubKey)
        nh.mixKeyAndHash(psk)

        val (ephPub, priv) = CryptoHelper.generateEcKeyPair()
        ephPriv = priv
        val ephPubBytes = CryptoHelper.uncompressECKey(ephPub)

        nh.mixHash(ephPubBytes)
        nh.mixKey(ephPubBytes)

        val encryptedEmptyPayload = nh.encryptAndHash(ByteArray(0))
        Log.d("ClientNoiseSession", "Generated 81-byte KNpsk0 ClientHello")
        return ephPubBytes + encryptedEmptyPayload
    }

    /**
     * Process the 81-byte ServerHello from the authenticator, perform ee and se ECDH agreements,
     * and split session traffic keys (k1 = initiator write, k2 = initiator read) per PXP §6.2.
     */
    @Synchronized
    fun processServerHello(serverHello: ByteArray) {
        val nh = checkNotNull(noiseState) { "Initiator handshake not initialized" }

        if (serverHello.size < 81) {
            throw IllegalArgumentException("ServerHello message too short: ${serverHello.size} bytes")
        }

        val peerEphPubBytes = serverHello.copyOfRange(0, 65)
        val ciphertext = serverHello.copyOfRange(65, serverHello.size)

        nh.mixHash(peerEphPubBytes)
        nh.mixKey(peerEphPubBytes)

        // Token 'ee': ECDH(initiator ephemeral priv, responder ephemeral pub)
        val eeDh = CryptoHelper.recd(ephPriv, peerEphPubBytes)
        nh.mixKey(eeDh)

        // Token 'se': ECDH(initiator static identity priv, responder ephemeral pub)
        val seDh = CryptoHelper.recd(identityPrivateKey, peerEphPubBytes)
        nh.mixKey(seDh)

        val plaintext = nh.decryptAndHash(ciphertext)
        if (plaintext.isNotEmpty()) {
            throw IllegalArgumentException("ServerHello decrypted payload must be empty per PXP §6.2, got ${plaintext.size} bytes")
        }

        // Per PXP §6.2, split() assigns k1 to client-to-CMHD (write) and k2 to CMHD-to-client (read)
        val (clientWriteKey, clientReadKey) = nh.splitSessionKeys()
        crypter = NoiseCrypter(rKey = clientReadKey, wKey = clientWriteKey)
        noiseState = null
        isHandshakeComplete = true

        Log.d("ClientNoiseSession", "ServerHello verified; Noise KNpsk0 initiator handshake complete.")
    }

    @Synchronized
    fun encrypt(plaintext: ByteArray): ByteArray {
        return checkNotNull(crypter) { "Handshake not complete" }.encrypt(plaintext)
    }

    @Synchronized
    fun decrypt(ciphertext: ByteArray): ByteArray {
        return checkNotNull(crypter) { "Handshake not complete" }.decrypt(ciphertext)
    }
}