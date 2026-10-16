package com.dev.fido.bridge.core.transport.noise

import android.util.Log

class NoiseSession {
    var isHandshakeComplete = false
        private set

    private var noiseState: NoiseHandshakeState? = null
    private var crypter: NoiseCrypter? = null
    private var peerPublicKeyBytes: ByteArray? = null

    // Inject the PC's public key (scanned from QR)
    fun setPeerPublicKey(keyBytes: ByteArray) {
        this.peerPublicKeyBytes = keyBytes
    }

    // Step 1: Initialize the noise state machine with derived PSK
    fun initializeHandshake(psk: ByteArray) {
        val peerKey = peerPublicKeyBytes ?: throw IllegalStateException("Peer public key not set")
        // Reset handshake flag and session crypter so subsequent QR scans on a singleTop Activity
        // process the new ClientHello instead of treating it as post-handshake ciphertext.
        isHandshakeComplete = false
        crypter = null

        val nh = NoiseHandshakeState(mode = 3) // Noise KNpsk0
        noiseState = nh

        nh.mixHash(byteArrayOf(1))
        nh.mixHash(peerKey)
        nh.mixKeyAndHash(psk)
        Log.d("NoiseSession", "Noise KNpsk0 initialized with derived PSK, waiting for ClientHello")
    }

    // Step 2: Process the incoming ClientHello and generate ServerHello
    fun processClientHelloAndGenerateServerHello(clientHello: ByteArray): ByteArray {
        val nh = noiseState ?: throw IllegalStateException("Handshake not initialized")
        val peerKey = peerPublicKeyBytes ?: throw IllegalStateException("Peer public key not set")

        if (clientHello.size < 81) {
            throw IllegalArgumentException("ClientHello message too short: ${clientHello.size} bytes")
        }

        val pcEphemeralPubKey = clientHello.copyOfRange(0, 65)
        val clientHelloPayload = clientHello.copyOfRange(65, clientHello.size)

        nh.mixHash(pcEphemeralPubKey)
        nh.mixKey(pcEphemeralPubKey)
        nh.decryptAndHash(clientHelloPayload)

        val (ephPub, ephPriv) = CryptoHelper.generateEcKeyPair()
        val phoneEphemeralPubKey = CryptoHelper.uncompressECKey(ephPub)

        nh.mixHash(phoneEphemeralPubKey)
        nh.mixKey(phoneEphemeralPubKey)

        val peDh = CryptoHelper.recd(ephPriv, pcEphemeralPubKey)
        nh.mixKey(peDh)

        val psDh = CryptoHelper.recd(ephPriv, peerKey)
        nh.mixKey(psDh)

        val serverHelloPayload = nh.encryptAndHash(ByteArray(0))
        val serverHello = phoneEphemeralPubKey + serverHelloPayload

        val (rx, tx) = nh.splitSessionKeys()
        crypter = NoiseCrypter(rx, tx)
        isHandshakeComplete = true

        Log.d("NoiseSession", "Processed ClientHello, generated ServerHello. Handshake complete.")
        return serverHello
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        check(isHandshakeComplete) { "Handshake not complete" }
        // Require initialized session crypter instead of falling back to unencrypted plaintext
        return checkNotNull(crypter) { "Session crypter not initialized" }.encrypt(plaintext)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        check(isHandshakeComplete) { "Handshake not complete" }
        return checkNotNull(crypter) { "Session crypter not initialized" }.decrypt(ciphertext)
    }
}