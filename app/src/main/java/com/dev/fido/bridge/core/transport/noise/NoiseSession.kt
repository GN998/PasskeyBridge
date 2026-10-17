package com.dev.fido.bridge.core.transport.noise

import android.util.Log

class NoiseSession {
    @Volatile
    var isHandshakeComplete = false
        private set

    private var noiseState: NoiseHandshakeState? = null
    private var crypter: NoiseCrypter? = null
    private lateinit var peerPublicKeyBytes: ByteArray

    // Inject the PC's public key (scanned from QR)
    @Synchronized
    fun setPeerPublicKey(keyBytes: ByteArray) {
        this.peerPublicKeyBytes = keyBytes
    }

    // Step 1: Initialize the noise state machine with derived PSK
    @Synchronized
    fun initializeHandshake(psk: ByteArray) {
        check(::peerPublicKeyBytes.isInitialized) { "Peer public key not set" }
        // Reset handshake flag and session crypter so subsequent QR scans on a singleTop Activity
        // process the new ClientHello instead of treating it as post-handshake ciphertext.
        isHandshakeComplete = false
        crypter = null

        val nh = NoiseHandshakeState()
        noiseState = nh

        nh.mixHash(byteArrayOf(1))
        nh.mixHash(peerPublicKeyBytes)
        nh.mixKeyAndHash(psk)
        Log.d("NoiseSession", "Noise KNpsk0 initialized with derived PSK, waiting for ClientHello")
    }

    // Step 2: Process the incoming ClientHello and generate ServerHello
    @Synchronized
    fun processClientHelloAndGenerateServerHello(clientHello: ByteArray): ByteArray {
        // Verify noiseState initialization, which inherently guarantees peerPublicKeyBytes is also initialized
        val nh = checkNotNull(noiseState) { "Handshake not initialized" }

        if (clientHello.size < 81) {
            throw IllegalArgumentException("ClientHello message too short: ${clientHello.size} bytes")
        }

        val pcEphemeralPubKey = clientHello.copyOfRange(0, 65)
        val clientHelloPayload = clientHello.copyOfRange(65, clientHello.size)

        nh.mixHash(pcEphemeralPubKey)
        nh.mixKey(pcEphemeralPubKey)
        val plaintext = nh.decryptAndHash(clientHelloPayload)
        // Reject non-empty ClientHello plaintext per CTAP 2.3 §11.5.1.2 handshake verification rules
        if (plaintext.isNotEmpty()) {
            throw IllegalArgumentException("ClientHello decrypted payload must be empty per CTAP 2.3 §11.5.1.2, got ${plaintext.size} bytes")
        }

        val (ephPub, ephPriv) = CryptoHelper.generateEcKeyPair()
        val phoneEphemeralPubKey = CryptoHelper.uncompressECKey(ephPub)

        nh.mixHash(phoneEphemeralPubKey)
        nh.mixKey(phoneEphemeralPubKey)

        val peDh = CryptoHelper.recd(ephPriv, pcEphemeralPubKey)
        nh.mixKey(peDh)

        val psDh = CryptoHelper.recd(ephPriv, peerPublicKeyBytes)
        nh.mixKey(psDh)

        val serverHelloPayload = nh.encryptAndHash(ByteArray(0))
        val serverHello = phoneEphemeralPubKey + serverHelloPayload

        val (rx, tx) = nh.splitSessionKeys()
        crypter = NoiseCrypter(rx, tx)
        isHandshakeComplete = true

        Log.d("NoiseSession", "Processed ClientHello, generated ServerHello. Handshake complete.")
        return serverHello
    }

    @Synchronized
    fun encrypt(plaintext: ByteArray): ByteArray {
        // Require initialized session crypter instead of falling back to unencrypted plaintext
        return checkNotNull(crypter) { "Handshake not complete" }.encrypt(plaintext)
    }

    @Synchronized
    fun decrypt(ciphertext: ByteArray): ByteArray {
        return checkNotNull(crypter) { "Handshake not complete" }.decrypt(ciphertext)
    }
}