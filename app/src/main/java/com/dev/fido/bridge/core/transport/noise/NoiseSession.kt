package com.dev.fido.bridge.core.transport.noise

import android.util.Log
import java.security.interfaces.ECPrivateKey

class NoiseSession {
    @Volatile
    var isHandshakeComplete = false
        private set

    @Volatile
    var handshakeHash: ByteArray = ByteArray(0)
        private set

    private var noiseState: NoiseHandshakeState? = null
    private var crypter: NoiseCrypter? = null
    private lateinit var peerPublicKeyBytes: ByteArray
    private lateinit var ephPriv: ECPrivateKey
    private lateinit var phoneEphemeralPubKey: ByteArray

    private var isStateAssistedMode: Boolean = false
    private var localStaticPrivKey: ECPrivateKey? = null

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
        handshakeHash = ByteArray(0)
        crypter = null
        isStateAssistedMode = false
        localStaticPrivKey = null

        val nh = NoiseHandshakeState(isNkPsk0 = false)
        noiseState = nh

        nh.mixHash(byteArrayOf(1))
        nh.mixHash(peerPublicKeyBytes)
        nh.mixKeyAndHash(psk)

        // Pre-compute ephemeral P-256 keypair during BLE advertising idle window to minimize ClientHello response latency
        val (pub, priv) = CryptoHelper.generateEcKeyPair()
        ephPriv = priv
        phoneEphemeralPubKey = CryptoHelper.uncompressECKey(pub)

        Log.d("NoiseSession", "Noise KNpsk0 initialized with derived PSK, waiting for ClientHello")
    }

    /**
     * Initialize the Noise NKpsk0 state machine for state-assisted (QR-less) transactions per CTAP 2.3 §11.5.2 and PXP §6.2.
     */
    @Synchronized
    fun initializeStateAssistedHandshake(
        psk: ByteArray,
        localStaticPubKeyBytes: ByteArray,
        localStaticPrivateKey: ECPrivateKey
    ) {
        require(localStaticPubKeyBytes.size == 65 && localStaticPubKeyBytes[0] == 0x04.toByte()) {
            "Authenticator static public key must be a 65-byte uncompressed P-256 point"
        }
        isHandshakeComplete = false
        handshakeHash = ByteArray(0)
        crypter = null
        isStateAssistedMode = true
        localStaticPrivKey = localStaticPrivateKey

        val nh = NoiseHandshakeState(isNkPsk0 = true)
        noiseState = nh

        // Mix 1-byte zero prologue and the authenticator's static public key per PXP §6.2 initialHandshakeMessage
        nh.mixHash(byteArrayOf(0))
        nh.mixHash(localStaticPubKeyBytes)
        nh.mixKeyAndHash(psk)

        val (pub, priv) = CryptoHelper.generateEcKeyPair()
        ephPriv = priv
        phoneEphemeralPubKey = CryptoHelper.uncompressECKey(pub)

        Log.d("NoiseSession", "Noise NKpsk0 initialized with derived PSK, waiting for ClientHello")
    }

    // Step 2: Process the incoming ClientHello and generate ServerHello
    @Synchronized
    fun processClientHelloAndGenerateServerHello(clientHello: ByteArray): ByteArray {
        // Verify noiseState initialization, which inherently guarantees peerPublicKeyBytes and ephemeral keys are initialized
        val nh = checkNotNull(noiseState) { "Handshake not initialized" }

        if (clientHello.size < 81) {
            throw IllegalArgumentException("ClientHello message too short: ${clientHello.size} bytes")
        }

        val pcEphemeralPubKey = clientHello.copyOfRange(0, 65)
        val clientHelloPayload = clientHello.copyOfRange(65, clientHello.size)

        nh.mixHash(pcEphemeralPubKey)
        nh.mixKey(pcEphemeralPubKey)

        // In NKpsk0 (state-assisted), the initiator mixes es (ECDH of initiator ephemeral and responder static) before encrypting ClientHello
        if (isStateAssistedMode) {
            val staticPriv = checkNotNull(localStaticPrivKey) { "Authenticator static private key not initialized" }
            val esDh = CryptoHelper.recd(staticPriv, pcEphemeralPubKey)
            nh.mixKey(esDh)
        }

        val plaintext = nh.decryptAndHash(clientHelloPayload)
        // Reject non-empty ClientHello plaintext per CTAP 2.3 §11.5.1.2 handshake verification rules
        if (plaintext.isNotEmpty()) {
            throw IllegalArgumentException("ClientHello decrypted payload must be empty per CTAP 2.3 §11.5.1.2, got ${plaintext.size} bytes")
        }

        nh.mixHash(phoneEphemeralPubKey)
        nh.mixKey(phoneEphemeralPubKey)

        val peDh = CryptoHelper.recd(ephPriv, pcEphemeralPubKey)
        nh.mixKey(peDh)

        // In KNpsk0 (QR-initiated), the responder mixes se (ECDH of responder ephemeral and initiator QR static) before encrypting ServerHello
        if (!isStateAssistedMode) {
            val psDh = CryptoHelper.recd(ephPriv, peerPublicKeyBytes)
            nh.mixKey(psDh)
        }

        val serverHelloPayload = nh.encryptAndHash(ByteArray(0))
        val serverHello = phoneEphemeralPubKey + serverHelloPayload

        val (rx, tx) = nh.splitSessionKeys()
        handshakeHash = nh.currentHandshakeHash()
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