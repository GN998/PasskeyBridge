package com.yourcompany.passkeybridge.core.transport.noise

import android.util.Log
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

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

        val (ephPub, ephPriv) = generateEcKeyPair()
        val phoneEphemeralPubKey = uncompressECKey(ephPub)
        
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
        return crypter?.encrypt(plaintext) ?: plaintext
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        check(isHandshakeComplete) { "Handshake not complete" }
        return crypter?.decrypt(ciphertext) ?: ciphertext
    }
    
    // Helper to generate EC Key Pair
    private fun generateEcKeyPair(): Pair<ECPublicKey, ECPrivateKey> {
        val kpg = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val kp = kpg.generateKeyPair()
        return (kp.public as ECPublicKey) to (kp.private as ECPrivateKey)
    }
    
    // Helper to uncompress EC Public Key
    private fun uncompressECKey(pub: ECPublicKey): ByteArray {
        val p = pub.w
        val x = p.affineX.toByteArray()
        val y = p.affineY.toByteArray()
        return ByteArray(65).apply {
            this[0] = 0x04
            System.arraycopy(x, (x.size - 32).coerceAtLeast(0), this, 1 + (32 - x.size).coerceAtLeast(0), x.size.coerceAtMost(32))
            System.arraycopy(y, (y.size - 32).coerceAtLeast(0), this, 33 + (32 - y.size).coerceAtLeast(0), y.size.coerceAtMost(32))
        }
    }
}
