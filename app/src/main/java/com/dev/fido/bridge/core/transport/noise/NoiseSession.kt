package com.dev.fido.bridge.core.transport.noise

import android.util.Log
import com.dev.fido.bridge.core.security.CryptoHelper
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Manage Noise handshake lifecycle and transport encryption session supporting both KNpsk0 and NKpsk0 modes.
 */
class NoiseSession : NoiseHandshakeEngine {

    override var isHandshakeComplete: Boolean = false
        private set

    private var noiseState: NoiseHandshakeState? = null
    private var crypter: NoiseCrypter? = null
    private var peerPublicKeyBytes: ByteArray? = null
    private var localStaticKeyPair: Pair<ECPublicKey, ECPrivateKey>? = null

    /**
     * Set local static key pair (required when executing Noise NKpsk0 mode as Responder).
     */
    fun setLocalStaticKeyPair(keyPair: Pair<ECPublicKey, ECPrivateKey>) {
        this.localStaticKeyPair = keyPair
    }

    override fun setPeerPublicKey(keyBytes: ByteArray) {
        this.peerPublicKeyBytes = keyBytes
    }

    override fun initializeHandshake(psk: ByteArray) {
        initializeHandshake(NoiseHandshakeMode.KNpsk0, psk)
    }

    override fun initializeHandshake(mode: NoiseHandshakeMode, psk: ByteArray) {
        val nh = NoiseHandshakeState(mode)
        noiseState = nh

        when (mode) {
            NoiseHandshakeMode.KNpsk0 -> {
                val peerKey = peerPublicKeyBytes ?: throw IllegalStateException("Peer public key not set for KNpsk0")
                nh.mixHash(byteArrayOf(1))
                nh.mixHash(peerKey)
                nh.mixKeyAndHash(psk)
                Log.d("NoiseSession", "Noise KNpsk0 initialized with derived PSK")
            }
            NoiseHandshakeMode.NKpsk0 -> {
                val localStatic = localStaticKeyPair ?: generateEcKeyPair().also { localStaticKeyPair = it }
                val uncompressedLocalStatic = uncompressECKey(localStatic.first)
                nh.mixHash(byteArrayOf(1))
                nh.mixHash(uncompressedLocalStatic)
                nh.mixKeyAndHash(psk)
                Log.d("NoiseSession", "Noise NKpsk0 initialized with derived PSK")
            }
        }
    }

    override fun processClientHelloAndGenerateServerHello(clientHello: ByteArray): ByteArray {
        val nh = noiseState ?: throw IllegalStateException("Handshake not initialized")

        return when (nh.mode) {
            NoiseHandshakeMode.KNpsk0 -> processClientHelloKNpsk0(nh, clientHello)
            NoiseHandshakeMode.NKpsk0 -> processClientHelloNKpsk0(nh, clientHello)
        }
    }

    private fun processClientHelloKNpsk0(nh: NoiseHandshakeState, clientHello: ByteArray): ByteArray {
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

        val peDh = CryptoHelper.computeEcdhSecret(ephPriv, pcEphemeralPubKey)
        nh.mixKey(peDh)

        val psDh = CryptoHelper.computeEcdhSecret(ephPriv, peerKey)
        nh.mixKey(psDh)

        val serverHelloPayload = nh.encryptAndHash(ByteArray(0))
        val serverHello = phoneEphemeralPubKey + serverHelloPayload

        val (rx, tx) = nh.splitSessionKeys()
        crypter = NoiseCrypter(rx, tx)
        isHandshakeComplete = true

        Log.d("NoiseSession", "Processed ClientHello (KNpsk0), generated ServerHello. Handshake complete.")
        return serverHello
    }

    private fun processClientHelloNKpsk0(nh: NoiseHandshakeState, clientHello: ByteArray): ByteArray {
        val localStatic = localStaticKeyPair ?: throw IllegalStateException("Local static key pair not set for NKpsk0")

        if (clientHello.size < 81) {
            throw IllegalArgumentException("ClientHello message too short: ${clientHello.size} bytes")
        }

        val pcEphemeralPubKey = clientHello.copyOfRange(0, 65)
        val clientHelloPayload = clientHello.copyOfRange(65, clientHello.size)

        nh.mixHash(pcEphemeralPubKey)
        nh.mixKey(pcEphemeralPubKey)

        val esDh = CryptoHelper.computeEcdhSecret(localStatic.second, pcEphemeralPubKey)
        nh.mixKey(esDh)

        nh.decryptAndHash(clientHelloPayload)

        val (ephPub, ephPriv) = generateEcKeyPair()
        val phoneEphemeralPubKey = uncompressECKey(ephPub)

        nh.mixHash(phoneEphemeralPubKey)
        nh.mixKey(phoneEphemeralPubKey)

        val eeDh = CryptoHelper.computeEcdhSecret(ephPriv, pcEphemeralPubKey)
        nh.mixKey(eeDh)

        val serverHelloPayload = nh.encryptAndHash(ByteArray(0))
        val serverHello = phoneEphemeralPubKey + serverHelloPayload

        val (rx, tx) = nh.splitSessionKeys()
        crypter = NoiseCrypter(rx, tx)
        isHandshakeComplete = true

        Log.d("NoiseSession", "Processed ClientHello (NKpsk0), generated ServerHello. Handshake complete.")
        return serverHello
    }

    override fun encrypt(plaintext: ByteArray): ByteArray {
        check(isHandshakeComplete) { "Handshake not complete" }
        return crypter?.encrypt(plaintext) ?: plaintext
    }

    override fun decrypt(ciphertext: ByteArray): ByteArray {
        check(isHandshakeComplete) { "Handshake not complete" }
        return crypter?.decrypt(ciphertext) ?: ciphertext
    }

    private fun generateEcKeyPair(): Pair<ECPublicKey, ECPrivateKey> {
        val kpg = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val kp = kpg.generateKeyPair()
        return (kp.public as ECPublicKey) to (kp.private as ECPrivateKey)
    }

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
