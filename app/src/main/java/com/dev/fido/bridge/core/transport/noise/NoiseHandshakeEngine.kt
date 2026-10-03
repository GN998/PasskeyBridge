package com.dev.fido.bridge.core.transport.noise

/**
 * Define contract for Noise protocol handshake execution and transport frame encryption.
 */
interface NoiseHandshakeEngine {

    /**
     * Indicate whether the Noise handshake protocol exchange has completed successfully.
     */
    val isHandshakeComplete: Boolean

    /**
     * Configure peer public key required for handshake processing.
     */
    fun setPeerPublicKey(keyBytes: ByteArray)

    /**
     * Initialize Noise state machine in KNpsk0 mode using pre-shared key.
     */
    fun initializeHandshake(psk: ByteArray)

    /**
     * Initialize Noise state machine with explicit mode (KNpsk0 or NKpsk0) and pre-shared key.
     */
    fun initializeHandshake(mode: NoiseHandshakeMode, psk: ByteArray)

    /**
     * Process incoming ClientHello message and generate ServerHello response payload.
     */
    fun processClientHelloAndGenerateServerHello(clientHello: ByteArray): ByteArray

    /**
     * Encrypt CTAP transport message frame using established Noise session keys.
     */
    fun encrypt(plaintext: ByteArray): ByteArray

    /**
     * Decrypt CTAP transport message frame using established Noise session keys.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray
}
