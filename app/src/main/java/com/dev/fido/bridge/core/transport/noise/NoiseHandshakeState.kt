package com.dev.fido.bridge.core.transport.noise

import com.dev.fido.bridge.core.security.AES_ALGORITHM
import com.dev.fido.bridge.core.security.HKDF_ALGORITHM
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Specify Noise protocol handshake patterns supported in caBLE v2.
 */
enum class NoiseHandshakeMode(val code: Int, val protocolName: String) {
    /**
     * Noise_NKpsk0_P256_AESGCM_SHA256 for state-assisted (linked) caBLE connections.
     * Initiator (PC) knows Responder's (Phone) static key in advance.
     */
    NKpsk0(2, "Noise_NKpsk0_P256_AESGCM_SHA256"),

    /**
     * Noise_KNpsk0_P256_AESGCM_SHA256 for ad-hoc (QR code) caBLE connections.
     * Initiator's static key is conveyed in the QR payload.
     */
    KNpsk0(3, "Noise_KNpsk0_P256_AESGCM_SHA256")
}

/**
 * Maintain state machine for Noise protocol symmetric handshake digest, chaining key, and cipher operations.
 */
class NoiseHandshakeState(val mode: NoiseHandshakeMode) {

    private var handshakeHash: ByteArray = mode.protocolName.toByteArray().let { bytes ->
        if (bytes.size <= 32) {
            bytes + ByteArray(32 - bytes.size)
        } else {
            MessageDigest.getInstance("SHA-256").digest(bytes)
        }
    }

    private var chainingKey: ByteArray = handshakeHash.clone()
    private var cipherKey: ByteArray? = null

    /**
     * Update handshake digest with arbitrary message data to preserve transcript integrity.
     */
    fun mixHash(data: ByteArray) {
        handshakeHash = MessageDigest.getInstance("SHA-256").run {
            update(handshakeHash)
            digest(data)
        }
    }

    /**
     * Mix input key material into chaining key and derive new cipher key without altering hash transcript.
     */
    fun mixKey(inputKeyMaterial: ByteArray) {
        val (ck, k) = hkdfMulti(chainingKey, inputKeyMaterial, 2)
        chainingKey = ck
        cipherKey = k
    }

    /**
     * Mix input key material into chaining key, update handshake hash transcript, and derive new cipher key.
     */
    fun mixKeyAndHash(inputKeyMaterial: ByteArray) {
        val (ck, tempHash, k) = hkdfMulti(chainingKey, inputKeyMaterial, 3)
        chainingKey = ck
        mixHash(tempHash)
        cipherKey = k
    }

    /**
     * Encrypt handshake payload authenticated with current handshake hash as Associated Authenticated Data (AAD).
     */
    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val key = cipherKey ?: ByteArray(32)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, AES_ALGORITHM), GCMParameterSpec(128, ByteArray(12)))
            updateAAD(handshakeHash)
        }
        return cipher.doFinal(plaintext).also { ciphertext ->
            mixHash(ciphertext)
        }
    }

    /**
     * Decrypt handshake payload and verify authentication tag using handshake hash as AAD.
     */
    fun decryptAndHash(ct: ByteArray): ByteArray {
        val key = cipherKey ?: ByteArray(32)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        val gcm = GCMParameterSpec(128, ByteArray(12))
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, AES_ALGORITHM), gcm)
        c.updateAAD(handshakeHash)
        val pt = c.doFinal(ct)
        mixHash(ct)
        return pt
    }

    /**
     * Finalize Noise handshake and derive symmetric read/write transport session keys.
     */
    fun splitSessionKeys(): Pair<ByteArray, ByteArray> {
        val (k1, k2) = hkdfMulti(chainingKey, ByteArray(0), 2)
        return k1 to k2
    }

    private fun hkdfMulti(chainingKey: ByteArray, inputKeyMaterial: ByteArray, outputs: Int): List<ByteArray> {
        val prk = hkdfExtract(chainingKey, inputKeyMaterial)
        val mac = Mac.getInstance(HKDF_ALGORITHM).apply {
            init(SecretKeySpec(prk, HKDF_ALGORITHM))
        }
        val result = ArrayList<ByteArray>(outputs)
        var previous = ByteArray(0)
        repeat(outputs) { index ->
            mac.reset()
            if (previous.isNotEmpty()) mac.update(previous)
            mac.update((index + 1).toByte())
            previous = mac.doFinal()
            result += previous
        }
        return result
    }

    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val s = if (salt.isEmpty()) ByteArray(32) else salt
        val mac = Mac.getInstance(HKDF_ALGORITHM).apply { init(SecretKeySpec(s, HKDF_ALGORITHM)) }
        return mac.doFinal(ikm)
    }
}
