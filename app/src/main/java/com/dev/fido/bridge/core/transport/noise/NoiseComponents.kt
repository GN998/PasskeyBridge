package com.dev.fido.bridge.core.transport.noise

import com.dev.fido.bridge.core.security.CryptoUtils
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

const val HKDF_ALGORITHM = "HmacSHA256"
const val AEMK_ALGORITHM = "AES"
const val EC_ALGORITHM = "EC"

/**
 * Provide Noise handshake cryptographic operations and caBLE v2 EID generation helpers.
 *
 * Delegate foundational cryptographic primitives (HKDF, ECDH, EC decompression) to [CryptoUtils]
 * to establish a single source of truth in core:security while retaining transport-specific EID formatting.
 */
object CryptoHelper {

    /**
     * Decompress 33-byte EC public key by delegating to [CryptoUtils].
     */
    fun decompressECKey(compressed: ByteArray): ByteArray {
        return CryptoUtils.decompressECKey(compressed)
    }

    /**
     * Construct 16-byte seed bound to routing ID, domain ID, and current timestamp.
     *
     * Embed timestamp and routing parameters into the seed payload to guarantee uniqueness and freshness
     * for ephemeral BLE advertising payloads.
     */
    fun generateSeed(routingId: ByteArray, domainId: Int): ByteArray {
        val seed = ByteArray(16)
        seed[0] = 0x00
        val timestamp = System.currentTimeMillis()
        val buffer = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.BIG_ENDIAN).putLong(timestamp)
        System.arraycopy(buffer.array(), 0, seed, 1, 8)
        System.arraycopy(routingId, 0, seed, 11, 3)
        seed[14] = (domainId and 0xFF).toByte()
        seed[15] = ((domainId ushr 8) and 0xFF).toByte()
        return seed
    }

    /**
     * Generate 20-byte EID for caBLE v2 using derived 64-byte EID key and 16-byte advertisement seed.
     *
     * Encrypt advertisement seed using AES-CBC (32-byte key) and append 4-byte HMAC-SHA256 tag (32-byte key)
     * to fulfill caBLE v2 BLE advertisement payload specification.
     */
    fun generateEid(eidKey: ByteArray, seed: ByteArray): ByteArray {
        val aesKey = eidKey.copyOfRange(0, 32)
        val hmacKey = eidKey.copyOfRange(32, 64)

        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, AEMK_ALGORITHM), IvParameterSpec(ByteArray(16)))
        val ciphertext = cipher.doFinal(seed)

        val mac = Mac.getInstance(HKDF_ALGORITHM)
        mac.init(SecretKeySpec(hmacKey, HKDF_ALGORITHM))
        val tag = mac.doFinal(ciphertext).copyOf(4)

        val result = ByteArray(20)
        System.arraycopy(ciphertext, 0, result, 0, 16)
        System.arraycopy(tag, 0, result, 16, 4)
        return result
    }

    /**
     * Overload to generate 20-byte EID directly from QR secret, routing ID, and domain ID.
     */
    fun generateEid(qrSecret: ByteArray, routingId: ByteArray, domainId: Int): ByteArray {
        val eidKey = endif(ikm = qrSecret, salt = ByteArray(0), info = byteArrayOf(1, 0, 0, 0), length = 64)
        val seed = generateSeed(routingId, domainId)
        return generateEid(eidKey, seed)
    }

    /**
     * Perform ECDH shared secret computation by delegating to [CryptoUtils].
     */
    fun recd(privy: ECPrivateKey, peerUncompressedOrDer: ByteArray): ByteArray {
        return CryptoUtils.computeECDHSecret(privy, peerUncompressedOrDer)
    }

    /**
     * Perform HKDF key derivation by delegating to [CryptoUtils].
     */
    fun endif(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        return CryptoUtils.hkdf(ikm, salt, info, length)
    }
}

/**
 * Manage Noise Protocol handshake state transitions, running digests, and key mixings.
 *
 * Implement Noise KNpsk0 and NKpsk0 handshake state machines to negotiate symmetric session keys
 * over unauthenticated web sockets prior to CTAP message exchange.
 */
class NoiseHandshakeState(mode: Int) {
    private val protocolName = when (mode) {
        2 -> "Noise_NKpsk0_P256_AESGCM_SHA256"
        3 -> "Noise_KNpsk0_P256_AESGCM_SHA256"
        else -> "Noise_NK_P256_AESGCM_SHA256"
    }

    private var handshakeHash: ByteArray = protocolName.toByteArray() + ByteArray(32 - protocolName.length)
    private var chainingKey: ByteArray = handshakeHash.clone()
    private var cipherKey: ByteArray? = null

    /**
     * Update running handshake digest with new message or key data.
     */
    fun mixHash(data: ByteArray) {
        handshakeHash = CryptoUtils.sha256(handshakeHash + data)
    }

    /**
     * Mix input key material into chaining key and derive new cipher key.
     */
    fun mixKey(inputKeyMaterial: ByteArray) {
        val (ck, k) = endif(chainingKey, inputKeyMaterial, 2)
        chainingKey = ck
        cipherKey = k
    }

    /**
     * Mix input key material into chaining key, mix temporary hash into running digest, and derive cipher key.
     */
    fun mixKeyAndHash(inputKeyMaterial: ByteArray) {
        val (ck, tempHash, k) = endif(chainingKey, inputKeyMaterial, 3)
        chainingKey = ck
        mixHash(tempHash)
        cipherKey = k
    }

    /**
     * Encrypt handshake payload with current cipher key and bind running handshake hash as AEAD data.
     */
    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val key = cipherKey ?: ByteArray(32)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, AEMK_ALGORITHM), GCMParameterSpec(128, ByteArray(12)))
            updateAAD(handshakeHash)
        }
        return cipher.doFinal(plaintext).also { ciphertext ->
            mixHash(ciphertext)
        }
    }

    /**
     * Decrypt incoming handshake payload using current cipher key and authenticate AEAD data.
     */
    fun decryptAndHash(ct: ByteArray): ByteArray {
        val key = cipherKey ?: ByteArray(32)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        val gcm = GCMParameterSpec(128, ByteArray(12))
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, AEMK_ALGORITHM), gcm)
        c.updateAAD(handshakeHash)
        val pt = c.doFinal(ct)
        mixHash(ct)
        return pt
    }

    /**
     * Split chaining key into reader and writer keys upon completing Noise handshake.
     */
    fun splitSessionKeys(): Pair<ByteArray, ByteArray> {
        val (k1, k2) = endif(chainingKey, ByteArray(0), 2)
        return k1 to k2
    }

    /**
     * Expand chaining key into multiple output keys using HKDF-Extract and HKDF-Expand rounds.
     */
    private fun endif(chainingKey: ByteArray, inputKeyMaterial: ByteArray, outputs: Int): List<ByteArray> {
        val prk = CryptoUtils.hkdfExtract(chainingKey, inputKeyMaterial)
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
}

/**
 * Handle symmetric AEAD encryption and decryption of transport frames post-handshake.
 *
 * Maintain incremental nonces for read/write directions to enforce replay protection over WebSocket frames.
 */
class NoiseCrypter(private val rKey: ByteArray, private val wKey: ByteArray) {
    private var rCtr = 0
    private var wCtr = 0

    /**
     * Encrypt transport frame bytes with incrementing write nonce and 32-byte block padding.
     */
    fun encrypt(plain: ByteArray): ByteArray? = try {
        val padded = pad32(plain)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(wKey, AEMK_ALGORITHM), GCMParameterSpec(128, nonce(wCtr++)))
        c.doFinal(padded)
    } catch (_: Throwable) {
        null
    }

    /**
     * Decrypt transport frame bytes with incrementing read nonce and unpad 32-byte blocks.
     */
    fun decrypt(cipher: ByteArray): ByteArray? = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(rKey, AEMK_ALGORITHM), GCMParameterSpec(128, nonce(rCtr++)))
        val padded = c.doFinal(cipher)
        unpad32(padded)
    } catch (_: Throwable) {
        null
    }

    private fun pad32(src: ByteArray): ByteArray {
        val block = 32
        val rem = src.size % block
        val pad = if (rem == 0) block else (block - rem)
        val out = ByteArray(src.size + pad)
        System.arraycopy(src, 0, out, 0, src.size)
        out[out.lastIndex] = (pad - 1).toByte()
        return out
    }

    private fun nonce(c: Int) = byteArrayOf(
        0, 0, 0, 0, 0, 0, 0, 0, ((c ushr 24) and 0xFF).toByte(), ((c ushr 16) and 0xFF).toByte(), ((c ushr 8) and 0xFF).toByte(), (c and 0xFF).toByte()
    )

    private fun unpad32(padded: ByteArray): ByteArray? {
        if (padded.isEmpty()) return null
        val padLen = (padded[padded.lastIndex].toInt() and 0xFF) + 1
        if (padLen < 1 || padLen > 32 || padLen > padded.size) return null
        val dataLen = padded.size - padLen
        return padded.copyOfRange(0, dataLen)
    }
}
