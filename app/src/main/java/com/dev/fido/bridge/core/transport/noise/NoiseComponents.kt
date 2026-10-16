package com.dev.fido.bridge.core.transport.noise

import com.dev.fido.bridge.core.security.toFixedLengthBytes
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil

const val HKDF_ALGORITHM = "HmacSHA256"
const val AEMK_ALGORITHM = "AES"
const val EC_ALGORITHM = "EC"

object CryptoHelper {
    private val secureRandom = SecureRandom()

    // Cache P-256 curve parameters once to avoid expensive dummy keypair generation on every ECDH/decompression call
    private val secp256r1Params: ECParameterSpec by lazy {
        val kpg = KeyPairGenerator.getInstance(EC_ALGORITHM).apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        (kpg.generateKeyPair().public as ECPublicKey).params
    }

    /**
     * Generate an ephemeral P-256 key pair reusing cached curve parameters.
     */
    fun generateEcKeyPair(): Pair<ECPublicKey, ECPrivateKey> {
        val kp = KeyPairGenerator.getInstance(EC_ALGORITHM).apply {
            initialize(secp256r1Params)
        }.generateKeyPair()
        return (kp.public as ECPublicKey) to (kp.private as ECPrivateKey)
    }

    /**
     * Encode P-256 affine coordinates into a 65-byte X9.62 uncompressed point (0x04 || X || Y).
     */
    fun encodeUncompressedPoint(x: BigInteger, y: BigInteger): ByteArray =
        byteArrayOf(0x04) + x.toFixedLengthBytes(32) + y.toFixedLengthBytes(32)

    /**
     * Convert JCA ECPublicKey into a 65-byte X9.62 uncompressed byte array for Noise handshake framing.
     */
    fun uncompressECKey(pub: ECPublicKey): ByteArray =
        encodeUncompressedPoint(pub.w.affineX, pub.w.affineY)

    /**
     * Decompress 33-byte SEC1 compressed EC public key from QR payload into 65-byte uncompressed format.
     */
    fun decompressECKey(compressed: ByteArray): ByteArray {
        if (compressed.size == 65 && compressed[0] == 0x04.toByte()) return compressed
        if (compressed.size != 33) return compressed

        val prefix = compressed[0].toInt()
        val xBytes = compressed.copyOfRange(1, 33)
        val x = BigInteger(1, xBytes)

        val p = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        val b = secp256r1Params.curve.b

        val x3 = x.modPow(BigInteger.valueOf(3), p)
        val ax = x.multiply(BigInteger.valueOf(3)).mod(p)
        val ySquared = x3.subtract(ax).add(b).mod(p)

        val exp = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4))
        var y = ySquared.modPow(exp, p)

        val isYEven = !y.testBit(0)
        val isPrefixEven = (prefix == 0x02)
        if (isYEven != isPrefixEven) {
            y = p.subtract(y)
        }

        return encodeUncompressedPoint(x, y)
    }

    // Populate a full 10-byte cryptographic random nonce (bytes 1..10) per CTAP 2.3 Hybrid specification to guarantee proximity entropy
    fun generateSeed(routingId: ByteArray, domainId: Int): ByteArray {
        val seed = ByteArray(16)
        seed[0] = 0x00 // Flags byte (reserved, must be zero)
        val nonce = ByteArray(10).also { secureRandom.nextBytes(it) }
        System.arraycopy(nonce, 0, seed, 1, 10)
        System.arraycopy(routingId, 0, seed, 11, minOf(routingId.size, 3))
        seed[14] = (domainId and 0xFF).toByte()
        seed[15] = ((domainId ushr 8) and 0xFF).toByte()
        return seed
    }

    // Generate standard 20-byte EID for caBLE v2 given derived 64-byte eidKey and 16-byte seed
    fun generateEid(eidKey: ByteArray, seed: ByteArray): ByteArray {
        val aesKey = eidKey.copyOfRange(0, 32)
        val hmacKey = eidKey.copyOfRange(32, 64)

        // Encrypt single 16-byte block using AES-256-ECB (equivalent to CBC with zero IV for a single block) per caBLE v2 spec
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

    fun recd(privy: ECPrivateKey, peerUncompressedOrDer: ByteArray): ByteArray {
        val pub = try {
            if (peerUncompressedOrDer.size == 65 && peerUncompressedOrDer[0] == 0x04.toByte()) {
                val x = peerUncompressedOrDer.sliceArray(1..32)
                val y = peerUncompressedOrDer.sliceArray(33..64)
                val spec = ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), secp256r1Params)
                KeyFactory.getInstance(EC_ALGORITHM).generatePublic(spec) as ECPublicKey
            } else {
                KeyFactory.getInstance(EC_ALGORITHM).generatePublic(X509EncodedKeySpec(peerUncompressedOrDer)) as ECPublicKey
            }
        } catch (_: Throwable) {
            val derPrefix = byteArrayOf(
                0x30, 89, 0x30, 19, 0x06, 7, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 8, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 66, 0
            )
            val full = derPrefix + peerUncompressedOrDer
            KeyFactory.getInstance(EC_ALGORITHM).generatePublic(X509EncodedKeySpec(full)) as ECPublicKey
        }

        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privy)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    fun endif(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hkdfExtract(salt, ikm)
        return endifExpand(prk, info, length)
    }

    /**
     * Compute RFC 5869 HKDF-Extract PRK shared by caBLE key derivation and Noise chaining key updates.
     */
    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val s = if (salt.isEmpty()) ByteArray(32) else salt
        val mac = Mac.getInstance(HKDF_ALGORITHM).apply { init(SecretKeySpec(s, HKDF_ALGORITHM)) }
        return mac.doFinal(ikm)
    }

    private fun endifExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val glen = 32
        val rounds = ceil(length / glen.toDouble()).toInt()
        val mac = Mac.getInstance(HKDF_ALGORITHM).apply { init(SecretKeySpec(prk, HKDF_ALGORITHM)) }

        val out = ByteArray(length)
        var prev = ByteArray(0)
        repeat(rounds) { i ->
            mac.reset()
            if (prev.isNotEmpty()) mac.update(prev)
            mac.update(info)
            mac.update((i + 1).toByte())
            prev = mac.doFinal()
            val copy = minOf(glen, length - i * glen)
            System.arraycopy(prev, 0, out, i * glen, copy)
        }
        return out
    }
}

class NoiseHandshakeState(mode: Int) {
    private val protocolName = when (mode) {
        2 -> "Noise_NKpsk0_P256_AESGCM_SHA256"
        3 -> "Noise_KNpsk0_P256_AESGCM_SHA256"
        else -> "Noise_NK_P256_AESGCM_SHA256"
    }

    private var handshakeHash: ByteArray = protocolName.toByteArray() + ByteArray(32 - protocolName.length)
    private var chainingKey: ByteArray = handshakeHash.clone()
    private var cipherKey: ByteArray? = null

    fun mixHash(data: ByteArray) {
        handshakeHash = MessageDigest.getInstance("SHA-256").run {
            update(handshakeHash)
            digest(data)
        }
    }

    fun mixKey(inputKeyMaterial: ByteArray) {
        val (ck, k) = hkdfOutputs(chainingKey, inputKeyMaterial, 2)
        chainingKey = ck
        cipherKey = k
    }

    fun mixKeyAndHash(inputKeyMaterial: ByteArray) {
        val (ck, tempHash, k) = hkdfOutputs(chainingKey, inputKeyMaterial, 3)
        chainingKey = ck
        mixHash(tempHash)
        cipherKey = k
    }

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

    fun splitSessionKeys(): Pair<ByteArray, ByteArray> {
        val (k1, k2) = hkdfOutputs(chainingKey, ByteArray(0), 2)
        return k1 to k2
    }

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

    private fun hkdfOutputs(chainingKey: ByteArray, inputKeyMaterial: ByteArray, outputs: Int): List<ByteArray> {
        val prk = CryptoHelper.hkdfExtract(chainingKey, inputKeyMaterial)
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

class NoiseCrypter(private val rKey: ByteArray, private val wKey: ByteArray) {
    private var rCtr = 0
    private var wCtr = 0

    /**
     * Pad and encrypt transport payload with AES-256-GCM.
     * Propagate cryptographic exceptions directly to prevent accidental plaintext fallback.
     */
    fun encrypt(plain: ByteArray): ByteArray {
        val padded = pad32(plain)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(wKey, AEMK_ALGORITHM), GCMParameterSpec(128, nonce(wCtr++)))
        return c.doFinal(padded)
    }

    /**
     * Authenticate, decrypt, and unpad transport ciphertext with AES-256-GCM.
     * Throw GeneralSecurityException if GCM tag verification or 32-byte padding validation fails.
     */
    fun decrypt(cipher: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(rKey, AEMK_ALGORITHM), GCMParameterSpec(128, nonce(rCtr++)))
        val padded = c.doFinal(cipher)
        return unpad32(padded) ?: throw GeneralSecurityException("Invalid caBLE transport padding")
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