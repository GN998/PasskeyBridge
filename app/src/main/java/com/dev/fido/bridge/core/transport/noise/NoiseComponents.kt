package com.dev.fido.bridge.core.transport.noise

import com.dev.fido.bridge.core.security.toFixedLengthBytes
import java.math.BigInteger
import java.security.AlgorithmParameters
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

/**
 * Unpacked fields from a verified 16-byte caBLE v2 BLE proximity advertisement plaintext per CTAP 2.3 §11.5.1.1.
 */
data class DecryptedBleAdvert(
    val plaintext: ByteArray,
    val nonce: ByteArray,
    val routingId: ByteArray,
    val encodedTunnelServerDomain: Int
)

object CryptoHelper {
    private val secureRandom = SecureRandom()

    // Resolve P-256 curve parameters via AlgorithmParameters to avoid generating a throwaway keypair and consuming entropy on cold start
    private val secp256r1Params: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance(EC_ALGORITHM).apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
    }

    /**
     * Trigger lazy initialization of P-256 curve parameters and JCA providers during application startup.
     */
    fun warmup() {
        secp256r1Params
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
     * Compress JCA ECPublicKey into a 33-byte SEC1 point (0x02/0x03 || X) for QR CBOR Key 0 per CTAP 2.3 §11.5.1.1.
     */
    fun compressECKey(pub: ECPublicKey): ByteArray {
        val prefix: Byte = if (pub.w.affineY.testBit(0)) 0x03 else 0x02
        return byteArrayOf(prefix) + pub.w.affineX.toFixedLengthBytes(32)
    }

    /**
     * Decompress and validate 33-byte SEC1 compressed EC public key from QR payload into 65-byte uncompressed format per CTAP 2.3 §11.5.1.
     */
    fun decompressECKey(compressed: ByteArray): ByteArray {
        require(compressed.size == 33 && (compressed[0] == 0x02.toByte() || compressed[0] == 0x03.toByte())) {
            "Peer public key must be a 33-byte SEC1 compressed P-256 point (0x02 or 0x03 prefix)"
        }

        val prefix = compressed[0].toInt() and 0xFF
        val xBytes = compressed.copyOfRange(1, 33)
        val x = BigInteger(1, xBytes)

        val p = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        require(x > BigInteger.ZERO && x < p) { "P-256 X coordinate out of prime field range" }

        val b = secp256r1Params.curve.b

        val x3 = x.modPow(BigInteger.valueOf(3), p)
        val ax = x.multiply(BigInteger.valueOf(3)).mod(p)
        val ySquared = x3.subtract(ax).add(b).mod(p)

        val exp = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4))
        var y = ySquared.modPow(exp, p)

        // Verify that ySquared is a valid quadratic residue mod p to prevent invalid curve attacks
        require(y.modPow(BigInteger.valueOf(2), p) == ySquared) {
            "Decompressed point does not lie on the secp256r1 curve"
        }

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

    /**
     * Trial-decrypt a candidate BLE service data payload (at least 20 bytes) using the 64-byte derived EID key
     * per CTAP 2.3 §11.5.1.1. Ignore trailing extended advertising suffix bytes if present.
     */
    fun trialDecryptEid(eidKey: ByteArray, candidateServiceData: ByteArray): DecryptedBleAdvert? {
        if (eidKey.size != 64 || candidateServiceData.size < 20) return null

        val hmacKey = eidKey.copyOfRange(32, 64)
        val mac = Mac.getInstance(HKDF_ALGORITHM)
        mac.init(SecretKeySpec(hmacKey, HKDF_ALGORITHM))
        mac.update(candidateServiceData, 0, 16)
        val expectedTag = mac.doFinal()

        // Constant-time 4-byte HMAC tag comparison
        var diff = 0
        for (i in 0 until 4) {
            diff = diff or (expectedTag[i].toInt() xor candidateServiceData[16 + i].toInt())
        }
        if (diff != 0) return null

        val aesKey = eidKey.copyOfRange(0, 32)
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, AEMK_ALGORITHM), IvParameterSpec(ByteArray(16)))
        val plaintext = cipher.doFinal(candidateServiceData, 0, 16)

        // Reject advertisement if reserved flags byte (byte 0) is non-zero per CTAP 2.3 §11.5.1.1
        if (plaintext[0] != 0x00.toByte()) return null

        val nonce = plaintext.copyOfRange(1, 11)
        val routingId = plaintext.copyOfRange(11, 14)
        val encodedDomain = (plaintext[14].toInt() and 0xFF) or ((plaintext[15].toInt() and 0xFF) shl 8)

        return DecryptedBleAdvert(
            plaintext = plaintext,
            nonce = nonce,
            routingId = routingId,
            encodedTunnelServerDomain = encodedDomain
        )
    }

    /**
     * Perform P-256 ECDH key agreement strictly against a 65-byte X9.62 uncompressed peer point per CTAP 2.3 Hybrid specification.
     */
    fun recd(privy: ECPrivateKey, peerUncompressed: ByteArray): ByteArray {
        require(peerUncompressed.size == 65 && peerUncompressed[0] == 0x04.toByte()) {
            "Peer public key must be a 65-byte uncompressed P-256 point"
        }
        val x = BigInteger(1, peerUncompressed.copyOfRange(1, 33))
        val y = BigInteger(1, peerUncompressed.copyOfRange(33, 65))
        val spec = ECPublicKeySpec(ECPoint(x, y), secp256r1Params)
        val pub = KeyFactory.getInstance(EC_ALGORITHM).generatePublic(spec) as ECPublicKey

        return KeyAgreement.getInstance("ECDH").run {
            init(privy)
            doPhase(pub, true)
            generateSecret()
        }
    }

    /**
     * Execute AES-256-GCM encryption or decryption to unify cipher initialization across Noise handshake and transport phases.
     */
    fun aesGcm(mode: Int, key: ByteArray, nonce: ByteArray, input: ByteArray, aad: ByteArray? = null): ByteArray {
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(mode, SecretKeySpec(key, AEMK_ALGORITHM), GCMParameterSpec(128, nonce))
            if (aad != null) updateAAD(aad)
            doFinal(input)
        }
    }

    /**
     * Compute RFC 5869 HKDF-Extract and HKDF-Expand reusing a single Mac instance to halve JCA provider lookups.
     */
    fun endif(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance(HKDF_ALGORITHM)
        val s = if (salt.isEmpty()) ByteArray(32) else salt
        mac.init(SecretKeySpec(s, HKDF_ALGORITHM))
        val prk = mac.doFinal(ikm)

        val glen = 32
        val rounds = ceil(length / glen.toDouble()).toInt()
        mac.init(SecretKeySpec(prk, HKDF_ALGORITHM))

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

class NoiseHandshakeState {
    // Reuse a single SHA-256 MessageDigest instance across all mixHash calls within the handshake session
    private val sha256 = MessageDigest.getInstance("SHA-256")
    // Initialize 32-byte Noise protocol name buffer for QR-initiated KNpsk0 handshakes per CTAP 2.3 §11.5.1.2
    private var handshakeHash: ByteArray = "Noise_KNpsk0_P256_AESGCM_SHA256".toByteArray(Charsets.US_ASCII).copyOf(32)
    private var chainingKey: ByteArray = handshakeHash.copyOf()
    private var cipherKey: ByteArray? = null

    fun mixHash(data: ByteArray) {
        sha256.update(handshakeHash)
        handshakeHash = sha256.digest(data)
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
        val key = checkNotNull(cipherKey) { "Handshake cipher key not initialized" }
        return CryptoHelper.aesGcm(Cipher.ENCRYPT_MODE, key, ByteArray(12), plaintext, handshakeHash).also {
            mixHash(it)
        }
    }

    fun splitSessionKeys(): Pair<ByteArray, ByteArray> {
        val (k1, k2) = hkdfOutputs(chainingKey, ByteArray(0), 2)
        return k1 to k2
    }

    fun decryptAndHash(ct: ByteArray): ByteArray {
        val key = checkNotNull(cipherKey) { "Handshake cipher key not initialized" }
        return CryptoHelper.aesGcm(Cipher.DECRYPT_MODE, key, ByteArray(12), ct, handshakeHash).also {
            mixHash(ct)
        }
    }

    /**
     * Derive 32-byte Noise chaining and cipher keys by delegating to RFC 5869 HKDF with empty info.
     */
    private fun hkdfOutputs(chainingKey: ByteArray, inputKeyMaterial: ByteArray, outputs: Int): List<ByteArray> {
        val derived = CryptoHelper.endif(
            ikm = inputKeyMaterial,
            salt = chainingKey,
            info = ByteArray(0),
            length = outputs * 32
        )
        return List(outputs) { i -> derived.copyOfRange(i * 32, (i + 1) * 32) }
    }
}

class NoiseCrypter(private val rKey: ByteArray, private val wKey: ByteArray) {
    private var rCtr = 0
    private var wCtr = 0

    /**
     * Pad and encrypt transport payload with AES-256-GCM.
     * Synchronize counter increment across OkHttp reader and Dispatchers.IO coroutine threads.
     */
    @Synchronized
    fun encrypt(plain: ByteArray): ByteArray {
        val padded = pad32(plain)
        return CryptoHelper.aesGcm(Cipher.ENCRYPT_MODE, wKey, nonce(wCtr++), padded)
    }

    /**
     * Authenticate, decrypt, and unpad transport ciphertext with AES-256-GCM.
     * Throw GeneralSecurityException if GCM tag verification or 32-byte padding validation fails.
     */
    @Synchronized
    fun decrypt(cipher: ByteArray): ByteArray {
        val padded = CryptoHelper.aesGcm(Cipher.DECRYPT_MODE, rKey, nonce(rCtr++), cipher)
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
        if (padLen > 32 || padLen > padded.size) return null
        val dataLen = padded.size - padLen
        return padded.copyOfRange(0, dataLen)
    }
}