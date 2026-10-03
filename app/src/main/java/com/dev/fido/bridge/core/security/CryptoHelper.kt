package com.dev.fido.bridge.core.security

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
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
const val AES_ALGORITHM = "AES"
const val EC_ALGORITHM = "EC"

/**
 * Provide cryptographic primitives for NIST P-256 ECDH, HKDF key derivation, and caBLE v2 EID generation.
 */
object CryptoHelper {

    /**
     * Decompress a 33-byte compressed SEC1 P-256 public key into 65-byte uncompressed format (0x04 || X || Y).
     * Solve the curve equation y^2 = x^3 - 3x + b (mod p) to recover the Y coordinate matching the prefix parity.
     */
    fun decompressECKey(compressed: ByteArray): ByteArray {
        if (compressed.size == 65 && compressed[0] == 0x04.toByte()) return compressed
        if (compressed.size != 33) return compressed

        val prefix = compressed[0].toInt()
        val xBytes = compressed.copyOfRange(1, 33)
        val x = BigInteger(1, xBytes)

        val spec = ECGenParameterSpec("secp256r1")
        val kpg = KeyPairGenerator.getInstance(EC_ALGORITHM).apply { initialize(spec) }
        val params = (kpg.generateKeyPair().public as ECPublicKey).params
        val p = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        val b = params.curve.b

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

        val uncompressed = ByteArray(65)
        uncompressed[0] = 0x04
        val yBytes = y.toByteArray()
        val yOffset = Math.max(0, yBytes.size - 32)
        val yDestOffset = 33 + Math.max(0, 32 - yBytes.size)
        val yLength = Math.min(32, yBytes.size)
        System.arraycopy(xBytes, 0, uncompressed, 1, 32)
        System.arraycopy(yBytes, yOffset, uncompressed, yDestOffset, yLength)

        return uncompressed
    }

    /**
     * Generate a 16-byte advertPlaintext seed bound to routing ID, current timestamp, and domain ID per CTAP 2.3.
     */
    fun generateSeed(routingId: ByteArray, domainId: Int): ByteArray {
        val seed = ByteArray(16)
        seed[0] = 0x00
        val timestamp = System.currentTimeMillis()
        val buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(timestamp)
        System.arraycopy(buffer.array(), 0, seed, 1, 8)
        System.arraycopy(routingId, 0, seed, 11, 3)
        seed[14] = (domainId and 0xFF).toByte()
        seed[15] = ((domainId ushr 8) and 0xFF).toByte()
        return seed
    }

    /**
     * Construct 20-byte BLE EID payload for ad-hoc caBLE v2 transactions using AES-CBC encryption and truncated HMAC-SHA256 tag.
     */
    fun generateEid(eidKey: ByteArray, seed: ByteArray): ByteArray {
        val aesKey = eidKey.copyOfRange(0, 32)
        val hmacKey = eidKey.copyOfRange(32, 64)

        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, AES_ALGORITHM), IvParameterSpec(ByteArray(16)))
        val ciphertext = cipher.doFinal(seed)

        val mac = Mac.getInstance(HKDF_ALGORITHM)
        mac.init(SecretKeySpec(hmacKey, HKDF_ALGORITHM))
        val tag = mac.doFinal(ciphertext).copyOf(4)

        val result = ByteArray(20)
        System.arraycopy(ciphertext, 0, result, 0, 16)
        System.arraycopy(tag, 0, result, 16, 4) // Wait, tag is mac.doFinal(ciphertext).copyOf(4), so tag[0..3]
        return result
    }

    /**
     * Convenience overload deriving 64-byte eidKey from QR secret before generating 20-byte EID payload.
     */
    fun generateEid(qrSecret: ByteArray, routingId: ByteArray, domainId: Int): ByteArray {
        val eidKey = hkdf(ikm = qrSecret, salt = ByteArray(0), info = byteArrayOf(1, 0, 0, 0), length = 64)
        val seed = generateSeed(routingId, domainId)
        return generateEid(eidKey, seed)
    }

    /**
     * Compute Elliptic Curve Diffie-Hellman (ECDH) shared secret between local private key and remote public key.
     * Support raw uncompressed SEC1 points (65 bytes) as well as X.509 DER encoded public keys.
     */
    fun computeEcdhSecret(privKey: ECPrivateKey, peerUncompressedOrDer: ByteArray): ByteArray {
        val pub = try {
            if (peerUncompressedOrDer.size == 65 && peerUncompressedOrDer[0] == 0x04.toByte()) {
                val x = peerUncompressedOrDer.sliceArray(1..32)
                val y = peerUncompressedOrDer.sliceArray(33..64)
                val kg = KeyPairGenerator.getInstance(EC_ALGORITHM).apply { initialize(ECGenParameterSpec("secp256r1")) }
                val tmp = (kg.generateKeyPair().public as ECPublicKey).params
                val spec = ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), tmp)
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
        ka.init(privKey)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    /**
     * Perform HKDF-SHA256 (Extract-and-Expand) key derivation per RFC 5869.
     */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hkdfExtract(salt, ikm)
        return hkdfExpand(prk, info, length)
    }

    /**
     * Extract pseudorandom key (PRK) from input key material and salt using HMAC-SHA256.
     */
    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val s = if (salt.isEmpty()) ByteArray(32) else salt
        val mac = Mac.getInstance(HKDF_ALGORITHM).apply { init(SecretKeySpec(s, HKDF_ALGORITHM)) }
        return mac.doFinal(ikm)
    }

    /**
     * Expand pseudorandom key (PRK) into required key output length using HMAC-SHA256.
     */
    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
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
