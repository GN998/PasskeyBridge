package com.dev.fido.bridge.core.security

import android.util.Base64
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
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
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil

/**
 * Provide unified cryptographic primitives and encoding utilities across FIDO CTAP and transport modules.
 *
 * Centralize cryptographic operations (SHA-256, Base64URL, HKDF, ECDH, EC key decompression) in core:security
 * to eliminate duplicate algorithm implementations and ensure consistent security boundaries across the codebase.
 */
object CryptoUtils {

    private const val HKDF_ALGORITHM = "HmacSHA256"
    private const val EC_ALGORITHM = "EC"
    private const val AES_ALGORITHM = "AES"

    /**
     * Encode binary data into URL-safe Base64 representation without padding.
     *
     * Format client data hashes, credential IDs, and authenticator parameters into URL-safe strings
     * required by WebAuthn and CredentialManager API payloads.
     */
    fun encodeBase64UrlNoPadding(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    /**
     * Decode URL-safe Base64 strings into raw byte arrays safely without truncation.
     *
     * Sanitize Base64URL input strings by removing whitespace, restoring standard URL-safe padding,
     * and employing URL_SAFE decoding flags with fallback logic to prevent premature character truncation
     * during WebAuthn assertion signature parsing.
     */
    fun decodeBase64Url(base64Str: String): ByteArray {
        var cleanStr = base64Str.trim().replace('-', '+').replace('_', '/')
        val pad = cleanStr.length % 4
        if (pad > 0) {
            cleanStr += "=".repeat(4 - pad)
        }
        return try {
            Base64.decode(cleanStr, Base64.URL_SAFE or Base64.NO_WRAP)
        } catch (_: Exception) {
            Base64.decode(cleanStr, Base64.DEFAULT or Base64.NO_WRAP)
        }
    }

    /**
     * Calculate SHA-256 digest over given binary payload.
     */
    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

    /**
     * Derive cryptographically strong key material using HKDF (RFC 5869) with HMAC-SHA256.
     *
     * Combine HKDF-Extract and HKDF-Expand into a single call to generate session keys, tunnel IDs,
     * and Noise protocol preshared keys from input keying material (IKM).
     */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hkdfExtract(salt, ikm)
        return hkdfExpand(prk, info, length)
    }

    /**
     * Perform HKDF-Extract step to produce a pseudo-random key (PRK) from salt and input keying material.
     */
    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val actualSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val mac = Mac.getInstance(HKDF_ALGORITHM).apply { init(SecretKeySpec(actualSalt, HKDF_ALGORITHM)) }
        return mac.doFinal(ikm)
    }

    /**
     * Perform HKDF-Expand step to expand pseudo-random key (PRK) to desired byte length.
     */
    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hashLen = 32
        val rounds = ceil(length / hashLen.toDouble()).toInt()
        val mac = Mac.getInstance(HKDF_ALGORITHM).apply { init(SecretKeySpec(prk, HKDF_ALGORITHM)) }

        val out = ByteArray(length)
        var prev = ByteArray(0)
        repeat(rounds) { i ->
            mac.reset()
            if (prev.isNotEmpty()) mac.update(prev)
            mac.update(info)
            mac.update((i + 1).toByte())
            prev = mac.doFinal()
            val copy = minOf(hashLen, length - i * hashLen)
            System.arraycopy(prev, 0, out, i * hashLen, copy)
        }
        return out
    }

    /**
     * Decompress 33-byte secp256r1 EC public key into 65-byte uncompressed format (0x04 || X || Y).
     *
     * Reconstruct the Y coordinate on curve secp256r1 using modular square root calculation
     * because standard Java Security KeyFactory requires uncompressed point representation.
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
     * Compute raw ECDH shared secret between local private key and peer public key.
     *
     * Support raw uncompressed points as well as DER SubjectPublicKeyInfo encoded representations
     * to seamlessly interoperate with various browser and authenticator implementations.
     */
    fun computeECDHSecret(privateKey: ECPrivateKey, peerPublicKeyBytes: ByteArray): ByteArray {
        val pubKey = try {
            if (peerPublicKeyBytes.size == 65 && peerPublicKeyBytes[0] == 0x04.toByte()) {
                val x = peerPublicKeyBytes.sliceArray(1..32)
                val y = peerPublicKeyBytes.sliceArray(33..64)
                val kg = KeyPairGenerator.getInstance(EC_ALGORITHM).apply { initialize(ECGenParameterSpec("secp256r1")) }
                val tmp = (kg.generateKeyPair().public as ECPublicKey).params
                val spec = ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), tmp)
                KeyFactory.getInstance(EC_ALGORITHM).generatePublic(spec) as ECPublicKey
            } else {
                KeyFactory.getInstance(EC_ALGORITHM).generatePublic(X509EncodedKeySpec(peerPublicKeyBytes)) as ECPublicKey
            }
        } catch (_: Throwable) {
            val derPrefix = byteArrayOf(
                0x30, 89, 0x30, 19, 0x06, 7, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 8, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 66, 0
            )
            val full = derPrefix + peerPublicKeyBytes
            KeyFactory.getInstance(EC_ALGORITHM).generatePublic(X509EncodedKeySpec(full)) as ECPublicKey
        }

        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(pubKey, true)
        return keyAgreement.generateSecret()
    }
}
