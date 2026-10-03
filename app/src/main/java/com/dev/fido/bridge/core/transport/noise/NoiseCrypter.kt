package com.dev.fido.bridge.core.transport.noise

import com.dev.fido.bridge.core.security.AES_ALGORITHM
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encapsulate transport layer AES-128-GCM encryption and decryption with 32-byte alignment padding per caBLE specification.
 */
class NoiseCrypter(
    private val readKey: ByteArray,
    private val writeKey: ByteArray
) {
    private var readCounter = 0
    private var writeCounter = 0

    /**
     * Pad plaintext to 32-byte boundary and encrypt using AES-GCM with incrementing write nonce.
     */
    fun encrypt(plain: ByteArray): ByteArray? = try {
        val padded = pad32(plain)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(writeKey, AES_ALGORITHM), GCMParameterSpec(128, buildNonce(writeCounter++)))
        c.doFinal(padded)
    } catch (_: Throwable) {
        null
    }

    /**
     * Decrypt ciphertext frame using AES-GCM with incrementing read nonce and unpad 32-byte alignment bytes.
     */
    fun decrypt(cipher: ByteArray): ByteArray? = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(readKey, AES_ALGORITHM), GCMParameterSpec(128, buildNonce(readCounter++)))
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

    private fun unpad32(padded: ByteArray): ByteArray? {
        if (padded.isEmpty()) return null
        val padLen = (padded[padded.lastIndex].toInt() and 0xFF) + 1
        if (padLen < 1 || padLen > 32 || padLen > padded.size) return null
        val dataLen = padded.size - padLen
        return padded.copyOfRange(0, dataLen)
    }

    private fun buildNonce(counter: Int): ByteArray {
        return byteArrayOf(
            0, 0, 0, 0, 0, 0, 0, 0,
            ((counter ushr 24) and 0xFF).toByte(),
            ((counter ushr 16) and 0xFF).toByte(),
            ((counter ushr 8) and 0xFF).toByte(),
            (counter and 0xFF).toByte()
        )
    }
}
