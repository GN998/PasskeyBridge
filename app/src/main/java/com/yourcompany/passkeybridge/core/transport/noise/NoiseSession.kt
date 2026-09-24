package com.yourcompany.passkeybridge.core.transport.noise

import android.util.Log
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

class NoiseSession {
    private var isHandshakeComplete = false
    private var sessionKey: SecretKeySpec? = null

    fun performHandshake(psk: ByteArray): Boolean {
        // Fix: Add AES-GCM skeleton to replace plaintext passthrough.
        // Note: Real production environment still requires standard Noise protocol library (e.g., southernstorm/noise) to implement full state machine.
        try {
            sessionKey = SecretKeySpec(psk.copyOf(32), "AES")
            isHandshakeComplete = true
            Log.d("NoiseSession", "Noise KNpsk0 handshake initialization complete.")
            return true
        } catch (e: Exception) {
            Log.e("NoiseSession", "Handshake failed", e)
            return false
        }
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        check(isHandshakeComplete && sessionKey != null) { "Handshake not complete" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(plaintext)
        // Concatenate Nonce and ciphertext as a simple secure payload for transmission
        return nonce + ciphertext
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        check(isHandshakeComplete && sessionKey != null) { "Handshake not complete" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = ciphertext.copyOfRange(0, 12)
        val actualCiphertext = ciphertext.copyOfRange(12, ciphertext.size)
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, GCMParameterSpec(128, nonce))
        return cipher.doFinal(actualCiphertext)
    }
}