package com.dev.fido.bridge.core.storage.model

import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

/**
 * Holds the authenticator device's persistent NIST P-256 EC identity key pair.
 *
 * Use this identity key across caBLE v2 sessions to sign linking updates and authenticate
 * state-assisted transactions, ensuring client platforms can verify device identity and deduplicate links.
 *
 * @property publicKey Uncompressed EC public key instance.
 * @property privateKey Corresponding EC private key instance.
 * @property rawPublicKey 65-byte X9.62 uncompressed binary representation (0x04 || X || Y).
 */
data class IdentityKeyPair(
    val publicKey: ECPublicKey,
    val privateKey: ECPrivateKey,
    val rawPublicKey: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IdentityKeyPair
        if (publicKey != other.publicKey) return false
        if (privateKey != other.privateKey) return false
        return rawPublicKey.contentEquals(other.rawPublicKey)
    }

    override fun hashCode(): Int {
        var result = publicKey.hashCode()
        result = 31 * result + privateKey.hashCode()
        result = 31 * result + rawPublicKey.contentHashCode()
        return result
    }
}
