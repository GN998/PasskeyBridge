package com.dev.fido.bridge.core.security

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.dev.fido.bridge.core.hybrid.LinkRecord
import com.dev.fido.bridge.core.hybrid.StateAssistedCodec
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import com.dev.fido.bridge.core.transport.noise.EC_ALGORITHM
import com.dev.fido.bridge.core.transport.noise.HKDF_ALGORITHM
import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Persist authenticator identity keys, WebPush credentials, and linked desktop secrets using Android Keystore encryption.
 * Prevent plaintext extraction of long-term link secrets or authenticator private keys on rooted devices or backups.
 */
object LinkStore {
    private const val PREFS_NAME = "passkey_bridge_link_store"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val MASTER_KEY_ALIAS = "passkey_bridge_link_master_key"

    private const val KEY_CONTACT_ID_RAW = "enc_contact_id_raw"
    private const val KEY_AUTH_PUB_UNCOMPRESSED = "enc_auth_pub"
    private const val KEY_AUTH_PRIV_SCALAR = "enc_auth_priv"
    private const val KEY_WEBPUSH_PUB_B64 = "enc_webpush_pub"
    private const val KEY_WEBPUSH_PRIV_SCALAR = "enc_webpush_priv"
    private const val KEY_WEBPUSH_AUTH_B64 = "enc_webpush_auth"
    private const val KEY_VAPID_PUBLIC_KEY = "vapid_public_key"
    private const val KEY_PUSH_REGISTERED = "push_registered"
    private const val KEY_PUSH_ENDPOINT = "enc_push_endpoint"
    private const val KEY_LINK_RECORDS = "enc_link_records"

    private const val MAX_LINKED_CLIENTS = 32

    private val secureRandom = SecureRandom()
    private lateinit var prefs: SharedPreferences

    private val secp256r1Params: ECParameterSpec by lazy {
        val kpg = KeyPairGenerator.getInstance(EC_ALGORITHM).apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        (kpg.generateKeyPair().public as ECPublicKey).params
    }

    fun init(context: Context) {
        prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        ensureIdentityInitialized()
    }

    /**
     * Provision a 16-byte raw Contact ID and long-term P-256 authenticator key pair on first launch.
     */
    @Synchronized
    private fun ensureIdentityInitialized() {
        if (getDecryptedBytes(KEY_CONTACT_ID_RAW) == null) {
            val rawContactId = ByteArray(16).also { secureRandom.nextBytes(it) }
            putEncryptedBytes(KEY_CONTACT_ID_RAW, rawContactId)
        }

        if (getDecryptedBytes(KEY_AUTH_PRIV_SCALAR) == null || getDecryptedBytes(KEY_AUTH_PUB_UNCOMPRESSED) == null) {
            val (pub, priv) = CryptoHelper.generateEcKeyPair()
            putEncryptedBytes(KEY_AUTH_PUB_UNCOMPRESSED, CryptoHelper.uncompressECKey(pub))
            putEncryptedBytes(KEY_AUTH_PRIV_SCALAR, priv.s.toFixedLengthBytes(32))
        }

        if (getDecryptedBytes(KEY_WEBPUSH_PRIV_SCALAR) == null) {
            val wpKeys = WebPushCrypto.generateSubscriptionKeys()
            putEncryptedBytes(KEY_WEBPUSH_PUB_B64, wpKeys.p256dhPublicKeyB64.toByteArray(Charsets.US_ASCII))
            putEncryptedBytes(KEY_WEBPUSH_PRIV_SCALAR, wpKeys.p256dhPrivateKeyScalar)
            putEncryptedBytes(KEY_WEBPUSH_AUTH_B64, wpKeys.authSecretB64.toByteArray(Charsets.US_ASCII))
        }
    }

    /**
     * Return raw Contact ID bytes to embed in UpdateMessage CBOR Key 1.
     * Desktop clients Base64Url-encode these bytes when constructing `/cable/contact/<contact_id>`.
     */
    fun getContactIdRawBytes(): ByteArray {
        ensureIdentityInitialized()
        return checkNotNull(getDecryptedBytes(KEY_CONTACT_ID_RAW))
    }

    /**
     * Return the Base64Url-encoded Contact ID string used in `/cable/register/<contact_id>` and `/cable/contact/<contact_id>`.
     */
    fun getContactIdString(): String = CryptoUtils.encodeBase64UrlNoPadding(getContactIdRawBytes())

    /**
     * Rotate the Contact ID and generate fresh WebPush keys after an explicit unlink or HTTP 410 expiration.
     */
    @Synchronized
    fun rotateContactIdentity(): String {
        val rawContactId = ByteArray(16).also { secureRandom.nextBytes(it) }
        putEncryptedBytes(KEY_CONTACT_ID_RAW, rawContactId)

        val wpKeys = WebPushCrypto.generateSubscriptionKeys()
        putEncryptedBytes(KEY_WEBPUSH_PUB_B64, wpKeys.p256dhPublicKeyB64.toByteArray(Charsets.US_ASCII))
        putEncryptedBytes(KEY_WEBPUSH_PRIV_SCALAR, wpKeys.p256dhPrivateKeyScalar)
        putEncryptedBytes(KEY_WEBPUSH_AUTH_B64, wpKeys.authSecretB64.toByteArray(Charsets.US_ASCII))

        setPushRegistered(false, null)
        return CryptoUtils.encodeBase64UrlNoPadding(rawContactId)
    }

    fun getAuthenticatorPublicKeyBytes(): ByteArray {
        ensureIdentityInitialized()
        return checkNotNull(getDecryptedBytes(KEY_AUTH_PUB_UNCOMPRESSED))
    }

    fun getAuthenticatorPrivateKey(): ECPrivateKey {
        ensureIdentityInitialized()
        val scalarBytes = checkNotNull(getDecryptedBytes(KEY_AUTH_PRIV_SCALAR))
        return reconstructPrivateKey(scalarBytes)
    }

    fun getWebPushPublicKeyB64(): String {
        ensureIdentityInitialized()
        return String(checkNotNull(getDecryptedBytes(KEY_WEBPUSH_PUB_B64)), Charsets.US_ASCII)
    }

    fun getWebPushPublicKeyUncompressed(): ByteArray =
        CryptoUtils.decodeBase64Url(getWebPushPublicKeyB64())

    fun getWebPushPrivateKey(): ECPrivateKey {
        ensureIdentityInitialized()
        val scalarBytes = checkNotNull(getDecryptedBytes(KEY_WEBPUSH_PRIV_SCALAR))
        return reconstructPrivateKey(scalarBytes)
    }

    fun getWebPushAuthSecretB64(): String {
        ensureIdentityInitialized()
        return String(checkNotNull(getDecryptedBytes(KEY_WEBPUSH_AUTH_B64)), Charsets.US_ASCII)
    }

    fun getWebPushAuthSecretBytes(): ByteArray =
        CryptoUtils.decodeBase64Url(getWebPushAuthSecretB64())

    fun setVapidPublicKey(vapidKey: String) {
        prefs.edit().putString(KEY_VAPID_PUBLIC_KEY, vapidKey.trim()).apply()
    }

    fun getVapidPublicKey(): String? = prefs.getString(KEY_VAPID_PUBLIC_KEY, null)

    fun setPushRegistered(registered: Boolean, endpoint: String?) {
        prefs.edit().putBoolean(KEY_PUSH_REGISTERED, registered).apply()
        if (endpoint != null) {
            putEncryptedBytes(KEY_PUSH_ENDPOINT, endpoint.toByteArray(Charsets.UTF_8))
        } else {
            prefs.edit().remove(KEY_PUSH_ENDPOINT).apply()
        }
    }

    fun isPushRegistered(): Boolean = prefs.getBoolean(KEY_PUSH_REGISTERED, false)

    fun getPushEndpoint(): String? =
        getDecryptedBytes(KEY_PUSH_ENDPOINT)?.let { String(it, Charsets.UTF_8) }

    /**
     * Create a new link record for a QR-initiated session and return the ready-to-send 0x02 UpdateMessage frame.
     * Compute the linking signature as HMAC-SHA256(ECDH(authStaticPriv, qrPeerUncompressedPub), handshakeHash) per PXP §6.2.
     */
    @Synchronized
    fun createLinkAndBuildUpdateFrame(
        qrPeerUncompressedPubKey: ByteArray,
        handshakeHash: ByteArray
    ): ByteArray {
        val linkId = ByteArray(8).also { secureRandom.nextBytes(it) }
        val linkSecret = ByteArray(32).also { secureRandom.nextBytes(it) }

        saveLinkRecord(
            LinkRecord(
                linkId = linkId,
                linkSecret = linkSecret,
                createdAtEpochMs = System.currentTimeMillis()
            )
        )

        val sharedKey = CryptoHelper.recd(getAuthenticatorPrivateKey(), qrPeerUncompressedPubKey)
        val mac = Mac.getInstance(HKDF_ALGORITHM).apply {
            init(SecretKeySpec(sharedKey, HKDF_ALGORITHM))
        }
        val signature = mac.doFinal(handshakeHash)

        val deviceName = Build.MODEL?.takeIf { it.isNotBlank() } ?: "Android Authenticator"

        return StateAssistedCodec.encodeUpdateMessageFrame(
            contactIdRawBytes = getContactIdRawBytes(),
            linkId = linkId,
            linkSecret = linkSecret,
            authenticatorPublicKey = getAuthenticatorPublicKeyBytes(),
            authenticatorName = deviceName,
            handshakeSignature = signature
        )
    }

    /**
     * Look up the 32-byte link secret corresponding to the 8-byte link ID received in X-caBLE-Client-Payload.
     */
    @Synchronized
    fun findLinkSecret(linkId: ByteArray): ByteArray? {
        return loadAllLinkRecords().firstOrNull { it.linkId.contentEquals(linkId) }?.linkSecret
    }

    @Synchronized
    fun clearAllLinks() {
        prefs.edit().remove(KEY_LINK_RECORDS).apply()
    }

    @Synchronized
    private fun saveLinkRecord(newRecord: LinkRecord) {
        val existing = loadAllLinkRecords()
            .filterNot { it.linkId.contentEquals(newRecord.linkId) }
            .toMutableList()
        existing.add(0, newRecord)

        // Evict oldest link records beyond MAX_LINKED_CLIENTS to bound encrypted storage size.
        val trimmed = existing.take(MAX_LINKED_CLIENTS)
        val jsonArray = JSONArray()
        for (rec in trimmed) {
            jsonArray.put(
                JSONObject().apply {
                    put("id", rec.linkId.toHex())
                    put("secret", rec.linkSecret.toHex())
                    put("ts", rec.createdAtEpochMs)
                }
            )
        }
        putEncryptedBytes(KEY_LINK_RECORDS, jsonArray.toString().toByteArray(Charsets.UTF_8))
    }

    @Synchronized
    private fun loadAllLinkRecords(): List<LinkRecord> {
        val raw = getDecryptedBytes(KEY_LINK_RECORDS) ?: return emptyList()
        return try {
            val arr = JSONArray(String(raw, Charsets.UTF_8))
            buildList {
                for (i in 0 until arr.length()) {
                    val obj = arr.getJSONObject(i)
                    val id = obj.getString("id").hexToByteArray()
                    val secret = obj.getString("secret").hexToByteArray()
                    val ts = obj.optLong("ts", 0L)
                    if (id.size == 8 && secret.size == 32) {
                        add(LinkRecord(id, secret, ts))
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("LinkStore", "Failed to parse stored link records", e)
            emptyList()
        }
    }

    private fun reconstructPrivateKey(scalar32: ByteArray): ECPrivateKey {
        val s = BigInteger(1, scalar32)
        val spec = ECPrivateKeySpec(s, secp256r1Params)
        return KeyFactory.getInstance(EC_ALGORITHM).generatePrivate(spec) as ECPrivateKey
    }

    private fun getOrCreateMasterKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val existing = ks.getEntry(MASTER_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }

    private fun putEncryptedBytes(prefKey: String, plaintext: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMasterKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)

        val combined = ByteArray(1 + iv.size + ciphertext.size)
        combined[0] = iv.size.toByte()
        System.arraycopy(iv, 0, combined, 1, iv.size)
        System.arraycopy(ciphertext, 0, combined, 1 + iv.size, ciphertext.size)

        prefs.edit().putString(prefKey, CryptoUtils.encodeBase64UrlNoPadding(combined)).apply()
    }

    private fun getDecryptedBytes(prefKey: String): ByteArray? {
        val encoded = prefs.getString(prefKey, null) ?: return null
        return try {
            val combined = CryptoUtils.decodeBase64Url(encoded)
            val ivLen = combined[0].toInt() and 0xFF
            if (combined.size <= 1 + ivLen) return null
            val iv = combined.copyOfRange(1, 1 + ivLen)
            val ciphertext = combined.copyOfRange(1 + ivLen, combined.size)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateMasterKey(), GCMParameterSpec(128, iv))
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            Log.e("LinkStore", "Keystore decryption failed for key: $prefKey", e)
            null
        }
    }
}