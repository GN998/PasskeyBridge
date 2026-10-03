package com.dev.fido.bridge.core.storage.repository

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.dev.fido.bridge.core.security.CryptoUtils
import com.dev.fido.bridge.core.storage.model.IdentityKeyPair
import com.dev.fido.bridge.core.storage.model.LinkingRecord
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Production implementation of [LinkingRepository] providing encrypted persistence for caBLE v2 state.
 *
 * Store paired client metadata securely using Android SharedPreferences with Base64URL-encoded entries
 * and manage the persistent P-256 Identity Key inside Android KeyStore (TEE/StrongBox) for hardware security.
 */
class EncryptedLinkingRepositoryImpl(
    context: Context,
    prefName: String = "cable_linking_store"
) : LinkingRepository {

    private val prefs: SharedPreferences = context.getSharedPreferences(prefName, Context.MODE_PRIVATE)
    private val keyStoreAlias = "fido_bridge_caBLE_identity_key"
    private val lock = Any()

    override fun getOrCreateIdentityKeyPair(): IdentityKeyPair = synchronized(lock) {
        return try {
            loadIdentityKeyFromKeyStore() ?: generateAndSaveIdentityKey()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to manage KeyStore identity key, falling back to software key", e)
            getOrCreateSoftwareIdentityKey()
        }
    }

    override fun saveLinkingRecord(record: LinkingRecord): Unit = synchronized(lock) {
        val records = getAllLinkingRecordsInternal().toMutableList()
        records.removeAll { 
            it.linkId.contentEquals(record.linkId) || 
            it.authenticatorPublicKey.contentEquals(record.authenticatorPublicKey) 
        }
        records.add(record)
        saveAllRecordsInternal(records)
    }

    override fun getLinkingRecordByLinkId(linkId: ByteArray): LinkingRecord? = synchronized(lock) {
        return getAllLinkingRecordsInternal().firstOrNull { it.linkId.contentEquals(linkId) }
    }

    override fun getLinkingRecordByContactId(contactId: ByteArray): LinkingRecord? = synchronized(lock) {
        return getAllLinkingRecordsInternal().firstOrNull { it.contactId.contentEquals(contactId) }
    }

    override fun getAllLinkingRecords(): List<LinkingRecord> = synchronized(lock) {
        return getAllLinkingRecordsInternal()
    }

    override fun removeLinkingRecord(linkId: ByteArray): Boolean = synchronized(lock) {
        val records = getAllLinkingRecordsInternal().toMutableList()
        val removed = records.removeAll { it.linkId.contentEquals(linkId) }
        if (removed) {
            saveAllRecordsInternal(records)
        }
        return removed
    }

    override fun clearAllLinkingRecords(): Unit = synchronized(lock) {
        prefs.edit().remove(KEY_LINKING_RECORDS).apply()
    }

    private fun getAllLinkingRecordsInternal(): List<LinkingRecord> {
        val rawJson = prefs.getString(KEY_LINKING_RECORDS, null) ?: return emptyList()
        return try {
            val jsonArray = JSONArray(rawJson)
            val result = mutableListOf<LinkingRecord>()
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                result.add(
                    LinkingRecord(
                        linkId = CryptoUtils.decodeBase64Url(obj.getString("linkId")),
                        linkSecret = CryptoUtils.decodeBase64Url(obj.getString("linkSecret")),
                        contactId = CryptoUtils.decodeBase64Url(obj.getString("contactId")),
                        authenticatorPublicKey = CryptoUtils.decodeBase64Url(obj.getString("authPubKey")),
                        authenticatorName = obj.getString("authName"),
                        tunnelServerDomain = obj.getString("domain"),
                        createdAtTimestamp = obj.optLong("createdAt", System.currentTimeMillis())
                    )
                )
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse linking records JSON", e)
            emptyList()
        }
    }

    private fun saveAllRecordsInternal(records: List<LinkingRecord>) {
        val jsonArray = JSONArray()
        for (r in records) {
            val obj = JSONObject().apply {
                put("linkId", CryptoUtils.encodeBase64UrlNoPadding(r.linkId))
                put("linkSecret", CryptoUtils.encodeBase64UrlNoPadding(r.linkSecret))
                put("contactId", CryptoUtils.encodeBase64UrlNoPadding(r.contactId))
                put("authPubKey", CryptoUtils.encodeBase64UrlNoPadding(r.authenticatorPublicKey))
                put("authName", r.authenticatorName)
                put("domain", r.tunnelServerDomain)
                put("createdAt", r.createdAtTimestamp)
            }
            jsonArray.put(obj)
        }
        prefs.edit().putString(KEY_LINKING_RECORDS, jsonArray.toString()).apply()
    }

    private fun loadIdentityKeyFromKeyStore(): IdentityKeyPair? {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!ks.containsAlias(keyStoreAlias)) return null

        val entry = ks.getEntry(keyStoreAlias, null) as? KeyStore.PrivateKeyEntry ?: return null
        val pubKey = entry.certificate.publicKey as? ECPublicKey ?: return null
        val privKey = entry.privateKey as? ECPrivateKey ?: return null

        val rawPub = exportUncompressedPublicKeyBytes(pubKey)
        return IdentityKeyPair(pubKey, privKey, rawPub)
    }

    private fun generateAndSaveIdentityKey(): IdentityKeyPair {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val spec = KeyGenParameterSpec.Builder(
            keyStoreAlias,
            KeyProperties.PURPOSE_AGREE_KEY or KeyProperties.PURPOSE_SIGN
        ).apply {
            setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            setDigests(KeyProperties.DIGEST_SHA256)
        }.build()

        kpg.initialize(spec)
        val kp = kpg.generateKeyPair()
        val pubKey = kp.public as ECPublicKey
        val privKey = kp.private as ECPrivateKey
        val rawPub = exportUncompressedPublicKeyBytes(pubKey)

        return IdentityKeyPair(pubKey, privKey, rawPub)
    }

    private fun getOrCreateSoftwareIdentityKey(): IdentityKeyPair {
        val pubBase64 = prefs.getString(KEY_SW_PUB_KEY, null)
        val privBase64 = prefs.getString(KEY_SW_PRIV_KEY, null)

        val kf = KeyFactory.getInstance("EC")
        if (pubBase64 != null && privBase64 != null) {
            try {
                val pubSpec = X509EncodedKeySpec(Base64.decode(pubBase64, Base64.DEFAULT))
                val privSpec = PKCS8EncodedKeySpec(Base64.decode(privBase64, Base64.DEFAULT))

                val pubKey = kf.generatePublic(pubSpec) as ECPublicKey
                val privKey = kf.generatePrivate(privSpec) as ECPrivateKey
                val rawPub = exportUncompressedPublicKeyBytes(pubKey)
                return IdentityKeyPair(pubKey, privKey, rawPub)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to load software identity key, generating new one", e)
            }
        }

        val kpg = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val kp = kpg.generateKeyPair()
        val pubKey = kp.public as ECPublicKey
        val privKey = kp.private as ECPrivateKey

        prefs.edit()
            .putString(KEY_SW_PUB_KEY, Base64.encodeToString(pubKey.encoded, Base64.NO_WRAP))
            .putString(KEY_SW_PRIV_KEY, Base64.encodeToString(privKey.encoded, Base64.NO_WRAP))
            .apply()

        val rawPub = exportUncompressedPublicKeyBytes(pubKey)
        return IdentityKeyPair(pubKey, privKey, rawPub)
    }

    private fun exportUncompressedPublicKeyBytes(pubKey: ECPublicKey): ByteArray {
        val w = pubKey.w
        val xBytes = w.affineX.toByteArray()
        val yBytes = w.affineY.toByteArray()

        val raw = ByteArray(65)
        raw[0] = 0x04
        val xOffset = Math.max(0, xBytes.size - 32)
        val xDestOffset = 1 + Math.max(0, 32 - xBytes.size)
        val xLen = Math.min(32, xBytes.size)
        System.arraycopy(xBytes, xOffset, raw, xDestOffset, xLen)

        val yOffset = Math.max(0, yBytes.size - 32)
        val yDestOffset = 33 + Math.max(0, 32 - yBytes.size)
        val yLen = Math.min(32, yBytes.size)
        System.arraycopy(yBytes, yOffset, raw, yDestOffset, yLen)

        return raw
    }

    companion object {
        private const val TAG = "EncryptedLinkingRepo"
        private const val KEY_LINKING_RECORDS = "key_cable_linking_records_v1"
        private const val KEY_SW_PUB_KEY = "key_sw_identity_pub_key"
        private const val KEY_SW_PRIV_KEY = "key_sw_identity_priv_key"
    }
}

