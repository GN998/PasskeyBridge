package com.dev.fido.bridge.core.storage.repository

import com.dev.fido.bridge.core.storage.model.IdentityKeyPair
import com.dev.fido.bridge.core.storage.model.LinkingRecord

/**
 * Defines data storage contract for caBLE v2 pairing state and persistent identity keys.
 *
 * Decouple storage mechanics from protocol controllers to allow flexible persistence backends
 * (e.g., EncryptedSharedPreferences, Android KeyStore, or Room database) and enable easy mocking.
 */
interface LinkingRepository {

    /**
     * Retrieve existing device identity key pair or generate a fresh P-256 key pair in Android KeyStore.
     *
     * Ensure the identity key remains stable across application restarts to maintain persistent
     * trust relationships with linked client platforms per CTAP 2.3 §11.5.
     */
    fun getOrCreateIdentityKeyPair(): IdentityKeyPair

    /**
     * Persist or update a caBLE v2 linking record established during a QR transaction.
     *
     * Overwrite any existing record matching the same [LinkingRecord.linkId] or [LinkingRecord.authenticatorPublicKey]
     * to support key updates from client platforms.
     */
    fun saveLinkingRecord(record: LinkingRecord)

    /**
     * Query paired client linking record by its 8-byte link identifier.
     *
     * Use when processing incoming caBLE `X-caBLE-Client-Payload` headers on contact tunnels
     * to look up the associated `linkSecret` for state-assisted Noise NKpsk0 handshakes.
     */
    fun getLinkingRecordByLinkId(linkId: ByteArray): LinkingRecord?

    /**
     * Query paired client linking record by its relay contact identifier.
     *
     * Use when receiving incoming push notifications to determine which paired device context
     * initiated the state-assisted connection request.
     */
    fun getLinkingRecordByContactId(contactId: ByteArray): LinkingRecord?

    /**
     * Fetch all active pairing records currently stored on the device.
     */
    fun getAllLinkingRecords(): List<LinkingRecord>

    /**
     * Remove a single pairing link using its 8-byte link identifier.
     *
     * Invoke when client platform unlinks the authenticator or when receiving an HTTP 410 Gone error.
     */
    fun removeLinkingRecord(linkId: ByteArray): Boolean

    /**
     * Clear all stored pairing links and wipe persisted client relationships.
     */
    fun clearAllLinkingRecords()
}
