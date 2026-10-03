package com.dev.fido.bridge.feature.session

import com.dev.fido.bridge.core.storage.model.LinkingRecord

/**
 * Represent discrete lifecycle states of a caBLE v2 Passkey Bridge session.
 *
 * Enable reactive state observation across UI layers and transport managers
 * during QR-initiated and State-assisted authentication transactions.
 */
sealed class BridgeSessionState {

    /**
     * Indicate that no active FIDO transaction is in progress.
     */
    object Idle : BridgeSessionState()

    /**
     * Indicate that a QR-initiated ad-hoc session has been started.
     *
     * @property domainId Target caBLE tunnel server domain identifier.
     */
    data class QrSessionInitiated(
        val domainId: Int
    ) : BridgeSessionState()

    /**
     * Indicate that a State-assisted reconnection session is being established for a paired client.
     *
     * @property linkId 8-byte pairing identifier associated with the client platform.
     */
    data class StateAssistedSessionInitiated(
        val linkId: ByteArray
    ) : BridgeSessionState() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as StateAssistedSessionInitiated
            return linkId.contentEquals(other.linkId)
        }

        override fun hashCode(): Int = linkId.contentHashCode()
    }

    /**
     * Indicate that WebSocket tunnel connection and BLE advertising are actively running.
     */
    object TransportConnected : BridgeSessionState()

    /**
     * Indicate that Noise cryptographic handshake (KNpsk0 or NKpsk0) completed successfully.
     */
    object HandshakeCompleted : BridgeSessionState()

    /**
     * Indicate that an incoming CTAP2 command is currently being processed by CredentialManager.
     *
     * @property commandName Human-readable CTAP command type (e.g., "MakeCredential", "GetAssertion").
     */
    data class ProcessingCtapRequest(
        val commandName: String
    ) : BridgeSessionState()

    /**
     * Indicate that a caBLE v2 pairing relationship was established and persisted.
     *
     * @property record Persistent pairing record containing keys and push identifiers.
     */
    data class PairingPersisted(
        val record: LinkingRecord
    ) : BridgeSessionState()

    /**
     * Indicate a fatal error encountered during transport setup, Noise cryptography, or CTAP execution.
     *
     * @property message Human-readable error description.
     * @property cause Optional underlying exception triggering the error.
     */
    data class Error(
        val message: String,
        val cause: Throwable? = null
    ) : BridgeSessionState()
}
