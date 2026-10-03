package com.dev.fido.bridge.feature.session

import android.content.Context
import android.util.Log
import com.dev.fido.bridge.BuildConfig
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.proxy.CredentialManagerProxy
import com.dev.fido.bridge.core.storage.model.IdentityKeyPair
import com.dev.fido.bridge.core.storage.model.LinkingRecord
import com.dev.fido.bridge.core.storage.repository.EncryptedLinkingRepositoryImpl
import com.dev.fido.bridge.core.storage.repository.LinkingRepository
import com.dev.fido.bridge.core.transport.TransportManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/**
 * Orchestrate caBLE v2 Passkey session lifecycle across transport, cryptography, storage, and CredentialManager.
 *
 * Serve as the central facade for coordinating QR-initiated ad-hoc transactions and State-assisted
 * re-connections, maintaining unified session state and persisting client pairing metadata.
 */
class BridgeSessionController(
    private val context: Context,
    private val transportManager: TransportManager? = null,
    private val linkingRepository: LinkingRepository = EncryptedLinkingRepositoryImpl(context)
) {
    private val proxy = CredentialManagerProxy(context)
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    private val _sessionState = MutableStateFlow<BridgeSessionState>(BridgeSessionState.Idle)
    
    /**
     * Expose an observable flow of session lifecycle state transitions.
     */
    val sessionState: StateFlow<BridgeSessionState> = _sessionState.asStateFlow()

    /**
     * Maintain backward compatibility with text-based status listeners.
     */
    var onStatusUpdate: ((String) -> Unit)? = null

    init {
        transportManager?.onStatusUpdate = { status ->
            scope.launch {
                onStatusUpdate?.invoke(status)
                if (status.contains("Handshake Success")) {
                    _sessionState.value = BridgeSessionState.HandshakeCompleted
                } else if (status.contains("BLE Advertising Started") || status.contains("WebSocket Tunnel Connected")) {
                    _sessionState.value = BridgeSessionState.TransportConnected
                } else if (status.contains("Error")) {
                    _sessionState.value = BridgeSessionState.Error(status)
                }
            }
        }
    }

    /**
     * Launch a KNpsk0 caBLE session initialized by scanning a client platform QR code.
     *
     * Derive tunnel keys, open a WebSocket tunnel, broadcast a 20-byte BLE EID, and dispatch incoming
     * CTAP requests to CredentialManager.
     *
     * @param peerPublicKey Client platform ephemeral public key extracted from QR.
     * @param psk 32-byte pre-shared secret extracted from QR.
     * @param domainId Target caBLE tunnel server domain identifier.
     */
    fun onQrCodeScanned(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int = BuildConfig.TUNNEL_ID
    ) {
        _sessionState.value = BridgeSessionState.QrSessionInitiated(domainId)

        transportManager?.startQrSession(peerPublicKey, psk, domainId) { rawCtapRequest ->
            processRawCtapRequest(rawCtapRequest)
        }
    }

    /**
     * Launch a State-assisted reconnection session for a previously paired client platform.
     *
     * Query persistent pairing record by linkId, retrieve hardware-backed IdentityKey, initialize
     * NKpsk0 Noise handshake, and broadcast a 15-byte BLE Nonce without requiring a QR scan.
     *
     * @param linkId 8-byte pairing identifier.
     */
    fun startStateAssistedSession(linkId: ByteArray) {
        val record = linkingRepository.getLinkingRecordByLinkId(linkId)
        if (record == null) {
            val errorMsg = "No persistent pairing record found for linkId: ${linkId.joinToString("") { "%02x".format(it) }}"
            Log.e(TAG, errorMsg)
            _sessionState.value = BridgeSessionState.Error(errorMsg)
            return
        }

        val identityKey = linkingRepository.getOrCreateIdentityKeyPair()
        startStateAssistedSessionInternal(record, identityKey)
    }

    /**
     * Launch a State-assisted reconnection session matching a given push notification contactId.
     *
     * Query persistent pairing record by contactId, retrieve hardware-backed IdentityKey, and launch session.
     *
     * @param contactId Push notification contact token bytes.
     */
    fun startStateAssistedSessionByContactId(contactId: ByteArray) {
        val record = linkingRepository.getLinkingRecordByContactId(contactId)
        if (record == null) {
            val errorMsg = "No pairing record matched push contactId"
            Log.e(TAG, errorMsg)
            _sessionState.value = BridgeSessionState.Error(errorMsg)
            return
        }

        val identityKey = linkingRepository.getOrCreateIdentityKeyPair()
        startStateAssistedSessionInternal(record, identityKey)
    }

    /**
     * Persist or update a caBLE v2 client pairing record after establishing a new connection.
     *
     * Save metadata to encrypted storage and notify state observers of pairing persistence.
     *
     * @param record Pairing metadata to persist in secure storage.
     */
    fun savePairing(record: LinkingRecord) {
        linkingRepository.saveLinkingRecord(record)
        _sessionState.value = BridgeSessionState.PairingPersisted(record)
        Log.d(TAG, "Persisted client pairing record for linkId: ${record.linkIdHex}")
    }

    /**
     * Query all active client pairing records persisted on this device.
     */
    fun getActivePairings(): List<LinkingRecord> {
        return linkingRepository.getAllLinkingRecords()
    }

    /**
     * Stop active BLE advertising, disconnect WebSocket tunnels, and reset state to Idle.
     */
    fun stopSession() {
        transportManager?.stopSession()
        _sessionState.value = BridgeSessionState.Idle
        Log.d(TAG, "Bridge session stopped.")
    }

    /**
     * Execute internal State-assisted session launch logic.
     */
    private fun startStateAssistedSessionInternal(
        record: LinkingRecord,
        identityKey: IdentityKeyPair
    ) {
        _sessionState.value = BridgeSessionState.StateAssistedSessionInitiated(record.linkId)

        transportManager?.startStateAssistedSession(record, identityKey) { rawCtapRequest ->
            processRawCtapRequest(rawCtapRequest)
        }
    }

    /**
     * Decode incoming CTAP2 request, dispatch execution to CredentialManager on Main thread, and encode response.
     */
    private fun processRawCtapRequest(rawCtapRequest: ByteArray): ByteArray {
        var responseBytes = byteArrayOf(CtapStatus.ERR_OPERATION_DENIED)

        try {
            val parsedRequest = CtapCodec.decodeRequest(rawCtapRequest)
            val commandName = when (parsedRequest) {
                is Ctap2Request.GetInfo -> "GetInfo"
                is Ctap2Request.MakeCredential -> "MakeCredential"
                is Ctap2Request.GetAssertion -> "GetAssertion"
            }

            scope.launch {
                _sessionState.value = BridgeSessionState.ProcessingCtapRequest(commandName)
            }

            val response = runBlocking(Dispatchers.Main) {
                proxy.handleCtapRequest(parsedRequest)
            }

            responseBytes = CtapCodec.encodeResponse(response)
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "Invalid CTAP request format", e)
            responseBytes = byteArrayOf(CtapStatus.ERR_INVALID_CBOR)
            scope.launch {
                _sessionState.value = BridgeSessionState.Error("Invalid CTAP CBOR format", e)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Unhandled exception during CTAP request execution", e)
            responseBytes = byteArrayOf(CtapStatus.ERR_OPERATION_DENIED)
            scope.launch {
                _sessionState.value = BridgeSessionState.Error("CTAP execution failed: ${e.message}", e)
            }
        }

        return responseBytes
    }

    companion object {
        private const val TAG = "BridgeSessionController"
    }
}
