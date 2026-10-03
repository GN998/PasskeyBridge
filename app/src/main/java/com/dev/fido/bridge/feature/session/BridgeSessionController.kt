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
 * Coordinate caBLE v2 Passkey session lifecycle across transport, cryptography, storage, and CredentialManager.
 *
 * Serve as the single entry point for orchestrating QR-initiated ad-hoc transactions and State-assisted
 * re-connections, maintaining unified session state and persisting client pairing data.
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
     * Expose a observable flow of session lifecycle state transitions.
     */
    val sessionState: StateFlow<BridgeSessionState> = _sessionState.asStateFlow()

    /**
     * Backward-compatible callback for simple text status updates.
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
     * Process a scanned FIDO QR code payload and launch a KNpsk0 caBLE session.
     *
     * Derive tunnel keys, open WebSocket tunnel, broadcast 20-byte BLE EID, and dispatch incoming
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
     * Lookup persistent pairing record by linkId, initialize NKpsk0 Noise handshake, and broadcast
     * 15-byte BLE Nonce without requiring QR scan.
     *
     * @param linkId 8-byte pairing identifier.
     */
    fun startStateAssistedSession(linkId: ByteArray) {
        val record = linkingRepository.getLinkingRecord(linkId)
        if (record == null) {
            val errorMsg = "No persistent pairing record found for linkId: ${linkId.joinToString("") { "%02x".format(it) }}"
            Log.e(TAG, errorMsg)
            _sessionState.value = BridgeSessionState.Error(errorMsg)
            return
        }

        val identityKey = linkingRepository.getOrCreateDeviceIdentityKey()
        startStateAssistedSessionInternal(record, identityKey)
    }

    /**
     * Launch a State-assisted reconnection session matching a given push notification contactId.
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

        val identityKey = linkingRepository.getOrCreateDeviceIdentityKey()
        startStateAssistedSessionInternal(record, identityKey)
    }

    /**
     * Explicitly save or update a caBLE v2 client pairing record after successful initial transaction.
     *
     * @param record Pairing metadata to persist in secure storage.
     */
    fun savePairing(record: LinkingRecord) {
        linkingRepository.saveLinkingRecord(record)
        _sessionState.value = BridgeSessionState.PairingPersisted(record)
        Log.d(TAG, "Persisted client pairing record for linkId: ${record.linkIdHex}")
    }

    /**
     * Retrieve all active client pairing records persisted on this device.
     */
    fun getActivePairings(): List<LinkingRecord> {
        return linkingRepository.getAllLinkingRecords()
    }

    /**
     * Stop active BLE advertising, disconnect WebSocket tunnels, and return to idle state.
     */
    fun stopSession() {
        transportManager?.stopSession()
        _sessionState.value = BridgeSessionState.Idle
        Log.d(TAG, "Bridge session stopped.")
    }

    /**
     * Execute internal State-assisted session launch.
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
     * Decode CTAP2 request, dispatch to CredentialManager on Main thread, and encode response.
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

