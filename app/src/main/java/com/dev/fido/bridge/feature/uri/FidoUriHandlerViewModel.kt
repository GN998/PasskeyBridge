package com.dev.fido.bridge.feature.uri

import android.app.Application
import android.bluetooth.BluetoothManager
import android.content.Context
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.dev.fido.bridge.core.hybrid.HybridQrParser
import com.dev.fido.bridge.core.transport.TransportManager
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.feature.session.BridgeSessionController

/**
 * Manage FIDO session state and isolate background authentication workflows from the Activity UI layer.
 *
 * Encapsulate BLE advertisement setup, WebSocket transport lifecycle, and URI parsing inside an
 * AndroidViewModel to preserve ongoing authentication sessions across UI reconfigurations
 * (such as screen rotations) and prevent memory leaks.
 */
class FidoUriHandlerViewModel(application: Application) : AndroidViewModel(application) {

    private val _statusText = MutableLiveData<String>()
    val statusText: LiveData<String> get() = _statusText

    private var sessionController: BridgeSessionController? = null

    /**
     * Process an incoming FIDO URI deep-link and trigger cross-device passkey authentication.
     *
     * Extract caBLE parameters (peer public key and pre-shared secret) from the URI payload,
     * initialize transport hardware wrappers via application context, and start the Noise/BLE session.
     */
    fun processFidoUri(uriString: String?) {
        if (uriString.isNullOrBlank()) {
            _statusText.value = "No URI provided. Waiting for FIDO URI intent.\nMake sure you scan a valid FIDO QR code."
            return
        }

        _statusText.value = "FIDO URI Captured:\n$uriString\n\nParsing..."

        val qrData = HybridQrParser.parse(uriString)
        if (qrData == null) {
            appendStatus("Invalid or unsupported FIDO URI.")
            return
        }

        appendStatus("Parsed successfully. Routing to CTAP Dispatcher...")

        try {
            initializeAndStartSession(qrData.publicKey, qrData.secret, BuildConfig.TUNNEL_ID)
            appendStatus("Session initiated.\nBLE Advertising & WebSocket connecting...")
        } catch (e: Exception) {
            Log.e("FidoUriHandlerViewModel", "Failed to start FIDO session", e)
            appendStatus("Error starting session: ${e.message}")
        }
    }

    /**
     * Instantiate transport hardware managers using Application context to avoid Activity leaks.
     *
     * Retrieve system Bluetooth services safely, construct the BridgeSessionController,
     * and wire status callbacks to post observable LiveData updates to the UI.
     */
    private fun initializeAndStartSession(peerPublicKey: ByteArray, psk: ByteArray, domainId: Int) {
        // Terminate any stale transport channels before initiating a new authentication attempt
        sessionController?.stopSession()

        val bluetoothManager = getApplication<Application>().getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val bluetoothAdapter = bluetoothManager?.adapter
        val bleAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser

        val hybridBleAdvertiser = HybridBleAdvertiser(bleAdvertiser)
        val transportManager = TransportManager(hybridBleAdvertiser)

        sessionController = BridgeSessionController(
            context = getApplication(),
            transportManager = transportManager
        ).apply {
            onStatusUpdate = { status ->
                appendStatus(status)
            }
        }

        sessionController?.onQrCodeScanned(peerPublicKey, psk, domainId)
    }

    /**
     * Append log entries to LiveData for observable UI status rendering.
     */
    private fun appendStatus(status: String) {
        val current = _statusText.value ?: ""
        _statusText.postValue("$current\n➜ $status")
    }

    /**
     * Teardown active transport resources when ViewModel is cleared to prevent resource leaks.
     */
    override fun onCleared() {
        super.onCleared()
        sessionController?.stopSession()
        sessionController = null
    }
}
