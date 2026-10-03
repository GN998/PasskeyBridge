package com.dev.fido.bridge.feature.uri

import android.Manifest
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.dev.fido.bridge.core.hybrid.HybridQrParser
import com.dev.fido.bridge.core.storage.repository.EncryptedLinkingRepositoryImpl
import com.dev.fido.bridge.core.transport.TransportManager
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.feature.session.BridgeSessionController
import com.dev.fido.bridge.feature.session.BridgeSessionState
import kotlinx.coroutines.launch

/**
 * Handle incoming FIDO URIs, QR code intents, and caBLE v2 push notification triggers.
 *
 * Initialize transport layers, observe BridgeSessionState transitions reactively with lifecycle awareness,
 * and route incoming intents to either QR-initiated or State-assisted passkey bridge sessions.
 */
class FidoUriHandlerActivity : AppCompatActivity() {

    private lateinit var tvStatus: TextView
    private lateinit var sessionController: BridgeSessionController
    private val PERMISSION_REQUEST_CODE = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tvStatus = TextView(this).apply {
            text = "Passkey Bridge\nInitializing session..."
            textSize = 16f
            setPadding(40, 80, 40, 40)
        }
        setContentView(tvStatus)

        checkAndRequestPermissions()
    }

    /**
     * Ensure runtime permissions required for BLE advertising and Bluetooth connection are granted.
     */
    private fun checkAndRequestPermissions() {
        val permissions = listOf(
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_FINE_LOCATION
        )

        val missingPermissions = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, missingPermissions.toTypedArray(), PERMISSION_REQUEST_CODE)
        } else {
            initializeController()
            handleIntent(intent)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            initializeController()
            handleIntent(intent)
        }
    }

    /**
     * Construct transport dependencies and launch reactive session state observer.
     */
    private fun initializeController() {
        if (::sessionController.isInitialized) return

        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val bluetoothAdapter = bluetoothManager.adapter
        val bleAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser

        val hybridBleAdvertiser = HybridBleAdvertiser(bleAdvertiser)
        val transportManager = TransportManager(hybridBleAdvertiser)
        val linkingRepository = EncryptedLinkingRepositoryImpl(this)

        sessionController = BridgeSessionController(this, transportManager, linkingRepository)

        sessionController.onStatusUpdate = { status ->
            tvStatus.append("\n➜ $status")
        }

        observeSessionState()
    }

    /**
     * Observe reactive [BridgeSessionState] lifecycle events when Activity is in STARTED state.
     *
     * Collect state updates safely within coroutine scope bound to UI lifecycle to prevent leaks.
     */
    private fun observeSessionState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                sessionController.sessionState.collect { state ->
                    when (state) {
                        is BridgeSessionState.Idle -> {
                            Log.d(TAG, "Session State: Idle")
                        }
                        is BridgeSessionState.QrSessionInitiated -> {
                            tvStatus.append("\n[State] QR Session Initiated (Domain ID: ${state.domainId})")
                        }
                        is BridgeSessionState.StateAssistedSessionInitiated -> {
                            tvStatus.append("\n[State] State-assisted Session Initiated for paired client")
                        }
                        is BridgeSessionState.TransportConnected -> {
                            tvStatus.append("\n[State] BLE Advertising & WebSocket Tunnel Active")
                        }
                        is BridgeSessionState.HandshakeCompleted -> {
                            tvStatus.append("\n[State] Noise Cryptographic Handshake Complete")
                        }
                        is BridgeSessionState.ProcessingCtapRequest -> {
                            tvStatus.append("\n[State] Executing CTAP Command: ${state.commandName}")
                        }
                        is BridgeSessionState.PairingPersisted -> {
                            tvStatus.append("\n[State] Client Pairing Saved (LinkID: ${state.record.linkIdHex})")
                        }
                        is BridgeSessionState.Error -> {
                            tvStatus.append("\n[Error] ${state.message}")
                        }
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (::sessionController.isInitialized) {
            handleIntent(intent)
        }
    }

    /**
     * Parse incoming Intent data and route to QR scan or State-assisted reconnection flow.
     */
    private fun handleIntent(intent: Intent?) {
        val uriString = intent?.dataString ?: intent?.getStringExtra(Intent.EXTRA_TEXT)

        if (uriString != null) {
            tvStatus.text = "Captured FIDO URI:\n$uriString\n\nParsing payload..."

            val qrData = HybridQrParser.parse(uriString)
            if (qrData != null) {
                tvStatus.append("\nParsed FIDO QR Data successfully. Starting QR Session...")
                sessionController.onQrCodeScanned(qrData.publicKey, qrData.secret)
            } else {
                tvStatus.append("\nFailed to parse FIDO QR URI.")
            }
        } else if (intent?.hasExtra("cable_link_id") == true) {
            val linkId = intent.getByteArrayExtra("cable_link_id")
            if (linkId != null) {
                tvStatus.text = "Received caBLE Reconnection Trigger for LinkID: ${linkId.joinToString("") { "%02x".format(it) }}"
                sessionController.startStateAssistedSession(linkId)
            }
        }
    }

    companion object {
        private const val TAG = "FidoUriHandlerActivity"
    }
}
