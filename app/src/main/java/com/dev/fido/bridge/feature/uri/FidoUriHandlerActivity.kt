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
import androidx.lifecycle.lifecycleScope
import com.dev.fido.bridge.core.hybrid.HybridQrParser
import com.dev.fido.bridge.core.transport.TransportManager
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.feature.session.BridgeSessionController
import kotlinx.coroutines.launch

class FidoUriHandlerActivity : AppCompatActivity() {

    private lateinit var tv: TextView
    private lateinit var sessionController: BridgeSessionController
    private val PERMISSION_REQUEST_CODE = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tv = TextView(this).apply {
            text = "Passkey Bridge\nProcessing FIDO URI..."
            textSize = 18f
            setPadding(50, 100, 50, 0)
        }
        setContentView(tv)
        
        checkAndRequestPermissions()
    }

    private fun checkAndRequestPermissions() {
        // Request only BLUETOOTH_ADVERTISE and BLUETOOTH_CONNECT on Android 14+ without legacy location permissions
        val permissions = listOf(
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT
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

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                initializeController()
                handleIntent(intent)
            } else {
                tv.text = "Bluetooth permissions are required for FIDO proximity verification."
            }
        }
    }

    private fun initializeController() {
        if (::sessionController.isInitialized) return

        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val bluetoothAdapter = bluetoothManager.adapter
        val bleAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser

        val hybridBleAdvertiser = HybridBleAdvertiser(bleAdvertiser)
        val transportManager = TransportManager(hybridBleAdvertiser)
        
        sessionController = BridgeSessionController(this, transportManager)
        
        // Append background network and crypto status directly to UI TextView
        sessionController.onStatusUpdate = { status ->
            tv.append("\n➜ $status")
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (::sessionController.isInitialized) {
            handleIntent(intent)
        }
    }

    private fun handleIntent(intent: Intent?) {
        // Verify Bluetooth is enabled before starting a caBLE session so users are not stuck waiting on silent BLE failure
        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val bluetoothAdapter = bluetoothManager.adapter
        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled) {
            tv.text = "Bluetooth is turned off.\nPlease enable Bluetooth and scan the FIDO QR code again."
            return
        }

        val uriString = intent?.dataString ?: intent?.getStringExtra(Intent.EXTRA_TEXT)
        
        if (uriString != null) {
            tv.text = "FIDO URI Captured:\n$uriString\n\nParsing..."
            val qrData = HybridQrParser.parse(uriString)
            
            if (qrData != null) {
                tv.append("\n\nParsed successfully. Routing to CTAP Dispatcher...")
                
                lifecycleScope.launch {
                    try {
                        // Pass extracted tunnelServerId from QR payload to prevent routing to wrong tunnel domain
                        sessionController.onQrCodeScanned(
                            qrData.publicKey,
                            qrData.secret,
                            qrData.tunnelServerId
                        )
                        tv.append("\n\nSession initiated.\nBLE Advertising & WebSocket connecting...")
                    } catch (e: Exception) {
                        Log.e("FidoUriHandler", "Error starting session", e)
                        tv.append("\n\nError: ${e.message}")
                    }
                }
            } else {
                tv.append("\n\nInvalid or unsupported FIDO URI.")
            }
        } else {
            tv.text = "No URI provided. Waiting for FIDO URI intent.\nMake sure you scan a valid FIDO QR code."
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Ensure active BLE advertising and WebSocket connections are terminated when Activity exits
        if (::sessionController.isInitialized) {
            sessionController.stopSession()
        }
    }
}