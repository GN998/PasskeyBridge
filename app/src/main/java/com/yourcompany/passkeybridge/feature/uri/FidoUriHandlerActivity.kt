package com.yourcompany.passkeybridge.feature.uri

import android.Manifest
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.yourcompany.passkeybridge.core.hybrid.HybridQrParser
import com.yourcompany.passkeybridge.core.transport.TransportManager
import com.yourcompany.passkeybridge.core.transport.ble.HybridBleAdvertiser
import com.yourcompany.passkeybridge.feature.session.BridgeSessionController
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
        val permissions = mutableListOf<String>()
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissions.add(Manifest.permission.BLUETOOTH_ADVERTISE)
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION)
        } else {
            permissions.add(Manifest.permission.BLUETOOTH)
            permissions.add(Manifest.permission.BLUETOOTH_ADMIN)
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }

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
            initializeController()
            handleIntent(intent)
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
        if (::sessionController.isInitialized) {
            handleIntent(intent)
        }
    }

    private fun handleIntent(intent: Intent?) {
        val uriString = intent?.dataString ?: intent?.getStringExtra(Intent.EXTRA_TEXT)
        
        if (uriString != null) {
            tv.text = "FIDO URI Captured:\n$uriString\n\nParsing..."
            val qrData = HybridQrParser.parse(uriString)
            
            if (qrData != null) {
                tv.append("\n\nParsed successfully. Routing to CTAP Dispatcher...")
                
                lifecycleScope.launch {
                    try {
                        sessionController.onQrCodeScanned(qrData.publicKey, qrData.secret)
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
}