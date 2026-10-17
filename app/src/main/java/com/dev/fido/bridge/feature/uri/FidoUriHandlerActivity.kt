package com.dev.fido.bridge.feature.uri

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.InputFilter
import android.text.InputType
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.dev.fido.bridge.core.hybrid.HybridQrParser
import com.dev.fido.bridge.core.security.TunnelConfigManager
import com.dev.fido.bridge.core.transport.TransportManager
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.feature.session.BridgeSessionController

class FidoUriHandlerActivity : AppCompatActivity() {

    private lateinit var tv: TextView
    private lateinit var sessionController: BridgeSessionController
    private val PERMISSION_REQUEST_CODE = 1001

    // Track active FIDO URI to prevent scanner apps from dispatching duplicate intents that cancel ongoing CredentialManager prompts
    private var activeFidoUri: String? = null

    private val bluetoothAdapter: BluetoothAdapter?
        get() = (getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Delegate title and settings button to the native ActionBar and inset status text below system bars on Android 15+
        tv = TextView(this).apply {
            text = "Processing FIDO URI..."
            textSize = 18f
        }

        // Apply system bar and display cutout insets dynamically so content is never obscured under Android 15+ forced edge-to-edge
        ViewCompat.setOnApplyWindowInsetsListener(tv) { view, windowInsets ->
            val insets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            view.setPadding(
                insets.left + 50,
                insets.top + 40,
                insets.right + 50,
                insets.bottom
            )
            windowInsets
        }

        setContentView(tv)

        checkAndRequestPermissions()
    }

    // Mount settings trigger directly inside the native ActionBar so it aligns with the app title and avoids status bar overlap
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(Menu.NONE, 1, Menu.NONE, "⚙").apply {
            setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS)
        }
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == 1) {
            showTunnelSettingsDialog()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    /**
     * Present dialog to configure or clear custom tunnel domain ID.
     * Apply changes on subsequent scans to avoid invalidating active BLE EID and Noise PSK state mid-handshake.
     */
    private fun showTunnelSettingsDialog() {
        val customId = TunnelConfigManager.getCustomTunnelId()

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(60, 40, 60, 10)
        }

        val statusView = TextView(this).apply {
            // Conceal build-time default ID to prevent reverse-deriving the default tunnel domain
            text = if (customId != null) "Custom configuration active" else "Currently using default configuration"
            textSize = 14f
            setPadding(0, 0, 0, 20)
        }

        val inputField = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            filters = arrayOf(InputFilter.LengthFilter(5))
            hint = "256 - 65535"
            if (customId != null) {
                setText(customId.toString())
                setSelection(text.length)
            }
        }

        container.addView(statusView)
        container.addView(inputField)

        val dialog = AlertDialog.Builder(this)
            .setTitle("Extended Domain Settings")
            .setView(container)
            .setPositiveButton("Confirm", null)
            .setNeutralButton("Delete") { _, _ ->
                TunnelConfigManager.clearCustomTunnelId()
                Toast.makeText(this, "Default configuration restored (applies on next scan)", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .create()

        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).isEnabled = (customId != null)
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val parsed = inputField.text.toString().trim().toIntOrNull()
                if (parsed == null || !TunnelConfigManager.isValidTunnelId(parsed)) {
                    inputField.error = "Enter a number between 256 and 65535"
                } else {
                    TunnelConfigManager.setCustomTunnelId(parsed)
                    Toast.makeText(this, "Custom configuration saved (applies on next scan)", Toast.LENGTH_SHORT).show()
                    dialog.dismiss()
                }
            }
        }

        dialog.show()
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

        val hybridBleAdvertiser = HybridBleAdvertiser(bluetoothAdapter?.bluetoothLeAdvertiser)
        val transportManager = TransportManager(hybridBleAdvertiser)

        sessionController = BridgeSessionController(this, transportManager).apply {
            // Append background network and crypto status directly to UI TextView
            onStatusUpdate = { status ->
                tv.append("\n➜ $status")
            }
            // Reset active URI guard via explicit termination callback instead of fragile log prefix matching
            onSessionTerminated = {
                activeFidoUri = null
            }
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
        val adapter = bluetoothAdapter
        if (adapter == null || !adapter.isEnabled) {
            tv.text = "Bluetooth is turned off.\nPlease enable Bluetooth and scan the FIDO QR code again."
            return
        }

        val uriString = intent?.dataString

        if (uriString != null) {
            // Ignore duplicate intent deliveries of the exact same QR URI to avoid aborting an active CredentialManager prompt
            if (uriString == activeFidoUri) {
                Log.d("FidoUriHandler", "Ignoring duplicate FIDO URI intent")
                return
            }
            activeFidoUri = uriString

            // Start status output directly from Parsing without exposing raw FIDO URI payload on screen
            tv.text = "Parsing..."
            val qrData = HybridQrParser.parse(uriString)

            if (qrData != null) {
                tv.append("\nParsed successfully. Routing to CTAP Dispatcher...")

                try {
                    sessionController.onQrCodeScanned(
                        qrData.publicKey,
                        qrData.secret,
                        qrData.tunnelServerId
                    )
                    tv.append("\n\nSession initiated.\nBLE Advertising & WebSocket connecting...")
                } catch (e: Exception) {
                    activeFidoUri = null
                    Log.e("FidoUriHandler", "Error starting session", e)
                    tv.append("\n\nError: ${e.message}")
                }
            } else {
                activeFidoUri = null
                tv.append("\n\nInvalid or unsupported FIDO URI.")
            }
        } else if (activeFidoUri == null) {
            tv.text = "No URI provided. Waiting for FIDO URI intent.\nMake sure you scan a valid FIDO QR code."
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        activeFidoUri = null
        // Ensure active BLE advertising and WebSocket connections are terminated when Activity exits
        if (::sessionController.isInitialized) {
            sessionController.stopSession()
        }
    }
}