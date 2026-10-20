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
import android.widget.Button
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
import androidx.lifecycle.lifecycleScope
import com.dev.fido.bridge.core.hybrid.HybridQrParser
import com.dev.fido.bridge.core.security.LinkStore
import com.dev.fido.bridge.core.security.TunnelConfigManager
import com.dev.fido.bridge.core.transport.TransportManager
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.core.transport.push.TunnelRegistrationClient
import com.dev.fido.bridge.feature.push.CableWakeupService
import com.dev.fido.bridge.feature.session.BridgeSessionController
import kotlinx.coroutines.launch
import org.unifiedpush.android.connector.UnifiedPush

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

        CableWakeupService.onPushRegistrationStatusChanged = { _, message ->
            runOnUiThread {
                tv.append("\n➜ $message")
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            }
        }

        checkAndRequestPermissions()
    }

    override fun onResume() {
        super.onResume()
        // Intercept incoming state-assisted wakeups directly when the Activity is already in the foreground
        CableWakeupService.onForegroundWakeupIntercepted = { contactId, payloadHex ->
            runOnUiThread {
                startStateAssistedFlow(contactId, payloadHex)
            }
            true
        }
    }

    override fun onPause() {
        super.onPause()
        CableWakeupService.onForegroundWakeupIntercepted = null
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
     * Present dialog to configure custom tunnel domain ID and manage Sunup (UnifiedPush) QR-less registration.
     * Apply changes on subsequent scans to avoid invalidating active BLE EID and Noise PSK state mid-handshake.
     */
    private fun showTunnelSettingsDialog() {
        val customId = TunnelConfigManager.getCustomTunnelId()
        val isPushActive = LinkStore.isPushRegistered()

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(60, 40, 60, 10)
        }

        val statusView = TextView(this).apply {
            // Conceal build-time default ID to prevent reverse-deriving the default tunnel domain
            val domainState = if (customId != null) "Custom configuration active" else "Currently using default configuration"
            val pushState = if (isPushActive) "QR-less Push: Registered (Sunup)" else "QR-less Push: Not registered"
            text = "$domainState\n$pushState"
            textSize = 14f
            setPadding(0, 0, 0, 20)
        }

        val inputField = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            filters = arrayOf(InputFilter.LengthFilter(5))
            hint = "Tunnel ID (256 - 65535)"
            if (customId != null) {
                setText(customId.toString())
                setSelection(text.length)
            }
        }

        val pushActionButton = Button(this).apply {
            text = if (isPushActive) "Unlink & Disable QR-less Push" else "Enable QR-less Push (Sunup)"
        }

        container.addView(statusView)
        container.addView(inputField)
        container.addView(pushActionButton)

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

        pushActionButton.setOnClickListener {
            dialog.dismiss()
            if (isPushActive) {
                unlinkStateAssistedPush()
            } else {
                registerStateAssistedPush()
            }
        }

        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).isEnabled = (customId != null)
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val rawText = inputField.text.toString().trim()
                if (rawText.isEmpty()) {
                    dialog.dismiss()
                    return@setOnClickListener
                }
                val parsed = rawText.toIntOrNull()
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

    /**
     * Fetch the VAPID public key from cable-tunnel-server (if not cached) and subscribe via UnifiedPush 3.x API (Sunup).
     */
    private fun registerStateAssistedPush() {
        tv.append("\n➜ Registering QR-less push with Sunup...")
        lifecycleScope.launch {
            val vapidKey = LinkStore.getVapidPublicKey()?.takeIf { it.isNotBlank() }
                ?: TunnelRegistrationClient.fetchVapidPublicKey().getOrElse { err ->
                    tv.append("\n➜ Failed to fetch VAPID key: ${err.message}")
                    Toast.makeText(this@FidoUriHandlerActivity, "VAPID fetch failed: ${err.message}", Toast.LENGTH_LONG).show()
                    return@launch
                }

            try {
                val distributors = UnifiedPush.getDistributors(this@FidoUriHandlerActivity)
                if (distributors.isEmpty()) {
                    tv.append("\n➜ No UnifiedPush distributor found. Please ensure Sunup is installed.")
                    Toast.makeText(this@FidoUriHandlerActivity, "Sunup not found on device", Toast.LENGTH_LONG).show()
                    return@launch
                }

                val instanceId = LinkStore.getContactIdString()
                if (distributors.size == 1) {
                    UnifiedPush.saveDistributor(this@FidoUriHandlerActivity, distributors.first())
                    UnifiedPush.register(
                        context = this@FidoUriHandlerActivity,
                        instance = instanceId,
                        vapid = vapidKey
                    )
                } else {
                    val items = distributors.toTypedArray()
                    AlertDialog.Builder(this@FidoUriHandlerActivity)
                        .setTitle("Select Push Distributor")
                        .setItems(items) { _, which ->
                            UnifiedPush.saveDistributor(this@FidoUriHandlerActivity, items[which])
                            UnifiedPush.register(
                                context = this@FidoUriHandlerActivity,
                                instance = instanceId,
                                vapid = vapidKey
                            )
                        }
                        .show()
                }
            } catch (e: Exception) {
                Log.e("FidoUriHandler", "UnifiedPush registration call failed", e)
                tv.append("\n➜ Sunup registration error: ${e.message}")
            }
        }
    }

    /**
     * Unregister from UnifiedPush and send DELETE `/cable/register/<contact_id>` so linked desktops receive HTTP 410 Gone.
     */
    private fun unlinkStateAssistedPush() {
        val currentContactId = LinkStore.getContactIdString()
        tv.append("\n➜ Unlinking QR-less push subscription...")
        lifecycleScope.launch {
            try {
                UnifiedPush.unregister(this@FidoUriHandlerActivity, currentContactId)
            } catch (e: Exception) {
                Log.w("FidoUriHandler", "UnifiedPush unregister warning", e)
            }
            val res = TunnelRegistrationClient.unregisterPushSubscription(currentContactId)
            if (res.isSuccess) {
                tv.append("\n➜ QR-less push unlinked and Contact ID rotated.")
                Toast.makeText(this@FidoUriHandlerActivity, "Unlinked successfully", Toast.LENGTH_SHORT).show()
            } else {
                tv.append("\n➜ Unlink error: ${res.exceptionOrNull()?.message}")
            }
        }
    }

    private fun checkAndRequestPermissions() {
        // Request BLUETOOTH_ADVERTISE, BLUETOOTH_CONNECT, and POST_NOTIFICATIONS on Android 14+ without legacy location permissions
        val permissions = listOf(
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.POST_NOTIFICATIONS
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
            val btAdvertiseGranted = ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED
            val btConnectGranted = ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED
            if (btAdvertiseGranted && btConnectGranted) {
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

        // 1. Check if launched from a state-assisted WebPush wakeup notification
        val wakeupContactId = intent?.getStringExtra(CableWakeupService.EXTRA_CONTACT_ID)
        if (!wakeupContactId.isNullOrEmpty()) {
            val payloadHex = intent.getStringExtra(CableWakeupService.EXTRA_CLIENT_PAYLOAD_HEX)
            intent.removeExtra(CableWakeupService.EXTRA_CONTACT_ID)
            CableWakeupService.stopWakeup(this)
            startStateAssistedFlow(wakeupContactId, payloadHex)
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

                // Surface user flow hint immediately upon scan per CTAP 2.3 §11.5.1.1 before receiving CTAP frames
                val flowLabel = if (qrData.operationHint == "mc") "MakeCredential (Register)" else "GetAssertion (Sign In)"
                tv.append("\n➜ Flow Hint: $flowLabel")

                // Warn user if scanned QR timestamp exceeds typical client platform session lifetime
                qrData.timestampSeconds?.let { qrTimestamp ->
                    if ((System.currentTimeMillis() / 1000L) - qrTimestamp > 120L) {
                        tv.append("\n➜ Warning: QR code may be expired.")
                    }
                }

                try {
                    sessionController.onQrCodeScanned(
                        qrData.publicKey,
                        qrData.secret,
                        qrData.tunnelServerId,
                        qrData.supportsStateAssisted
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
            val pushReady = if (LinkStore.isPushRegistered()) "Active (Sunup)" else "Inactive (Configure in ⚙)"
            tv.text = "No URI provided. Waiting for FIDO URI intent or QR-less push.\n➜ QR-less Push Status: $pushReady"
        }
    }

    private fun startStateAssistedFlow(contactId: String, clientPayloadHex: String?) {
        val guardKey = "contact:$contactId:${clientPayloadHex.orEmpty()}"
        if (activeFidoUri == guardKey) {
            Log.d("FidoUriHandler", "Ignoring duplicate state-assisted wakeup intent")
            return
        }
        activeFidoUri = guardKey

        tv.text = "State-Assisted Wakeup Received.\nConnecting to contact tunnel & advertising BLE EID..."
        try {
            sessionController.onStateAssistedWakeup(
                contactId = contactId,
                clientPayloadHex = clientPayloadHex,
                domainId = TunnelConfigManager.getEffectiveTunnelId()
            )
        } catch (e: Exception) {
            activeFidoUri = null
            Log.e("FidoUriHandler", "Error starting state-assisted session", e)
            tv.append("\n\nError: ${e.message}")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        CableWakeupService.onPushRegistrationStatusChanged = null
        CableWakeupService.onForegroundWakeupIntercepted = null
        activeFidoUri = null
        // Ensure active BLE advertising and WebSocket connections are terminated when Activity exits
        if (::sessionController.isInitialized) {
            sessionController.stopSession()
        }
    }
}