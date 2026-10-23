package com.dev.fido.bridge.feature.uri

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputFilter
import android.text.InputType
import android.util.Log
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
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

    private lateinit var scrollContainer: ScrollView
    private lateinit var tv: TextView
    private lateinit var sessionController: BridgeSessionController
    private val PERMISSION_REQUEST_CODE = 1001

    // Track active FIDO URI to prevent scanner apps from dispatching duplicate intents that cancel ongoing CredentialManager prompts
    private var activeFidoUri: String? = null
    private var isQrScanMode: Boolean = false

    private val Int.dp: Int
        get() = (this * resources.displayMetrics.density).toInt()

    private val bluetoothAdapter: BluetoothAdapter?
        get() = (getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        tv = TextView(this).apply {
            text = "Processing FIDO URI..."
            textSize = 14f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.parseColor("#E2E8F0"))
        }

        scrollContainer = ScrollView(this).apply {
            clipToPadding = false
            addView(tv)
        }

        // Reserve upper half of the active window as a dim scrim in QR mode while preserving system bar and cutout insets across both modes
        ViewCompat.setOnApplyWindowInsetsListener(scrollContainer) { view, windowInsets ->
            val insets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            val padCard = 20.dp
            if (isQrScanMode) {
                val windowHeight = windowManager.currentWindowMetrics.bounds.height()
                view.setPadding(insets.left, windowHeight / 2, insets.right, 0)
                tv.setPadding(padCard, padCard, padCard, padCard + insets.bottom)
            } else {
                val pad = 16.dp
                view.setPadding(insets.left + pad, insets.top + pad, insets.right + pad, insets.bottom + pad)
                tv.setPadding(padCard, padCard, padCard, padCard)
            }
            windowInsets
        }

        setContentView(scrollContainer)
        applyUiMode(intent?.dataString != null)
        checkAndRequestPermissions()
    }

    /**
     * Switch between full-screen terminal mode (launcher) and half-screen bottom-sheet mode (QR scan).
     */
    private fun applyUiMode(scanMode: Boolean) {
        isQrScanMode = scanMode
        val padCard = 20.dp

        if (scanMode) {
            setTranslucent(true)
            supportActionBar?.hide()

            scrollContainer.isFillViewport = true
            scrollContainer.setBackgroundColor(Color.parseColor("#88000000"))
            // Remove the transient QR task from Recents on scrim dismissal to prevent system re-creation with stale FIDO URIs
            scrollContainer.setOnClickListener { finishAndRemoveTask() }

            val r = 24.dp.toFloat()
            tv.apply {
                setOnClickListener { }
                gravity = Gravity.CENTER
                setLineSpacing(4.dp.toFloat(), 1.15f)
                setPadding(padCard, padCard, padCard, padCard)
                background = createCardBackground(floatArrayOf(r, r, r, r, 0f, 0f, 0f, 0f))
                layoutParams = FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.MATCH_PARENT
                )
            }
        } else {
            setTranslucent(false)
            supportActionBar?.show()

            scrollContainer.isFillViewport = false
            scrollContainer.setBackgroundColor(Color.parseColor("#020617"))
            scrollContainer.setOnClickListener(null)
            scrollContainer.setClickable(false)

            val r = 14.dp.toFloat()
            tv.apply {
                setOnClickListener(null)
                setClickable(false)
                gravity = Gravity.START or Gravity.TOP
                setLineSpacing(6.dp.toFloat(), 1.1f)
                setPadding(padCard, padCard, padCard, padCard)
                background = createCardBackground(FloatArray(8) { r })
                layoutParams = FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT
                )
            }
        }
        ViewCompat.requestApplyInsets(scrollContainer)
    }

    private fun createCardBackground(radii: FloatArray) = GradientDrawable().apply {
        setColor(Color.parseColor("#0F172A"))
        cornerRadii = radii
        setStroke(1.dp.coerceAtLeast(1), getColor(android.R.color.system_accent1_400) and 0x55FFFFFF)
    }

    /**
     * Overwrite centered status text on state changes in QR scan mode, or append multi-line logs in launcher mode.
     */
    private fun updateStatus(status: String, resetTerminal: Boolean = false) {
        if (isQrScanMode) {
            tv.text = status.lineSequence().map { it.trim() }.lastOrNull { it.isNotEmpty() } ?: status.trim()
        } else {
            if (resetTerminal) tv.text = status else tv.append("\n➜ $status")
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(Menu.NONE, 1, Menu.NONE, "⚙").setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS)
        menu.add(Menu.NONE, 2, Menu.NONE, "Enable Client Provider").setShowAsAction(MenuItem.SHOW_AS_ACTION_NEVER)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == 1) {
            showTunnelSettingsDialog()
            return true
        } else if (item.itemId == 2) {
            try {
                val pendingIntent = androidx.credentials.CredentialManager.create(this).createSettingsPendingIntent()
                startIntentSenderForResult(pendingIntent.intentSender, 1002, null, 0, 0, 0)
            } catch (e: Exception) {
                Toast.makeText(this, "Open Settings > Passwords & passkeys to enable Passkey Bridge", Toast.LENGTH_LONG).show()
            }
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    private fun showTunnelSettingsDialog() {
        val customId = TunnelConfigManager.getCustomTunnelId()
        val statusView = TextView(this).apply {
            text = if (customId != null) "Custom configuration active" else "Currently using default configuration"
            textSize = 14f
            setPadding(0, 0, 0, 8.dp)
        }
        val inputField = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            filters = arrayOf(InputFilter.LengthFilter(5))
            hint = "0 or 256 - 65535"
            customId?.let {
                setText(it.toString())
                setSelection(text.length)
            }
        }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24.dp, 16.dp, 24.dp, 4.dp)
            addView(statusView)
            addView(inputField)
        }

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
                    inputField.error = "Enter 0 or a number between 256 and 65535"
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
        val missing = arrayOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
            .filter { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }

        if (missing.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), PERMISSION_REQUEST_CODE)
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
                updateStatus("Bluetooth permissions are required for FIDO proximity verification.", resetTerminal = true)
            }
        }
    }

    private fun initializeController() {
        if (::sessionController.isInitialized) return

        val hybridBleAdvertiser = HybridBleAdvertiser { bluetoothAdapter?.bluetoothLeAdvertiser }
        sessionController = BridgeSessionController(this, TransportManager(hybridBleAdvertiser)).apply {
            onStatusUpdate = { status ->
                updateStatus(status)
            }
            onSessionTerminated = {
                activeFidoUri = null
                // Evict the QR scan task from Recents upon completion, cancellation, or error to return cleanly to the scanner
                if (isQrScanMode) {
                    finishAndRemoveTask()
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        val hasUri = intent?.dataString != null
        // Clean up any lingering QR scan session if the user relaunches the app from the home screen launcher icon
        if (!hasUri && activeFidoUri != null) {
            activeFidoUri = null
            if (::sessionController.isInitialized) sessionController.stopSession()
        }
        applyUiMode(hasUri)
        if (::sessionController.isInitialized) handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val adapter = bluetoothAdapter
        if (adapter == null || !adapter.isEnabled) {
            updateStatus("Bluetooth is turned off. Please enable Bluetooth and scan again.", resetTerminal = true)
            return
        }

        val uriString = intent?.dataString
        if (uriString != null) {
            if (uriString == activeFidoUri) {
                Log.d("FidoUriHandler", "Ignoring duplicate FIDO URI intent")
                return
            }
            activeFidoUri = uriString

            val qrData = HybridQrParser.parse(uriString)
            if (qrData == null) {
                activeFidoUri = null
                updateStatus("Invalid or unsupported FIDO URI.", resetTerminal = true)
                return
            }

            if (!isQrScanMode) {
                val flowLabel = if (qrData.operationHint == "mc") "MakeCredential (Register)" else "GetAssertion (Sign In)"
                tv.text = "Parsing...\nParsed successfully. Routing to CTAP Dispatcher...\n➜ Flow Hint: $flowLabel"
                qrData.timestampSeconds?.let { ts ->
                    if ((System.currentTimeMillis() / 1000L) - ts > 120L) {
                        tv.append("\n➜ Warning: QR code may be expired.")
                    }
                }
            }

            try {
                sessionController.onQrCodeScanned(qrData.publicKey, qrData.secret, qrData.tunnelServerId)
                if (isQrScanMode) {
                    updateStatus("BLE Advertising & WebSocket connecting...")
                } else {
                    tv.append("\n\nSession initiated.\nBLE Advertising & WebSocket connecting...")
                }
            } catch (e: Exception) {
                activeFidoUri = null
                Log.e("FidoUriHandler", "Error starting session", e)
                updateStatus("Error: ${e.message}")
            }
        } else if (activeFidoUri == null) {
            updateStatus("No URI provided. Waiting for FIDO URI intent.\nMake sure you scan a valid FIDO QR code.", resetTerminal = true)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        activeFidoUri = null
        if (::sessionController.isInitialized) sessionController.stopSession()
    }
}