package com.dev.fido.bridge.client.ui

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
import android.util.Log
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialCustomException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCustomException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.provider.PendingIntentHandler
import com.dev.fido.bridge.client.ctap.ClientWebAuthnAssembler
import com.dev.fido.bridge.client.ctap.PreparedClientCeremony
import com.dev.fido.bridge.client.provider.PrivilegedAllowlist
import com.dev.fido.bridge.client.qr.HybridQrGenerator
import com.dev.fido.bridge.client.qr.QrBitmapRenderer
import com.dev.fido.bridge.client.transport.ClientTransportManager
import com.dev.fido.bridge.client.transport.ble.HybridBleScanner
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.feature.session.BridgeForegroundService

/**
 * Translucent bottom-sheet Activity invoked by Android CredentialManager when the user selects
 * Passkey Bridge as the credential provider. Displays the FIDO:/ QR code and orchestrates the
 * PXP client session.
 */
class ClientQrPromptActivity : AppCompatActivity() {

    private lateinit var rootScrim: FrameLayout
    private lateinit var titleView: TextView
    private lateinit var qrImageView: ImageView
    private lateinit var statusView: TextView
    private lateinit var transportManager: ClientTransportManager
    private lateinit var serviceIntent: Intent

    private var isCreateMode = false
    private val PERMISSION_REQ_CODE = 2001

    private val Int.dp: Int
        get() = (this * resources.displayMetrics.density).toInt()

    private val bluetoothAdapter: BluetoothAdapter?
        get() = (getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setTranslucent(true)
        supportActionBar?.hide()

        serviceIntent = Intent(this, BridgeForegroundService::class.java)
        transportManager = ClientTransportManager(
            HybridBleScanner { bluetoothAdapter?.bluetoothLeScanner }
        ).apply {
            onStatusUpdate = { status ->
                runOnUiThread { statusView.text = status }
            }
        }

        buildBottomSheetUi()
        checkPermissionsAndStartCeremony()
    }

    private fun buildBottomSheetUi() {
        titleView = TextView(this).apply {
            text = "Scan QR Code with Passkey Device"
            textSize = 16f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#F8FAFC"))
            gravity = Gravity.CENTER
        }

        val qrPadding = 12.dp
        qrImageView = ImageView(this).apply {
            scaleType = ImageView.ScaleType.FIT_CENTER
            setPadding(qrPadding, qrPadding, qrPadding, qrPadding)
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = 16.dp.toFloat()
            }
            visibility = View.INVISIBLE
        }

        statusView = TextView(this).apply {
            text = "Preparing FIDO hybrid session..."
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.parseColor("#94A3B8"))
            gravity = Gravity.CENTER
            setPadding(0, 16.dp, 0, 0)
        }

        val r = 24.dp.toFloat()
        val cardContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            val pad = 24.dp
            setPadding(pad, pad, pad, pad)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0F172A"))
                cornerRadii = floatArrayOf(r, r, r, r, 0f, 0f, 0f, 0f)
                setStroke(1.dp.coerceAtLeast(1), getColor(android.R.color.system_accent1_400) and 0x55FFFFFF)
            }
            // Consume clicks on the card so tapping inside does not trigger scrim cancellation
            setOnClickListener { }

            addView(titleView, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = 20.dp })

            val qrSize = 230.dp
            addView(qrImageView, LinearLayout.LayoutParams(qrSize, qrSize))

            addView(statusView, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
        }

        rootScrim = FrameLayout(this).apply {
            setBackgroundColor(Color.parseColor("#88000000"))
            setOnClickListener { cancelCeremony() }
            addView(cardContainer, FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM
            ))
        }

        ViewCompat.setOnApplyWindowInsetsListener(rootScrim) { _, windowInsets ->
            val insets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            cardContainer.setPadding(24.dp + insets.left, 24.dp, 24.dp + insets.right, 24.dp + insets.bottom)
            windowInsets
        }

        setContentView(rootScrim)
    }

    private fun checkPermissionsAndStartCeremony() {
        val missing = arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT
        ).filter { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }

        if (missing.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), PERMISSION_REQ_CODE)
        } else {
            startCeremonyFromIntent()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQ_CODE) {
            if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                startCeremonyFromIntent()
            } else {
                failCeremony("Bluetooth Scan permission is required to detect the nearby authenticator.")
            }
        }
    }

    private fun startCeremonyFromIntent() {
        val adapter = bluetoothAdapter
        if (adapter == null || !adapter.isEnabled) {
            failCeremony("Bluetooth is turned off. Please enable Bluetooth and try again.")
            return
        }

        val prepared = try {
            extractAndPrepareCeremony()
        } catch (e: Exception) {
            Log.e("ClientQrPrompt", "Failed to parse CredentialProvider request", e)
            failCeremony(e.message ?: "Invalid WebAuthn request")
            return
        }

        if (prepared == null) {
            failCeremony("No valid PublicKeyCredential request found in intent.")
            return
        }

        titleView.text = if (isCreateMode) "Scan to Create Passkey" else "Scan to Sign In with Passkey"

        val qrSession = HybridQrGenerator.generateQrSession(prepared.operationHint)

        // Dispatch physical BLE scanning first before rendering the 230dp QR bitmap
        transportManager.startClientSession(
            qrSession = qrSession,
            ctapRequest = prepared.ctapRequest,
            onSuccess = { ctapResponse ->
                runOnUiThread {
                    handleCtapResponse(prepared, ctapResponse)
                }
            },
            onError = { errorMsg ->
                runOnUiThread {
                    failCeremony(errorMsg)
                }
            }
        )

        startForegroundService(serviceIntent)

        // Render the QR matrix off the main thread so window transition and BLE startup are never blocked
        val qrSizePx = 230.dp
        Thread {
            val qrBitmap = QrBitmapRenderer.render(qrSession.fidoUri, qrSizePx)
            runOnUiThread {
                if (!isFinishing && !isDestroyed) {
                    qrImageView.setImageBitmap(qrBitmap)
                    qrImageView.visibility = View.VISIBLE
                }
            }
        }.start()
    }

    private fun extractAndPrepareCeremony(): PreparedClientCeremony? {
        val getReq = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (getReq != null) {
            isCreateMode = false
            val pubKeyOption = getReq.credentialOptions
                .filterIsInstance<GetPublicKeyCredentialOption>()
                .firstOrNull() ?: return null

            val origin = PrivilegedAllowlist.resolveOrigin(this, getReq.callingAppInfo)
            val callerPkg = if (getReq.callingAppInfo.isOriginPopulated()) null else getReq.callingAppInfo.packageName

            return ClientWebAuthnAssembler.prepareGetAssertion(
                requestJson = pubKeyOption.requestJson,
                origin = origin,
                providedClientDataHash = pubKeyOption.clientDataHash,
                packageName = callerPkg
            )
        }

        val createReq = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        if (createReq != null) {
            isCreateMode = true
            val pubKeyCreate = createReq.callingRequest as? CreatePublicKeyCredentialRequest ?: return null

            val origin = PrivilegedAllowlist.resolveOrigin(this, createReq.callingAppInfo)
            val callerPkg = if (createReq.callingAppInfo.isOriginPopulated()) null else createReq.callingAppInfo.packageName

            return ClientWebAuthnAssembler.prepareMakeCredential(
                requestJson = pubKeyCreate.requestJson,
                origin = origin,
                providedClientDataHash = pubKeyCreate.clientDataHash,
                packageName = callerPkg
            )
        }

        return null
    }

    private fun handleCtapResponse(prepared: PreparedClientCeremony, response: Ctap2Response) {
        stopService(serviceIntent)

        when (response) {
            is Ctap2Response.GetAssertionResponse -> {
                val allowList = (prepared.ctapRequest as? Ctap2Request.GetAssertion)?.allowList
                val responseJson = ClientWebAuthnAssembler.buildGetAssertionResponseJson(
                    response = response,
                    clientDataJsonBytes = prepared.clientDataJsonBytes,
                    fallbackAllowList = allowList
                )
                val resultIntent = Intent()
                PendingIntentHandler.setGetCredentialResponse(
                    resultIntent,
                    GetCredentialResponse(PublicKeyCredential(responseJson))
                )
                setResult(RESULT_OK, resultIntent)
                finish()
            }
            is Ctap2Response.MakeCredentialResponse -> {
                val responseJson = ClientWebAuthnAssembler.buildMakeCredentialResponseJson(
                    response = response,
                    clientDataJsonBytes = prepared.clientDataJsonBytes
                )
                val resultIntent = Intent()
                PendingIntentHandler.setCreateCredentialResponse(
                    resultIntent,
                    CreatePublicKeyCredentialResponse(responseJson)
                )
                setResult(RESULT_OK, resultIntent)
                finish()
            }
            is Ctap2Response.ErrorResponse -> {
                val statusHex = "0x%02X".format(response.errorCode)
                Log.w("ClientQrPrompt", "Authenticator returned CTAP error status: $statusHex")
                val resultIntent = Intent()
                if (isCreateMode) {
                    val exc = if (response.errorCode == CtapStatus.ERR_OPERATION_DENIED) {
                        CreateCredentialCancellationException("Operation denied on authenticator ($statusHex)")
                    } else {
                        CreateCredentialUnknownException("Authenticator returned CTAP error $statusHex")
                    }
                    PendingIntentHandler.setCreateCredentialException(resultIntent, exc)
                } else {
                    val exc = when (response.errorCode) {
                        CtapStatus.ERR_NO_CREDENTIALS -> NoCredentialException("No matching credentials on authenticator")
                        CtapStatus.ERR_OPERATION_DENIED -> GetCredentialCancellationException("Operation denied on authenticator ($statusHex)")
                        else -> GetCredentialUnknownException("Authenticator returned CTAP error $statusHex")
                    }
                    PendingIntentHandler.setGetCredentialException(resultIntent, exc)
                }
                setResult(RESULT_OK, resultIntent)
                finish()
            }
            else -> failCeremony("Unexpected CTAP response type")
        }
    }

    private fun cancelCeremony() {
        transportManager.stopSession()
        stopService(serviceIntent)
        val resultIntent = Intent()
        if (isCreateMode) {
            PendingIntentHandler.setCreateCredentialException(
                resultIntent,
                CreateCredentialCancellationException("User dismissed QR code prompt")
            )
        } else {
            PendingIntentHandler.setGetCredentialException(
                resultIntent,
                GetCredentialCancellationException("User dismissed QR code prompt")
            )
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    private fun failCeremony(message: String) {
        transportManager.stopSession()
        stopService(serviceIntent)
        val resultIntent = Intent()
        if (isCreateMode) {
            PendingIntentHandler.setCreateCredentialException(
                resultIntent,
                CreateCredentialCustomException("com.dev.fido.bridge.CLIENT_ERROR", message)
            )
        } else {
            PendingIntentHandler.setGetCredentialException(
                resultIntent,
                GetCredentialCustomException("com.dev.fido.bridge.CLIENT_ERROR", message)
            )
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        transportManager.stopSession()
        stopService(serviceIntent)
    }
}