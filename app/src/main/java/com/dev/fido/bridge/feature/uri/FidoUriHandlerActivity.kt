package com.dev.fido.bridge.feature.uri

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.TextView
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

/**
 * Handle user permissions and display authentication status for FIDO deep-link intents.
 *
 * Keep UI logic strictly lean by delegating URI parsing and session lifecycle management
 * to [FidoUriHandlerViewModel], ensuring Android UI components only handle runtime permission
 * requests and text view rendering.
 */
class FidoUriHandlerActivity : AppCompatActivity() {

    private lateinit var tv: TextView
    private val viewModel: FidoUriHandlerViewModel by viewModels()

    companion object {
        private const val PERMISSION_REQUEST_CODE = 1001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        tv = TextView(this).apply {
            text = "Passkey Bridge\nProcessing FIDO URI..."
            textSize = 18f
            setPadding(50, 100, 50, 0)
        }
        setContentView(tv)

        observeViewModel()
        checkAndRequestPermissions()
    }

    /**
     * Bind LiveData from ViewModel to observe status updates and reflect background progression in UI.
     */
    private fun observeViewModel() {
        viewModel.statusText.observe(this) { status ->
            tv.text = status
        }
    }

    /**
     * Ensure mandatory BLE and Location permissions are granted before triggering session processing.
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
            handleIncomingIntent(intent)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            handleIncomingIntent(intent)
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleIncomingIntent(intent)
    }

    /**
     * Extract URI string from intent extras or data payload and delegate processing to ViewModel.
     */
    private fun handleIncomingIntent(intent: Intent?) {
        val uriString = intent?.dataString ?: intent?.getStringExtra(Intent.EXTRA_TEXT)
        viewModel.processFidoUri(uriString)
    }
}
