package com.yourcompany.passkeybridge.feature.uri

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.yourcompany.passkeybridge.core.hybrid.HybridQrParser
import com.yourcompany.passkeybridge.feature.session.BridgeSessionController
import kotlinx.coroutines.launch

class FidoUriHandlerActivity : AppCompatActivity() {

    private lateinit var tv: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tv = TextView(this).apply {
            text = "Passkey Bridge\nProcessing FIDO URI..."
            textSize = 18f
            setPadding(50, 100, 50, 0)
        }
        setContentView(tv)

        handleIntent(intent)
    }

    // Capture intent if the activity is brought to foreground
    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        // Broaden the capture to support different QR scanners
        val uriString = intent?.dataString ?: intent?.getStringExtra(Intent.EXTRA_TEXT)
        
        if (uriString != null) {
            tv.text = "FIDO URI Captured:\n$uriString\n\nParsing..."
            val qrData = HybridQrParser.parse(uriString)
            
            if (qrData != null && qrData.tunnelServerId == 266) {
                tv.append("\n\nParsed successfully. Running Step 2 Spike...")
                runStep2Spike()
            } else {
                tv.append("\n\nInvalid or unsupported FIDO URI.")
            }
        } else {
            tv.text = "No URI provided. Waiting for FIDO URI intent.\nMake sure you scan a valid FIDO QR code."
        }
    }

    private fun runStep2Spike() {
        lifecycleScope.launch {
            try {
                // Initialize controller without transport manager for this specific spike
                val controller = BridgeSessionController(this@FidoUriHandlerActivity, null)
                val resultMsg = controller.runStep2HashVerificationSpike()
                tv.append("\n\n=== Spike Result ===\n$resultMsg")
            } catch (e: Exception) {
                Log.e("FidoUriHandler", "Error executing Step 2 Spike", e)
                tv.append("\n\nError: ${e.message}")
            }
        }
    }
}