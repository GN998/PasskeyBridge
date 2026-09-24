package com.yourcompany.passkeybridge.feature.uri

import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.yourcompany.passkeybridge.core.hybrid.HybridQrParser
import com.yourcompany.passkeybridge.feature.session.BridgeSessionController
import kotlinx.coroutines.launch

class FidoUriHandlerActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val tv = TextView(this).apply {
            text = "Passkey Bridge\nProcessing FIDO URI..."
            textSize = 20f
            setPadding(50, 100, 50, 0)
        }
        setContentView(tv)

        val uri = intent.data
        if (uri != null) {
            val qrData = HybridQrParser.parse(uri.toString())
            if (qrData != null && qrData.tunnelServerId == 266) {
                tv.text = "FIDO URI Parsed successfully.\nRunning Privileged API Spike (Step 2)..."
                runStep2Spike()
            } else {
                tv.text = "Invalid or unsupported FIDO URI."
            }
        } else {
            tv.text = "No URI provided. Waiting for FIDO URI intent."
        }
    }

    private fun runStep2Spike() {
        lifecycleScope.launch {
            try {
                // Initialize controller without transport manager for this specific spike
                val controller = BridgeSessionController(this@FidoUriHandlerActivity, null)
                controller.runStep2HashVerificationSpike()
            } catch (e: Exception) {
                Log.e("FidoUriHandler", "Error executing Step 2 Spike", e)
            }
        }
    }
}