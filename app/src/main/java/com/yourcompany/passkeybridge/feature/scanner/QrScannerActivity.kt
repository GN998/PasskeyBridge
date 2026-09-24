package com.yourcompany.passkeybridge.feature.scanner

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class QrScannerActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate()
        val tv = TextView(this).apply {
            text = "Passkey Bridge\nReady for QR scanning and session setup"
            textSize = 20f
            setPadding(50, 100, 50, 0)
        }
        setContentView(tv)
    }
}