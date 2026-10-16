package com.dev.fido.bridge

import android.app.Application
import android.util.Log
import com.dev.fido.bridge.core.security.TunnelConfigManager

class BridgeApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Initialize persistent tunnel configuration store before any FIDO intent is processed
        TunnelConfigManager.init(this)
        Log.d("BridgeApplication", "Passkey Bridge Application initialized.")
    }
}