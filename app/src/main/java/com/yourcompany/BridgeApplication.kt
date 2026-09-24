package com.yourcompany.passkeybridge

import android.app.Application
import android.util.Log

class BridgeApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Log.d("BridgeApplication", "Passkey Bridge Application initialized.")
    }
}