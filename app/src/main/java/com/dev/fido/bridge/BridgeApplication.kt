package com.dev.fido.bridge

import android.app.Application
import android.util.Log
import com.dev.fido.bridge.core.security.LinkStore
import com.dev.fido.bridge.core.security.TunnelConfigManager
import com.dev.fido.bridge.feature.push.CableWakeupService

class BridgeApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Initialize persistent tunnel configuration store before any FIDO intent is processed
        TunnelConfigManager.init(this)
        // Initialize Android Keystore link repository and notification channel for background WebPush wakeups
        LinkStore.init(this)
        if (BuildConfig.DEFAULT_VAPID_PUBLIC_KEY.isNotBlank() && LinkStore.getVapidPublicKey().isNullOrBlank()) {
            LinkStore.setVapidPublicKey(BuildConfig.DEFAULT_VAPID_PUBLIC_KEY)
        }
        CableWakeupService.ensureNotificationChannel(this)
        Log.d("BridgeApplication", "Passkey Bridge Application initialized.")
    }
}