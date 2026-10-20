package com.dev.fido.bridge

import android.app.Application
import android.util.Log
import com.dev.fido.bridge.core.security.LinkStore
import com.dev.fido.bridge.core.security.TunnelConfigManager
import com.dev.fido.bridge.core.transport.push.TunnelRegistrationClient
import com.dev.fido.bridge.feature.push.CableWakeupService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class BridgeApplication : Application() {
    private val appScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

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

        // Re-synchronize cached push endpoint with tunnel server on startup to recover from prior 401 or server resets
        LinkStore.getPushEndpoint()?.takeIf { it.isNotBlank() }?.let { cachedEndpoint ->
            appScope.launch {
                TunnelRegistrationClient.registerPushSubscription(
                    contactId = LinkStore.getContactIdString(),
                    endpoint = cachedEndpoint
                )
            }
        }

        Log.d("BridgeApplication", "Passkey Bridge Application initialized.")
    }
}