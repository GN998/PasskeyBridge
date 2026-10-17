package com.dev.fido.bridge.core.security

import android.content.Context
import android.content.SharedPreferences
import com.dev.fido.bridge.BuildConfig

object TunnelConfigManager {
    private const val PREFS_NAME = "passkey_bridge_config"
    private const val KEY_CUSTOM_TUNNEL_ID = "custom_tunnel_id"
    private const val NO_CUSTOM_ID = -1

    // Enforce CTAP 2.3 §11.5.1.1.1 hashed tunnel domain range (256..65535) to avoid reserved assigned domains (<256) and uint16 overflow
    const val MIN_TUNNEL_ID = 256
    const val MAX_TUNNEL_ID = 65535

    private lateinit var prefs: SharedPreferences

    fun init(context: Context) {
        prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /**
     * Resolve active tunnel domain ID by prioritizing user-configured override over build-time default.
     */
    fun getEffectiveTunnelId(): Int {
        return getCustomTunnelId() ?: BuildConfig.TUNNEL_ID
    }

    /**
     * Retrieve user-defined tunnel ID if present; return null when using default to prevent exposing BuildConfig.TUNNEL_ID in UI.
     */
    fun getCustomTunnelId(): Int? {
        val value = prefs.getInt(KEY_CUSTOM_TUNNEL_ID, NO_CUSTOM_ID)
        return if (isValidTunnelId(value)) value else null
    }

    fun isValidTunnelId(id: Int): Boolean = id in MIN_TUNNEL_ID..MAX_TUNNEL_ID

    fun setCustomTunnelId(id: Int) {
        prefs.edit().putInt(KEY_CUSTOM_TUNNEL_ID, id).apply()
    }

    /**
     * Remove user override so subsequent sessions revert to the build-time injected tunnel ID.
     */
    fun clearCustomTunnelId() {
        prefs.edit().remove(KEY_CUSTOM_TUNNEL_ID).apply()
    }
}