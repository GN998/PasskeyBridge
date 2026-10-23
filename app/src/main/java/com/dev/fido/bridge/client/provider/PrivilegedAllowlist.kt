package com.dev.fido.bridge.client.provider

import android.content.Context
import androidx.credentials.provider.CallingAppInfo
import com.dev.fido.bridge.core.security.CryptoUtils

object PrivilegedAllowlist {

    @Volatile
    private var cachedAllowlistJson: String? = null

    /**
     * Load and cache privileged_apps.json from assets so browser origin checks do not repeat disk I/O.
     */
    private fun getAllowlistJson(context: Context): String {
        cachedAllowlistJson?.let { return it }
        return synchronized(this) {
            cachedAllowlistJson ?: context.applicationContext.assets
                .open("privileged_apps.json")
                .bufferedReader(Charsets.UTF_8)
                .use { it.readText() }
                .also { cachedAllowlistJson = it }
        }
    }

    /**
     * Resolve the WebAuthn origin for the calling application per Android CredentialProvider guidelines.
     * Return the browser-supplied web origin if [callingAppInfo] is on the privileged allowlist,
     * or compute the standard "android:apk-key-hash:<base64url>" origin for native Android apps.
     */
    fun resolveOrigin(context: Context, callingAppInfo: CallingAppInfo): String {
        if (callingAppInfo.isOriginPopulated()) {
            val allowlist = getAllowlistJson(context)
            val privilegedOrigin = callingAppInfo.getOrigin(allowlist)
            return requireNotNull(privilegedOrigin) {
                "Caller (${callingAppInfo.packageName}) requested a privileged origin but is not in privileged_apps.json"
            }.removeSuffix("/")
        }

        val signerBytes = if (callingAppInfo.signingInfo.hasMultipleSigners()) {
            callingAppInfo.signingInfo.apkContentsSigners.first().toByteArray()
        } else {
            callingAppInfo.signingInfo.signingCertificateHistory.first().toByteArray()
        }
        val certHash = CryptoUtils.sha256(signerBytes)
        return "android:apk-key-hash:${CryptoUtils.encodeBase64UrlNoPadding(certHash)}"
    }
}