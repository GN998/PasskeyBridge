package com.dev.fido.bridge.util

import android.util.Log
import com.dev.fido.bridge.BuildConfig

/**
 * Centralized logger that gates verbose output on [BuildConfig.DEBUG] and redacts
 * protocol secrets (FIDO:/ QR URIs, hex payloads, and JSON token values) in non-debug builds.
 */
object BridgeLogger {

    // Matches FIDO:/ digit-encoded QR payloads containing the 16-byte qrSecret.
    private val FIDO_URI_REGEX = Regex("""(?i)FIDO:/\d+""")

    // Matches sensitive JSON key-value pairs in WebAuthn requests/responses.
    private val SENSITIVE_JSON_FIELD_REGEX = Regex(
        """("(?:challenge|clientDataJSON|attestationObject|authenticatorData|signature|userHandle|id|rawId)"\s*:\s*")[^"]+(")"""
    )

    // Matches contiguous hex dumps (32+ hex chars, i.e. >= 16 bytes such as keys/nonces/hashes).
    private val LONG_HEX_REGEX = Regex("""\b[0-9a-fA-F]{32,}\b""")

    fun d(tag: String, message: String) {
        if (BuildConfig.DEBUG) {
            Log.d(tag, message)
        }
    }

    fun i(tag: String, message: String) {
        if (BuildConfig.DEBUG) {
            Log.i(tag, message)
        } else {
            Log.i(tag, redact(message))
        }
    }

    fun w(tag: String, message: String, tr: Throwable? = null) {
        val safeMsg = if (BuildConfig.DEBUG) message else redact(message)
        if (tr != null) {
            Log.w(tag, safeMsg, if (BuildConfig.DEBUG) tr else null)
        } else {
            Log.w(tag, safeMsg)
        }
    }

    fun e(tag: String, message: String, tr: Throwable? = null) {
        val safeMsg = if (BuildConfig.DEBUG) message else redact(message)
        if (tr != null) {
            Log.e(tag, safeMsg, if (BuildConfig.DEBUG) tr else null)
        } else {
            Log.e(tag, safeMsg)
        }
    }

    private fun redact(input: String): String {
        return input
            .replace(FIDO_URI_REGEX, "FIDO:/<REDACTED>")
            .replace(SENSITIVE_JSON_FIELD_REGEX, "$1<REDACTED>$2")
            .replace(LONG_HEX_REGEX, "<REDACTED_HEX>")
    }
}