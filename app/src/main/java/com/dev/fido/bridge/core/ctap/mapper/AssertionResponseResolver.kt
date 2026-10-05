package com.dev.fido.bridge.core.ctap.mapper

import com.dev.fido.bridge.core.ctap.model.CredentialDescriptor
import com.dev.fido.bridge.core.security.CryptoUtils
import org.json.JSONObject

/**
 * Resolve the exact credential identifier selected by the user during authentication.
 *
 * Prevent Relying Party public-key verification mismatches in multi-account or discoverable credential
 * flows by strictly deriving the active credential ID from the Android CredentialManager response JSON
 * rather than guessing or defaulting to the first element in the request allowList.
 */
object AssertionResponseResolver {

    /**
     * Extract and decode the active credential ID chosen by the user.
     *
     * Inspect the system response JSON for "id" and "rawId" fields first because the client platform
     * may receive an allowList containing multiple registered accounts. Defaulting to allowList[0]
     * causes signature verification failures if the user selects any non-first credential in the prompt.
     */
    fun resolveCredentialId(
        responseJsonStr: String,
        allowList: List<CredentialDescriptor>?
    ): ByteArray {
        val parsedId = try {
            val root = JSONObject(responseJsonStr)
            val idStr = root.optString("id", "").ifEmpty { root.optString("rawId", "") }
            if (idStr.isNotEmpty()) {
                CryptoUtils.decodeBase64Url(idStr)
            } else {
                ByteArray(0)
            }
        } catch (_: Exception) {
            ByteArray(0)
        }

        // Return the explicitly returned credential ID immediately to honor user selection
        if (parsedId.isNotEmpty()) {
            return parsedId
        }

        // Permit fallback only when the request unambiguously provided exactly one target credential
        if (allowList?.size == 1 && allowList.first().id.isNotEmpty()) {
            return allowList.first().id
        }

        return ByteArray(0)
    }
}