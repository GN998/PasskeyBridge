package com.dev.fido.bridge.feature.push

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.dev.fido.bridge.core.hybrid.StateAssistedCodec
import com.dev.fido.bridge.core.security.LinkStore
import com.dev.fido.bridge.core.security.WebPushCrypto
import com.dev.fido.bridge.core.transport.push.TunnelRegistrationClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Handle UnifiedPush (Sunup / Mozilla Autopush) lifecycle and wakeup broadcasts.
 * Use goAsync() to safely complete network registration or payload decryption within BroadcastReceiver execution limits.
 */
class CablePushReceiver : BroadcastReceiver() {

    companion object {
        const val ACTION_NEW_ENDPOINT = "org.unifiedpush.android.connector.NEW_ENDPOINT"
        const val ACTION_MESSAGE = "org.unifiedpush.android.connector.MESSAGE"
        const val ACTION_UNREGISTERED = "org.unifiedpush.android.connector.UNREGISTERED"
        const val ACTION_REGISTRATION_FAILED = "org.unifiedpush.android.connector.REGISTRATION_FAILED"

        private const val EXTRA_ENDPOINT = "endpoint"
        private const val EXTRA_BYTES_MESSAGE = "bytesMessage"
        private const val EXTRA_MESSAGE = "message"
        private const val EXTRA_P256DH = "pubKey"
        private const val EXTRA_AUTH = "auth"

        private val receiverScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        LinkStore.init(context.applicationContext)

        when (action) {
            ACTION_NEW_ENDPOINT -> handleNewEndpoint(context, intent)
            ACTION_MESSAGE -> handleWakeupMessage(context, intent)
            ACTION_UNREGISTERED -> {
                Log.w("CablePushReceiver", "UnifiedPush distributor unregistered endpoint")
                LinkStore.setPushRegistered(false, null)
                CableWakeupService.notifyPushStateChanged(false, "Sunup push unregistered")
            }
            ACTION_REGISTRATION_FAILED -> {
                Log.e("CablePushReceiver", "UnifiedPush registration failed")
                LinkStore.setPushRegistered(false, null)
                CableWakeupService.notifyPushStateChanged(false, "Sunup registration failed")
            }
        }
    }

    private fun handleNewEndpoint(context: Context, intent: Intent) {
        val rawEndpoint = intent.getStringExtra(EXTRA_ENDPOINT)?.trim()
        if (rawEndpoint.isNullOrEmpty()) {
            Log.e("CablePushReceiver", "NEW_ENDPOINT broadcast missing endpoint URL")
            return
        }

        // Normalize UnifiedPush Sunup URLs (`?up=1`) to standard WebPush endpoints accepted by Mozilla Autopush.
        val cleanEndpoint = rawEndpoint.removeSuffix("?up=1")
        val distributorP256dh = intent.getStringExtra(EXTRA_P256DH)?.takeIf { it.isNotBlank() }
        val distributorAuth = intent.getStringExtra(EXTRA_AUTH)?.takeIf { it.isNotBlank() }

        val contactId = LinkStore.getContactIdString()
        val pendingResult = goAsync()

        receiverScope.launch {
            try {
                val res = TunnelRegistrationClient.registerPushSubscription(
                    contactId = contactId,
                    endpoint = cleanEndpoint,
                    p256dhB64 = distributorP256dh ?: LinkStore.getWebPushPublicKeyB64(),
                    authB64 = distributorAuth ?: LinkStore.getWebPushAuthSecretB64()
                )
                if (res.isSuccess) {
                    CableWakeupService.notifyPushStateChanged(true, "QR-less push active via Sunup")
                } else {
                    val err = res.exceptionOrNull()?.message ?: "Registration failed"
                    Log.e("CablePushReceiver", "Tunnel server rejected push registration: $err")
                    CableWakeupService.notifyPushStateChanged(false, "Server rejected push: $err")
                }
            } finally {
                pendingResult.finish()
            }
        }
    }

    private fun handleWakeupMessage(context: Context, intent: Intent) {
        val rawBytes = intent.getByteArrayExtra(EXTRA_BYTES_MESSAGE)
            ?: intent.getStringExtra(EXTRA_MESSAGE)?.toByteArray(Charsets.ISO_8859_1)

        // Decrypt RFC 8291 aes128gcm payload if present; otherwise allow CableWakeupService to fetch X-caBLE-Client-Payload from WebSocket 101 headers.
        val decryptedHex = if (rawBytes != null && rawBytes.isNotEmpty()) {
            WebPushCrypto.decryptWakeupPayload(
                rawPushBytes = rawBytes,
                recipientPrivateKey = LinkStore.getWebPushPrivateKey(),
                recipientPublicKeyUncompressed = LinkStore.getWebPushPublicKeyUncompressed(),
                authSecretBytes = LinkStore.getWebPushAuthSecretBytes()
            )
        } else {
            null
        }

        val parsedPayload = decryptedHex?.let { StateAssistedCodec.parseClientPayloadHex(it) }
        if (parsedPayload != null) {
            val linkSecret = LinkStore.findLinkSecret(parsedPayload.linkId)
            if (linkSecret == null) {
                Log.w("CablePushReceiver", "Ignoring wakeup for unknown link ID")
                return
            }
        }

        Log.d("CablePushReceiver", "Dispatching state-assisted wakeup to CableWakeupService")
        CableWakeupService.startWakeup(
            context = context.applicationContext,
            contactId = LinkStore.getContactIdString(),
            clientPayloadHex = decryptedHex,
            operationHint = parsedPayload?.operationHint ?: "ga"
        )
    }
}