package com.dev.fido.bridge.client.provider

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.dev.fido.bridge.client.ui.ClientQrPromptActivity
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicInteger

/**
 * Android 14+ CredentialProviderService that exposes a cross-device hybrid QR code option
 * during WebAuthn getCredential and createCredential ceremonies.
 */
class BridgeCredentialProviderService : CredentialProviderService() {

    companion object {
        const val ACTION_CLIENT_GET_PASSKEY = "com.dev.fido.bridge.client.ACTION_GET_PASSKEY"
        const val ACTION_CLIENT_CREATE_PASSKEY = "com.dev.fido.bridge.client.ACTION_CREATE_PASSKEY"
        private val requestCodeGenerator = AtomicInteger(2000)
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        try {
            val entries = mutableListOf<CredentialEntry>()
            val icon = Icon.createWithResource(applicationContext, applicationInfo.icon)

            for (option in request.beginGetCredentialOptions) {
                if (option is BeginGetPublicKeyCredentialOption) {
                    val rpId = runCatching {
                        JSONObject(option.requestJson).optString("rpId", "")
                    }.getOrDefault("")
                    val subtitle = rpId.ifEmpty { "Other device" }

                    val pendingIntent = buildSelectionPendingIntent(ACTION_CLIENT_GET_PASSKEY)
                    entries.add(
                        PublicKeyCredentialEntry.Builder(
                            context = applicationContext,
                            username = "Scan QR code",
                            pendingIntent = pendingIntent,
                            beginGetPublicKeyCredentialOption = option
                        )
                            .setDisplayName(subtitle)
                            .setIcon(icon)
                            .build()
                    )
                }
            }

            callback.onResult(BeginGetCredentialResponse(credentialEntries = entries))
        } catch (e: Exception) {
            Log.e("BridgeProviderService", "Failed to process onBeginGetCredentialRequest", e)
            callback.onError(GetCredentialUnknownException(e.message))
        }
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        try {
            if (request is BeginCreatePublicKeyCredentialRequest) {
                val rpId = runCatching {
                    JSONObject(request.requestJson).optJSONObject("rp")?.optString("id", "") ?: ""
                }.getOrDefault("")
                val description = if (rpId.isNotEmpty()) {
                    "Save to other device • $rpId"
                } else {
                    "Save to other device"
                }

                val icon = Icon.createWithResource(applicationContext, applicationInfo.icon)
                val pendingIntent = buildSelectionPendingIntent(ACTION_CLIENT_CREATE_PASSKEY)

                val createEntry = CreateEntry.Builder(
                    accountName = "Scan QR code",
                    pendingIntent = pendingIntent
                )
                    .setDescription(description)
                    .setIcon(icon)
                    .build()

                callback.onResult(BeginCreateCredentialResponse(createEntries = listOf(createEntry)))
            } else {
                callback.onResult(BeginCreateCredentialResponse())
            }
        } catch (e: Exception) {
            Log.e("BridgeProviderService", "Failed to process onBeginCreateCredentialRequest", e)
            callback.onError(CreateCredentialUnknownException(e.message))
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        // Stateless hybrid bridge maintains no persistent credential cache
        callback.onResult(null)
    }

    private fun buildSelectionPendingIntent(action: String): PendingIntent {
        val intent = Intent(applicationContext, ClientQrPromptActivity::class.java).apply {
            this.action = action
            setPackage(packageName)
        }
        return PendingIntent.getActivity(
            applicationContext,
            requestCodeGenerator.incrementAndGet(),
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }
}