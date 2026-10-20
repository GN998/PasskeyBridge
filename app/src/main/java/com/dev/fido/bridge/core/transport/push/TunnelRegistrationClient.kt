package com.dev.fido.bridge.core.transport.push

import android.util.Log
import com.dev.fido.bridge.core.security.DomainDerivation
import com.dev.fido.bridge.core.security.LinkStore
import com.dev.fido.bridge.core.security.TunnelConfigManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Manage REST lifecycle operations against cable-tunnel-server (`/cable/vapid-public-key` and `/cable/register/<contact_id>`).
 */
object TunnelRegistrationClient {

    private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .build()

    private fun resolveBaseHttpsUrl(): String {
        val tunnelId = TunnelConfigManager.getEffectiveTunnelId()
        val domain = DomainDerivation.deriveDomainForTunnelId(tunnelId)
        return "https://$domain"
    }

    /**
     * Fetch the server's VAPID public key from `GET /cable/vapid-public-key` and cache it in LinkStore.
     */
    suspend fun fetchVapidPublicKey(): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val url = "${resolveBaseHttpsUrl()}/cable/vapid-public-key"
            val request = Request.Builder()
                .url(url)
                .get()
                .build()

            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw IOException("Server returned HTTP ${response.code} when fetching VAPID key")
                }
                val bodyStr = response.body?.string()
                    ?: throw IOException("Empty response body from /cable/vapid-public-key")
                val pubKey = JSONObject(bodyStr).getString("publicKey").trim()
                LinkStore.setVapidPublicKey(pubKey)
                pubKey
            }
        }
    }

    /**
     * Register the Sunup / Mozilla Autopush subscription endpoint and RFC 8291 encryption keys with the contact Durable Object.
     */
    suspend fun registerPushSubscription(
        contactId: String,
        endpoint: String,
        p256dhB64: String = LinkStore.getWebPushPublicKeyB64(),
        authB64: String = LinkStore.getWebPushAuthSecretB64()
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching<Unit> {
            val url = "${resolveBaseHttpsUrl()}/cable/register/$contactId"
            val payloadJson = JSONObject().apply {
                put("endpoint", endpoint)
                put("keys", JSONObject().apply {
                    put("p256dh", p256dhB64)
                    put("auth", authB64)
                })
            }.toString()

            val reqBuilder = Request.Builder()
                .url(url)
                .post(payloadJson.toRequestBody(JSON_MEDIA_TYPE))

            LinkStore.getRegistrationSecret()?.takeIf { it.isNotEmpty() }?.let { secret ->
                reqBuilder.header("Authorization", "Bearer $secret")
            }

            httpClient.newCall(reqBuilder.build()).execute().use { response ->
                if (!response.isSuccessful) {
                    throw IOException("Push registration rejected with HTTP ${response.code}")
                }
                LinkStore.setPushRegistered(true, endpoint)
                Log.d("TunnelRegClient", "Successfully registered state-assisted contact ID with tunnel server")
            }
        }
    }

    /**
     * Permanently tombstone the Contact ID on the tunnel server (`DELETE /cable/register/<contact_id>`) so desktop clients receive HTTP 410 Gone.
     */
    suspend fun unregisterPushSubscription(contactId: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching<Unit> {
            val url = "${resolveBaseHttpsUrl()}/cable/register/$contactId"
            val reqBuilder = Request.Builder()
                .url(url)
                .delete()

            LinkStore.getRegistrationSecret()?.takeIf { it.isNotEmpty() }?.let { secret ->
                reqBuilder.header("Authorization", "Bearer $secret")
            }

            httpClient.newCall(reqBuilder.build()).execute().use { response ->
                if (!response.isSuccessful && response.code != 410) {
                    throw IOException("Unregister failed with HTTP ${response.code}")
                }
                LinkStore.clearAllLinks()
                LinkStore.rotateContactIdentity()
                Log.d("TunnelRegClient", "Unlinked contact ID and rotated local identity")
            }
        }
    }
}