package com.dev.fido.bridge.feature.push

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.dev.fido.bridge.feature.uri.FidoUriHandlerActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Maintain process priority and display a high-priority full-screen notification during state-assisted wakeups.
 * Satisfy Android 14+ background activity launch restrictions while keeping the caBLE session alive until the user authenticates.
 */
class CableWakeupService : Service() {

    companion object {
        const val CHANNEL_ID = "passkey_bridge_cable_wakeup"
        private const val NOTIFICATION_ID = 2026

        const val ACTION_START_WAKEUP = "com.dev.fido.bridge.action.START_WAKEUP"
        const val ACTION_STOP_WAKEUP = "com.dev.fido.bridge.action.STOP_WAKEUP"

        const val EXTRA_CONTACT_ID = "extra_contact_id"
        const val EXTRA_CLIENT_PAYLOAD_HEX = "extra_client_payload_hex"
        const val EXTRA_OPERATION_HINT = "extra_operation_hint"

        @Volatile
        var onPushRegistrationStatusChanged: ((Boolean, String) -> Unit)? = null

        @Volatile
        var onForegroundWakeupIntercepted: ((String, String?) -> Boolean)? = null

        fun notifyPushStateChanged(registered: Boolean, message: String) {
            onPushRegistrationStatusChanged?.invoke(registered, message)
        }

        fun ensureNotificationChannel(context: Context) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
            if (nm.getNotificationChannel(CHANNEL_ID) != null) return

            val channel = NotificationChannel(
                CHANNEL_ID,
                "Passkey Proximity Requests",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Real-time notifications for linked desktop passkey authentication requests"
                setBypassDnd(true)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            nm.createNotificationChannel(channel)
        }

        fun startWakeup(
            context: Context,
            contactId: String,
            clientPayloadHex: String?,
            operationHint: String
        ) {
            // Fast-path: if FidoUriHandlerActivity is already visible in the foreground, hand off directly without notification delay.
            if (onForegroundWakeupIntercepted?.invoke(contactId, clientPayloadHex) == true) {
                return
            }

            val serviceIntent = Intent(context, CableWakeupService::class.java).apply {
                action = ACTION_START_WAKEUP
                putExtra(EXTRA_CONTACT_ID, contactId)
                putExtra(EXTRA_CLIENT_PAYLOAD_HEX, clientPayloadHex)
                putExtra(EXTRA_OPERATION_HINT, operationHint)
            }
            ContextCompat.startForegroundService(context, serviceIntent)
        }

        fun stopWakeup(context: Context) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            nm?.cancel(NOTIFICATION_ID)
            context.stopService(Intent(context, CableWakeupService::class.java))
        }
    }

    private val serviceScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var autoStopJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP_WAKEUP) {
            stopSelfCleanly()
            return START_NOT_STICKY
        }

        val contactId = intent?.getStringExtra(EXTRA_CONTACT_ID)
        if (contactId.isNullOrEmpty()) {
            stopSelfCleanly()
            return START_NOT_STICKY
        }
        val payloadHex = intent.getStringExtra(EXTRA_CLIENT_PAYLOAD_HEX)
        val hint = intent.getStringExtra(EXTRA_OPERATION_HINT) ?: "ga"

        val notification = buildWakeupNotification(contactId, payloadHex, hint)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Log.e("CableWakeupService", "Failed to promote wakeup service to foreground", e)
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            nm?.notify(NOTIFICATION_ID, notification)
        }

        // Enforce 60-second TTL matching the server's WebPush TTL so unacknowledged notifications auto-dismiss.
        autoStopJob?.cancel()
        autoStopJob = serviceScope.launch {
            delay(60_000)
            Log.d("CableWakeupService", "Wakeup notification expired after 60s")
            stopSelfCleanly()
        }

        return START_NOT_STICKY
    }

    private fun buildWakeupNotification(
        contactId: String,
        payloadHex: String?,
        operationHint: String
    ): Notification {
        val activityIntent = Intent(this, FidoUriHandlerActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_CONTACT_ID, contactId)
            putExtra(EXTRA_CLIENT_PAYLOAD_HEX, payloadHex)
            putExtra(EXTRA_OPERATION_HINT, operationHint)
        }

        val contentPendingIntent = PendingIntent.getActivity(
            this,
            0,
            activityIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val dismissIntent = Intent(this, CableWakeupService::class.java).apply {
            action = ACTION_STOP_WAKEUP
        }
        val dismissPendingIntent = PendingIntent.getService(
            this,
            1,
            dismissIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val title = if (operationHint == "mc") {
            "Passkey Registration Request"
        } else {
            "Passkey Sign-In Request"
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle(title)
            .setContentText("Tap to verify proximity and authenticate with your linked desktop")
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setAutoCancel(true)
            .setOngoing(true)
            .setTimeoutAfter(60_000)
            .setContentIntent(contentPendingIntent)
            .setFullScreenIntent(contentPendingIntent, true)
            .addAction(0, "Authenticate", contentPendingIntent)
            .addAction(0, "Dismiss", dismissPendingIntent)
            .build()
    }

    private fun stopSelfCleanly() {
        autoStopJob?.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        autoStopJob?.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}