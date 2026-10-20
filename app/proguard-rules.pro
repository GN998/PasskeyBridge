# Preserve UnifiedPush broadcast receiver and foreground wakeup service entry points from R8 stripping in release builds
-keep class com.dev.fido.bridge.feature.push.CablePushReceiver { *; }
-keep class com.dev.fido.bridge.feature.push.CableWakeupService { *; }
-keep class org.unifiedpush.android.connector.** { *; }
-dontwarn org.unifiedpush.android.connector.**

# Retain Kotlin coroutine internal fields and OkHttp platform reflection required for TLS/WebSocket transport
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**