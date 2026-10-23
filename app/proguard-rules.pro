# Strip verbose and debug log calls in release builds to prevent leaking WebAuthn PII
# (rpId, credentialId, userHandle, and raw JSON payloads) to system logcat per WebAuthn §14.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

# Preserve Android 14+ CredentialProviderService Binder entrypoints from aggressive R8 method inlining
-keep class * extends androidx.credentials.provider.CredentialProviderService {
    public <init>();
    public void onBeginGetCredentialRequest(***);
    public void onBeginCreateCredentialRequest(***);
    public void onClearCredentialStateRequest(***);
}