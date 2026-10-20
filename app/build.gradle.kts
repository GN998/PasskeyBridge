import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) {
        load(file.inputStream())
    }
}

val rawTunnelId = System.getenv("CUSTOM_TUNNEL_ID")?.takeIf { it.isNotBlank() }
    ?: localProperties.getProperty("TUNNEL_ID")?.takeIf { it.isNotBlank() }
    ?: throw GradleException("Build failed: TUNNEL_ID is not specified!")

val tunnelId = rawTunnelId.toIntOrNull()
    ?: throw GradleException("Build failed: TUNNEL_ID must be a valid integer.")

// Resolve optional build-time VAPID public key fallback so devices can subscribe to Sunup without an extra HTTP round-trip
val defaultVapidPublicKey = System.getenv("VAPID_PUBLIC_KEY")?.takeIf { it.isNotBlank() }
    ?: localProperties.getProperty("VAPID_PUBLIC_KEY")?.takeIf { it.isNotBlank() }
    ?: ""

// Inject registration bearer secret at build time to authenticate state-assisted push endpoints without manual user input
val registrationSecret = System.getenv("REGISTRATION_SECRET")?.takeIf { it.isNotBlank() }
    ?: localProperties.getProperty("REGISTRATION_SECRET")?.takeIf { it.isNotBlank() }
    ?: ""

println("--> [Gradle Build Config] Successfully resolved TUNNEL_ID: $tunnelId")

android {
    namespace = "com.dev.fido.bridge"
    // Target API 35 for modern AGP and AndroidX compatibility while preserving Android 14+ (API 34) runtime floor
    compileSdk = 35

    // Enforce deterministic APK signing certificate so external credential providers
    // (e.g., Authnkey, Bitwarden) can reliably verify the app's SHA-256 fingerprint allowlist.
    signingConfigs {
        create("fixedConfig") {
            val keystoreFile = rootProject.file("my-release-key.jks")
            if (keystoreFile.exists()) {
                storeFile = keystoreFile
                // Prioritize environment variables (CI), fallback to local.properties (local dev)
                storePassword = System.getenv("STORE_PASSWORD") ?: localProperties.getProperty("STORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS") ?: localProperties.getProperty("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD") ?: localProperties.getProperty("KEY_PASSWORD")
            } else if (System.getenv("CI") == "true" || System.getenv("GITHUB_ACTIONS") == "true") {
                // Fail fast in CI environments to prevent producing unsigned or mismatched APKs
                // that silently break CredentialManager privileged allowlist checks.
                throw GradleException("Build failed: my-release-key.jks is missing in CI environment!")
            }
        }
    }

    defaultConfig {
        applicationId = "com.dev.fido.bridge"
        minSdk = 34
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("int", "TUNNEL_ID", "$tunnelId")
        buildConfigField("String", "DEFAULT_VAPID_PUBLIC_KEY", "\"$defaultVapidPublicKey\"")
        buildConfigField("String", "REGISTRATION_SECRET", "\"$registrationSecret\"")
    }

    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("fixedConfig")
        }
        release {
            signingConfig = signingConfigs.getByName("fixedConfig")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        // Disable viewBinding as UI is constructed programmatically, reducing build overhead
        buildConfig = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")

    // Android 14+ CredentialManager (Core API)
    // Omit legacy credentials-play-services-auth dependency to prevent unwanted GMS permissions
    implementation("androidx.credentials:credentials:1.3.0")

    // Coroutines & WebSockets
    // Match Kotlin 2.x metadata format to prevent binary compatibility warnings during R8 shrinking
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // UnifiedPush connector for registering and receiving state-assisted wakeup broadcasts via Sunup / Mozilla Autopush
    implementation("org.unifiedpush.android:connector:3.0.4")
}