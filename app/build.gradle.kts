import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
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

println("--> [Gradle Build Config] Successfully resolved TUNNEL_ID: $tunnelId")

android {
    namespace = "com.yourcompany.passkeybridge"
    compileSdk = 34

    // Add signingConfigs for fixed certificate
    signingConfigs {
        create("fixedConfig") {
            val keystoreFile = rootProject.file("my-release-key.jks")
            if (keystoreFile.exists()) {
                storeFile = keystoreFile
                // Prioritize environment variables (CI), fallback to local.properties (local dev)
                storePassword = System.getenv("STORE_PASSWORD") ?: localProperties.getProperty("STORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS") ?: localProperties.getProperty("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD") ?: localProperties.getProperty("KEY_PASSWORD")
            }
        }
    }

    defaultConfig {
        applicationId = "com.yourcompany.passkeybridge"
        minSdk = 28
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("int", "TUNNEL_ID", "$tunnelId")
    }

    buildTypes {
        // Apply fixedConfig to debug build
        getByName("debug") {
            signingConfig = signingConfigs.getByName("fixedConfig")
        }
        release {
            // Apply fixedConfig to release build
            signingConfig = signingConfigs.getByName("fixedConfig")
            isMinifyEnabled = false
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
        viewBinding = true
        buildConfig = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")

    // Android 14 CredentialManager
    implementation("androidx.credentials:credentials:1.3.0-alpha04")
    implementation("androidx.credentials:credentials-play-services-auth:1.3.0-alpha04")

    // kotlinx.serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-core:1.6.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-cbor:1.6.3")

    // Coroutines & WebSockets
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Note: CameraX & ZXing dependencies removed for Step 1 (External FIDO URI integration)
}