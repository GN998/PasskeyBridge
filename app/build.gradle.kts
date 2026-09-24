import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

// Load local.properties file for local development 
// (This file should be ignored by version control like Git)
val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) {
        load(file.inputStream())
    }
}

// Strict priority mapping: 
// 1. CI Environment Variable (CUSTOM_TUNNEL_ID from GitHub Actions)
// 2. Local properties file (TUNNEL_ID from local.properties)
// Fail-fast: Throw an exception if neither is provided to prevent invalid builds.
val rawTunnelId = System.getenv("CUSTOM_TUNNEL_ID") 
    ?: localProperties.getProperty("TUNNEL_ID")
    ?: throw GradleException("Build failed: TUNNEL_ID is not specified! Please configure it in CI environment variables or local.properties.")

// Validate that the provided ID is a valid integer
val tunnelId = rawTunnelId.toIntOrNull() 
    ?: throw GradleException("Build failed: TUNNEL_ID must be a valid integer. Current value is: '$rawTunnelId'")

android {
    namespace = "com.yourcompany.passkeybridge"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.yourcompany.passkeybridge"
        minSdk = 28
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Inject the validated tunnel ID into BuildConfig so Kotlin code can use it securely
        buildConfigField("int", "TUNNEL_ID", "$tunnelId")
    }

    buildTypes {
        release {
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
        // Enable BuildConfig generation to access the injected TUNNEL_ID from Kotlin code
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

    // CameraX & ZXing
    implementation("androidx.camera:camera-camera2:1.3.3")
    implementation("androidx.camera:camera-lifecycle:1.3.3")
    implementation("androidx.camera:camera-view:1.3.3")
    implementation("com.google.zxing:core:3.5.3")
}