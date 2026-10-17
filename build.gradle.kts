// Align AGP and Kotlin compiler versions with Gradle 8.14.5 to prevent build-time API incompatibilities
plugins {
    id("com.android.application") version "8.11.1" apply false
    id("org.jetbrains.kotlin.android") version "2.1.20" apply false
}