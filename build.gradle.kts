// Root build.gradle.kts
// Explicitly declare plugin IDs and versions to avoid Version Catalog (libs) accessor generation issues
plugins {
    id("com.android.application") version "8.3.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "1.9.24" apply false
}