plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.lightphone.passkey.core"
    compileSdk = 36

    defaultConfig {
        minSdk = 34
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // api: consumers (the app) call suspend functions directly.
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    // implementation: only the core touches BiometricPrompt.
    implementation("androidx.biometric:biometric:1.1.0")
    // Metadata codec round-trip + migration tests (pure JVM — no Android).
    testImplementation(kotlin("test"))
    // The real org.json (the android.jar stub isn't runnable on the JVM).
    testImplementation("org.json:json:20240303")
}
