plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.lightphone.passkey.server"
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
    // SDK modules come from the included ../light-sdk build (see
    // settings.gradle.kts). sdk-server = LightSdkServer + LightSdkService (the
    // binder). Since the single-module merge this library ships INSIDE the
    // tool APK, which hosts the service and binds to itself
    // (lighttool.toml serverPackage = com.lightphone.passkey).
    implementation("com.thelightphone:sdk-server:0.1.0")
    implementation("com.thelightphone:sdk-shared:0.1.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    // Tunnel websocket (the caBLE relay); frames are binary.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // UvActivity is a FragmentActivity (the BiometricPrompt needs a
    // FragmentManager); UvPrompt's gate signature carries
    // BiometricPrompt.CryptoObject (:core keeps its biometric dep
    // implementation-only).
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation(project(":core"))
    implementation(project(":cable"))
}
