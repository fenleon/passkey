plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
    // The light-sdk plugin self-adds its KSP processor (which generates the
    // LightSdkRegistry from @InitialScreen) only when KSP is applied here.
    id("com.google.devtools.ksp") version "2.3.6"
    id("com.thelightphone.light-sdk")
}

android {
    compileSdk = 36

    signingConfigs {
        // Workspace dev signing (same key as the SDK tools/emulator).
        create("lightsdkDev") {
            storeFile = file("../../light-sdk/sdk/keys/lightsdk-dev.jks")
            storePassword = "android"
            keyAlias = "lightsdk-dev"
            keyPassword = "android"
        }
    }

    defaultConfig {
        minSdk = 34
        targetSdk = 36

        // Consumed by the plugin's generated manifest (SDK_VERSION metadata).
        manifestPlaceholders["sdkVersion"] = property("sdkVersion") as String
    }

    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("lightsdkDev")
        }
        getByName("release") {
            signingConfig = signingConfigs.getByName("lightsdkDev")
        }
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
    // SDK modules come from the included ../light-sdk build (see settings.gradle.kts).
    // sdk-client pulls sdk:ui — the LightQrCodeScanner (CameraX + ML Kit) is
    // the scanner UI's core, so no exclusions here (unlike audiobooks).
    implementation("com.thelightphone:sdk-client:0.1.0")
    // The caBLE session + authenticator, merged into the tool APK
    // (single-module build, 2026-08-21): its manifest contributes the SDK
    // server components (LightSdkService, UvActivity), its
    // ServerBootstrapProvider wires the SDK server at app start, and the
    // tool binds to itself (lighttool.toml serverPackage = own id).
    implementation(project(":server"))
    // Qr encode for the debug auto-QR button (pure JVM, no Android deps).
    implementation(project(":cable"))
}
