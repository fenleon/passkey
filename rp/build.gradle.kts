plugins {
    id("org.jetbrains.kotlin.jvm")
    id("application")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

application {
    mainClass.set("com.lightphone.passkey.rp.MainKt")
}

dependencies {
    implementation("com.webauthn4j:webauthn4j-core:0.31.9.RELEASE")
}
