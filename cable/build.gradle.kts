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

// `./gradlew :cable:run` runs the protocol self-check (CheckKt).
application {
    mainClass.set("com.lightphone.passkey.cable.CheckKt")
}

// Live tunnel-server check (needs network; hits Google's production relay):
// ./gradlew :cable:tunnelCheck
tasks.register<JavaExec>("tunnelCheck") {
    group = "verification"
    description = "Runs the caBLE tunnel flow against the real tunnel server (cable.ua5v.com)."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.lightphone.passkey.cable.TunnelCheckKt")
}

// Simulated desktop (browser) for testing the phone app over the live relay:
// ./gradlew :cable:desktopClient --args="<advertHex> <tunnelIdHex> <qrKeyHex> [uv]"
tasks.register<JavaExec>("desktopClient") {
    group = "verification"
    description = "Plays the desktop side against the phone app (args: advert tunnelId qrKey hex)."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.lightphone.passkey.cable.DesktopClientKt")
}

// Print the runtime classpath so DesktopClient can run via `java` directly
// (gradle startup eats into the tunnel's ~30s TTL):
//   java -cp "$(./gradlew -q :cable:classpath)" com.lightphone.passkey.cable.DesktopClientKt ...
tasks.register("classpath") {
    doLast { println(sourceSets.main.get().runtimeClasspath.asPath) }
}

// Zero dependencies: everything is javax.crypto / java.math (P-256, HKDF,
// AES-GCM). The Android app slices depend on this module later for the
// GATT/tunnel transport work.
