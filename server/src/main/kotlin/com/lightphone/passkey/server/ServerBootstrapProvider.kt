package com.lightphone.passkey.server

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.database.Cursor
import android.net.Uri
import com.thelightphone.sdk.server.ClientCertType
import com.thelightphone.sdk.server.ClientFilterLevel
import com.thelightphone.sdk.server.LightSdkServer
import java.security.MessageDigest

// SHA-256 fingerprint of sdk/keys/lightsdk-dev.jks (alias: lightsdk-dev). Any
// APK signed with the workspace dev key is treated as Light-SDK-signed.
private const val LIGHTSDK_DEV_CERT_SHA256 =
    "B9C33E29B0CCAD2BFF11ACAB55F65A3C517EF4BC92CD9C77785366FA353D5F28"

/**
 * Single-module build: the embedded LightSdkServer wiring runs here, inside
 * the merged tool APK. A ContentProvider is the only app-start hook with a
 * real [Context] that is not part of the tool-plugin scanned module — it
 * wires the SDK server (settings relay, cert check, passkey methods, device
 * keys) before the tool's first binder call.
 */
class ServerBootstrapProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val context = context?.applicationContext ?: return false
        SessionManager.init(context)

        with(LightSdkServer) {
            defaultClientFilterLevel = ClientFilterLevel.AllowLightSignedApks
            provideSdkSettings = { RelaySdkServerSettings(it) }
            checkCert = { callingPackage -> checkLightSdkCert(context, callingPackage) }
            customServiceMethodResolver = { _, methodId, payload ->
                PasskeyServiceMethods.dispatch(methodId, payload)
            }
            // Passkey consumes no hardware keys — every DeviceKeyEvent goes to
            // LightOS (volume panel, brightness wheel, camera/flashlight) and
            // haptics answer from the real setting (PLATFORM-RELAY.md).
            onDeviceKeyEvent = { _, event -> PlatformRelay.sendDeviceKeyEvent(event) }
        }

        // One connection to the already-running platform SDK server.
        PlatformRelay.bind(context)
        return true
    }

    private fun checkLightSdkCert(context: Context, callingPackage: String): ClientCertType {
        val info = try {
            context.packageManager.getPackageInfo(
                callingPackage,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
        } catch (e: PackageManager.NameNotFoundException) {
            return ClientCertType.Unknown
        }
        val signingInfo = info.signingInfo ?: return ClientCertType.Unknown
        val signers: Array<Signature> = if (signingInfo.hasMultipleSigners()) {
            signingInfo.apkContentsSigners
        } else {
            signingInfo.signingCertificateHistory
        }
        val md = MessageDigest.getInstance("SHA-256")
        val matches = signers.any { sig ->
            md.digest(sig.toByteArray()).toHexString()
                .equals(LIGHTSDK_DEV_CERT_SHA256, ignoreCase = true)
        }
        return if (matches) ClientCertType.LightSdkSignedUnverified else ClientCertType.Unknown
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02X".format(it) }

    // The provider exists for its onCreate only; no content is served.
    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0

    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?): Int = 0
}
