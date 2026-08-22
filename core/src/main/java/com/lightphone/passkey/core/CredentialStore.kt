package com.lightphone.passkey.core

import android.content.Context
import android.app.KeyguardManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * One resident credential's metadata. The private key itself lives in the
 * Android Keystore under alias "passkey:<b64u credId>" — it never leaves the
 * TEE. The metadata JSON (app-private storage) is non-secret bookkeeping.
 */
data class Credential(
    val credentialId: ByteArray,
    val rpId: String,
    val userName: String,
    val userHandle: ByteArray,
    val uvBound: Boolean,
    val signCount: Long,
    /** Epoch millis of registration; 0 = legacy row (created before timestamps were stored). */
    val createdAt: Long = 0,
    /** Epoch millis of the last sign-in; 0 = never used. */
    val lastUsedAt: Long = 0,
)

/**
 * UV was required but the device has no secure lock — no Gatekeeper HAT can
 * be minted, so neither a UV-bound key nor a UV-required sign-in can work.
 * The session layer maps this to an honest status instead of a raw keygen
 * failure.
 */
class UvUnavailableException : Exception("UV unavailable — no secure lock on this device")

class CredentialStore(private val context: Context) {

    private val file = File(context.filesDir, "passkey_credentials.json")
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun alias(credentialId: ByteArray) = "passkey:${Base64Url.encode(credentialId)}"

    /** A secure lock exists (device credential or biometrics) — UV can work. */
    fun isUvAvailable(): Boolean =
        (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure

    /**
     * Creates an EC P-256 keypair in the Keystore. With [requireUv] the key is
     * bound to user verification (fingerprint OR device credential) for every
     * use — keygen throws if no secure lock screen / enrolled biometric exists.
     */
    @Synchronized
    fun createCredential(rpId: String, userName: String, userHandle: ByteArray, requireUv: Boolean): Credential {
        if (requireUv && !isUvAvailable()) throw UvUnavailableException()
        val credId = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val spec = KeyGenParameterSpec.Builder(alias(credId), KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply {
                if (requireUv) {
                    setUserAuthenticationRequired(true)
                    setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                }
            }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            .apply { initialize(spec) }
            .generateKeyPair()
        val credential = Credential(
            credId, rpId, userName, userHandle, requireUv, 0,
            createdAt = System.currentTimeMillis(),
        )
        save(load() + credential)
        return credential
    }

    @Synchronized
    fun get(credentialId: ByteArray): Credential? =
        load().firstOrNull { it.credentialId.contentEquals(credentialId) }

    @Synchronized
    fun list(rpId: String? = null): List<Credential> =
        load().filter { rpId == null || it.rpId == rpId }

    @Synchronized
    fun publicKey(credentialId: ByteArray): ECPublicKey =
        ks.getCertificate(alias(credentialId))?.publicKey as? ECPublicKey
            ?: throw IllegalArgumentException("no key for credential")

    /** A Signature pre-initSign'd with the credential's key, for the BiometricPrompt CryptoObject. */
    @Synchronized
    fun signerFor(credentialId: ByteArray): Signature {
        val key = ks.getKey(alias(credentialId), null) as PrivateKey
        return Signature.getInstance("SHA256withECDSA").apply { initSign(key) }
    }

    @Synchronized
    fun bumpCounter(credentialId: ByteArray) {
        val now = System.currentTimeMillis()
        save(load().map {
            if (it.credentialId.contentEquals(credentialId)) {
                it.copy(signCount = it.signCount + 1, lastUsedAt = now)
            } else {
                it
            }
        })
    }

    /** Removes the Keystore key + metadata row for [credentialId]; no-op when unknown. */
    @Synchronized
    fun delete(credentialId: ByteArray) {
        val creds = load()
        if (creds.none { it.credentialId.contentEquals(credentialId) }) return
        ks.deleteEntry(alias(credentialId))
        save(creds.filterNot { it.credentialId.contentEquals(credentialId) })
    }

    @Synchronized
    fun clearAll() {
        ks.aliases().toList().filter { it.startsWith("passkey:") }.forEach { ks.deleteEntry(it) }
        file.delete()
    }

    // ---- metadata persistence (pure-JVM codec — see CredentialCodec) ----

    private fun load(): List<Credential> {
        if (!file.exists()) return emptyList()
        return CredentialCodec.decode(file.readText())
    }

    private fun save(creds: List<Credential>) {
        file.writeText(CredentialCodec.encode(creds))
    }
}
