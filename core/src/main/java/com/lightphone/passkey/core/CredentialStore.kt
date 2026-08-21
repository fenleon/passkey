package com.lightphone.passkey.core

import android.content.Context
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
import org.json.JSONArray
import org.json.JSONObject

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
)

class CredentialStore(private val context: Context) {

    private val file = File(context.filesDir, "passkey_credentials.json")
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun alias(credentialId: ByteArray) = "passkey:${Base64Url.encode(credentialId)}"

    /**
     * Creates an EC P-256 keypair in the Keystore. With [requireUv] the key is
     * bound to user verification (fingerprint OR device credential) for every
     * use — keygen throws if no secure lock screen / enrolled biometric exists.
     */
    @Synchronized
    fun createCredential(rpId: String, userName: String, userHandle: ByteArray, requireUv: Boolean): Credential {
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
        val credential = Credential(credId, rpId, userName, userHandle, requireUv, 0)
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
        save(load().map {
            if (it.credentialId.contentEquals(credentialId)) it.copy(signCount = it.signCount + 1) else it
        })
    }

    @Synchronized
    fun clearAll() {
        ks.aliases().toList().filter { it.startsWith("passkey:") }.forEach { ks.deleteEntry(it) }
        file.delete()
    }

    // ---- metadata persistence ----

    private fun load(): List<Credential> {
        if (!file.exists()) return emptyList()
        val arr = JSONArray(file.readText())
        return buildList {
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                add(
                    Credential(
                        credentialId = Base64Url.decode(o.getString("credentialId")),
                        rpId = o.getString("rpId"),
                        userName = o.getString("userName"),
                        userHandle = Base64Url.decode(o.getString("userHandle")),
                        uvBound = o.optBoolean("uvBound", false),
                        signCount = o.getLong("signCount"),
                    )
                )
            }
        }
    }

    private fun save(creds: List<Credential>) {
        val arr = JSONArray()
        for (c in creds) {
            arr.put(
                JSONObject()
                    .put("credentialId", Base64Url.encode(c.credentialId))
                    .put("rpId", c.rpId)
                    .put("userName", c.userName)
                    .put("userHandle", Base64Url.encode(c.userHandle))
                    .put("uvBound", c.uvBound)
                    .put("signCount", c.signCount)
            )
        }
        file.writeText(arr.toString())
    }
}
