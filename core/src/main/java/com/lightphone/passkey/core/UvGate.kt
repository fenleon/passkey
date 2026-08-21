package com.lightphone.passkey.core

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executor
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * One-shot user-verification gate: fingerprint (strong) OR the device lock
 * credential — the same choice platform authenticators offer. With a [crypto]
 * object (a Signature pre-initSign'd with a UV-bound Keystore key), success
 * also authorizes the key's use.
 */
object UvGate {
    suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        crypto: BiometricPrompt.CryptoObject? = null,
    ): Boolean = suspendCancellableCoroutine { cont ->
        val prompt = BiometricPrompt(
            activity,
            Executor { r -> r.run() },
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (cont.isActive) cont.resume(true)
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    if (cont.isActive) cont.resume(false)
                }

                override fun onAuthenticationFailed() {
                    // Wrong finger: the prompt stays open, keep waiting.
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()
        if (crypto != null) prompt.authenticate(info, crypto) else prompt.authenticate(info)
    }
}
