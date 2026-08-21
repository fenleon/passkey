package com.lightphone.passkey.core

import androidx.biometric.BiometricPrompt
import java.security.MessageDigest
import org.json.JSONObject

/**
 * Transport-independent WebAuthn authenticator core (Phase 1): MakeCredential /
 * GetAssertion with attestation "none", hardware-backed keys, and a UV gate.
 * Produces standard WebAuthn response JSON; the transports (USB-HID / caBLE)
 * plug in below this layer later.
 */
class PasskeyAuthenticator(
    private val store: CredentialStore,
    /**
     * User-verification gate: [UvGate.authenticate] when a FragmentActivity is
     * available (loopback/tests), or a companion-side prompt bridge that
     * launches a UV activity (the tool model — the tool runtime forbids
     * BiometricPrompt, so UV lives in the server module).
     */
    private val uvGate: suspend (title: String, subtitle: String, crypto: BiometricPrompt.CryptoObject?) -> Boolean =
        { _, _, _ -> false },
) {
    // attestation:none authenticators send an all-zero AAGUID
    private val aaguid = ByteArray(16)

    suspend fun register(options: RegistrationOptions): RegistrationResponseJson {
        val credential = store.createCredential(
            options.rpId, options.userName, options.userId, options.requireUserVerification,
        )
        val uv = if (options.requireUserVerification) {
            check(uvGate("Passkey", "Register this credential", null)) {
                "user verification cancelled"
            }
            true
        } else false

        val clientDataJson = clientData("webauthn.create", options.challenge, options.origin)
        val clientDataHash = sha256(clientDataJson)
        val coseKey = Cose.encodeEc2PublicKey(store.publicKey(credential.credentialId))
        val authData = AuthData.registrationAuthData(
            AuthData.rpIdHash(options.rpId), uv, aaguid, credential.credentialId, coseKey,
        )
        val attestationObject = Cbor.encode(
            mapOf<Any, Any>(
                "fmt" to "none",
                "attStmt" to emptyMap<String, Any>(),
                "authData" to authData,
            )
        )
        return RegistrationResponseJson(
            id = Base64Url.encode(credential.credentialId),
            rawId = Base64Url.encode(credential.credentialId),
            type = "public-key",
            response = RegistrationResponse(
                clientDataJSON = Base64Url.encode(clientDataJson),
                attestationObject = Base64Url.encode(attestationObject),
            ),
        )
    }

    suspend fun assert(options: AssertionOptions): AssertionResponseJson {
        val credentials = options.allowCredentialIds?.let { ids ->
            store.list().filter { c -> ids.any { it.contentEquals(c.credentialId) } }
        } ?: store.list(options.rpId)
        val credential = credentials.firstOrNull()
            ?: throw IllegalArgumentException("no credential for rp ${options.rpId}")

        val clientDataJson = clientData("webauthn.get", options.challenge, options.origin)
        val clientDataHash = sha256(clientDataJson)
        val authData = AuthData.assertionAuthData(
            AuthData.rpIdHash(options.rpId), credential.uvBound, credential.signCount + 1,
        )

        val signer = store.signerFor(credential.credentialId)
        if (credential.uvBound) {
            require(
                uvGate("Passkey", "Sign in", BiometricPrompt.CryptoObject(signer))
            ) { "user verification cancelled" }
        }
        signer.update(authData + clientDataHash)
        val signature = signer.sign()
        store.bumpCounter(credential.credentialId)

        return AssertionResponseJson(
            id = Base64Url.encode(credential.credentialId),
            rawId = Base64Url.encode(credential.credentialId),
            type = "public-key",
            response = AssertionResponse(
                clientDataJSON = Base64Url.encode(clientDataJson),
                authenticatorData = Base64Url.encode(authData),
                signature = Base64Url.encode(signature),
                userHandle = Base64Url.encode(credential.userHandle),
            ),
        )
    }

    suspend fun registerCtap(req: RegisterCtapRequest): RegisterCtapResult {
        val excluded = req.excludeCredentialIds.any { id ->
            store.list(req.rpId).any { it.credentialId.contentEquals(id) }
        }
        if (excluded) throw CtapError(CTAP_ERR_CREDENTIAL_EXCLUDED)
        val credential = store.createCredential(
            req.rpId, req.userName, req.userId, req.requireUserVerification,
        )
        val uv = if (req.requireUserVerification) {
            if (!uvGate("Passkey", "Register this credential", null)) {
                throw CtapError(CTAP_ERR_OPERATION_DENIED)
            }
            true
        } else false

        val coseKey = Cose.encodeEc2PublicKey(store.publicKey(credential.credentialId))
        val authData = AuthData.registrationAuthData(
            AuthData.rpIdHash(req.rpId), uv, aaguid, credential.credentialId, coseKey,
        )
        return RegisterCtapResult(credential.credentialId, authData, "none", emptyMap())
    }

    suspend fun assertCtap(req: AssertCtapRequest): AssertCtapResult {
        val credentials = req.allowCredentialIds?.let { ids ->
            store.list().filter { c -> ids.any { it.contentEquals(c.credentialId) } }
        } ?: store.list(req.rpId)
        val credential = credentials.firstOrNull() ?: throw CtapError(CTAP_ERR_NO_CREDENTIALS)

        // UV is required when the request asks for it or the credential was
        // created UV-bound — and a UV-bound key only signs through a
        // CryptoObject-authorized prompt, so the gate always passes the signer.
        val needUv = req.requireUserVerification || credential.uvBound
        val signer = store.signerFor(credential.credentialId)
        if (needUv) {
            val ok = uvGate("Passkey", "Sign in", BiometricPrompt.CryptoObject(signer))
            if (!ok) throw CtapError(CTAP_ERR_OPERATION_DENIED)
        }
        val authData = AuthData.assertionAuthData(
            AuthData.rpIdHash(req.rpId), needUv, credential.signCount + 1,
        )
        signer.update(authData + req.clientDataHash)
        val signature = signer.sign()
        store.bumpCounter(credential.credentialId)
        return AssertCtapResult(
            credential.credentialId, authData, signature, credential.userHandle, credential.userName, needUv,
        )
    }

    private fun clientData(type: String, challenge: ByteArray, origin: String): ByteArray =
        JSONObject()
            .put("type", type)
            .put("challenge", Base64Url.encode(challenge))
            .put("origin", origin)
            .put("crossOrigin", false)
            .toString()
            .toByteArray(Charsets.UTF_8)

    private fun sha256(data: ByteArray) = MessageDigest.getInstance("SHA-256").digest(data)
}
