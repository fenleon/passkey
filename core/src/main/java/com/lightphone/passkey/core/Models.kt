package com.lightphone.passkey.core

/** Registration options handed to the authenticator (subset of PublicKeyCredentialCreationOptions). */
data class RegistrationOptions(
    val challenge: ByteArray,
    val rpId: String,
    val rpName: String,
    val userId: ByteArray,
    val userName: String,
    val origin: String,
    val requireUserVerification: Boolean,
)

/** Assertion options (subset of PublicKeyCredentialRequestOptions). */
data class AssertionOptions(
    val challenge: ByteArray,
    val rpId: String,
    val origin: String,
    val allowCredentialIds: List<ByteArray>?,
    val requireUserVerification: Boolean,
)

/** Standard WebAuthn registration response; string fields are base64url-encoded. */
data class RegistrationResponseJson(
    val id: String,
    val rawId: String,
    val type: String,
    val response: RegistrationResponse,
    val clientExtensionResults: Map<String, Any> = emptyMap(),
)

data class RegistrationResponse(
    val clientDataJSON: String,
    val attestationObject: String,
)

/** Standard WebAuthn assertion response; string fields are base64url-encoded. */
data class AssertionResponseJson(
    val id: String,
    val rawId: String,
    val type: String,
    val response: AssertionResponse,
)

data class AssertionResponse(
    val clientDataJSON: String,
    val authenticatorData: String,
    val signature: String,
    val userHandle: String? = null,
)
