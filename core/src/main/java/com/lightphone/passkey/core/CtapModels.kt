package com.lightphone.passkey.core

/** CTAP2 (caBLE hybrid) request/result pieces — raw bytes only. CTAP2 sends the
 *  clientDataHash precomputed, so there is no origin/challenge/JSON in this
 *  path; the WebAuthn JSON variants ([PasskeyAuthenticator.register]/[assert])
 *  stay untouched. */
data class RegisterCtapRequest(
    val rpId: String,
    val userId: ByteArray,
    val userName: String,
    val clientDataHash: ByteArray,
    val requireUserVerification: Boolean,
    val excludeCredentialIds: List<ByteArray> = emptyList(),
)

data class RegisterCtapResult(
    val credentialId: ByteArray,
    val authData: ByteArray,
    val fmt: String, // "none"
    val attStmt: Map<String, Any>, // empty
)

data class AssertCtapRequest(
    val rpId: String,
    val clientDataHash: ByteArray,
    val allowCredentialIds: List<ByteArray>?,
    val requireUserVerification: Boolean,
)

data class AssertCtapResult(
    val credentialId: ByteArray,
    val authData: ByteArray,
    val signature: ByteArray,
    val userHandle: ByteArray,
    val uv: Boolean,
)

/** Failure to report to the client as a bare CTAP2 status byte (CTAP2 §5.4). */
class CtapError(val status: Int) : Exception("ctap2 error 0x%02x".format(status))

const val CTAP_ERR_CREDENTIAL_EXCLUDED = 0x19
const val CTAP_ERR_NO_CREDENTIALS = 0x2e
const val CTAP_ERR_OPERATION_DENIED = 0x2f
