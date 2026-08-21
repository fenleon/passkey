package com.lightphone.passkey.cable

/**
 * Minimal CTAP2 wire constants + the hybrid authenticator's getInfo response,
 * byte-identical to Chromium's `BuildGetInfoResponse` (v2_authenticator.cc):
 *
 *   {1: ["FIDO_2_0","FIDO_2_1"], 2: ["prf"], 3: <16 zero bytes>,
 *    4: {"rk":true,"uv":true}, 9: ["cable","hybrid","internal"]}
 *
 * In the caBLE v2 tunnel flow the phone pushes this map right after the
 * handshake (post-handshake message, key 1) and Chrome never sends its own
 * getInfo request; answering one anyway makes the protocol loop testable.
 */
object Ctap {
    // caBLE v2 message types (Chromium cablev2::MessageType) — every
    // post-handshake frame carries the type byte as the first plaintext byte.
    const val MSG_SHUTDOWN = 0
    const val MSG_CTAP = 1

    const val CMD_MAKE_CREDENTIAL = 0x01
    const val CMD_GET_ASSERTION = 0x02
    const val CMD_GET_INFO = 0x04

    const val CTAP_OK = 0x00
    const val ERR_INVALID_CBOR = 0x12
    const val ERR_CREDENTIAL_EXCLUDED = 0x19
    const val ERR_UNSUPPORTED_ALGORITHM = 0x26
    const val ERR_UNSUPPORTED_OPTION = 0x2b
    const val ERR_NO_CREDENTIALS = 0x2e
    const val ERR_OPERATION_DENIED = 0x2f

    fun getInfo(): ByteArray = CableCbor.encode(
        mapOf<Any, Any?>(
            1L to listOf("FIDO_2_0", "FIDO_2_1"),
            2L to listOf("prf"),
            3L to ByteArray(16), // zero AAGUID (attestation none)
            4L to mapOf<Any, Any?>("rk" to true, "uv" to true),
            9L to listOf("cable", "hybrid", "internal"),
        )
    )
}
