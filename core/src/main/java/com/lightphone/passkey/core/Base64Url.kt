package com.lightphone.passkey.core

import java.util.Base64

/** Base64url (RFC 4648 §5) without padding — the WebAuthn wire format. */
object Base64Url {
    fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun decode(s: String): ByteArray = Base64.getUrlDecoder().decode(s)
}
