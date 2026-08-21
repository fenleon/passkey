package com.lightphone.passkey.core

import java.security.MessageDigest

/** Authenticator data assembly (WebAuthn spec §6.1). */
object AuthData {
    const val FLAG_UP = 0x01
    const val FLAG_UV = 0x04
    const val FLAG_AT = 0x40

    fun rpIdHash(rpId: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8))

    /** Assertion authData: rpIdHash ‖ flags ‖ signCount(4B BE). */
    fun assertionAuthData(rpIdHash: ByteArray, uv: Boolean, signCount: Long): ByteArray {
        var flags = FLAG_UP
        if (uv) flags = flags or FLAG_UV
        return rpIdHash + byteArrayOf(flags.toByte()) + u32(signCount)
    }

    /** Registration authData with attested credential data appended. */
    fun registrationAuthData(
        rpIdHash: ByteArray,
        uv: Boolean,
        aaguid: ByteArray,
        credentialId: ByteArray,
        coseKey: ByteArray,
    ): ByteArray {
        var flags = FLAG_UP
        if (uv) flags = flags or FLAG_UV
        flags = flags or FLAG_AT
        return rpIdHash + byteArrayOf(flags.toByte()) + u32(0) + aaguid + u16(credentialId.size) + credentialId + coseKey
    }

    fun u16(v: Int) = byteArrayOf(((v shr 8) and 0xff).toByte(), (v and 0xff).toByte())

    fun u32(v: Long) = byteArrayOf(
        ((v shr 24) and 0xff).toByte(),
        ((v shr 16) and 0xff).toByte(),
        ((v shr 8) and 0xff).toByte(),
        (v and 0xff).toByte(),
    )
}
