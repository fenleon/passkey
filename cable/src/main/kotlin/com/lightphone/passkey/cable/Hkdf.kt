package com.lightphone.passkey.cable

import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 5869 HKDF-SHA256. Used in three places, all matching BoringSSL's
 * `crypto::kdf::Hkdf` (Chromium) byte-for-byte:
 *
 *  - `derive` (caBLEv2 `Derive`): salt = nonce, info = 4-byte LE type.
 *  - Noise `HKDF2` / 96-byte `MixKeyAndHash` mixes: salt = chaining key,
 *    info = empty.
 *  - BoringSSL `EC_KEY_derive_from_secret` (seed → P-256 scalar): salt =
 *    empty, info = "derive EC key P-256", 48 bytes out.
 *
 * An empty salt is equivalent to a zero-filled key for HMAC (keys are padded
 * to the block size), so `ByteArray(0)` is safe where BoringSSL passes NULL.
 */
object Hkdf {
    fun sha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        require(outLen in 1..(32 * 255)) { "HKDF output too long" }
        val mac = Mac.getInstance("HmacSHA256")
        // An empty salt is RFC 5869's "not provided" case = HashLen zeros; HMAC
        // pads short keys with zeros anyway, so this is byte-identical. JDK 21
        // rejects zero-length SecretKeySpec keys outright.
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArrayOutputStream(outLen)
        var t = ByteArray(0)
        var i = 1
        while (out.size() < outLen) {
            mac.reset()
            mac.update(t)
            mac.update(info)
            mac.update(i.toByte())
            t = mac.doFinal()
            out.write(t)
            i++
        }
        return out.toByteArray().copyOf(outLen)
    }

    /** Noise's two-output HKDF (32 + 32). */
    fun noise2(ck: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
        val out = sha256(ikm, ck, ByteArray(0), 64)
        return out.copyOfRange(0, 32) to out.copyOfRange(32, 64)
    }
}
