package com.lightphone.passkey.core

import java.math.BigInteger
import java.security.interfaces.ECPublicKey

/** COSE key encoding (RFC 9052) for an ES256 (alg -7) P-256 EC2 public key. */
object Cose {
    fun encodeEc2PublicKey(pub: ECPublicKey): ByteArray =
        Cbor.encode(
            mapOf<Any, Any>(
                1 to 2,   // kty: EC2
                3 to -7,  // alg: ES256
                -1 to 1,  // crv: P-256
                -2 to fixed32(pub.w.affineX),
                -3 to fixed32(pub.w.affineY),
            )
        )

    /** Big-endian unsigned 32-byte representation of a P-256 coordinate. */
    private fun fixed32(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        val out = ByteArray(32)
        when {
            b.size == 33 && b[0] == 0.toByte() -> System.arraycopy(b, 1, out, 0, 32)
            b.size <= 32 -> System.arraycopy(b, 0, out, 32 - b.size, b.size)
            else -> throw IllegalArgumentException("coordinate too large")
        }
        return out
    }
}
