package com.lightphone.passkey.cable

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * P-256 (secp256r1) helpers. The curve constants are read from a throwaway
 * JCA keypair (no hardcoded hex); point math (decompress / validate /
 * multiply) is done with BigInteger because JCA has no raw point API — needed
 * for QR-key decompression and the BoringSSL-compatible seed→key derivation.
 */
object Ec {
    const val X962_LEN = 65 // 0x04 || x || y
    const val COMPRESSED_LEN = 33 // 0x02/0x03 || x

    val params: ECParameterSpec = run {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        (kpg.generateKeyPair().public as ECPublicKey).params
    }
    private val p: BigInteger = (params.curve.field as ECFieldFp).p
    private val a: BigInteger = params.curve.a
    private val b: BigInteger = params.curve.b
    val order: BigInteger = params.order
    val generator: ECPoint = params.generator

    fun generateKeyPair(): java.security.KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        return kpg.generateKeyPair()
    }

    fun ecPrivateKey(d: BigInteger) =
        KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(d, params))

    fun ecPublicKey(point: ECPoint) =
        KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))

    /** Raw P-256 ECDH shared secret — the x-coordinate, 32 bytes, no KDF. */
    fun ecdh(privateKey: PrivateKey, peer: ECPoint): ByteArray =
        KeyAgreement.getInstance("ECDH").run {
            init(privateKey)
            doPhase(ecPublicKey(peer), true)
            generateSecret()
        }

    /** Public point of a private scalar d (d·G). */
    fun publicPoint(d: BigInteger): ECPoint = multiply(generator, d)

    // --- raw point math (affine, correct-by-construction double-and-add) ---

    private fun onCurve(pt: ECPoint): Boolean {
        val x = pt.affineX
        val y = pt.affineY
        return y.modPow(BigInteger.TWO, p) == x.modPow(THREE, p).add(a.multiply(x)).add(b).mod(p)
    }

    /** Decompresses an X9.62 compressed point; null if off-curve or bad parity. */
    fun decompress(compressed: ByteArray): ECPoint? {
        if (compressed.size != COMPRESSED_LEN) return null
        val prefix = compressed[0].toInt()
        if (prefix != 0x02 && prefix != 0x03) return null
        val x = BigInteger(1, compressed.copyOfRange(1, COMPRESSED_LEN))
        if (x >= p) return null
        // y² = x³ - 3x + b; p ≡ 3 (mod 4) so sqrt = z^((p+1)/4).
        val alpha = x.modPow(THREE, p).add(a.multiply(x)).add(b).mod(p)
        var y = alpha.modPow(p.add(ONE).divide(FOUR), p)
        if (y.multiply(y).mod(p) != alpha) return null
        if (y.testBit(0) != (prefix == 0x03)) y = p.subtract(y)
        return ECPoint(x, y)
    }

    /** Validates an uncompressed/raw point is on the curve. */
    fun validate(x: BigInteger, y: BigInteger): Boolean = ECPoint(x, y).let { onCurve(it) }

    /** Scalar multiplication k·point (affine double-and-add). */
    fun multiply(point: ECPoint, k: BigInteger): ECPoint {
        require(k.signum() >= 0) { "negative scalar" }
        var result: ECPoint? = null // infinity
        var addend = point
        var bits = k
        while (bits.signum() > 0) {
            if (bits.testBit(0)) result = if (result == null) addend else add(result, addend)
            bits = bits.shiftRight(1)
            if (bits.signum() > 0) addend = double(addend)
        }
        return result ?: error("zero scalar")
    }

    private fun double(pt: ECPoint): ECPoint {
        val x = pt.affineX
        val y = pt.affineY
        val m = x.multiply(x).multiply(THREE).add(a).multiply(y.multiply(TWO).modInverse(p)).mod(p)
        val nx = m.multiply(m).subtract(x.multiply(TWO)).mod(p)
        val ny = m.multiply(x.subtract(nx)).subtract(y).mod(p)
        return ECPoint(nx, ny)
    }

    private fun add(p1: ECPoint, p2: ECPoint): ECPoint {
        val m = p2.affineY.subtract(p1.affineY)
            .multiply(p2.affineX.subtract(p1.affineX).modInverse(p)).mod(p)
        val nx = m.multiply(m).subtract(p1.affineX).subtract(p2.affineX).mod(p)
        val ny = m.multiply(p1.affineX.subtract(nx)).subtract(p1.affineY).mod(p)
        return ECPoint(nx, ny)
    }

    /**
     * BoringSSL `EC_KEY_derive_from_secret` (Chromium): the P-256 scalar from
     * a 32-byte seed. d = HKDF-SHA256(seed, salt=∅, info="derive EC key P-256",
     * 48 bytes) mod n.
     */
    fun keyFromSeed(seed: ByteArray): Pair<BigInteger, ECPoint> {
        val info = "derive EC key P-256".toByteArray(Charsets.US_ASCII)
        val derived = Hkdf.sha256(seed, ByteArray(0), info, 48)
        val d = BigInteger(1, derived).mod(order)
        return d to publicPoint(d)
    }

    private val ONE = BigInteger.ONE
    private val TWO = BigInteger.TWO
    private val THREE = BigInteger.valueOf(3)
    private val FOUR = BigInteger.valueOf(4)
}

/** X9.62 uncompressed (65 B) ↔ point, and compressed (33 B) ↔ point. */
fun ECPoint.toX962(): ByteArray = byteArrayOf(0x04) + affineX.toFixed(32) + affineY.toFixed(32)

fun ECPoint.toCompressed(): ByteArray =
    byteArrayOf((if (affineY.testBit(0)) 0x03 else 0x02).toByte()) + affineX.toFixed(32)

fun ByteArray.toEcPoint(): ECPoint {
    require(this.size == Ec.X962_LEN && this[0].toInt() == 0x04) { "not an uncompressed X9.62 point" }
    val x = BigInteger(1, this.copyOfRange(1, 33))
    val y = BigInteger(1, this.copyOfRange(33, Ec.X962_LEN))
    require(Ec.validate(x, y)) { "point not on curve" }
    return ECPoint(x, y)
}

fun BigInteger.toFixed(len: Int): ByteArray {
    val raw = toByteArray() // may carry a sign byte
    val out = ByteArray(len)
    val src = if (raw.size > len) raw.copyOfRange(raw.size - len, raw.size) else raw
    System.arraycopy(src, 0, out, len - src.size, src.size)
    return out
}
