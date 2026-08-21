package com.lightphone.passkey.cable

/**
 * caBLE v2 QR payloads (Chromium `cablev2_handshake.cc`).
 *
 * The QR is `FIDO:/` + a base-10 digits encoding of a CBOR map:
 *
 *   0: compressed P-256 public key of the desktop (from its 32-byte QR seed)
 *   1: 16-byte secret
 *   2: number of registered tunnel-server domains the desktop knows (int)
 *   3: unix timestamp (int)
 *   4: supports_linking (bool) — always false for WebAuthn
 *   5: request type ("ga" / "mc", default "ga")
 *
 * Bytes are turned into digits in 7-byte → 17-digit chunks
 * (imperialviolet.org/2021/08/26/qrencoding.html). The digits codec has a
 * fixed test vector: [0x61 0x62 0xFF] → "16736865".
 */
object Qr {
    const val PREFIX = "FIDO:/"
    const val SECRET_LEN = 16

    data class Components(
        val peerIdentity: ByteArray, // uncompressed X9.62, 65 B
        val secret: ByteArray, // 16 B
        val numKnownDomains: Long,
        val supportsLinking: Boolean?,
        val requestType: String,
    ) {
        override fun equals(other: Any?) = other is Components &&
            peerIdentity.contentEquals(other.peerIdentity) &&
            secret.contentEquals(other.secret) &&
            numKnownDomains == other.numKnownDomains &&
            supportsLinking == other.supportsLinking &&
            requestType == other.requestType

        override fun hashCode() =
            peerIdentity.contentHashCode() * 31 + secret.contentHashCode()
    }

    fun parse(qr: String): Components? {
        if (qr.length < PREFIX.length || !qr.startsWith(PREFIX, ignoreCase = true)) return null
        val bytes = digitsToBytes(qr.substring(PREFIX.length)) ?: return null
        val map = CableCbor.decode(bytes) as? Map<*, *> ?: return null

        val compressed = map[0L] as? ByteArray ?: return null
        val point = Ec.decompress(compressed) ?: return null
        val secret = map[1L] as? ByteArray ?: return null
        if (secret.size != SECRET_LEN) return null

        val numDomains = when (val v = map[2L]) {
            null -> 0L
            is Long -> v
            else -> return null // present but not an integer
        }
        val linking = when (val v = map[4L]) {
            null -> null
            is Boolean -> v
            else -> return null
        }
        val request = when (val v = map[5L]) {
            null -> "ga"
            is String -> v
            else -> return null
        }

        return Components(point.toX962(), secret, numDomains, linking, request)
    }

    /** Desktop-side QR string for a 48-byte QR key (seed ‖ secret). */
    fun encode(qrKey: ByteArray, requestType: String = "ga"): String {
        require(qrKey.size == 48) { "QR key must be 48 bytes" }
        val seed = qrKey.copyOfRange(0, 32)
        val secret = qrKey.copyOfRange(32, 48)
        val (_, point) = Ec.keyFromSeed(seed)
        val map = linkedMapOf<Long, Any?>(
            0L to point.toCompressed(),
            1L to secret,
            2L to 2L, // assigned tunnel-server domains known to the desktop
            3L to (System.currentTimeMillis() / 1000),
            4L to false, // WebAuthn never offers linking
            5L to requestType,
        )
        return PREFIX + bytesToDigits(CableCbor.encode(map))
    }

    // --- 7-byte → 17-digit codec (Chromium qr::BytesToDigits/DigitsToBytes) ---

    private const val CHUNK_BYTES = 7
    private const val CHUNK_DIGITS = 17
    private val WIDTHS = intArrayOf(0, 3, 5, 8, 10, 13, 15, 17)

    fun bytesToDigits(input: ByteArray): String {
        val sb = StringBuilder((input.size + CHUNK_BYTES - 1) / CHUNK_BYTES * CHUNK_DIGITS)
        var i = 0
        while (i < input.size) {
            val n = minOf(CHUNK_BYTES, input.size - i)
            var v = 0L
            for (j in 0 until n) v = v or ((input[i + j].toLong() and 0xff) shl (8 * j))
            sb.append(String.format("%0${WIDTHS[n]}d", v))
            i += n
        }
        return sb.toString()
    }

    fun digitsToBytes(digits: String): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i + CHUNK_DIGITS <= digits.length) {
            val v = digits.substring(i, i + CHUNK_DIGITS).toLongOrNull() ?: return null
            if (v shr (CHUNK_BYTES * 8) != 0L) return null
            for (j in 0 until CHUNK_BYTES) out.write((v shr (8 * j)).toInt() and 0xff)
            i += CHUNK_DIGITS
        }
        if (i < digits.length) {
            val rest = digits.length - i
            val nBytes = when (rest) {
                3 -> 1
                5 -> 2
                8 -> 3
                10 -> 4
                13 -> 5
                15 -> 6
                else -> return null
            }
            val v = digits.substring(i).toLongOrNull() ?: return null
            if (v shr (nBytes * 8) != 0L) return null
            for (j in 0 until nBytes) out.write((v shr (8 * j)).toInt() and 0xff)
        }
        return out.toByteArray()
    }
}
