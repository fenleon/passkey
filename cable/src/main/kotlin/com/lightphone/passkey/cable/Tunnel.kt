package com.lightphone.passkey.cable

/**
 * caBLE v2 tunnel server (Chromium `v2_handshake.cc` tunnelserver::*).
 *
 * The tunnel server relays websocket messages between the phone and the
 * desktop. The phone opens a tunnel with `newUrl(tunnelId)` and receives its
 * routing ID in the `X-caBLE-Routing-ID` handshake header; the desktop
 * connects with `connectUrl(routingId, tunnelId)`. The 16-bit "domain" in the
 * EID selects the server: 0 → cable.ua5v.com, 1 → cable.auth.com, 256..64K →
 * a hashed `cable.<base32>.com` name.
 */
object TunnelServer {
    private val ASSIGNED = arrayOf("cable.ua5v.com", "cable.auth.com")
    private const val HASH_PREFIX = "caBLEv2 tunnel server domain"
    private val BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
    private val TLDS = arrayOf("com", "org", "net", "info")

    /** KnownDomainID → dotted name. [domain] must be < [ASSIGNED].size or ≥ 256. */
    fun decodeDomain(domain: Int): String {
        if (domain < ASSIGNED.size) return ASSIGNED[domain]
        require(domain in 256..0xffff) { "invalid tunnel server domain $domain" }
        // [28-byte prefix][2-byte LE domain][NUL] → SHA-256 → LE uint64.
        val template = ByteArray(31)
        HASH_PREFIX.toByteArray(Charsets.UTF_8).copyInto(template)
        template[28] = (domain and 0xff).toByte()
        template[29] = (domain ushr 8).toByte()
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(template)
        var result = 0L
        for (i in 7 downTo 0) result = (result shl 8) or (digest[i].toLong() and 0xff)
        val tld = result and 3
        result = result ushr 2
        val sb = StringBuilder("cable.")
        while (result != 0L) {
            sb.append(BASE32[(result and 31).toInt()])
            result = result ushr 5
        }
        return sb.append('.').append(TLDS[tld.toInt()]).toString()
    }

    fun newUrl(tunnelId: ByteArray): String =
        "wss://${decodeDomain(0)}/cable/new/${tunnelId.toHex()}"

    fun connectUrl(routingId: ByteArray, tunnelId: ByteArray): String =
        "wss://${decodeDomain(0)}/cable/connect/${routingId.toHex()}/${tunnelId.toHex()}"
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
