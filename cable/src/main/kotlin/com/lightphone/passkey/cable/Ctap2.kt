package com.lightphone.passkey.cable

/**
 * CTAP2 wire codec for the caBLE hybrid flow — the subset a browser sends on a
 * QR sign-in: MakeCredential / GetAssertion with ES256 public-key credentials.
 * Uses [CableCbor] so it runs on plain JVM (the `:cable:run` self-check).
 *
 * Wire shapes (CTAP2 §6.1/§6.2 — key order + text keys verified against
 * Chromium's ctap_make_credential_request.cc / ctap_get_assertion_request.cc
 * and a live Chrome 151 request captured 2026-08-21):
 *  MC request:  {1: clientDataHash, 2: rp{id, name}, 3: user{id, name,
 *                displayName}, 4: [{alg, type}], 5: exclude[{id}],
 *                7: options{rk, uv}}
 *  GA request:  {1: rpId, 2: clientDataHash, 3: allow[{id}], 5: options{uv}}
 *  MC response: {1:"none", 2:authData, 3:attStmt{}}
 *  GA response: {1:{1:credId, 2:"public-key"}, 2:authData, 3:signature,
 *                4:{1:userHandle}, 5:numberOfCredentials}
 *
 * (The pre-interop draft had 1:rp/2:user/3:clientDataHash with int keys —
 * self-consistent with DesktopClient but wrong against real Chrome: "MC
 * decode failed" on the 219-byte request; fixed 2026-08-21.)
 *
 * uv defaults to true when the options map omits it — the platform-authenticator
 * posture (this is a resident-key, on-device authenticator).
 */
object Ctap2 {
    const val ES256 = -7

    data class MakeCredentialRequest(
        val rpId: String,
        val rpName: String?,
        val userId: ByteArray,
        val userName: String?,
        val clientDataHash: ByteArray,
        val algorithms: List<Int>,
        val excludeCredentialIds: List<ByteArray>,
        val requireUserVerification: Boolean,
    )

    data class GetAssertionRequest(
        val rpId: String,
        val clientDataHash: ByteArray,
        /** Null when the request carries no allowList = match every resident key for the RP. */
        val allowCredentialIds: List<ByteArray>?,
        val requireUserVerification: Boolean,
    )

    /** Returns null when the bytes are not a well-formed MC request. */
    fun decodeMakeCredential(bytes: ByteArray): MakeCredentialRequest? {
        val m = CableCbor.decode(bytes) as? Map<*, *> ?: return null
        val cdh = m[1L] as? ByteArray ?: return null
        if (cdh.size != 32) return null
        val rp = m[2L] as? Map<*, *> ?: return null
        val rpId = rp["id"] as? String ?: return null
        val user = m[3L] as? Map<*, *> ?: return null
        val userId = user["id"] as? ByteArray ?: return null
        val algorithms = (m[4L] as? List<*>)?.mapNotNull { p ->
            val pm = p as? Map<*, *> ?: return@mapNotNull null
            if (pm["type"] == "public-key") (pm["alg"] as? Long)?.toInt() else null
        }.orEmpty()
        val exclude = (m[5L] as? List<*>)?.mapNotNull { it as? Map<*, *> }?.mapNotNull { it["id"] as? ByteArray }.orEmpty()
        val opts = m[7L] as? Map<*, *>
        val uv = opts?.get("uv") as? Boolean ?: true
        return MakeCredentialRequest(
            rpId = rpId,
            rpName = rp["name"] as? String,
            userId = userId,
            userName = user["name"] as? String,
            clientDataHash = cdh,
            algorithms = algorithms,
            excludeCredentialIds = exclude,
            requireUserVerification = uv,
        )
    }

    /** Returns null when the bytes are not a well-formed GA request. */
    fun decodeGetAssertion(bytes: ByteArray): GetAssertionRequest? {
        val m = CableCbor.decode(bytes) as? Map<*, *> ?: return null
        val rpId = m[1L] as? String ?: return null
        val cdh = m[2L] as? ByteArray ?: return null
        if (cdh.size != 32) return null
        // Absent allowList stays null (match all resident keys for the RP —
        // the account-picker path); a present-but-empty list is a real
        // "nothing allowed" and decodes as empty.
        val allow = (m[3L] as? List<*>)?.mapNotNull { it as? Map<*, *> }?.mapNotNull { it["id"] as? ByteArray }
        val uv = (m[5L] as? Map<*, *>)?.get("uv") as? Boolean ?: true
        return GetAssertionRequest(rpId, cdh, allow, uv)
    }

    fun encodeMakeCredentialResponse(credentialId: ByteArray, authData: ByteArray): ByteArray =
        CableCbor.encode(
            mapOf<Any, Any?>(
                1L to "none",
                2L to authData,
                3L to emptyMap<Any, Any?>(),
            )
        )

    fun encodeGetAssertionResponse(
        credentialId: ByteArray,
        authData: ByteArray,
        signature: ByteArray,
        userHandle: ByteArray?,
        userName: String? = null,
        numberOfCredentials: Long = 1,
    ): ByteArray {
        // Credential descriptor + user entity use STRING keys ("id"/"type",
        // "id"/"name"/"displayName") — Chrome's CreateFromCBORValue parsers
        // look them up by name; int-keyed maps were rejected ("rejected CBOR
        // structure", bisected against real Chrome 151 2026-08-21). The
        // signature stays DER (Chrome's own kDeviceGetAssertionResponse test
        // vector is DER).
        val m = linkedMapOf<Any, Any?>(
            1L to mapOf<Any, Any?>("id" to credentialId, "type" to "public-key"),
            2L to authData,
            3L to signature,
        )
        if (userHandle != null) {
            val user = linkedMapOf<Any, Any?>("id" to userHandle)
            if (userName != null) {
                user["name"] = userName
                user["displayName"] = userName
            }
            m[4L] = user
        }
        if (numberOfCredentials >= 0) m[5L] = numberOfCredentials
        return CableCbor.encode(m)
    }

    data class ParsedAuthData(
        val rpIdHash: ByteArray,
        val flags: Int,
        val signCount: Long,
        val credentialId: ByteArray?,
        val coseKey: ByteArray?,
    )

    /** authData: rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ [aaguid(16) ‖
     *  credIdLen(2) ‖ credId ‖ coseKey] when the AT flag is set. */
    fun parseAuthData(b: ByteArray): ParsedAuthData? {
        if (b.size < 37) return null
        val rpIdHash = b.copyOfRange(0, 32)
        val flags = b[32].toInt() and 0xff
        val signCount = u32(b, 33)
        if (flags and 0x40 == 0) return ParsedAuthData(rpIdHash, flags, signCount, null, null)
        var p = 37
        if (b.size < p + 18) return null
        p += 16 // aaguid
        val credLen = (b[p].toInt() and 0xff) shl 8 or (b[p + 1].toInt() and 0xff)
        p += 2
        if (b.size < p + credLen) return null
        val credentialId = b.copyOfRange(p, p + credLen)
        p += credLen
        return ParsedAuthData(rpIdHash, flags, signCount, credentialId, b.copyOfRange(p, b.size))
    }

    /** (x, y) as 32-byte big-endian coordinates from a COSE EC2 key map. */
    fun parseCoseEc2(cose: ByteArray): Pair<ByteArray, ByteArray>? {
        val m = CableCbor.decode(cose) as? Map<*, *> ?: return null
        val x = m[-2L] as? ByteArray ?: return null
        val y = m[-3L] as? ByteArray ?: return null
        if (x.size != 32 || y.size != 32) return null
        return x to y
    }

    private fun u32(b: ByteArray, p: Int): Long =
        ((b[p].toLong() and 0xff) shl 24) or ((b[p + 1].toLong() and 0xff) shl 16) or
            ((b[p + 2].toLong() and 0xff) shl 8) or (b[p + 3].toLong() and 0xff)
}
