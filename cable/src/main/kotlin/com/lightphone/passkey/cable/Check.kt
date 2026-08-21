package com.lightphone.passkey.cable

import java.security.KeyPair

/**
 * caBLE v2 protocol self-check. Mirrors Chromium's own
 * `v2_handshake_unittest.cc` cases (fixed vectors + failure modes) and then
 * runs a full QR-flow simulation: desktop encodes a QR, the phone parses it,
 * derives the EID key, advertises, the desktop decrypts the advert, both
 * sides derive the PSK and complete the KNpsk0 handshake, and a message
 * round-trips through the post-handshake crypters.
 *
 * Run: `./gradlew :cable:run`. Any failed `check` throws and exits non-zero.
 */
fun main() {
    var checks = 0
    fun check(cond: Boolean, what: String) {
        checks++
        if (!cond) throw AssertionError("FAIL: $what")
    }

    // --- digits codec (fixed vector + rejection cases from Chromium) ---
    check(Qr.bytesToDigits(byteArrayOf('a'.code.toByte(), 'b'.code.toByte(), 0xff.toByte())) == "16736865",
        "digits fixed vector")
    check(Qr.digitsToBytes("16736865")!!.contentEquals(byteArrayOf('a'.code.toByte(), 'b'.code.toByte(), 0xff.toByte())),
        "digits fixed vector round-trip")
    for (len in 0..24) {
        val data = ByteArray(len) { (it * 7 + 3).toByte() }
        val back = Qr.digitsToBytes(Qr.bytesToDigits(data))
        check(back != null && back.contentEquals(data), "digits round-trip len=$len")
    }
    check(Qr.digitsToBytes("a") == null && Qr.digitsToBytes("ab") == null && Qr.digitsToBytes("abc") == null,
        "digits rejects non-numeric")
    check(Qr.digitsToBytes("999") == null, "digits rejects out-of-range tail")
    val twentyZeros = "0".repeat(20)
    val parsedZeros = Qr.digitsToBytes(twentyZeros)
    check(parsedZeros == null || parsedZeros.all { it == 0.toByte() }, "digits impossible lengths")

    // --- QR parse (KnownQRs cases, Chromium's fixed compressed point) ---
    val knownPoint = "03364c15eec34331d2865757421d497e569e1eba6cff9a69d32e90f19e7f6fd15e"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    check(Ec.decompress(knownPoint) != null, "Chromium's known compressed point decompresses")
    val point2 = Ec.decompress(knownPoint)!!
    // Chromium's invalid-point case: tampering x yields no point for the prefix.
    val badX = knownPoint.copyOf()
    badX[badX.size - 1] = (badX[badX.size - 1].toInt() xor 3).toByte()
    check(Ec.decompress(badX) == null, "tampered x rejected")
    // The other parity prefix decodes to the mirrored point (valid X9.62).
    val mirrored = Ec.decompress(byteArrayOf(0x02) + point2.affineX.toFixed(32))
    check(mirrored != null && mirrored.affineX == point2.affineX && mirrored.affineY != point2.affineY,
        "prefix parity selects the mirrored y")

    fun qrFromMap(map: Map<Long, Any?>): String =
        Qr.PREFIX + Qr.bytesToDigits(CableCbor.encode(map))

    val basic = qrFromMap(mapOf(0L to knownPoint, 1L to ByteArray(16)))
    val parsedBasic = Qr.parse(basic)
    check(parsedBasic != null, "basic QR parses")
    check(parsedBasic!!.secret.contentEquals(ByteArray(16)), "basic QR secret")
    check(parsedBasic.numKnownDomains == 0L && parsedBasic.requestType == "ga" && parsedBasic.supportsLinking == null,
        "basic QR defaults")
    check(Qr.parse(qrFromMap(mapOf(0L to knownPoint, 1L to ByteArray(16), 2L to 4567L)))!!.numKnownDomains == 4567L,
        "QR num_known_domains")
    check(Qr.parse(qrFromMap(mapOf(0L to 42, 1L to ByteArray(16)))) == null, "QR rejects int pubkey")
    check(Qr.parse(qrFromMap(mapOf(0L to knownPoint, 1L to ByteArray(16), 2L to "foo"))) == null, "QR rejects string domain count")
    check(Qr.parse("nonsense") == null && Qr.parse(Qr.PREFIX + "x") == null, "QR rejects garbage")

    // --- EID (Chromium EIDToFromComponents / EIDEncrypt) ---
    val nonce = ByteArray(10) { (it + 1).toByte() }
    val routing = byteArrayOf(9, 10, 11)
    val domain = 0x0102
    val eid = Eid.fromComponents(Eid.Components(nonce, routing, domain))
    check(eid[0] == 0.toByte() && eid.size == 16, "EID reserved byte")
    val compsBack = Eid.toComponents(eid)
    check(compsBack.nonce.contentEquals(nonce) && compsBack.routingId.contentEquals(routing) &&
        compsBack.tunnelServerDomain == domain, "EID components round-trip")
    val eidKey = ByteArray(Eid.KEY_LEN) { (it + 1).toByte() }
    val advert = Eid.encrypt(eid, eidKey)
    check(advert.size == Eid.ADVERT_LEN, "advert is 20 bytes")
    check(Eid.decrypt(advert, eidKey)!!.contentEquals(eid), "EID encrypt/decrypt round-trip")
    val tampered = advert.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
    check(Eid.decrypt(tampered, eidKey) == null, "EID tamper rejected")
    val badDomainEid = Eid.fromComponents(Eid.Components(nonce, routing, 255))
    check(Eid.decrypt(Eid.encrypt(badDomainEid, eidKey), eidKey) == null, "unknown tunnel domain rejected")

    // --- Crypter (Chromium MessageEncrytion) ---
    val crypterA = Crypter(ByteArray(32) { 1 }, ByteArray(32) { 2 })
    val crypterB = Crypter(ByteArray(32) { 2 }, ByteArray(32) { 1 })
    for (len in 0..529) {
        val msg = ByteArray(len) { (it and 0xff).toByte() }
        val ct = crypterA.encrypt(msg)
        check(crypterB.decrypt(ct)!!.contentEquals(msg), "crypter round-trip len=$len")
        val badCt = ct.copyOf().also { it[(13 * len) % it.size] = (it[(13 * len) % it.size].toInt() xor 1).toByte() }
        check(crypterB.decrypt(badCt) == null, "crypter tamper rejected len=$len")
    }

    // --- NKpsk0 handshake (Chromium NKHandshake) ---
    val psk = ByteArray(32)
    val wrongPsk = ByteArray(32).also { it[0] = 1 }
    val identitySeed = ByteArray(32) { 2 }
    val (d, identityPoint) = Ec.keyFromSeed(identitySeed)
    val identityKey = KeyPair(Ec.ecPublicKey(identityPoint), Ec.ecPrivateKey(d))
    val identityPublic = identityPoint.toX962()

    for (useCorrect in listOf(true, false)) {
        val initiator = HandshakeInitiator(if (useCorrect) psk else wrongPsk, identityPublic, null)
        val msg = initiator.buildInitialMessage()
        val resp = respondToHandshake(psk, identityKey, null, msg)
        check(resp != null == useCorrect, "NK handshake success=$useCorrect")
        if (!useCorrect) continue
        val (responderResult, response) = resp!!
        val initiatorResult = initiator.processResponse(response)
        check(initiatorResult != null, "NK initiator processes response")
        check(initiatorResult!!.handshakeHash.contentEquals(responderResult.handshakeHash), "NK handshake hash equal")
        val hello = "NK hello".toByteArray()
        check(responderResult.crypter.decrypt(initiatorResult.crypter.encrypt(hello))!!.contentEquals(hello),
            "NK phone→desktop message")
        check(initiatorResult.crypter.decrypt(responderResult.crypter.encrypt(hello))!!.contentEquals(hello),
            "NK desktop→phone message")
    }

    // --- KNpsk0 handshake (Chromium KNHandshake; the QR flow) ---
    for (useCorrect in listOf(true, false)) {
        val seed = if (useCorrect) identitySeed else ByteArray(32) { 9 }
        val initiator = HandshakeInitiator(psk, null, seed)
        val msg = initiator.buildInitialMessage()
        val resp = respondToHandshake(psk, null, identityPublic, msg)
        check(resp != null == useCorrect, "KN handshake success=$useCorrect")
        if (!useCorrect) continue
        val (responderResult, response) = resp!!
        val initiatorResult = initiator.processResponse(response)
        check(initiatorResult != null, "KN initiator processes response")
        check(initiatorResult!!.handshakeHash.contentEquals(responderResult.handshakeHash), "KN handshake hash equal")
        val hello = "KN hello".toByteArray()
        check(responderResult.crypter.decrypt(initiatorResult.crypter.encrypt(hello))!!.contentEquals(hello),
            "KN phone→desktop message")
        check(initiatorResult.crypter.decrypt(responderResult.crypter.encrypt(hello))!!.contentEquals(hello),
            "KN desktop→phone message")
    }

    // --- real-Chrome interop vector (captured 2026-08-21, LP3 ↔ Chrome 151) ---
    // Chrome's KNpsk0 init message, decrypted with the psk + identity derived
    // from the same session's QR. This is the external anchor the handshake
    // tests lacked: before the zero-padding fix, the protocol name was hashed
    // as 31 bytes instead of Chromium's 32 (name ‖ 0x00), so every MixHash
    // diverged and Chrome's real handshake was rejected ("FAIL: handshake
    // rejected" on the LP3, 3×). The decrypt must succeed now.
    fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val chromePsk = hex("dcf1ae69cd391ead2deec8600d12c6be9a34e7c8c6b266dfab4dd9ee1f802429")
    val chromeIdentity = hex("04ad5b852256d893f76aa2f68a2f5fc960e762c926ff30c9cc3bc214fdc4d3fcc8c013c5f072404902fc5795ef271f886122070c287b2cd5f6058722c71fc9da3f")
    val chromeMsg = hex("046dfc11b426d36306c33d7e60224f4580db5760100677c69ba453541d04a73d10cde4c3ce795d26a0b11376b0deb0a41d5ffb05f80da2dc9f092c35b9c1b9f801d3e999d8f74fd98b950f077e7da6ed06")
    check(chromeMsg.size == 81 && chromeMsg[0].toInt() == 0x04, "chrome vector is 65B point + 16B tag")
    val chromeResp = respondToHandshake(chromePsk, null, chromeIdentity, chromeMsg)
    check(chromeResp != null, "real Chrome 151 KNpsk0 init decrypts (32B padded protocol name)")
    val (chromeResult, chromeResponse) = chromeResp!!
    check(chromeResponse.size == 81, "chrome responder response is 65B point + 16B tag")
    check(chromeResult.crypter.encrypt(byteArrayOf(0x01, 0x04, 0x02)).size == 48,
        "chrome vector crypter encrypts (32B pad + 16B GCM tag)")

    // --- tunnel server domains (Chromium TunnelServerURLs vectors) ---
    check(TunnelServer.decodeDomain(0) == "cable.ua5v.com", "assigned domain 0")
    check(TunnelServer.decodeDomain(266) == "cable.wufkweyy3uaxb.com", "hashed domain 266")

    // --- getInfo (string-keyed CBOR map, Chromium BuildGetInfoResponse) ---
    val getInfo = CableCbor.decode(Ctap.getInfo()) as? Map<*, *>
    check(getInfo != null, "getInfo decodes as a map")
    val getInfoMap = getInfo!!
    check((getInfoMap[1L] as? List<*>)?.containsAll(listOf("FIDO_2_0", "FIDO_2_1")) == true, "getInfo versions")
    check((getInfoMap[2L] as? List<*>) == listOf("prf"), "getInfo extensions")
    check((getInfoMap[3L] as? ByteArray)?.size == 16, "getInfo aaguid")
    val getInfoOptions = getInfoMap[4L] as? Map<*, *>
    check(getInfoOptions != null && getInfoOptions["rk"] == true && getInfoOptions["uv"] == true, "getInfo options")
    check((getInfoMap[9L] as? List<*>)?.containsAll(listOf("cable", "hybrid", "internal")) == true, "getInfo transports")

    // --- full QR flow (desktop QR → phone advert → KN handshake → messages) ---
    val qrKey = ByteArray(48) { (it + 5).toByte() }
    val qrString = Qr.encode(qrKey, "mc")
    val qr = Qr.parse(qrString)
    check(qr != null, "generated QR parses")
    check(qr!!.requestType == "mc" && qr.numKnownDomains == 2L && qr.supportsLinking == false,
        "generated QR fields")
    check(qr.secret.contentEquals(qrKey.copyOfRange(32, 48)), "QR secret round-trip")
    check(qr.peerIdentity.toEcPoint() == Ec.publicPoint(Ec.keyFromSeed(qrKey.copyOfRange(0, 32)).first),
        "QR pubkey matches seed")

    val secret = qr.secret
    val eidKeyPhone = derive(secret, ByteArray(0), DerivedValueType.EID_KEY, Eid.KEY_LEN)
    val tunnelId = derive(secret, ByteArray(0), DerivedValueType.TUNNEL_ID, 16)
    check(tunnelId.size == 16, "tunnel ID derived")
    val phoneNonce = ByteArray(10) { 0x42 }
    val phoneRouting = byteArrayOf(7, 8, 9)
    val plaintextEid = Eid.fromComponents(Eid.Components(phoneNonce, phoneRouting, 0))
    val advertFlow = Eid.encrypt(plaintextEid, eidKeyPhone)

    // Desktop side: decrypt the advert, derive the same keys from the QR.
    val eidKeyDesktop = derive(secret, ByteArray(0), DerivedValueType.EID_KEY, Eid.KEY_LEN)
    check(eidKeyDesktop.contentEquals(eidKeyPhone), "desktop derives same EID key")
    val seen = Eid.decrypt(advertFlow, eidKeyDesktop)
    check(seen != null && seen.contentEquals(plaintextEid), "desktop decrypts advert")
    check(Eid.toComponents(seen!!).routingId.contentEquals(phoneRouting), "desktop reads routing ID")
    val pskFlow = derive(secret, plaintextEid, DerivedValueType.PSK, 32)

    val laptop = HandshakeInitiator(pskFlow, null, qrKey.copyOfRange(0, 32))
    val phoneResp = respondToHandshake(pskFlow, null, qr.peerIdentity, laptop.buildInitialMessage())
    check(phoneResp != null, "QR flow handshake succeeds")
    val (phoneResult, phoneResponse) = phoneResp!!
    val laptopResult = laptop.processResponse(phoneResponse)
    check(laptopResult != null, "laptop processes phone response")
    check(laptopResult!!.handshakeHash.contentEquals(phoneResult.handshakeHash), "QR flow handshake hash equal")
    val ctap = byteArrayOf(0x01, 0x11, 0x04.toByte(), 0x00, 0x00, 0x42)
    check(phoneResult.crypter.decrypt(laptopResult.crypter.encrypt(ctap))!!.contentEquals(ctap),
        "QR flow laptop→phone CTAP message")
    check(laptopResult.crypter.decrypt(phoneResult.crypter.encrypt(ctap))!!.contentEquals(ctap),
        "QR flow phone→laptop CTAP message")
    // Sequence-number discipline: the same crypter never reuses a nonce.
    check(laptopResult.crypter.decrypt(laptopResult.crypter.encrypt(ctap)) == null,
        "replayed ciphertext rejected")

    // --- CTAP2 codec (Ctap2.kt) ---
    fun sha256(b: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(b)
    val cdh = ByteArray(32) { (it + 1).toByte() }

    // MakeCredential decode: fields, algorithms, exclude, uv default true.
    val mc = Ctap2.decodeMakeCredential(
        CableCbor.encode(
            mapOf<Any, Any?>(
                1L to cdh,
                2L to mapOf<Any, Any?>("id" to "example.com", "name" to "Example"),
                3L to mapOf<Any, Any?>("id" to byteArrayOf(0x01, 0x02), "name" to "alice"),
                4L to listOf(mapOf<Any, Any?>("alg" to -7, "type" to "public-key")),
            )
        )
    )
    check(mc != null, "MC decodes")
    val mc2 = mc!!
    check(mc2.rpId == "example.com" && mc2.rpName == "Example", "MC rp fields")
    check(mc2.userId.contentEquals(byteArrayOf(0x01, 0x02)) && mc2.userName == "alice", "MC user fields")
    check(mc2.clientDataHash.contentEquals(cdh), "MC clientDataHash")
    check(mc2.algorithms == listOf(-7), "MC algorithms")
    check(mc2.excludeCredentialIds.isEmpty(), "MC no exclude")
    check(mc2.requireUserVerification, "MC uv defaults true")
    check(
        Ctap2.decodeMakeCredential(
            CableCbor.encode(
                mapOf<Any, Any?>(
                    1L to cdh,
                    2L to mapOf<Any, Any?>("id" to "example.com"),
                    3L to mapOf<Any, Any?>("id" to byteArrayOf(0x01)),
                    4L to listOf(mapOf<Any, Any?>("alg" to -7, "type" to "public-key")),
                    5L to listOf(mapOf<Any, Any?>("id" to byteArrayOf(9, 9, 9))),
                    7L to mapOf<Any, Any?>("uv" to false),
                )
            )
        )!!.let { it.excludeCredentialIds.single().contentEquals(byteArrayOf(9, 9, 9)) && !it.requireUserVerification },
        "MC exclude + uv:false"
    )
    check(Ctap2.decodeMakeCredential(CableCbor.encode(mapOf<Any, Any?>(2L to mapOf<Any, Any?>("id" to "x")))) == null,
        "MC rejects missing clientDataHash")
    check(
        Ctap2.decodeMakeCredential(
            CableCbor.encode(mapOf<Any, Any?>(1L to ByteArray(16), 2L to mapOf<Any, Any?>("id" to "x"), 3L to mapOf<Any, Any?>("id" to byteArrayOf(1))))
        ) == null,
        "MC rejects short clientDataHash"
    )

    // GetAssertion decode.
    val ga = Ctap2.decodeGetAssertion(
        CableCbor.encode(
            mapOf<Any, Any?>(
                1L to "example.com",
                2L to cdh,
                3L to listOf(mapOf<Any, Any?>("id" to byteArrayOf(4, 5, 6))),
            )
        )
    )
    check(ga != null && ga!!.rpId == "example.com" && ga.clientDataHash.contentEquals(cdh), "GA decodes")
    val ga2 = ga!!
    check(ga2.allowCredentialIds.single().contentEquals(byteArrayOf(4, 5, 6)), "GA allow list")
    check(ga2.requireUserVerification, "GA uv defaults true")
    check(Ctap2.decodeGetAssertion(CableCbor.encode(mapOf<Any, Any?>(1L to "x", 2L to ByteArray(31)))) == null,
        "GA rejects short clientDataHash")

    // Response encoders round-trip.
    val mcResp = CableCbor.decode(Ctap2.encodeMakeCredentialResponse(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))) as Map<*, *>
    check(mcResp[1L] == "none", "MC response fmt none")
    check((mcResp[2L] as? ByteArray)?.contentEquals(byteArrayOf(4, 5, 6)) == true, "MC response authData")
    check(mcResp[3L] is Map<*, *> && (mcResp[3L] as Map<*, *>).isEmpty(), "MC response attStmt {}")
    val gaResp = CableCbor.decode(
        Ctap2.encodeGetAssertionResponse(byteArrayOf(7, 8), byteArrayOf(9, 10), byteArrayOf(11, 12), byteArrayOf(13), "user", 1)
    ) as Map<*, *>
    val gaCred = gaResp[1L] as? Map<*, *>
    check(gaCred != null && (gaCred!!["id"] as? ByteArray)?.contentEquals(byteArrayOf(7, 8)) == true &&
        gaCred["type"] == "public-key", "GA response credential")
    check((gaResp[2L] as? ByteArray)?.contentEquals(byteArrayOf(9, 10)) == true, "GA response authData")
    check((gaResp[3L] as? ByteArray)?.contentEquals(byteArrayOf(11, 12)) == true, "GA response signature")
    check((gaResp[4L] as? Map<*, *>)?.get("id")?.let { (it as ByteArray).contentEquals(byteArrayOf(13)) } == true &&
        (gaResp[4L] as? Map<*, *>)?.get("name") == "user", "GA response user entity")
    check(gaResp[5L] == 1L, "GA response count")

    // Canonical map-key order (RFC 8949 §4.2.1) — Chromium's cbor::Reader
    // rejects out-of-order text keys ("Map keys must be strictly monotonically
    // increasing…"). The user entity keys must encode "id"(2B), "name"(4B),
    // "displayName"(11B) — NOT lexicographic (displayName first), which real
    // Chrome 151 rejected with a CBOR parse error (2026-08-21).
    val userBytes = CableCbor.encode(linkedMapOf<Any, Any?>("displayName" to "x", "id" to ByteArray(1), "name" to "y"))
    fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }
    val idAt = indexOf(userBytes, byteArrayOf(0x62, 'i'.code.toByte(), 'd'.code.toByte()))
    val nameAt = indexOf(userBytes, byteArrayOf(0x64, 'n'.code.toByte(), 'a'.code.toByte()))
    val dnAt = indexOf(userBytes, byteArrayOf(0x6b, 'd'.code.toByte()))
    check(idAt in 0 until nameAt && nameAt in 0 until dnAt, "user entity keys canonical (id < name < displayName)")

    // authData parser: assertion (no AT) and registration (AT + attested data).
    val rpIdHash = sha256("example.com".toByteArray())
    val assertAuthData = AuthDataCtap.assertion(ByteArray(32), true, 7)
    val parsedAssert = Ctap2.parseAuthData(assertAuthData)
    check(parsedAssert != null && parsedAssert!!.rpIdHash.contentEquals(ByteArray(32)) &&
        parsedAssert!!.flags == (0x01 or 0x04) && parsedAssert!!.signCount == 7L &&
        parsedAssert!!.credentialId == null, "authData assertion parse")
    val coseKey = CableCbor.encode(mapOf<Any, Any?>(1L to 2, 3L to -7, -1L to 1, -2L to ByteArray(32) { 1 }, -3L to ByteArray(32) { 2 }))
    val credId = byteArrayOf(0x55, 0x66, 0x77)
    val regAuthData = AuthDataCtap.registration(ByteArray(32), false, ByteArray(16), credId, coseKey)
    val parsedReg = Ctap2.parseAuthData(regAuthData)
    check(parsedReg != null && parsedReg!!.rpIdHash.contentEquals(ByteArray(32)) &&
        (parsedReg!!.flags and 0x40) != 0 && parsedReg!!.credentialId!!.contentEquals(credId) &&
        parsedReg!!.coseKey!!.contentEquals(coseKey), "authData registration parse")
    check(Ctap2.parseAuthData(ByteArray(36)) == null, "authData rejects short input")
    val (x, y) = Ctap2.parseCoseEc2(coseKey)!!
    check(x.contentEquals(ByteArray(32) { 1 }) && y.contentEquals(ByteArray(32) { 2 }), "COSE EC2 parse")

    // --- real-Chrome MC vector (captured 2026-08-21, LP3 ↔ Chrome 151) ---
    // Chrome's 219-byte MakeCredential: 1=clientDataHash, 2=rp, 3=user,
    // 4=params, 7=options — text keys inside. Before the layout fix our codec
    // read 1=rp/2=user/3=cdh with int keys and rejected it ("MC decode
    // failed"), stranding the ceremony after the (now fixed) handshake.
    val chromeMc = Ctap2.decodeMakeCredential(hex(
        "a50158202952abedf675411d596e250eb7fcfee404c97498822cde6a5b7beb5e405936ca" +
        "02a26269646b776562617574686e2e696f646e616d656b776562617574686e2e696f" +
        "03a362696456776562617574686e696f2d6c70332d696e7465726f70646e616d656b6c70332d696e7465726f70" +
        "6b646973706c61794e616d656b6c70332d696e7465726f70" +
        "0483a263616c672764747970656a7075626c69632d6b6579a263616c672664747970656a7075626c69632d6b6579" +
        "a263616c6739010064747970656a7075626c69632d6b6579" +
        "07a262726bf5627576f5"
    ))
    check(chromeMc != null, "real Chrome MC decodes")
    val chromeMc2 = chromeMc!!
    check(chromeMc2.rpId == "webauthn.io", "chrome MC rpId")
    check(chromeMc2.clientDataHash.contentEquals(hex("2952abedf675411d596e250eb7fcfee404c97498822cde6a5b7beb5e405936ca")),
        "chrome MC clientDataHash")
    check(chromeMc2.userId.contentEquals("webauthnio-lp3-interop".toByteArray()), "chrome MC userId")
    check(chromeMc2.algorithms == listOf(-8, -7, -257), "chrome MC algorithms (EdDSA, ES256, RS256)")
    check(chromeMc2.requireUserVerification, "chrome MC uv:true (hybrid requests UV)")
    check(chromeMc2.excludeCredentialIds.isEmpty(), "chrome MC no exclude")

    println("OK — $checks checks passed (caBLE v2 QR + EID + Noise KN/NK + Crypter + CTAP2)")
}

/** Local authData builders so the codec check doesn't depend on :core. */
private object AuthDataCtap {
    fun assertion(rpIdHash: ByteArray, uv: Boolean, count: Long): ByteArray =
        rpIdHash + byteArrayOf((0x01 or if (uv) 0x04 else 0).toByte()) + u32(count)

    fun registration(rpIdHash: ByteArray, uv: Boolean, aaguid: ByteArray, credId: ByteArray, cose: ByteArray): ByteArray {
        var flags = 0x01 or 0x40
        if (uv) flags = flags or 0x04
        return rpIdHash + byteArrayOf(flags.toByte()) + u32(0) + aaguid +
            byteArrayOf(((credId.size shr 8) and 0xff).toByte(), (credId.size and 0xff).toByte()) + credId + cose
    }

    private fun u32(v: Long) = byteArrayOf(
        ((v shr 24) and 0xff).toByte(), ((v shr 16) and 0xff).toByte(),
        ((v shr 8) and 0xff).toByte(), (v and 0xff).toByte(),
    )
}
