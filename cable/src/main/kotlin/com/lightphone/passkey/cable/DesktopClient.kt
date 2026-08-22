package com.lightphone.passkey.cable

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64

/**
 * Simulates the desktop (browser) side of a caBLE v2 QR login, used to test
 * the phone app end-to-end through the real tunnel server without BLE or
 * Chrome. Args: `advertHex tunnelIdHex qrKeyHex [uv]`.
 *
 * The advert/tunnel come from the app's log (in the real flow the desktop
 * gets them from the BLE advert); the QR key is what the app "scanned" (in
 * the real flow the desktop itself generated it). The advert is decrypted
 * with the EID key derived from the QR secret — exactly what a browser does —
 * which yields the routing ID and the PSK.
 *
 * Flow: connect → KNpsk0 handshake → read the phone's pushed getInfo → getInfo
 * round-trip → a full MakeCredential + GetAssertion ceremony (build the
 * clientDataJSON, hash it, send MC, validate rpIdHash/flags/attStmt + COSE
 * key, send GA, verify the ECDSA signature over authData ‖ clientDataHash with
 * the registered key) → shutdown. With `uv` the phone gates both ceremonies
 * behind its UV prompt (lock-screen PIN or fingerprint). With `multi` the GA
 * omits the allowList, so it matches every resident key for the RP — the path
 * that triggers the tool's account picker when several passkeys exist. The
 * optional trailing `userName` names the registered credential (default
 * "user"), so repeated runs can register several accounts for one RP.
 */
fun main(args: Array<String>) {
    var checks = 0
    fun check(cond: Boolean, what: String) {
        checks++
        if (!cond) throw AssertionError("FAIL: $what")
    }
    require(args.size in 3..6) { "usage: DesktopClient <advertHex> <tunnelIdHex> <qrKeyHex> [uv] [multi] [userName]" }
    val advert = args[0].toHexBytes()
    val tunnelId = args[1].toHexBytes()
    val qrKey = args[2].toHexBytes()
    val uv = args.getOrNull(3) == "uv"
    val multi = args.getOrNull(4) == "multi"
    val userName = args.getOrNull(5) ?: "user"
    require(advert.size == Eid.ADVERT_LEN && tunnelId.size == 16 && qrKey.size == 48) {
        "bad args: advert=${advert.size}B tunnel=${tunnelId.size}B qrKey=${qrKey.size}B"
    }

    val secret = qrKey.copyOfRange(32, 48)
    val seed = qrKey.copyOfRange(0, 32)

    // 1. "Scan" the advert: decrypt the EID, read the routing ID, derive the PSK.
    val eidKey = derive(secret, ByteArray(0), DerivedValueType.EID_KEY, Eid.KEY_LEN)
    val plaintextEid = Eid.decrypt(advert, eidKey)
    check(plaintextEid != null, "advert decrypts with the QR-derived EID key")
    val components = Eid.toComponents(plaintextEid!!)
    val psk = derive(secret, plaintextEid, DerivedValueType.PSK, 32)
    println("advert decrypted: routing=${components.routingId.toHex()} domain=${components.tunnelServerDomain}")

    // 2. Connect through the relay.
    val url = TunnelServer.connectUrl(components.routingId, tunnelId)
    println("desktop → $url")
    val ws = Ws(url)

    // 3. KNpsk0 handshake (desktop speaks first).
    val initiator = HandshakeInitiator(psk, null, seed)
    ws.sendBinary(initiator.buildInitialMessage())
    val handshakeResult = initiator.processResponse(ws.readBinary())
    check(handshakeResult != null, "handshake completes against the app")
    val crypter = handshakeResult!!.crypter
    println("handshake OK — hash ${handshakeResult.handshakeHash.toHex().take(16)}…")

    // 4. The phone pushes its post-handshake message: {1: getInfo, 3: features}.
    val pushed = crypter.decrypt(ws.readBinary())
    check(pushed != null, "post-handshake message decrypts")
    val pushedMap = CableCbor.decode(pushed!!) as? Map<*, *>
    check(pushedMap != null, "post-handshake message is a CBOR map")
    val pushedMap2 = pushedMap!!
    check((pushedMap2[3L] as? List<*>) == listOf("ctap"), "features = [\"ctap\"]")
    val pushedGetInfo = pushedMap2[1L] as? ByteArray
    check(pushedGetInfo != null, "pushed getInfo present")
    validateGetInfo(pushedGetInfo!!, ::check)
    println("pushed getInfo OK")

    // 5. A getInfo request round-trips through the app's CTAP loop. The frame
    // is [MessageType=kCTAP][encrypted([command][cbor])] — TunnelTransport::Write
    // prefixes the type byte before encrypting. The reply is standard CTAP2:
    // [0x00 status][cbor].
    ws.sendBinary(crypter.encrypt(byteArrayOf(0x01, Ctap.CMD_GET_INFO.toByte())))
    val reply = crypter.decrypt(ws.readBinary())
    check(reply != null, "getInfo reply decrypts")
    val reply2 = reply!!
    check(reply2.size > 2 && reply2[0].toInt() == Ctap.MSG_CTAP && reply2[1].toInt() == Ctap.CTAP_OK,
        "getInfo reply type kCTAP + status OK (0x00)")
    validateGetInfo(reply2.copyOfRange(2, reply2.size), ::check)
    println("getInfo reply OK")

    // 6. MakeCredential ceremony (the "webauthn.create" side).
    val mcChallenge = ByteArray(32) { (it * 3 + 1).toByte() }
    val mcClientData = """{"type":"webauthn.create","challenge":"${b64u(mcChallenge)}","origin":"https://example.com"}"""
    val mcClientDataHash = sha256(mcClientData.toByteArray())
    val mcReq = CableCbor.encode(
        mapOf<Any, Any?>(
            1L to mcClientDataHash,
            2L to mapOf<Any, Any?>("id" to "example.com", "name" to "Example"),
            3L to mapOf<Any, Any?>("id" to byteArrayOf(0x01, 0x02, 0x03), "name" to userName),
            4L to listOf(mapOf<Any, Any?>("alg" to -7, "type" to "public-key")),
            7L to mapOf<Any, Any?>("uv" to uv),
        )
    )
    ws.sendBinary(crypter.encrypt(byteArrayOf(0x01, Ctap.CMD_MAKE_CREDENTIAL.toByte()) + mcReq))
    val mcReply = crypter.decrypt(ws.readBinary())
    check(mcReply != null, "MC reply decrypts")
    val mcMap = CableCbor.decode(mcReply!!.copyOfRange(2, mcReply.size)) as? Map<*, *>
    check(mcReply.isNotEmpty() && (mcReply[0].toInt() and 0xff) == Ctap.MSG_CTAP &&
        (mcReply[1].toInt() and 0xff) == Ctap.CTAP_OK && mcMap != null,
        "MC reply type kCTAP + status OK (0x00) + decodes as a map")
    val mcMap2 = mcMap!!
    check(mcMap2[1L] == "none", "MC fmt none")
    check((mcMap2[3L] as? Map<*, *>)?.isEmpty() == true, "MC attStmt empty")
    val regAuthData = mcMap2[2L] as? ByteArray
    check(regAuthData != null, "MC authData present")
    val regParsed = Ctap2.parseAuthData(regAuthData!!)
    check(regParsed != null, "MC authData parses")
    val regParsed2 = regParsed!!
    check(regParsed2.rpIdHash.contentEquals(sha256("example.com".toByteArray())), "MC rpIdHash matches")
    check((regParsed2.flags and (0x01 or 0x40)) == (0x01 or 0x40), "MC flags UP+AT")
    check((regParsed2.flags and 0x04) != 0 == uv, "MC UV flag matches request")
    check(regParsed2.credentialId != null && regParsed2.coseKey != null, "MC attested credential data")
    val (x, y) = Ctap2.parseCoseEc2(regParsed2.coseKey!!) ?: throw AssertionError("FAIL: MC COSE key")
    val pubKey = ecPublicKey(x, y)
    println("MakeCredential OK — rpIdHash/flags/COSE key valid")

    // 7. GetAssertion ceremony: allow the credential we just registered (or
    // all resident keys with `multi` — the account-picker path), then verify
    // the ECDSA signature over authData ‖ clientDataHash.
    val gaChallenge = ByteArray(32) { (it * 5 + 2).toByte() }
    val gaClientData = """{"type":"webauthn.get","challenge":"${b64u(gaChallenge)}","origin":"https://example.com"}"""
    val gaClientDataHash = sha256(gaClientData.toByteArray())
    val gaReq = CableCbor.encode(
        buildMap {
            put(1L, "example.com")
            put(2L, gaClientDataHash)
            if (!multi) put(3L, listOf(mapOf<Any, Any?>("id" to regParsed2.credentialId!!, "type" to "public-key")))
            put(5L, mapOf<Any, Any?>("uv" to uv))
        }
    )
    ws.sendBinary(crypter.encrypt(byteArrayOf(0x01, Ctap.CMD_GET_ASSERTION.toByte()) + gaReq))
    val gaReply = crypter.decrypt(ws.readBinary())
    check(gaReply != null, "GA reply decrypts")
    val gaMap = CableCbor.decode(gaReply!!.copyOfRange(2, gaReply.size)) as? Map<*, *>
    check(gaReply.isNotEmpty() && (gaReply[0].toInt() and 0xff) == Ctap.MSG_CTAP &&
        (gaReply[1].toInt() and 0xff) == Ctap.CTAP_OK && gaMap != null,
        "GA reply type kCTAP + status OK (0x00) + decodes as a map")
    val gaMap2 = gaMap!!
    val gaCred = gaMap2[1L] as? Map<*, *>
    // With `multi` the phone may have picked any stored passkey (the tool's
    // account picker); the signature check below still proves it was the key
    // registered this run — the id is checked exactly only in single mode.
    check(gaCred != null && gaCred["type"] == "public-key" &&
        (multi || (gaCred["id"] as? ByteArray)?.contentEquals(regParsed2.credentialId) == true),
        "GA credential id matches registered")
    val assertAuthData = gaMap2[2L] as? ByteArray
    val signature = gaMap2[3L] as? ByteArray
    // User entity is string-keyed {id: userHandle, name, displayName} since
    // the Chrome interop fix — the handle is the "id" (WebAuthn user id).
    val userHandle = (gaMap2[4L] as? Map<*, *>)?.get("id") as? ByteArray
    check(assertAuthData != null && signature != null, "GA authData + signature present")
    val gaParsed = Ctap2.parseAuthData(assertAuthData!!)
    check(gaParsed != null && gaParsed!!.rpIdHash.contentEquals(sha256("example.com".toByteArray())), "GA rpIdHash matches")
    val gaParsed2 = gaParsed!!
    check((gaParsed2.flags and 0x01) != 0, "GA UP flag")
    check((gaParsed2.flags and 0x04) != 0 == uv, "GA UV flag matches request")
    check(gaParsed2.signCount == 1L, "GA signCount increments to 1")
    check(userHandle != null, "GA userHandle present")
    val verifier = Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(pubKey)
    verifier.update(assertAuthData + gaClientDataHash)
    check(verifier.verify(signature!!),
        "GA ECDSA signature verifies over authData ‖ clientDataHash")
    println("GetAssertion OK — signature verified (counter=${gaParsed2.signCount})")

    // 8. Shutdown and close.
    ws.sendBinary(crypter.encrypt(byteArrayOf(0x00)))
    ws.close()

    println("OK — $checks checks passed (full caBLE v2 MC/GA ceremony, uv=$uv)")
}

private fun validateGetInfo(getInfo: ByteArray, check: (Boolean, String) -> Unit) {
    val map = CableCbor.decode(getInfo) as? Map<*, *>
    check(map != null, "getInfo decodes as a map")
    val m = map!!
    check((m[1L] as? List<*>)?.contains("FIDO_2_0") == true, "getInfo versions")
    check((m[2L] as? List<*>) == listOf("prf"), "getInfo extensions")
    check((m[3L] as? ByteArray)?.size == 16, "getInfo aaguid (16 zero bytes)")
    val options = m[4L] as? Map<*, *>
    check(options != null && options["rk"] == true && options["uv"] == true, "getInfo options rk+uv")
    check((m[9L] as? List<*>)?.containsAll(listOf("cable", "hybrid", "internal")) == true, "getInfo transports")
}

private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

private fun b64u(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

/** Build a P-256 public key from 32-byte x/y (as parsed from a COSE EC2 key). */
private fun ecPublicKey(x: ByteArray, y: ByteArray): ECPublicKey {
    val params = (KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair().public as ECPublicKey).params
    return KeyFactory.getInstance("EC")
        .generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), params)) as ECPublicKey
}

private fun String.toHexBytes(): ByteArray =
    ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }
