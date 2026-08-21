package com.lightphone.passkey.cable

/**
 * Live tunnel check: runs a complete QR-flow caBLE v2 session through the
 * real tunnel server (domain 0 = cable.ua5v.com, Google's production relay).
 *
 * The phone opens a tunnel and gets its routing ID from the handshake
 * headers; the desktop connects via the routing ID; they complete the KNpsk0
 * handshake over the relay and exchange encrypted CTAP frames. This exercises
 * the exact URLs/headers/relay a real Chrome hybrid login uses, minus the BLE
 * leg (simulated: the advert bytes are built and decrypted in-process).
 *
 * Touches the network + a third-party service; run explicitly:
 *   ./gradlew :cable:tunnelCheck
 */
fun main() {
    var checks = 0
    fun check(cond: Boolean, what: String) {
        checks++
        if (!cond) throw AssertionError("FAIL: $what")
    }

    // A desktop's QR key (seed ‖ secret), as in the offline flow check.
    val qrKey = ByteArray(48) { (it * 3 + 1).toByte() }
    val secret = qrKey.copyOfRange(32, 48)
    val peerIdentity = Ec.keyFromSeed(qrKey.copyOfRange(0, 32)).second.toX962()

    // Phone side: tunnel ID + EID key come straight from the QR secret.
    val tunnelId = derive(secret, ByteArray(0), DerivedValueType.TUNNEL_ID, 16)
    val eidKey = derive(secret, ByteArray(0), DerivedValueType.EID_KEY, Eid.KEY_LEN)

    println("phone  → ${TunnelServer.newUrl(tunnelId)}")
    val phone = Ws(TunnelServer.newUrl(tunnelId))
    val routingHex = phone.header("x-cable-routing-id")
    check(routingHex != null, "tunnel server returned a routing ID")
    val routingIdHex = routingHex!!
    check(routingIdHex.length == 6, "routing ID is 3 bytes hex, got '$routingIdHex'")
    val routing = routingIdHex.toHexBytes()

    // BLE leg (simulated): plaintext EID + the 20-byte advert the LP3 would broadcast.
    val nonce = ByteArray(10) { 0x11 }
    val plaintextEid = Eid.fromComponents(Eid.Components(nonce, routing, 0))
    val advert = Eid.encrypt(plaintextEid, eidKey)
    println("advert (20B): ${advert.toHex()}")
    val seen = Eid.decrypt(advert, eidKey)!!
    check(seen.contentEquals(plaintextEid), "desktop decrypts the advert")
    check(Eid.toComponents(seen).routingId.contentEquals(routing), "routing ID round-trips")

    // PSK is derived from the secret + the plaintext EID on both sides.
    val psk = derive(secret, plaintextEid, DerivedValueType.PSK, 32)

    // Desktop connects via the advert's routing ID.
    val connectUrl = TunnelServer.connectUrl(routing, tunnelId)
    println("desktop → $connectUrl")
    val desktop = Ws(connectUrl)

    // KNpsk0 handshake over the relay: desktop speaks first.
    val laptop = HandshakeInitiator(psk, null, qrKey.copyOfRange(0, 32))
    val handshakeMsg = laptop.buildInitialMessage()
    desktop.sendBinary(handshakeMsg)

    val phoneResp = respondToHandshake(psk, null, peerIdentity, phone.readBinary())
    check(phoneResp != null, "phone completes the handshake over the relay")
    val (phoneResult, response) = phoneResp!!
    phone.sendBinary(response)

    val laptopResult = laptop.processResponse(desktop.readBinary())!!
    check(laptopResult.handshakeHash.contentEquals(phoneResult.handshakeHash),
        "handshake hashes match across the relay")

    // Post-handshake CTAP frames, framed per the tunnel transport
    // ([MessageType][encrypted]; CTAP = 1): desktop → phone and back.
    val ctapPayload = byteArrayOf(0x11, 0x04, 0x00, 0x00, 0x42) // authenticatorGetInfo-ish bytes
    desktop.sendBinary(laptopResult.crypter.encrypt(byteArrayOf(0x01) + ctapPayload))
    val phoneFrame = phone.readBinary()
    val phonePlain = phoneResult.crypter.decrypt(phoneFrame)
    check(phonePlain != null && phonePlain[0] == 0x01.toByte() &&
        phonePlain.copyOfRange(1, phonePlain.size).contentEquals(ctapPayload),
        "desktop→phone CTAP frame decrypts and matches")

    phone.sendBinary(phoneResult.crypter.encrypt(byteArrayOf(0x01) + ctapPayload))
    val desktopPlain = laptopResult.crypter.decrypt(desktop.readBinary())
    check(desktopPlain != null && desktopPlain[0] == 0x01.toByte() &&
        desktopPlain.copyOfRange(1, desktopPlain.size).contentEquals(ctapPayload),
        "phone→desktop CTAP frame decrypts and matches")

    phone.close()
    desktop.close()

    println("OK — $checks checks passed against the live tunnel server (cable.ua5v.com)")
}

private fun String.toHexBytes(): ByteArray =
    ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }
