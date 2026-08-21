package com.lightphone.passkey.rp

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.RegistrationData
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.security.SecureRandom
import java.util.Base64

/**
 * Local WebAuthn4J relying party for the Phase-1 loopback. Options endpoints
 * take query params (?username=&uv=), verify endpoints take the raw WebAuthn
 * response JSON; in-memory credential store; single-user. Run from the host;
 * the device reaches it via `adb reverse tcp:8787 tcp:8787`.
 */
private val b64e = Base64.getUrlEncoder().withoutPadding()

private const val ORIGIN = "http://127.0.0.1:8787"
private const val RP_ID = "localhost"
private const val RP_NAME = "LP3 Passkey Loopback"

private val random = SecureRandom()
private val manager = WebAuthnManager.createNonStrictWebAuthnManager()

/** credentialId (b64u) -> RegistrationData */
private val credentials = LinkedHashMap<String, RegistrationData>()
private val pendingChallenges = HashMap<String, ByteArray>()
private var lastUv = false

fun main() {
    val server = HttpServer.create(InetSocketAddress("0.0.0.0", 8787), 0)
    server.createContext("/") { ex ->
        try {
            when (ex.requestURI.path) {
                "/register/options" -> registerOptions(ex)
                "/register/verify" -> registerVerify(ex)
                "/assert/options" -> assertOptions(ex)
                "/assert/verify" -> assertVerify(ex)
                else -> respond(ex, 404, """{"ok":false,"message":"no such endpoint"}""")
            }
        } catch (e: Exception) {
            respond(ex, 400, """{"ok":false,"message":${json(e.message ?: e.javaClass.simpleName)}}""")
        }
    }
    server.start()
    println("RP listening on :8787 (origin=$ORIGIN rpId=$RP_ID)")
}

private fun registerOptions(ex: HttpExchange) {
    val username = queryParam(ex, "username", "fenn")
    lastUv = queryParam(ex, "uv", "false").toBoolean()
    val challenge = ByteArray(32).also { random.nextBytes(it) }
    val userId = ByteArray(16).also { random.nextBytes(it) }
    pendingChallenges["register"] = challenge
    respond(
        ex, 200,
        """{"challenge":"${b64e.encodeToString(challenge)}","rpId":"$RP_ID","rpName":"$RP_NAME",""" +
            """"userId":"${b64e.encodeToString(userId)}","userName":${json(username)},"requireUv":$lastUv}""",
    )
}

private fun registerVerify(ex: HttpExchange) {
    val data = manager.parseRegistrationResponseJSON(body(ex))
    val serverProperty = ServerProperty(Origin(ORIGIN), RP_ID, DefaultChallenge(pendingChallenges["register"]!!), null)
    val params = RegistrationParameters(
        serverProperty,
        listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
        lastUv,
        true,
    )
    manager.verify(data, params)
    val credId = b64e.encodeToString(data.attestationObject!!.authenticatorData.attestedCredentialData!!.credentialId)
    credentials[credId] = data
    println("registration verified: $credId (uv=$lastUv)")
    respond(ex, 200, """{"ok":true,"message":"registration verified","credentialId":${json(credId)}}""")
}

private fun assertOptions(ex: HttpExchange) {
    lastUv = queryParam(ex, "uv", "false").toBoolean()
    val challenge = ByteArray(32).also { random.nextBytes(it) }
    pendingChallenges["assert"] = challenge
    val allow = credentials.keys.joinToString(",") { json(it) }
    respond(
        ex, 200,
        """{"challenge":"${b64e.encodeToString(challenge)}","rpId":"$RP_ID","allowCredentialIds":[$allow],"requireUv":$lastUv}""",
    )
}

private fun assertVerify(ex: HttpExchange) {
    val data = manager.parseAuthenticationResponseJSON(body(ex))
    val credId = b64e.encodeToString(data.credentialId)
    val registration = credentials[credId] ?: throw RuntimeException("unknown credential $credId")
    val record = CredentialRecordImpl(
        registration.attestationObject!!,
        registration.collectedClientData,
        registration.clientExtensions,
        registration.transports,
    )
    val serverProperty = ServerProperty(Origin(ORIGIN), RP_ID, DefaultChallenge(pendingChallenges["assert"]!!), null)
    val params = AuthenticationParameters(serverProperty, record, listOf(data.credentialId), lastUv, true)
    manager.verify(data, params)
    println("assertion verified: $credId counter=${data.authenticatorData!!.signCount} (uv=$lastUv)")
    respond(
        ex, 200,
        """{"ok":true,"counter":${data.authenticatorData!!.signCount},"message":"assertion verified"}""",
    )
}

private fun queryParam(ex: HttpExchange, name: String, default: String): String {
    val q = ex.requestURI.rawQuery ?: return default
    return q.split('&').mapNotNull { kv ->
        val parts = kv.split('=', limit = 2)
        if (parts[0] == name) URLDecoder.decode(parts.getOrElse(1) { "" }, Charsets.UTF_8) else null
    }.firstOrNull() ?: default
}

private fun body(ex: HttpExchange): String = ex.requestBody.bufferedReader().use { it.readText() }

private fun json(s: String): String = buildString {
    append('"')
    for (c in s) when (c) {
        '"' -> append("\\\"")
        '\\' -> append("\\\\")
        '\n' -> append("\\n")
        '\r' -> append("\\r")
        '\t' -> append("\\t")
        else -> if (c < ' ') append("\\u%04x".format(c.code)) else append(c)
    }
    append('"')
}

private fun respond(ex: HttpExchange, code: Int, payload: String) {
    val bytes = payload.toByteArray(Charsets.UTF_8)
    ex.responseHeaders.set("Content-Type", "application/json")
    ex.sendResponseHeaders(code, bytes.size.toLong())
    ex.responseBody.use { it.write(bytes) }
}
