package com.lightphone.passkey.server

import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.ParcelUuid
import com.lightphone.passkey.cable.CableCbor
import com.lightphone.passkey.cable.Ctap
import com.lightphone.passkey.cable.Ctap2
import com.lightphone.passkey.cable.DerivedValueType
import com.lightphone.passkey.cable.Eid
import com.lightphone.passkey.cable.Qr
import com.lightphone.passkey.cable.TunnelServer
import com.lightphone.passkey.cable.derive
import com.lightphone.passkey.cable.respondToHandshake
import com.lightphone.passkey.cable.toHex
import com.lightphone.passkey.core.AssertCtapRequest
import com.lightphone.passkey.core.CtapError
import com.lightphone.passkey.core.PasskeyAuthenticator
import com.lightphone.passkey.core.RegisterCtapRequest
import com.lightphone.passkey.core.UvUnavailableException
import java.security.SecureRandom
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * The phone side of a caBLE v2 QR login (Chromium v2_authenticator.cc):
 * open a tunnel to the relay, get the routing ID, broadcast the EID advert,
 * respond to the desktop's KNpsk0 handshake, push getInfo, then answer CTAP
 * MakeCredential / GetAssertion frames with the [PasskeyAuthenticator].
 *
 * Runs in the merged server module (the tool runtime forbids websockets and
 * BLE); the tool drives it over the SDK binder via SessionManager.
 *
 * BLE is best-effort (the emulator has none) — the advert bytes are always
 * logged so the JVM DesktopClient can play the desktop without BLE.
 */
class HybridSession(
    private val context: Context,
    private val authenticator: PasskeyAuthenticator,
    private val log: (String) -> Unit,
) {
    private val client = OkHttpClient()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var webSocket: WebSocket? = null
    private var advertiser: android.bluetooth.le.BluetoothLeAdvertiser? = null
    private var advertCallback: AdvertiseCallback? = null
    private var crypter: com.lightphone.passkey.cable.Crypter? = null
    private var psk: ByteArray? = null
    private var handshakeDone = false

    fun start(qr: Qr.Components) {
        stop()
        val secret = qr.secret
        val tunnelId = derive(secret, ByteArray(0), DerivedValueType.TUNNEL_ID, 16)
        val eidKey = derive(secret, ByteArray(0), DerivedValueType.EID_KEY, Eid.KEY_LEN)
        val url = TunnelServer.newUrl(tunnelId)
        log("session: tunnel $url")

        val request = Request.Builder()
            .url(url)
            .addHeader("Sec-WebSocket-Protocol", "fido.cable")
            .build()
        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                val routingHex = response.header("X-caBLE-Routing-ID")
                if (routingHex == null) {
                    log("FAIL: no X-caBLE-Routing-ID header")
                    close()
                    return
                }
                val routing = routingHex.toByteArrayHex()
                val nonce = ByteArray(Eid.NONCE_LEN).also { SecureRandom().nextBytes(it) }
                val plaintextEid = Eid.fromComponents(Eid.Components(nonce, routing, 0))
                val advert = Eid.encrypt(plaintextEid, eidKey)
                log("routing=${routing.toHex()} advert=${advert.toHex()}")
                startBleAdvert(advert)
                psk = derive(secret, plaintextEid, DerivedValueType.PSK, 32)
                log("psk=${psk!!.toHex()} identity=${qr.peerIdentity.toHex()}")
            }

            override fun onMessage(ws: WebSocket, bytes: ByteString) {
                val psk = psk ?: run { log("FAIL: no psk"); return }
                if (!handshakeDone) {
                    log("hs msg ${bytes.size}B: ${bytes.hex()}")
                    val result = respondToHandshake(psk, null, qr.peerIdentity, bytes.toByteArray())
                    if (result == null) {
                        log("FAIL: handshake rejected")
                        close()
                        return
                    }
                    val (handshake, responseBytes) = result
                    crypter = handshake.crypter
                    handshakeDone = true
                    ws.send(responseBytes.toByteString())
                    log("handshake OK — pushing getInfo")
                    pushGetInfo()
                } else {
                    val crypter = crypter ?: return
                    val plaintext = crypter.decrypt(bytes.toByteArray())
                    if (plaintext == null) {
                        log("FAIL: decrypt")
                        return
                    }
                    handleFrame(ws, plaintext)
                }
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                log("FAIL: ${t.javaClass.simpleName}: ${t.message}")
                close()
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                log("closed ($code $reason)")
                close()
            }
        })
    }

    private fun pushGetInfo() {
        val msg = CableCbor.encode(
            mapOf<Any, Any?>(
                1L to Ctap.getInfo(),
                3L to listOf("ctap"),
            )
        )
        webSocket?.send(crypter!!.encrypt(msg).toByteString())
    }

    private fun handleFrame(ws: WebSocket, plaintext: ByteArray) {
        if (plaintext.isEmpty()) {
            log("FAIL: empty frame")
            return
        }
        val type = plaintext[0].toInt() and 0xff
        val payload = plaintext.copyOfRange(1, plaintext.size)
        when (type) {
            0 -> { // kShutdown
                log("shutdown from desktop")
                close()
            }
            1 -> { // kCTAP
                if (payload.isEmpty()) {
                    log("FAIL: empty CTAP frame")
                    return
                }
                val command = payload[0].toInt() and 0xff
                val body = payload.copyOfRange(1, payload.size)
                log("CTAP command 0x%02x (%d bytes)".format(command, body.size))
                when (command) {
                    Ctap.CMD_GET_INFO -> {
                        log("getInfo request — responding")
                        ws.send((crypter!!.encrypt(
                            byteArrayOf(Ctap.MSG_CTAP.toByte(), Ctap.CTAP_OK.toByte()) + Ctap.getInfo()
                        )).toByteString())
                    }
                    Ctap.CMD_MAKE_CREDENTIAL -> scope.launch { respondMakeCredential(ws, body) }
                    Ctap.CMD_GET_ASSERTION -> scope.launch { respondGetAssertion(ws, body) }
                    else -> log("unsupported CTAP command 0x%02x".format(command))
                }
            }
            else -> log("unknown message type $type")
        }
    }

    // Response framing is standard CTAP2: success = [0x00 status][cbor],
    // error = bare CTAP2 status byte. (The pre-interop DesktopClient framing
    // echoed the command byte — Chromium reads the first byte as the CTAP2
    // status, so [cmd] decoded as an error; fixed 2026-08-21 for the
    // real-Chrome gate. See the README's protocol notes.)
    private suspend fun respondMakeCredential(ws: WebSocket, body: ByteArray) {
        log("MC request (${body.size} bytes)")
        log("MC hex: ${body.toHex()}")
        val req = Ctap2.decodeMakeCredential(body)
        if (req == null) {
            log("MC decode failed")
            return sendCtapError(ws, Ctap.ERR_INVALID_CBOR)
        }
        log("MC: rp=${req.rpId} algs=${req.algorithms} uv=${req.requireUserVerification}")
        if (!req.algorithms.contains(Ctap2.ES256)) return sendCtapError(ws, Ctap.ERR_UNSUPPORTED_ALGORITHM)
        try {
            val res = authenticator.registerCtap(
                RegisterCtapRequest(
                    rpId = req.rpId,
                    userId = req.userId,
                    userName = req.userName ?: "user",
                    clientDataHash = req.clientDataHash,
                    requireUserVerification = req.requireUserVerification,
                    excludeCredentialIds = req.excludeCredentialIds,
                )
            )
            sendCtap(ws, Ctap2.encodeMakeCredentialResponse(res.credentialId, res.authData))
            log("MakeCredential OK — cred ${res.credentialId.toHex().take(8)}…")
        } catch (e: UvUnavailableException) {
            log("FAIL: ${e.message}")
            sendCtapError(ws, Ctap.ERR_OPERATION_DENIED)
        } catch (e: CtapError) {
            log("MakeCredential rejected: 0x%02x".format(e.status))
            sendCtapError(ws, e.status)
        } catch (e: Exception) {
            log("MakeCredential failed: ${e.stackTraceToString()}")
            sendCtapError(ws, Ctap.ERR_OPERATION_DENIED)
        }
    }

    private suspend fun respondGetAssertion(ws: WebSocket, body: ByteArray) {
        log("GA req hex: ${body.toHex()}")
        val req = Ctap2.decodeGetAssertion(body)
        if (req == null) return sendCtapError(ws, Ctap.ERR_INVALID_CBOR)
        try {
            val res = authenticator.assertCtap(
                AssertCtapRequest(
                    rpId = req.rpId,
                    clientDataHash = req.clientDataHash,
                    allowCredentialIds = req.allowCredentialIds,
                    requireUserVerification = req.requireUserVerification,
                )
            )
            val response = Ctap2.encodeGetAssertionResponse(
                res.credentialId, res.authData, res.signature, res.userHandle, res.userName,
            )
            log("GA resp hex: ${response.toHex()}")
            sendCtap(ws, response)
            log("GetAssertion OK — cred ${res.credentialId.toHex().take(8)}… uv=${res.uv}")
        } catch (e: UvUnavailableException) {
            log("FAIL: ${e.message}")
            sendCtapError(ws, Ctap.ERR_OPERATION_DENIED)
        } catch (e: CtapError) {
            log("GetAssertion rejected: 0x%02x".format(e.status))
            sendCtapError(ws, e.status)
        } catch (e: Exception) {
            log("GetAssertion failed: ${e.stackTraceToString()}")
            sendCtapError(ws, Ctap.ERR_OPERATION_DENIED)
        }
    }

    private fun sendCtap(ws: WebSocket, cbor: ByteArray) {
        // [MessageType kCTAP][CTAP2 status 0x00][cbor] — Chromium's tunnel
        // device reads the first plaintext byte as the message type; a reply
        // without the 0x01 prefix parses as kShutdown ("invalid shutdown
        // frame", seen against real Chrome 151 2026-08-21).
        ws.send(crypter!!.encrypt(byteArrayOf(Ctap.MSG_CTAP.toByte(), Ctap.CTAP_OK.toByte()) + cbor).toByteString())
    }

    private fun sendCtapError(ws: WebSocket, status: Int) {
        ws.send(crypter!!.encrypt(byteArrayOf(Ctap.MSG_CTAP.toByte(), status.toByte())).toByteString())
    }

    /** Best-effort EID advert; logs and continues when BLE is unavailable. */
    private fun startBleAdvert(advert: ByteArray) {
        runCatching {
            val btAdapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as android.bluetooth.BluetoothManager)
                .adapter
            val advertiser = btAdapter?.bluetoothLeAdvertiser
                ?: return log("BLE: no LeAdvertiser (emulator?) — advert logged instead")
            val uuid = ParcelUuid.fromString("0000fff9-0000-1000-8000-00805f9b34fb")
            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .setConnectable(false)
                .build()
            val data = AdvertiseData.Builder()
                .addServiceUuid(uuid)
                .addServiceData(uuid, advert)
                .build()
            this.advertiser = advertiser
            advertCallback = object : AdvertiseCallback() {
                override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
                    log("BLE: advertising EID (20B)")
                }

                override fun onStartFailure(errorCode: Int) {
                    log("BLE: advertise failed code=$errorCode")
                }
            }
            advertiser.startAdvertising(settings, data, advertCallback)
        }.onFailure { log("BLE: ${it.javaClass.simpleName}: ${it.message}") }
    }

    fun stop() {
        advertiser?.let { adv ->
            runCatching { adv.stopAdvertising(advertCallback) }
        }
        advertiser = null
        webSocket?.close(1000, "bye")
        webSocket = null
        crypter = null
        psk = null
        handshakeDone = false
    }

    private fun close() = stop()

    private fun String.toByteArrayHex(): ByteArray =
        ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}
