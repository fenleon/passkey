package com.lightphone.passkey.cable

import java.io.DataInputStream
import java.io.EOFException
import java.io.OutputStream
import java.net.URI
import java.security.SecureRandom
import java.util.Base64
import javax.net.ssl.SSLSocketFactory

/**
 * Minimal RFC 6455 websocket client for the tunnel check: TLS + HTTP/1.1
 * upgrade offering the `fido.cable` subprotocol, then masked binary frames
 * out and unmasked binary frames in (pings answered, text ignored). Reads the
 * handshake response headers — the tunnel server's `X-caBLE-Routing-ID`
 * arrives there. Not for production; the Android app uses a real websocket
 * client.
 */
class Ws(url: String) {
    private val headers: Map<String, String>
    private val out: OutputStream
    private val reader: DataInputStream
    private val socket: java.net.Socket

    init {
        val uri = URI(url)
        require(uri.scheme == "wss" && uri.host != null) { "expected wss URL, got $url" }
        val port = if (uri.port != -1) uri.port else 443
        val path = (uri.rawPath ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
        socket = SSLSocketFactory.getDefault().createSocket(uri.host, port)
        out = socket.getOutputStream()
        reader = DataInputStream(socket.getInputStream())

        val key = Base64.getEncoder().encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) })
        val request = buildString {
            append("GET ").append(path).append(" HTTP/1.1\r\n")
            append("Host: ").append(uri.host).append("\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: ").append(key).append("\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("Sec-WebSocket-Protocol: fido.cable\r\n")
            append("\r\n")
        }
        out.write(request.toByteArray(Charsets.US_ASCII))
        out.flush()

        val status = reader.readLine() ?: throw EOFException("no handshake response")
        require(status.startsWith("HTTP/1.1 101")) { "websocket upgrade failed: $status" }
        val parsed = mutableMapOf<String, String>()
        while (true) {
            val line = reader.readLine() ?: break
            if (line.isEmpty()) break
            val idx = line.indexOf(':')
            if (idx > 0) parsed[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
        }
        headers = parsed
    }

    /** Lowercased handshake response headers (e.g. "x-cable-routing-id"). */
    fun header(name: String): String? = headers[name.lowercase()]

    fun sendBinary(data: ByteArray) {
        val mask = ByteArray(4).also { SecureRandom().nextBytes(it) }
        val masked = ByteArray(data.size) { i -> (data[i].toInt() xor mask[i % 4].toInt()).toByte() }
        val header = java.io.ByteArrayOutputStream()
        header.write(0x82) // FIN + binary
        when {
            data.size < 126 -> header.write(0x80 or data.size)
            data.size <= 0xffff -> {
                header.write(0x80 or 126)
                header.write(data.size ushr 8)
                header.write(data.size)
            }
            else -> error("frame too large")
        }
        header.write(mask)
        out.write(header.toByteArray())
        out.write(masked)
        out.flush()
    }

    /** Reads one binary message; answers pings, ignores text, throws on close. */
    fun readBinary(): ByteArray {
        while (true) {
            val opcode = reader.readUnsignedByte() and 0x0f
            val b1 = reader.readUnsignedByte()
            var len = b1 and 0x7f
            if (len == 126) len = reader.readUnsignedShort()
            else if (len == 127) len = readLongLen()
            if (b1 and 0x80 != 0) throw EOFException("server must not mask frames")
            val payload = ByteArray(len)
            reader.readFully(payload)
            when (opcode) {
                0x9 -> sendControl(0xA, payload) // ping → pong
                0x8 -> throw EOFException("websocket closed by peer")
                0x2, 0x0 -> return payload // binary / continuation
                else -> {} // text/other: ignore
            }
        }
    }

    private fun sendControl(opcode: Int, payload: ByteArray) {
        val mask = ByteArray(4).also { SecureRandom().nextBytes(it) }
        val masked = ByteArray(payload.size) { i -> (payload[i].toInt() xor mask[i % 4].toInt()).toByte() }
        out.write(0x80 or opcode)
        out.write(if (payload.size < 126) 0x80 or payload.size else 0x80 or 126)
        if (payload.size >= 126) {
            out.write(payload.size ushr 8)
            out.write(payload.size)
        }
        out.write(mask)
        out.write(masked)
        out.flush()
    }

    private fun readLongLen(): Int {
        var len = 0L
        repeat(8) { len = (len shl 8) or reader.readUnsignedByte().toLong() }
        require(len <= Int.MAX_VALUE) { "frame too large" }
        return len.toInt()
    }

    fun close() = socket.close()
}
