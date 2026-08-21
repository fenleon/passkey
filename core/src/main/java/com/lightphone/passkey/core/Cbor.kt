package com.lightphone.passkey.core

import java.io.ByteArrayOutputStream

/**
 * Minimal CBOR (RFC 8949) encoder for the authenticator's data structures:
 * the attestationObject map and COSE keys. Decoding arrives with the CTAP
 * transport work — Phase 1 (loopback over JSON) only needs encoding.
 */
object Cbor {
    private const val MT_UINT = 0
    private const val MT_NEGINT = 1
    private const val MT_BYTES = 2
    private const val MT_TEXT = 3
    private const val MT_ARRAY = 4
    private const val MT_MAP = 5

    fun encode(value: Any?): ByteArray {
        val out = ByteArrayOutputStream()
        write(out, value)
        return out.toByteArray()
    }

    private fun write(out: ByteArrayOutputStream, v: Any?) {
        when (v) {
            null -> out.write(0xf6)
            is Boolean -> out.write(if (v) 0xf5 else 0xf4)
            is Int -> writeInt(out, v.toLong())
            is Long -> writeInt(out, v)
            is String -> {
                val b = v.toByteArray(Charsets.UTF_8)
                writeHead(out, MT_TEXT, b.size.toLong())
                out.write(b)
            }
            is ByteArray -> {
                writeHead(out, MT_BYTES, v.size.toLong())
                out.write(v)
            }
            is List<*> -> {
                writeHead(out, MT_ARRAY, v.size.toLong())
                v.forEach { write(out, it) }
            }
            is Map<*, *> -> {
                writeHead(out, MT_MAP, v.size.toLong())
                v.forEach { (k, value) ->
                    write(out, k)
                    write(out, value)
                }
            }
            else -> throw IllegalArgumentException("cannot CBOR-encode ${v.javaClass}")
        }
    }

    private fun writeInt(out: ByteArrayOutputStream, n: Long) {
        if (n >= 0) writeHead(out, MT_UINT, n) else writeHead(out, MT_NEGINT, -1 - n)
    }

    private fun writeHead(out: ByteArrayOutputStream, major: Int, value: Long) {
        val ai = major shl 5
        when {
            value < 24 -> out.write(ai or value.toInt())
            value <= 0xffL -> {
                out.write(ai or 24)
                out.write(value.toInt())
            }
            value <= 0xffffL -> {
                out.write(ai or 25)
                out.write((value ushr 8).toInt())
                out.write(value.toInt())
            }
            value <= 0xffffffffL -> {
                out.write(ai or 26)
                for (i in 3 downTo 0) out.write(((value ushr (8 * i)) and 0xff).toInt())
            }
            else -> {
                out.write(ai or 27)
                for (i in 7 downTo 0) out.write(((value ushr (8 * i)) and 0xff).toInt())
            }
        }
    }
}
