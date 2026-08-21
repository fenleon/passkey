package com.lightphone.passkey.cable

import java.io.ByteArrayOutputStream

/**
 * Minimal CBOR (RFC 8949) for the caBLE QR payload: a map with small-int keys
 * whose values are bytestring / int / bool / text. Encoding emits keys in
 * ascending order, matching Chromium's `std::map`-backed cbor::Value and the
 * byte-identical QR bytes a real browser produces.
 */
object CableCbor {
    fun encode(map: Map<*, *>): ByteArray {
        val out = ByteArrayOutputStream()
        writeHead(out, 5, map.size.toLong())
        sortedEntries(map).forEach { (k, v) ->
            write(out, k)
            write(out, v)
        }
        return out.toByteArray()
    }

    /**
     * Decodes into Kotlin values: Long, ByteArray, Boolean, String,
     * List<Any?>, Map<Long, Any?>. Returns null on anything the QR subset
     * doesn't allow.
     */
    fun decode(bytes: ByteArray): Any? {
        val (value, end) = read(bytes, 0)
        return if (end == bytes.size) value else null
    }

    private fun write(out: ByteArrayOutputStream, v: Any?) {
        when (v) {
            null -> out.write(0xf6)
            is Boolean -> out.write(if (v) 0xf5 else 0xf4)
            is Int -> writeInt(out, v.toLong())
            is Long -> writeInt(out, v)
            is String -> {
                val b = v.toByteArray(Charsets.UTF_8)
                writeHead(out, 3, b.size.toLong())
                out.write(b)
            }
            is ByteArray -> {
                writeHead(out, 2, v.size.toLong())
                out.write(v)
            }
            is List<*> -> {
                writeHead(out, 4, v.size.toLong())
                v.forEach { write(out, it) }
            }
            is Map<*, *> -> {
                writeHead(out, 5, v.size.toLong())
                sortedEntries(v).forEach { (k, value) ->
                    write(out, k)
                    write(out, value)
                }
            }
            else -> throw IllegalArgumentException("cannot CBOR-encode ${v.javaClass}")
        }
    }

    /**
     * Chromium's cbor::Value::MapValue is a std::map: integer keys sort before
     * text keys, each group lexicographically. Matches the ordering of the QR
     * and getInfo maps a real browser/authenticator encodes.
     */
    private fun sortedEntries(map: Map<*, *>): List<Map.Entry<*, *>> =
        map.entries.sortedWith(Comparator { a, b ->
            val ka = a.key
            val kb = b.key
            when {
                ka is Long && kb is Long -> ka.compareTo(kb)
                ka is Long -> -1
                kb is Long -> 1
                else -> ka.toString().compareTo(kb.toString())
            }
        })

    private fun writeInt(out: ByteArrayOutputStream, n: Long) =
        if (n >= 0) writeHead(out, 0, n) else writeHead(out, 1, -1 - n)

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

    private fun read(bytes: ByteArray, pos: Int): Pair<Any?, Int> {
        val b = bytes[pos].toInt() and 0xff
        val major = b ushr 5
        var ai = b and 0x1f
        var p = pos + 1
        var value: Long = ai.toLong()
        if (ai == 24) { value = (bytes[p].toLong() and 0xff); p++ }
        else if (ai == 25) { value = (bytes[p].toLong() and 0xff) shl 8 or (bytes[p + 1].toLong() and 0xff); p += 2 }
        else if (ai == 26) { value = read32(bytes, p); p += 4 }
        else if (ai == 27) { value = read64(bytes, p); p += 8 }
        else if (ai >= 28) return null to pos // indefinite / reserved

        return when (major) {
            0 -> value to p
            1 -> (-1 - value) to p
            2 -> {
                val b2 = bytes.copyOfRange(p, p + value.toInt())
                b2 to p + value.toInt()
            }
            3 -> String(bytes, p, value.toInt(), Charsets.UTF_8) to p + value.toInt()
            4 -> {
                val items = mutableListOf<Any?>()
                repeat(value.toInt()) {
                    val (item, np) = read(bytes, p) ?: return null to pos
                    items.add(item)
                    p = np
                }
                items to p
            }
            5 -> {
                val map = mutableMapOf<Any, Any?>()
                repeat(value.toInt()) {
                    val (k, np) = read(bytes, p) ?: return null to pos
                    if (k !is Long && k !is String) return null to pos
                    val (v, np2) = read(bytes, np) ?: return null to pos
                    map[k] = v
                    p = np2
                }
                map to p
            }
            6 -> null to pos // tag
            7 -> when (ai) {
                20 -> false to p
                21 -> true to p
                22 -> null to p
                else -> null to pos
            }
            else -> null to pos
        }
    }

    private fun read32(bytes: ByteArray, p: Int) =
        (bytes[p].toLong() and 0xff) shl 24 or
            ((bytes[p + 1].toLong() and 0xff) shl 16) or
            ((bytes[p + 2].toLong() and 0xff) shl 8) or
            (bytes[p + 3].toLong() and 0xff)

    private fun read64(bytes: ByteArray, p: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (bytes[p + i].toLong() and 0xff)
        return v
    }
}
