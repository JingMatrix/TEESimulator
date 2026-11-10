package org.matrix.teesim

/**
 * A reader for just enough CBOR (RFC 8949) to decode the one place Android puts it in a
 * certificate: Google's `provisioningInfo` extension (1.3.6.1.4.1.11129.2.1.30), a small map of
 * integer keys whose values are integers, text, byte strings and one nested map.
 *
 * It is deliberately a reader and not a codec — there is nothing here to encode — and it is total:
 * every malformed, truncated or absurdly-sized input returns null rather than throwing, because the
 * caller is parsing a file a user supplied and a bad keybox must render as "undecodable", never as
 * a crashed inspector. Lengths are checked against what is actually left in the buffer before
 * anything is allocated, so a header claiming four gigabytes costs nothing.
 *
 * Decoded shapes: [Long] for integers, [ByteArray] for byte strings, [String] for text, [List] for
 * arrays, [LinkedHashMap] for maps (insertion-ordered, so a renderer can show fields in the order
 * the issuer wrote them), [Boolean], [Double], and null for CBOR null/undefined. A tag is
 * transparent: its content is returned and the tag number dropped, which is right for this use —
 * nothing in provisioningInfo distinguishes itself by tag.
 */
object Cbor {

    /** Decode the single CBOR item in [bytes], or null if it is malformed or has trailing data. */
    fun decode(bytes: ByteArray): Any? =
        try {
            val r = Reader(bytes)
            val v = r.item(0)
            if (r.pos == bytes.size) v else null
        } catch (_: Throwable) {
            null
        }

    /** Thrown internally and swallowed by [decode]; never escapes this file. */
    private class Malformed : Exception()

    private class Reader(private val b: ByteArray) {
        var pos = 0

        private fun need(n: Int) {
            if (n < 0 || pos + n > b.size) throw Malformed()
        }

        private fun u8(): Int {
            need(1)
            return b[pos++].toInt() and 0xff
        }

        /** The argument encoded in [info], per RFC 8949 §3; 31 (indefinite) is the caller's job. */
        private fun argument(info: Int): Long {
            if (info < 24) return info.toLong()
            val width =
                when (info) {
                    24 -> 1
                    25 -> 2
                    26 -> 4
                    27 -> 8
                    else -> throw Malformed() // 28..30 are reserved, 31 handled by the caller
                }
            need(width)
            var v = 0L
            repeat(width) { v = (v shl 8) or (b[pos++].toLong() and 0xff) }
            if (v < 0) throw Malformed() // a 64-bit argument past Long.MAX_VALUE
            return v
        }

        /** A length that must be addressable in this buffer, so nothing oversized is allocated. */
        private fun count(info: Int): Int {
            val n = argument(info)
            if (n > b.size - pos) throw Malformed()
            return n.toInt()
        }

        /**
         * One item. [depth] bounds nesting: provisioningInfo is two levels deep, and a cap keeps a
         * hand-crafted file from recursing until the stack gives out.
         */
        fun item(depth: Int): Any? {
            if (depth > 16) throw Malformed()
            val head = u8()
            val major = head shr 5
            val info = head and 0x1f
            return when (major) {
                0 -> argument(info)
                1 -> -1L - argument(info)
                2 -> bytes(info, depth)
                3 -> String(bytes(info, depth), Charsets.UTF_8)
                4 -> array(info, depth)
                5 -> map(info, depth)
                6 -> {
                    argument(info) // the tag number itself carries nothing we need
                    item(depth + 1)
                }
                7 ->
                    when (info) {
                        20 -> false
                        21 -> true
                        22,
                        23 -> null // null and undefined both read as absent
                        25 -> halfFloat()
                        26 -> Float.fromBits(argument(26).toInt()).toDouble()
                        27 -> Double.fromBits(argument(27))
                        else -> if (info < 20) argument(info) else throw Malformed()
                    }
                else -> throw Malformed()
            }
        }

        /** A byte string, joining the chunks of an indefinite-length one. */
        private fun bytes(info: Int, depth: Int): ByteArray {
            if (info != 31) {
                val n = count(info)
                val out = b.copyOfRange(pos, pos + n)
                pos += n
                return out
            }
            val parts = ArrayList<ByteArray>()
            while (true) {
                if (peekBreak()) break
                val part = item(depth + 1)
                if (part !is ByteArray) throw Malformed()
                parts.add(part)
            }
            val out = ByteArray(parts.sumOf { it.size })
            var at = 0
            for (p in parts) {
                p.copyInto(out, at)
                at += p.size
            }
            return out
        }

        private fun array(info: Int, depth: Int): List<Any?> {
            val out = ArrayList<Any?>()
            if (info == 31) {
                while (!peekBreak()) out.add(item(depth + 1))
                return out
            }
            val n = argument(info)
            if (n > b.size - pos) throw Malformed() // one byte minimum per element
            repeat(n.toInt()) { out.add(item(depth + 1)) }
            return out
        }

        private fun map(info: Int, depth: Int): LinkedHashMap<Any?, Any?> {
            val out = LinkedHashMap<Any?, Any?>()
            if (info == 31) {
                while (!peekBreak()) {
                    val k = item(depth + 1)
                    out[key(k)] = item(depth + 1)
                }
                return out
            }
            val n = argument(info)
            if (n * 2 > b.size - pos) throw Malformed() // one byte minimum per key and value
            repeat(n.toInt()) {
                val k = item(depth + 1)
                out[key(k)] = item(depth + 1)
            }
            return out
        }

        /**
         * A map key, reduced to something hashable — a byte-string key would compare by identity.
         */
        private fun key(k: Any?): Any? = if (k is ByteArray) k.toHex() else k

        /** Consume a break (0xff) if one is next; used by the indefinite-length forms. */
        private fun peekBreak(): Boolean {
            need(1)
            if ((b[pos].toInt() and 0xff) != 0xff) return false
            pos++
            return true
        }

        private fun halfFloat(): Double {
            val h = argument(25).toInt()
            val exp = (h shr 10) and 0x1f
            val frac = h and 0x3ff
            val v =
                when (exp) {
                    0 -> Math.scalb(frac.toDouble(), -24)
                    31 -> if (frac == 0) Double.POSITIVE_INFINITY else Double.NaN
                    else -> Math.scalb((frac + 1024).toDouble(), exp - 25)
                }
            return if (h and 0x8000 != 0) -v else v
        }
    }

    fun ByteArray.toHex(): String {
        val sb = StringBuilder(size * 2)
        for (x in this) sb.append("%02x".format(x))
        return sb.toString()
    }
}
