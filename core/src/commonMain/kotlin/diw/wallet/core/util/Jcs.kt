package diw.wallet.core.util

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * RFC 8785 JSON Canonicalization Scheme: members sorted by UTF-16 code units, no whitespace, minimal string
 * escaping and ECMAScript number serialization. Used by did:key jwk_jcs-pub, the Data Integrity JCS cryptosuites
 * and anything that hashes JSON.
 */
object Jcs {
    fun canonicalize(e: JsonElement): String = StringBuilder().also { write(e, it) }.toString()

    fun canonicalBytes(e: JsonElement): ByteArray = canonicalize(e).encodeToByteArray()

    private fun write(e: JsonElement, out: StringBuilder) {
        when (e) {
            is JsonNull -> out.append("null")
            is JsonObject -> {
                out.append('{')
                e.keys.sortedWith { a, b -> a.compareTo(b) }.forEachIndexed { i, k ->
                    if (i > 0) out.append(',')
                    string(k, out)
                    out.append(':')
                    write(e.getValue(k), out)
                }
                out.append('}')
            }
            is JsonArray -> {
                out.append('[')
                e.forEachIndexed { i, v -> if (i > 0) out.append(','); write(v, out) }
                out.append(']')
            }
            is JsonPrimitive -> when {
                e.isString -> string(e.content, out)
                e.content == "true" || e.content == "false" -> out.append(e.content)
                else -> out.append(number(e.content))
            }
        }
    }

    private fun string(s: String, out: StringBuilder) {
        out.append('"')
        for (c in s) {
            when (c) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                else -> if (c < ' ') out.append("\\u").append(c.code.toString(16).padStart(4, '0')) else out.append(c)
            }
        }
        out.append('"')
    }

    /** ECMAScript Number.prototype.toString for a JSON number literal. */
    fun number(literal: String): String {
        val integer = literal.toLongOrNull()
        if (integer != null && kotlin.math.abs(integer) < (1L shl 53)) return integer.toString()
        val d = literal.toDoubleOrNull() ?: throw ProtocolException("invalid_json", "Not a number: $literal")
        if (d.isNaN() || d.isInfinite()) throw ProtocolException("invalid_json", "Number not representable in JSON: $literal")
        if (d == 0.0) return "0"
        val negative = d < 0
        val (digits, exponent) = shortestDigits(kotlin.math.abs(d))
        // digits d1d2...dk, value = 0.d1...dk * 10^exponent (exponent = n in the ECMAScript algorithm)
        val k = digits.length
        val n = exponent
        val body = when {
            n in k..21 -> digits + "0".repeat(n - k)
            n in 1..21 -> digits.substring(0, n) + "." + digits.substring(n)
            n in -5..0 -> "0." + "0".repeat(-n) + digits
            else -> {
                val e = n - 1
                val sign = if (e >= 0) "+" else "-"
                (if (k == 1) digits else digits[0] + "." + digits.substring(1)) + "e" + sign + kotlin.math.abs(e)
            }
        }
        return if (negative) "-$body" else body
    }

    /** Shortest round-trip decimal digits of a positive double and the decimal point position. */
    private fun shortestDigits(d: Double): Pair<String, Int> {
        val s = d.toString().lowercase()
        val mantissa = s.substringBefore('e')
        val exp = s.substringAfter('e', "0").toInt()
        val intPart = mantissa.substringBefore('.')
        val frac = mantissa.substringAfter('.', "")
        var digits = (intPart + frac).trimStart('0')
        val leadingZeros = (intPart + frac).length - (intPart + frac).trimStart('0').length
        var point = intPart.length - leadingZeros + exp
        digits = digits.trimEnd('0')
        if (digits.isEmpty()) { digits = "0"; point = 1 }
        return digits to point
    }
}
