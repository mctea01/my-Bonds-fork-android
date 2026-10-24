package diw.wallet.core.zktls

import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.http.encodeURLParameter
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/** A byte range [start, end) of a transcript. */
data class ZkTlsRange(val start: Int, val end: Int) {
    init {
        require(start in 0..end)
    }
}

/**
 * The holder's side of a profile (p4-circuits.md sections 4.2 and 4.3): the exact request, and which bytes of the
 * transcript to reveal. Of the request only the method and path (with the character after it) and the Host line are
 * revealed; the query, the form, cookies and Content-Length stay hidden. Of the response each rule's whole match is
 * revealed, so the verifier can read the value back with the same rule and nothing around it.
 */
object ZkTlsPlanner {
    /** The request bytes for [inputs]; throws when an input is missing or does not match its pattern. */
    fun request(profile: ZkTlsProfile, inputs: Map<String, String>): ByteArray {
        val r = profile.request
        for (input in r.inputs) {
            val value = inputs[input.name] ?: throw ProtocolException("invalid_input", "${input.label}未填寫")
            if (!Regex(input.pattern).matches(value)) throw ProtocolException("invalid_input", "${input.label}格式不符")
        }
        fun fill(template: String) = ZkTlsProfile.PLACEHOLDER.replace(template) { inputs.getValue(it.groupValues[1]).encodeURLParameter() }
        val target = r.path + (r.query?.let { "?" + fill(it) } ?: "")
        val body = r.body?.let { fill(it).encodeToByteArray() }
        val head = buildString {
            append(r.method).append(' ').append(target).append(" HTTP/1.1\r\n")
            append(hostLine(profile))
            r.headers.forEach { (k, v) -> append(k).append(": ").append(v).append("\r\n") }
            append("Accept-Encoding: identity\r\nConnection: close\r\n")
            if (body != null) append("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.size}\r\n")
            append("\r\n")
        }.encodeToByteArray()
        val bytes = if (body == null) head else head + body
        if (bytes.size > profile.limits.maxSent) throw ProtocolException("invalid_input", "請求超過 ${profile.limits.maxSent} 位元組")
        return bytes
    }

    /** "Host: name[:port]" with its line end, as the planner writes it and the verifier expects it. */
    fun hostLine(profile: ZkTlsProfile): String = "Host: " + profile.host + (if (profile.port == 443) "" else ":${profile.port}") + "\r\n"

    /**
     * The revealed parts of the request, exactly what the engine permits: method, path and the character after it
     * ('?' or the space before the version), and the Host line with its line end.
     */
    fun sentReveal(profile: ZkTlsProfile, request: ByteArray): List<ZkTlsRange> {
        val prefix = "${profile.request.method} ${profile.request.path}"
        val text = request.decodeToString()
        if (!text.startsWith(prefix) || text.length <= prefix.length) throw ProtocolException("invalid_input", "The request does not follow the profile")
        val host = "\r\n" + hostLine(profile)
        val at = text.indexOf(host)
        if (at < 0) throw ProtocolException("invalid_input", "The request has no Host line")
        // The request line and headers are ASCII, so character and byte offsets agree.
        return listOf(ZkTlsRange(0, prefix.length + 1), ZkTlsRange(at + 2, at + host.length))
    }

    /** What the holder will reveal of the response, and which requested fields the page does not have. */
    data class Plan(val received: List<ZkTlsRange>, val status: ZkTlsRange?, val fields: Map<String, ZkTlsRange>, val missing: List<String>)

    /**
     * Rules are matched on the response with its chunk framing taken out (ChunkedBody), so a value the server's
     * chunking happens to split still matches; its revealed range then includes the chunk-size line in between.
     */
    fun receivedReveal(profile: ZkTlsProfile, fields: List<String>, received: ByteArray): Plan {
        val body = ChunkedBody.of(received)
        val text = Utf8Text(body.bytes)
        fun find(rule: String): ZkTlsRange? {
            val regex = Regex(rule)
            val m = regex.find(text.string) ?: return null
            val range = text.byteRange(m.range.first, m.range.last + 1).takeIf { it.end > it.start }?.let(body::raw) ?: return null
            // Only a range the verifier reads back the same way is worth revealing.
            val seen = Utf8Text(ChunkedBody.strip(received.copyOfRange(range.start, range.end))).string
            return range.takeIf { regex.find(seen)?.value == m.value }
        }
        val status = find(profile.status.reveal)
        val found = linkedMapOf<String, ZkTlsRange>()
        val missing = mutableListOf<String>()
        for (name in fields) {
            val field = profile.field(name) ?: throw ProtocolException("invalid_request", "Unknown field $name")
            find(field.reveal)?.let { found[name] = it } ?: missing.add(name)
        }
        return Plan(merge(listOfNotNull(status) + found.values), status, found, missing)
    }

    /** Sorted ranges with overlaps joined, as the engine expects. */
    fun merge(ranges: List<ZkTlsRange>): List<ZkTlsRange> {
        val out = mutableListOf<ZkTlsRange>()
        for (r in ranges.sortedBy { it.start }) {
            val last = out.lastOrNull()
            if (last != null && r.start <= last.end) out[out.size - 1] = ZkTlsRange(last.start, maxOf(last.end, r.end)) else out.add(r)
        }
        return out
    }
}

/** What the verifier saw: the server, the time, and the transcript with only the revealed bytes (others zero). */
data class ZkTlsSeen(
    val serverName: String,
    val certChainDer: List<ByteArray>,
    val time: Long,
    val sent: ByteArray,
    val received: ByteArray,
    val sentMask: List<ZkTlsRange>,
    val receivedMask: List<ZkTlsRange>,
)

/** The verifier's reading of a session: the values read back with the profile's rules, and what did not hold. */
data class ZkTlsOutcome(
    val profile: ZkTlsProfile,
    val serverName: String,
    val time: Long,
    /** The status segment as revealed, and whether it matches the profile's success rule. */
    val statusText: String?,
    val found: Boolean,
    val fields: Map<String, String>,
    val missing: List<String>,
    val problems: List<String>,
) {
    /** The server and request are the profile's, the status says found, and every requested field was read. */
    val passed: Boolean get() = problems.isEmpty() && found && missing.isEmpty()

    /** The verdict as a verifier server reports it (values are what the holder chose to reveal). */
    fun toJson(): JsonObject = buildJsonObject {
        put("profile", profile.id)
        put("serverName", serverName)
        put("time", time)
        statusText?.let { put("status", it) }
        put("found", found)
        putJsonObject("fields") { fields.forEach { (k, v) -> put(k, v) } }
        putJsonArray("missing") { missing.forEach { add(it) } }
        putJsonArray("problems") { problems.forEach { add(it) } }
        put("passed", passed)
    }

    companion object {
        fun fromJson(o: JsonObject, profile: ZkTlsProfile): ZkTlsOutcome {
            if (o.str("profile") != profile.id) throw ProtocolException("invalid_response", "The verdict is for another verification page")
            return ZkTlsOutcome(
                profile,
                o.str("serverName") ?: throw ProtocolException("invalid_response", "No server name"),
                (o["time"] as? JsonPrimitive)?.content?.toLongOrNull() ?: 0,
                o.str("status"),
                (o["found"] as? JsonPrimitive)?.content == "true",
                (o["fields"] as? JsonObject)?.mapNotNull { (k, v) -> (v as? JsonPrimitive)?.content?.let { k to it } }?.toMap().orEmpty(),
                o.strList("missing"),
                o.strList("problems"),
            )
        }
    }
}

/**
 * Checks a verified transcript against the request and profile: the server is the profile's host, the revealed request
 * line and Host line are the profile's, and the rules are applied within each revealed response segment. Values are
 * read only from revealed segments, so hidden bytes (zeros) never become part of a value. The holder chooses where a
 * segment ends, so a rule must close on a delimiter after its value (a tag, a line end): a rule that could match a
 * cut-short value would accept one. Chunk-size lines inside a segment are taken out first (ChunkedBody.strip).
 */
object ZkTlsCheck {
    fun check(request: ZkTlsSessionRequest, profile: ZkTlsProfile, seen: ZkTlsSeen): ZkTlsOutcome {
        val problems = mutableListOf<String>()
        if (!seen.serverName.equals(profile.host, ignoreCase = true)) problems += "連線的網站是 ${seen.serverName}，不是 ${profile.host}"
        val sentParts = seen.sentMask.map { seen.sent.copyOfRange(it.start, it.end).decodeToString() to it }
        val line = "${profile.request.method} ${profile.request.path}"
        val first = sentParts.firstOrNull { it.second.start == 0 }?.first
        if (first == null || first.length != line.length + 1 || !first.startsWith(line) || first.last() !in setOf('?', ' ')) {
            problems += "請求的網址不是查驗頁描述檔指定的頁面"
        }
        if (sentParts.none { it.first == ZkTlsPlanner.hostLine(profile) }) problems += "請求沒有揭露指定網站的 Host 標頭"
        val segments = seen.receivedMask.map { Utf8Text(ChunkedBody.strip(seen.received.copyOfRange(it.start, it.end))).string }
        val statusText = segments.firstNotNullOfOrNull { Regex(profile.status.reveal).find(it)?.value }
        val found = statusText != null && Regex(profile.status.success).containsMatchIn(statusText)
        val fields = linkedMapOf<String, String>()
        val missing = mutableListOf<String>()
        for (name in request.fields) {
            val rule = profile.field(name)?.let { Regex(it.reveal) }
            val value = rule?.let { r -> segments.firstNotNullOfOrNull { s -> r.find(s)?.groupValues?.getOrNull(1) } }
            if (value != null) fields[name] = value.trim() else missing += name
        }
        if (statusText == null) problems += "回應沒有揭露查詢狀態"
        return ZkTlsOutcome(profile, seen.serverName, seen.time, statusText, found, fields, missing, problems)
    }
}

/**
 * The chunk framing of an HTTP/1.1 response (RFC 9112 section 7.1). Pages that need no Content-Length up front are
 * sent in chunks, and a chunk may end in the middle of a value, even inside a character.
 *
 * The holder matches rules on the response without the framing ([of]) and maps each match back to transcript bytes
 * ([raw]); a match that crosses a chunk boundary then reveals the framing in between: the CRLF that ends a chunk's
 * data and the next chunk-size line. The verifier takes those out of each revealed segment ([strip]). A server line
 * of only hex digits inside a revealed segment would be taken out too; it is the server's own text either way, so a
 * holder cannot make a value from bytes the server did not send.
 */
internal class ChunkedBody private constructor(val bytes: ByteArray, private val positions: IntArray?) {
    /** The transcript bytes of a range of [bytes], including any framing between its first and last byte. */
    fun raw(r: ZkTlsRange): ZkTlsRange = if (positions == null) r else ZkTlsRange(positions[r.start], positions[r.end - 1] + 1)

    companion object {
        private const val CR = '\r'.code.toByte()
        private const val LF = '\n'.code.toByte()
        private const val MAX_SIZE_DIGITS = 8

        /** [received] without its chunk framing when the response is chunked, else as it is. */
        fun of(received: ByteArray): ChunkedBody {
            val headEnd = indexOf(received, byteArrayOf(CR, LF, CR, LF), 0)
            if (headEnd < 0) return ChunkedBody(received, null)
            val chunked = received.decodeToString(0, headEnd).split("\r\n").drop(1).any { line ->
                line.substringBefore(':').trim().equals("Transfer-Encoding", ignoreCase = true) &&
                    line.substringAfter(':').split(',').any { it.trim().equals("chunked", ignoreCase = true) }
            }
            if (!chunked) return ChunkedBody(received, null)
            val out = ByteArray(received.size)
            val positions = IntArray(received.size)
            var n = 0
            fun copy(from: Int, to: Int) {
                for (i in from until to) { out[n] = received[i]; positions[n] = i; n++ }
            }
            var i = headEnd + 4
            copy(0, i)
            while (i < received.size) {
                val lineEnd = indexOf(received, byteArrayOf(CR, LF), i)
                val size = if (lineEnd < 0) null else chunkSize(received, i, lineEnd)
                if (size == null) {
                    // Not framing as expected (a cut-off transcript): the rest is matched as it is.
                    copy(i, received.size)
                    break
                }
                if (size == 0L) break
                val start = lineEnd + 2
                val end = minOf(received.size.toLong(), start + size).toInt()
                copy(start, end)
                i = end
                if (i + 2 <= received.size && received[i] == CR && received[i + 1] == LF) i += 2 else break
            }
            return ChunkedBody(out.copyOf(n), positions.copyOf(n))
        }

        /** [segment] without the chunk boundaries it contains: CRLF, a chunk-size line, CRLF. */
        fun strip(segment: ByteArray): ByteArray {
            val out = ArrayList<Byte>(segment.size)
            var i = 0
            while (i < segment.size) {
                if (segment[i] == CR && i + 1 < segment.size && segment[i + 1] == LF) {
                    val lineEnd = indexOf(segment, byteArrayOf(CR, LF), i + 2)
                    if (lineEnd > i + 2 && chunkSize(segment, i + 2, lineEnd) != null) {
                        i = lineEnd + 2
                        continue
                    }
                }
                out.add(segment[i])
                i++
            }
            return out.toByteArray()
        }

        /** The size of a chunk-size line [from, to) (hex digits, optionally followed by extensions), or null. */
        private fun chunkSize(bytes: ByteArray, from: Int, to: Int): Long? {
            var size = 0L
            var digits = 0
            var i = from
            while (i < to) {
                val d = Char(bytes[i].toInt() and 0xff).digitToIntOrNull(16) ?: break
                if (++digits > MAX_SIZE_DIGITS) return null
                size = size * 16 + d
                i++
            }
            if (digits == 0) return null
            while (i < to && (bytes[i] == ' '.code.toByte() || bytes[i] == '\t'.code.toByte())) i++
            if (i < to && bytes[i] != ';'.code.toByte()) return null
            for (k in i until to) if (bytes[k] == CR || bytes[k] == LF) return null
            return size
        }

        private fun indexOf(bytes: ByteArray, pattern: ByteArray, from: Int): Int {
            var i = from
            while (i <= bytes.size - pattern.size) {
                var k = 0
                while (k < pattern.size && bytes[i + k] == pattern[k]) k++
                if (k == pattern.size) return i
                i++
            }
            return -1
        }
    }
}

/**
 * UTF-8 text with byte offsets: each malformed byte becomes one U+FFFD, so a character offset always maps back to the
 * byte where it starts (the platform decoders may fold several bad bytes into one replacement).
 */
internal class Utf8Text(private val bytes: ByteArray) {
    val string: String
    private val starts: IntArray

    init {
        val sb = StringBuilder(bytes.size)
        val offsets = ArrayList<Int>(bytes.size + 1)
        var i = 0
        while (i < bytes.size) {
            val b = bytes[i].toInt() and 0xff
            val n = when {
                b < 0x80 -> 1
                b in 0xc2..0xdf -> 2
                b in 0xe0..0xef -> 3
                b in 0xf0..0xf4 -> 4
                else -> 0
            }
            val ok = n > 0 && i + n <= bytes.size && (1 until n).all { (bytes[i + it].toInt() and 0xc0) == 0x80 }
            if (!ok) {
                offsets.add(i); sb.append('�'); i++
                continue
            }
            var cp = if (n == 1) b else b and (0xff shr (n + 1))
            for (k in 1 until n) cp = (cp shl 6) or (bytes[i + k].toInt() and 0x3f)
            val overlong = (n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000)
            if (overlong || cp > 0x10ffff || cp in 0xd800..0xdfff) {
                offsets.add(i); sb.append('�'); i++
                continue
            }
            if (cp >= 0x10000) {
                val v = cp - 0x10000
                sb.append((0xd800 + (v shr 10)).toChar()); offsets.add(i)
                sb.append((0xdc00 + (v and 0x3ff)).toChar()); offsets.add(i)
            } else {
                sb.append(cp.toChar()); offsets.add(i)
            }
            i += n
        }
        offsets.add(bytes.size)
        string = sb.toString()
        starts = offsets.toIntArray()
    }

    /** Bytes of characters [from, to). A range ending inside a surrogate pair ends after the whole character. */
    fun byteRange(from: Int, to: Int): ZkTlsRange {
        var end = to
        while (end < string.length && starts[end] == starts[end - 1]) end++
        return ZkTlsRange(starts[from], starts[end])
    }
}
