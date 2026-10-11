package diw.wallet.core.profile.bonds

import diw.wallet.core.jose.PlatformCrypto

/** Raised for any frame or reassembly that does not follow the Bonds transport formats. */
class BondsTransportException(message: String) : Exception(message)

/** RFC 9285 Base45, as used in the BTWVP1 frames (QR alphanumeric mode). */
object Base45 {
    private const val ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

    fun encode(data: ByteArray): String {
        val sb = StringBuilder((data.size + 1) / 2 * 3)
        var i = 0
        while (i + 1 < data.size) {
            val v = ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)
            sb.append(ALPHABET[v % 45]).append(ALPHABET[(v / 45) % 45]).append(ALPHABET[v / 2025])
            i += 2
        }
        if (i < data.size) {
            val v = data[i].toInt() and 0xff
            sb.append(ALPHABET[v % 45]).append(ALPHABET[v / 45])
        }
        return sb.toString()
    }

    fun decode(text: String): ByteArray {
        val symbols = IntArray(text.length) { idx ->
            val c = text[idx]
            val v = ALPHABET.indexOf(c)
            if (c.code > 127 || v < 0) throw BondsTransportException("Invalid Base45 character")
            v
        }
        if (symbols.size % 3 == 1) throw BondsTransportException("Invalid Base45 length")
        val out = ArrayList<Byte>(symbols.size / 3 * 2 + 1)
        var i = 0
        while (i + 2 < symbols.size) {
            val v = symbols[i] + symbols[i + 1] * 45 + symbols[i + 2] * 2025
            if (v > 0xffff) throw BondsTransportException("Invalid Base45 triple")
            out.add((v shr 8).toByte()); out.add((v and 0xff).toByte())
            i += 3
        }
        if (i < symbols.size) {
            val v = symbols[i] + symbols[i + 1] * 45
            if (v > 0xff) throw BondsTransportException("Invalid Base45 pair")
            out.add(v.toByte())
        }
        return out.toByteArray()
    }
}

/** Compression shared by both transports: raw DEFLATE (RFC 1951), used only when it makes the payload smaller. */
internal object BondsDeflate {
    fun deflateIfSmaller(payload: ByteArray): ByteArray? =
        runCatching { PlatformCrypto.deflate(payload, raw = true) }.getOrNull()?.takeIf { it.isNotEmpty() && it.size < payload.size }

    fun inflate(body: ByteArray, limit: Int): ByteArray {
        val out = try {
            PlatformCrypto.inflate(body, raw = true, maxBytes = limit + 1)
        } catch (e: Exception) {
            throw BondsTransportException("Decompression failed")
        }
        if (out.isEmpty()) throw BondsTransportException("Decompression failed")
        if (out.size > limit) throw BondsTransportException("Payload too large")
        return out
    }
}

/**
 * Bonds chunked QR transport (BTWVP1): frames of the form BTWVP1:<Z|U>:<10 hex id>:<NN index>:<NN count>:<base45 chunk>,
 * Z meaning raw DEFLATE. The id is the first five bytes of SHA-256 of the uncompressed payload, checked after
 * reassembly. A frame is at most 574 characters (364 payload bytes), at most 99 frames, 64 KB in total.
 */
object BondsQrTransport {
    const val TAG = "BTWVP1"
    private const val ID_LENGTH = 10
    private const val COUNTER_DIGITS = 2
    const val HEADER_LENGTH = 6 + 1 + 1 + 1 + ID_LENGTH + 1 + COUNTER_DIGITS + 1 + COUNTER_DIGITS + 1
    const val FRAME_CHARACTER_BUDGET = 574
    const val CHUNK_BYTES = ((FRAME_CHARACTER_BUDGET - HEADER_LENGTH) / 3) * 2
    const val MAX_FRAMES = 99
    const val MAX_PAYLOAD = 64 * 1024
    private const val MAX_CHUNK_TEXT = 4296
    /** QR error correction level the frames are drawn with. */
    const val ERROR_CORRECTION = "Q"

    fun isFrame(scanned: String): Boolean = scanned.startsWith("BTWVP")

    fun frames(payload: ByteArray): List<String> {
        if (payload.isEmpty()) throw BondsTransportException("Empty payload")
        if (payload.size > MAX_PAYLOAD) throw BondsTransportException("Payload over $MAX_PAYLOAD bytes")
        val id = identifier(payload)
        val deflated = BondsDeflate.deflateIfSmaller(payload)
        val body = deflated ?: payload
        val flag = if (deflated == null) "U" else "Z"
        val chunks = (body.indices step CHUNK_BYTES).map { body.copyOfRange(it, minOf(it + CHUNK_BYTES, body.size)) }
        if (chunks.size > MAX_FRAMES) throw BondsTransportException("Payload needs more than $MAX_FRAMES frames")
        return chunks.mapIndexed { i, chunk ->
            listOf(TAG, flag, id, i.toString().padStart(2, '0'), chunks.size.toString().padStart(2, '0'), Base45.encode(chunk)).joinToString(":")
        }
    }

    internal fun identifier(payload: ByteArray): String =
        PlatformCrypto.sha256(payload).copyOfRange(0, ID_LENGTH / 2).joinToString("") { (it.toInt() and 0xff).toString(16).uppercase().padStart(2, '0') }

    internal class Frame(val id: String, val deflated: Boolean, val index: Int, val count: Int, val chunk: ByteArray)

    internal fun parse(scanned: String): Frame {
        if (!isFrame(scanned)) throw BondsTransportException("Not a BTWVP frame")
        val fields = scanned.split(":", limit = 6)
        if (fields.first() != TAG) throw BondsTransportException("Unsupported frame format ${fields.first()}")
        if (fields.size != 6) throw BondsTransportException("Malformed frame")
        val flag = fields[1]
        if (flag != "Z" && flag != "U") throw BondsTransportException("Malformed frame flag")
        val id = fields[2]
        if (id.length != ID_LENGTH || id.any { it !in "0123456789ABCDEF" }) throw BondsTransportException("Malformed frame id")
        if (fields[3].length != COUNTER_DIGITS || fields[4].length != COUNTER_DIGITS) throw BondsTransportException("Malformed counters")
        val index = fields[3].toIntOrNull() ?: throw BondsTransportException("Malformed index")
        val count = fields[4].toIntOrNull() ?: throw BondsTransportException("Malformed count")
        if (count !in 1..MAX_FRAMES || index !in 0 until count) throw BondsTransportException("Malformed counters")
        if (fields[5].length > MAX_CHUNK_TEXT) throw BondsTransportException("Oversized chunk")
        return Frame(id, flag == "Z", index, count, Base45.decode(fields[5]))
    }
}

/** Reassembly progress shared by both collectors. */
sealed interface BondsReception {
    data class Accepted(val received: Int, val total: Int) : BondsReception
    data class Duplicate(val received: Int, val total: Int) : BondsReception
    class Completed(val payload: ByteArray) : BondsReception
}

/** Collects BTWVP1 frames scanned in any order; a failed reassembly resets the collector. */
class BondsFrameCollector {
    private var id: String? = null
    private var deflated = false
    private var total = 0
    private val chunks = mutableMapOf<Int, ByteArray>()
    private var completed: ByteArray? = null

    val progress: Pair<Int, Int>? get() = id?.let { chunks.size to total }

    fun reset() {
        id = null; deflated = false; total = 0; chunks.clear(); completed = null
    }

    fun accept(scanned: String): BondsReception {
        val frame = BondsQrTransport.parse(scanned)
        val current = id
        if (current != null) {
            if (frame.id != current) throw BondsTransportException("Frame from another presentation")
            if (frame.count != total || frame.deflated != deflated) throw BondsTransportException("Inconsistent frame header")
        } else {
            id = frame.id; deflated = frame.deflated; total = frame.count
        }
        completed?.let { return BondsReception.Completed(it) }
        chunks[frame.index]?.let { held ->
            if (!held.contentEquals(frame.chunk)) throw BondsTransportException("Frame from another presentation")
            return BondsReception.Duplicate(chunks.size, total)
        }
        if (chunks.values.sumOf { it.size } + frame.chunk.size > BondsQrTransport.MAX_PAYLOAD) throw BondsTransportException("Payload too large")
        chunks[frame.index] = frame.chunk
        if (chunks.size < total) return BondsReception.Accepted(chunks.size, total)
        return try {
            val body = (0 until total).fold(ByteArray(0)) { acc, i -> acc + (chunks[i] ?: throw BondsTransportException("Missing frame")) }
            val payload = if (deflated) BondsDeflate.inflate(body, BondsQrTransport.MAX_PAYLOAD) else body
            if (payload.size > BondsQrTransport.MAX_PAYLOAD) throw BondsTransportException("Payload too large")
            if (BondsQrTransport.identifier(payload) != id) throw BondsTransportException("Payload digest mismatch")
            completed = payload
            BondsReception.Completed(payload)
        } catch (e: Exception) {
            reset()
            throw e as? BondsTransportException ?: BondsTransportException(e.message ?: "Reassembly failed")
        }
    }
}

/**
 * Bonds BLE link framing: a 10 byte header (version 1, flags bit0 = raw DEFLATE, total and index as big-endian
 * 16-bit, 4 byte transfer id = SHA-256 of the uncompressed payload) followed by a chunk sized to the negotiated MTU.
 * The holder is the GATT peripheral advertising the request's one-time service UUID; frames are notified on
 * [FRAMES_CHARACTERISTIC] and the verifier writes [RECEIVED] to [STATE_CHARACTERISTIC]. No session encryption:
 * authenticity comes from the signed presentation and the verifier's challenge.
 */
object BondsLinkTransport {
    const val VERSION: Byte = 1
    const val HEADER_BYTES = 10
    private const val DEFLATED: Int = 0x01
    const val MAX_PAYLOAD = 1024 * 1024
    const val MAX_CHUNKS = 4096
    const val FRAMES_CHARACTERISTIC = "2B1D0001-6B4E-4C3A-9E2F-4A7C51E0D9A1"
    const val STATE_CHARACTERISTIC = "2B1D0002-6B4E-4C3A-9E2F-4A7C51E0D9A1"
    const val RECEIVED: Byte = 0x01

    fun frames(payload: ByteArray, maxFrameBytes: Int): List<ByteArray> {
        if (payload.isEmpty()) throw BondsTransportException("Empty payload")
        if (payload.size > MAX_PAYLOAD) throw BondsTransportException("Payload over $MAX_PAYLOAD bytes")
        val budget = maxFrameBytes - HEADER_BYTES
        if (budget <= 0) throw BondsTransportException("Frame size too small")
        val id = identifier(payload)
        val deflated = BondsDeflate.deflateIfSmaller(payload)
        val body = deflated ?: payload
        val flags = if (deflated == null) 0 else DEFLATED
        val chunks = (body.indices step budget).map { body.copyOfRange(it, minOf(it + budget, body.size)) }
        if (chunks.size > MAX_CHUNKS) throw BondsTransportException("Payload needs more than $MAX_CHUNKS frames")
        return chunks.mapIndexed { i, chunk ->
            byteArrayOf(
                VERSION, flags.toByte(),
                (chunks.size shr 8).toByte(), (chunks.size and 0xff).toByte(),
                (i shr 8).toByte(), (i and 0xff).toByte(),
            ) + id + chunk
        }
    }

    fun identifier(payload: ByteArray): ByteArray = PlatformCrypto.sha256(payload).copyOfRange(0, 4)

    internal class Header(val flags: Int, val total: Int, val index: Int, val id: ByteArray) {
        val deflated: Boolean get() = flags and DEFLATED != 0
    }

    internal fun parse(frame: ByteArray): Pair<Header, ByteArray> {
        if (frame.size <= HEADER_BYTES) throw BondsTransportException("Frame too short")
        if (frame[0] != VERSION) throw BondsTransportException("Unsupported link version ${frame[0]}")
        val flags = frame[1].toInt() and 0xff
        if (flags and DEFLATED.inv() != 0) throw BondsTransportException("Unknown link flags")
        val total = ((frame[2].toInt() and 0xff) shl 8) or (frame[3].toInt() and 0xff)
        val index = ((frame[4].toInt() and 0xff) shl 8) or (frame[5].toInt() and 0xff)
        if (total == 0) throw BondsTransportException("Empty transfer")
        if (total > MAX_CHUNKS) throw BondsTransportException("Too many chunks")
        if (index >= total) throw BondsTransportException("Index out of range")
        return Header(flags, total, index, frame.copyOfRange(6, 10)) to frame.copyOfRange(HEADER_BYTES, frame.size)
    }
}

/** Collects link frames; verifies the transfer id after reassembly and resets on failure. */
class BondsLinkCollector {
    private var id: ByteArray? = null
    private var deflated = false
    private var total = 0
    private val chunks = mutableMapOf<Int, ByteArray>()
    private var held = 0

    fun reset() {
        id = null; deflated = false; total = 0; chunks.clear(); held = 0
    }

    fun accept(frame: ByteArray): BondsReception {
        val (header, body) = BondsLinkTransport.parse(frame)
        val current = id
        if (current != null) {
            if (!header.id.contentEquals(current)) throw BondsTransportException("Frame from another transfer")
            if (header.total != total || header.deflated != deflated) throw BondsTransportException("Inconsistent header")
        }
        if (held + body.size > BondsLinkTransport.MAX_PAYLOAD) throw BondsTransportException("Payload too large")
        if (current == null) {
            id = header.id; deflated = header.deflated; total = header.total
        }
        if (chunks.containsKey(header.index)) return BondsReception.Duplicate(chunks.size, total)
        chunks[header.index] = body
        held += body.size
        if (chunks.size < total) return BondsReception.Accepted(chunks.size, total)
        return try {
            val assembled = (0 until total).fold(ByteArray(0)) { acc, i -> acc + (chunks[i] ?: ByteArray(0)) }
            val payload = if (deflated) BondsDeflate.inflate(assembled, BondsLinkTransport.MAX_PAYLOAD) else assembled
            if (!BondsLinkTransport.identifier(payload).contentEquals(id)) throw BondsTransportException("Reassembly digest mismatch")
            BondsReception.Completed(payload)
        } catch (e: Exception) {
            reset()
            throw e as? BondsTransportException ?: BondsTransportException(e.message ?: "Reassembly failed")
        }
    }
}
