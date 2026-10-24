package diw.wallet.core.profile.bonds

import diw.wallet.core.jose.PlatformCrypto

/**
 * Animated QR for payloads far beyond BTWVP1's 64 KB, such as an age proof package (about 160 KB deflated), when
 * neither Bluetooth nor a shared network is available. This wallet's own format; Bonds has no equivalent.
 *
 * The (deflated) payload is cut into [BLOCK_BYTES] blocks. Seeds below the block count show one block each; every
 * later seed shows the XOR of a pseudo-random half of the blocks, so a scanner that misses frames needs only a few
 * more frames than there are blocks, in any order (a random linear fountain code over GF(2)). Frame text, all in QR
 * alphanumeric mode: DIWQ1:<Z|U>:<id 8 hex>:<blocks>:<length>:<seed>:<base45 block>. The id is the first four bytes
 * of SHA-256 of the payload, checked after reassembly; it also seeds the combinations.
 */
object AnimatedQrTransport {
    const val TAG = "DIWQ1"
    const val BLOCK_BYTES = 520
    const val MAX_BLOCKS = 4096
    const val MAX_PAYLOAD = 6_000_000

    fun isFrame(scanned: String): Boolean = scanned.startsWith("$TAG:")

    /** The frames of one payload; [frame] can be asked for any seed, the display simply counts up. */
    class Encoder(payload: ByteArray) {
        val id: String
        private val deflated: Boolean
        val length: Int
        val blocks: List<ByteArray>

        init {
            if (payload.isEmpty()) throw BondsTransportException("Empty payload")
            if (payload.size > MAX_PAYLOAD) throw BondsTransportException("Payload over $MAX_PAYLOAD bytes")
            id = identifier(payload)
            val packed = BondsDeflate.deflateIfSmaller(payload)
            deflated = packed != null
            val body = packed ?: payload
            length = body.size
            blocks = (body.indices step BLOCK_BYTES).map { body.copyOfRange(it, minOf(it + BLOCK_BYTES, body.size)).copyOf(BLOCK_BYTES) }
            if (blocks.size > MAX_BLOCKS) throw BondsTransportException("Payload needs more than $MAX_BLOCKS blocks")
        }

        val count: Int get() = blocks.size

        fun frame(seed: Int): String {
            require(seed >= 0)
            val data = ByteArray(BLOCK_BYTES)
            val mask = mask(id, seed, count)
            for (i in 0 until count) if (mask.has(i)) xorInto(data, blocks[i])
            return listOf(TAG, if (deflated) "Z" else "U", id, count.toString(), length.toString(), seed.toString(), Base45.encode(data))
                .joinToString(":")
        }
    }

    internal fun identifier(payload: ByteArray): String =
        PlatformCrypto.sha256(payload).copyOfRange(0, 4).joinToString("") { (it.toInt() and 0xff).toString(16).uppercase().padStart(2, '0') }

    /** Which blocks a seed combines: one for a seed below [count], else each with probability one half (never none). */
    internal fun mask(id: String, seed: Int, count: Int): LongArray {
        val bits = LongArray((count + 63) / 64)
        if (seed < count) {
            bits[seed / 64] = 1L shl (seed % 64)
            return bits
        }
        // SplitMix64 over the transfer id and the seed, so both ends derive the same subset; it mixes well even for
        // consecutive seeds, which a plain xorshift does not.
        var x = (id.toLong(16) shl 32) or seed.toLong()
        for (w in bits.indices) {
            x += -0x61c8864680b583ebL
            var z = x
            z = (z xor (z ushr 30)) * -0x40a7b892e31b1a47L
            z = (z xor (z ushr 27)) * -0x6b2fb644ecceee15L
            bits[w] = z xor (z ushr 31)
        }
        val tail = count % 64
        if (tail != 0) bits[bits.lastIndex] = bits.last() and ((1L shl tail) - 1)
        if (bits.all { it == 0L }) bits[(seed % count) / 64] = 1L shl ((seed % count) % 64)
        return bits
    }

    internal fun LongArray.has(i: Int): Boolean = (this[i / 64] ushr (i % 64)) and 1L == 1L

    internal fun xorInto(target: ByteArray, source: ByteArray) {
        for (i in target.indices) target[i] = (target[i].toInt() xor source[i].toInt()).toByte()
    }

    internal class Frame(val deflated: Boolean, val id: String, val count: Int, val length: Int, val seed: Int, val data: ByteArray)

    internal fun parse(scanned: String): Frame {
        val f = scanned.split(":", limit = 7)
        if (f.size != 7 || f[0] != TAG) throw BondsTransportException("Not a $TAG frame")
        val deflated = when (f[1]) { "Z" -> true; "U" -> false; else -> throw BondsTransportException("Unknown frame flag") }
        val id = f[2].takeIf { it.length == 8 && it.all { c -> c in '0'..'9' || c in 'A'..'F' } } ?: throw BondsTransportException("Malformed id")
        val count = f[3].toIntOrNull()?.takeIf { it in 1..MAX_BLOCKS } ?: throw BondsTransportException("Malformed block count")
        val length = f[4].toIntOrNull()?.takeIf { it in (count - 1) * BLOCK_BYTES + 1..count * BLOCK_BYTES } ?: throw BondsTransportException("Malformed length")
        val seed = f[5].toIntOrNull()?.takeIf { it >= 0 } ?: throw BondsTransportException("Malformed seed")
        val data = Base45.decode(f[6]).takeIf { it.size == BLOCK_BYTES } ?: throw BondsTransportException("Malformed block")
        return Frame(deflated, id, count, length, seed, data)
    }
}

/**
 * Collects [AnimatedQrTransport] frames by Gaussian elimination over GF(2): each frame that is not a combination of
 * those already held raises the rank, and the payload is solved once the rank reaches the block count. A frame from
 * another transfer starts over, since a holder showing a new proof replaces the old one.
 */
class AnimatedQrCollector(private val maxPayload: Int = AnimatedQrTransport.MAX_PAYLOAD) {
    private class Row(val mask: LongArray, val data: ByteArray)

    private var id: String? = null
    private var count = 0
    private var length = 0
    private var deflated = false
    private var pivots = arrayOfNulls<Row>(0)
    private var rank = 0

    fun reset() {
        id = null; count = 0; length = 0; deflated = false; pivots = arrayOfNulls(0); rank = 0
    }

    fun accept(scanned: String): BondsReception {
        val f = AnimatedQrTransport.parse(scanned)
        if (id != f.id || count != f.count || length != f.length || deflated != f.deflated) {
            reset()
            id = f.id; count = f.count; length = f.length; deflated = f.deflated
            pivots = arrayOfNulls(f.count)
        }
        val mask = AnimatedQrTransport.mask(f.id, f.seed, f.count)
        val data = f.data
        // Reduce by the pivots until the lowest set bit has none, then the row becomes that pivot.
        while (true) {
            val lead = lowest(mask) ?: return BondsReception.Duplicate(rank, count)
            val pivot = pivots[lead]
            if (pivot == null) {
                pivots[lead] = Row(mask, data)
                rank++
                break
            }
            for (w in mask.indices) mask[w] = mask[w] xor pivot.mask[w]
            AnimatedQrTransport.xorInto(data, pivot.data)
        }
        if (rank < count) return BondsReception.Accepted(rank, count)
        return try {
            BondsReception.Completed(solve())
        } catch (e: Exception) {
            reset()
            throw e as? BondsTransportException ?: BondsTransportException(e.message ?: "Reassembly failed")
        }
    }

    private fun lowest(mask: LongArray): Int? {
        for (w in mask.indices) if (mask[w] != 0L) return w * 64 + mask[w].countTrailingZeroBits()
        return null
    }

    private fun solve(): ByteArray {
        val rows = pivots.map { it!! }
        // Each pivot's lowest bit is its own index; clearing the higher bits from the top down leaves single blocks.
        for (i in count - 1 downTo 0) {
            val row = rows[i]
            for (j in i + 1 until count) {
                if ((row.mask[j / 64] ushr (j % 64)) and 1L == 1L) {
                    for (w in row.mask.indices) row.mask[w] = row.mask[w] xor rows[j].mask[w]
                    AnimatedQrTransport.xorInto(row.data, rows[j].data)
                }
            }
        }
        val body = ByteArray(length)
        for (i in 0 until count) rows[i].data.copyInto(body, i * AnimatedQrTransport.BLOCK_BYTES, 0, minOf(AnimatedQrTransport.BLOCK_BYTES, length - i * AnimatedQrTransport.BLOCK_BYTES))
        val payload = if (deflated) BondsDeflate.inflate(body, maxPayload) else body
        if (payload.size > maxPayload) throw BondsTransportException("Payload too large")
        if (AnimatedQrTransport.identifier(payload) != id) throw BondsTransportException("Reassembly digest mismatch")
        return payload
    }
}
