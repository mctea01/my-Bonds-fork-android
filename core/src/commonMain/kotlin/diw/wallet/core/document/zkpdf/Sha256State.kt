package diw.wallet.core.document.zkpdf

/** Immutable SHA-256 chaining state (FIPS 180-4, sections 5 and 6). */
class Sha256State private constructor(private val state: IntArray) {
    companion object {
        val INITIAL = Sha256State(intArrayOf(0x6a09e667, 0xbb67ae85.toInt(), 0x3c6ef372, 0xa54ff53a.toInt(),
            0x510e527f, 0x9b05688c.toInt(), 0x1f83d9ab, 0x5be0cd19))

        fun of(words: IntArray): Sha256State {
            require(words.size == 8) { "Invalid SHA-256 state size" }
            return Sha256State(words.copyOf())
        }

        private val K = longArrayOf(
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ).map { it.toInt() }.toIntArray()

        private fun rotr(value: Int, bits: Int) = (value ushr bits) or (value shl (32 - bits))
    }

    fun words(): IntArray = state.copyOf()
    fun toBytes(): ByteArray = ByteArray(32) { (state[it / 4] ushr (24 - 8 * (it % 4))).toByte() }

    fun compress(block: ByteArray): Sha256State {
        require(block.size == 64) { "Invalid SHA-256 block size" }
        val w = IntArray(64)
        for (i in 0..15) for (j in 0..3) w[i] = (w[i] shl 8) or (block[4 * i + j].toInt() and 255)
        for (i in 16..63) {
            val x = w[i - 15]
            val y = w[i - 2]
            w[i] = w[i - 16] + (rotr(x, 7) xor rotr(x, 18) xor (x ushr 3)) + w[i - 7] +
                (rotr(y, 17) xor rotr(y, 19) xor (y ushr 10))
        }
        var a = state[0]; var b = state[1]; var c = state[2]; var d = state[3]
        var e = state[4]; var f = state[5]; var g = state[6]; var h = state[7]
        for (i in 0..63) {
            val t1 = h + (rotr(e, 6) xor rotr(e, 11) xor rotr(e, 25)) + ((e and f) xor (e.inv() and g)) + K[i] + w[i]
            val t2 = (rotr(a, 2) xor rotr(a, 13) xor rotr(a, 22)) + ((a and b) xor (a and c) xor (b and c))
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2
        }
        return Sha256State(intArrayOf(state[0] + a, state[1] + b, state[2] + c, state[3] + d,
            state[4] + e, state[5] + f, state[6] + g, state[7] + h))
    }

    override fun equals(other: Any?): Boolean = other is Sha256State && state.contentEquals(other.state)
    override fun hashCode(): Int = state.contentHashCode()
}

/** An immutable, padded message. Block access always returns a defensive copy. */
class Sha256Message internal constructor(private val padded: ByteArray, val messageBytes: Int) {
    val blockCount: Int get() = padded.size / 64
    fun block(index: Int): ByteArray {
        require(index in 0 until blockCount) { "Invalid SHA-256 block index" }
        return padded.copyOfRange(index * 64, (index + 1) * 64)
    }
}

data class HashWindow(val firstBlock: Int, val blocks: Int, val midIn: Sha256State, val midOut: Sha256State)

object Sha256Chain {
    /** The two ByteRange parts, followed by SHA-256's length-dependent padding. */
    fun message(pdf: ByteArray, byteRange: IntArray): Sha256Message {
        byteRangeEnd(pdf.size, byteRange)
        val length = byteRange[1].toLong() + byteRange[3]
        val paddedSize = ((length + 9 + 63) / 64) * 64
        require(paddedSize <= Int.MAX_VALUE) { "SHA-256 message is too large" }
        val padded = ByteArray(paddedSize.toInt())
        pdf.copyInto(padded, 0, 0, byteRange[1])
        pdf.copyInto(padded, byteRange[1], byteRange[2], byteRange[2] + byteRange[3])
        padded[length.toInt()] = 0x80.toByte()
        val bits = length * 8
        for (i in 0..7) padded[padded.size - 1 - i] = (bits ushr (i * 8)).toByte()
        return Sha256Message(padded, length.toInt())
    }

    fun stateAt(message: Sha256Message, block: Int): Sha256State {
        require(block in 0..message.blockCount) { "Invalid SHA-256 boundary" }
        var state = Sha256State.INITIAL
        for (i in 0 until block) state = state.compress(message.block(i))
        return state
    }

    /** Uses proven outgoing states without reading the skipped blocks. Proof verification is the caller's job. */
    fun digestWithWindows(message: Sha256Message, windows: List<HashWindow>): ByteArray {
        val ordered = windows.sortedBy { it.firstBlock }
        var end = 0
        for (window in ordered) {
            require(window.firstBlock >= end && window.blocks > 0 &&
                window.firstBlock.toLong() + window.blocks <= message.messageBytes / 64) { "Invalid SHA-256 window" }
            end = window.firstBlock + window.blocks
        }
        var state = Sha256State.INITIAL
        var position = 0
        for (window in ordered) {
            while (position < window.firstBlock) state = state.compress(message.block(position++))
            require(state == window.midIn) { "SHA-256 window input mismatch" }
            state = window.midOut
            position += window.blocks
        }
        while (position < message.blockCount) state = state.compress(message.block(position++))
        return state.toBytes()
    }
}

/** Overflow-safe validation shared by PDF revision selection and hashing. */
internal fun byteRangeEnd(size: Int, range: IntArray): Int {
    require(range.size == 4 && range[0] == 0 && range.all { it >= 0 }) { "Invalid PDF ByteRange" }
    val end = range[2].toLong() + range[3]
    require(range[1] <= range[2] && end <= size) { "Invalid PDF ByteRange" }
    return end.toInt()
}
