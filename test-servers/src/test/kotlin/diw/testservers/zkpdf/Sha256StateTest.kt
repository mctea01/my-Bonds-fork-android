package diw.testservers.zkpdf

import diw.wallet.core.document.zkpdf.*
import kotlinx.coroutines.runBlocking
import java.security.MessageDigest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Sha256StateTest {
    private fun message(bytes: ByteArray) = Sha256Chain.message(bytes, intArrayOf(0, bytes.size, bytes.size, 0))
    private fun digest(bytes: ByteArray): ByteArray = message(bytes).let { Sha256Chain.stateAt(it, it.blockCount).toBytes() }
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun nistVectors() = runBlocking<Unit> {
        val vectors = listOf(
            "" to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "abc" to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" to
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "a".repeat(1_000_000) to "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        )
        for ((input, expected) in vectors) assertContentEquals(hex(expected), digest(input.toByteArray()))
    }

    @Test fun randomMessagesAndByteRangesMatchJca() = runBlocking<Unit> {
        val random = Random(0x504446)
        val lengths = listOf(0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128) + List(150) { random.nextInt(8192) }
        for (length in lengths) {
            val bytes = random.nextBytes(length)
            assertContentEquals(MessageDigest.getInstance("SHA-256").digest(bytes), digest(bytes))
            val gapStart = random.nextInt(length + 1)
            val gapEnd = random.nextInt(gapStart, length + 1)
            val m = Sha256Chain.message(bytes, intArrayOf(0, gapStart, gapEnd, length - gapEnd))
            val expected = MessageDigest.getInstance("SHA-256").digest(bytes.copyOfRange(0, gapStart) + bytes.copyOfRange(gapEnd, length))
            assertContentEquals(expected, Sha256Chain.stateAt(m, m.blockCount).toBytes())
        }
    }

    @Test fun windowsReplacePrivateBlocksAndCheckBoundaries() = runBlocking<Unit> {
        val bytes = Random(7).nextBytes(1031)
        val original = message(bytes)
        val windows = listOf(1 to 3, 4 to 2, 9 to 6).map { (first, blocks) ->
            HashWindow(first, blocks, Sha256Chain.stateAt(original, first), Sha256Chain.stateAt(original, first + blocks))
        }
        for (w in windows) bytes.fill(0, w.firstBlock * 64, (w.firstBlock + w.blocks) * 64)
        val redacted = message(bytes)
        assertContentEquals(Sha256Chain.stateAt(original, original.blockCount).toBytes(),
            Sha256Chain.digestWithWindows(redacted, windows.reversed()))
        assertFailsWith<IllegalArgumentException> { Sha256Chain.digestWithWindows(original, listOf(windows[0], windows[0])) }
        assertFailsWith<IllegalArgumentException> { Sha256Chain.digestWithWindows(original, listOf(windows[0].copy(blocks = 0))) }
        assertFailsWith<IllegalArgumentException> { Sha256Chain.digestWithWindows(original, listOf(windows[0].copy(firstBlock = -1))) }
        assertFailsWith<IllegalArgumentException> { Sha256Chain.digestWithWindows(original, listOf(windows[0].copy(blocks = Int.MAX_VALUE))) }
        assertFailsWith<IllegalArgumentException> { Sha256Chain.digestWithWindows(original, listOf(windows[0].copy(midIn = Sha256State.INITIAL))) }
        assertFailsWith<IllegalArgumentException> { Sha256Chain.digestWithWindows(original,
            listOf(HashWindow(16, 1, Sha256Chain.stateAt(original, 16), Sha256State.INITIAL))) }
    }

    @Test fun defensiveCopiesAndInvalidInputs() = runBlocking<Unit> {
        val words = Sha256State.INITIAL.words()
        val state = Sha256State.of(words)
        words.fill(0)
        state.words().fill(0)
        state.toBytes().fill(0)
        assertEquals(Sha256State.INITIAL, state)
        val input = ByteArray(64) { 7 }
        val m = message(input)
        input.fill(0)
        m.block(0).fill(0)
        assertEquals(7, m.block(0)[0].toInt())
        assertFailsWith<IllegalArgumentException> { Sha256State.of(IntArray(7)) }
        assertFailsWith<IllegalArgumentException> { state.compress(ByteArray(63)) }
        assertFailsWith<IllegalArgumentException> { Sha256Chain.stateAt(m, -1) }
        assertFailsWith<IllegalArgumentException> { Sha256Chain.stateAt(m, m.blockCount + 1) }
        for (range in listOf(intArrayOf(), intArrayOf(1, 1, 2, 2), intArrayOf(0, -1, 2, 1),
            intArrayOf(0, 3, 2, 1), intArrayOf(0, 1, Int.MAX_VALUE, 1))) {
            assertFailsWith<IllegalArgumentException> { Sha256Chain.message(input, range) }
        }
    }
}
