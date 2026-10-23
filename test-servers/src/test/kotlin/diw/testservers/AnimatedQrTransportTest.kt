package diw.testservers

import diw.wallet.core.profile.bonds.AnimatedQrCollector
import diw.wallet.core.profile.bonds.AnimatedQrTransport
import diw.wallet.core.profile.bonds.BondsReception
import diw.wallet.core.profile.bonds.BondsTransportException
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The fountain code must rebuild a proof-sized payload from frames seen in any order, with many missed. */
class AnimatedQrTransportTest {
    // Mostly incompressible, like a proof package: random bytes with some repeated JSON text around them.
    private fun payload(size: Int, seed: Int): ByteArray {
        val r = Random(seed)
        val out = ByteArray(size)
        for (i in out.indices) out[i] = if (i % 7 == 0) '"'.code.toByte() else r.nextInt(256).toByte()
        return out
    }

    private fun collect(encoder: AnimatedQrTransport.Encoder, seeds: Sequence<Int>): Pair<ByteArray, Int> {
        val collector = AnimatedQrCollector()
        var used = 0
        for (s in seeds) {
            used++
            val r = collector.accept(encoder.frame(s))
            if (r is BondsReception.Completed) return r.payload to used
        }
        error("Not completed after $used frames")
    }

    @Test
    fun rebuildsFromTheSystematicFramesAlone() {
        val data = payload(213_000, 1)
        val encoder = AnimatedQrTransport.Encoder(data)
        val (out, used) = collect(encoder, (0 until encoder.count).asSequence())
        assertContentEquals(data, out)
        assertTrue(used == encoder.count)
        assertTrue(encoder.frame(0).length < 1_000, "frame stays a mid-size QR")
    }

    @Test
    fun rebuildsWithMissedFramesInAnyOrder() {
        val data = payload(120_000, 2)
        val encoder = AnimatedQrTransport.Encoder(data)
        val r = Random(3)
        // A camera that misses about 40 percent of the loop and joins half way.
        val seeds = generateSequence(encoder.count / 2) { it + 1 }.filter { r.nextInt(10) >= 4 }
        val (out, used) = collect(encoder, seeds)
        assertContentEquals(data, out)
        assertTrue(used < encoder.count + 30, "needed $used frames for ${encoder.count} blocks")
    }

    @Test
    fun rebuildsFromCombinedFramesOnly() {
        val data = "{\"proof\":\"short\"}".encodeToByteArray()
        val encoder = AnimatedQrTransport.Encoder(data)
        val (out, _) = collect(encoder, (encoder.count until encoder.count + 50).asSequence())
        assertContentEquals(data, out)
    }

    @Test
    fun anotherTransferStartsOver() {
        val first = AnimatedQrTransport.Encoder(payload(5_000, 4))
        val second = AnimatedQrTransport.Encoder(payload(5_000, 5))
        val collector = AnimatedQrCollector()
        collector.accept(first.frame(0))
        var result: BondsReception? = null
        for (s in 0 until second.count) result = collector.accept(second.frame(s))
        assertContentEquals(payload(5_000, 5), (result as BondsReception.Completed).payload)
    }

    @Test
    fun rejectsMalformedAndOversizedFrames() {
        val collector = AnimatedQrCollector()
        assertFailsWith<BondsTransportException> { collector.accept("DIWQ1:Z:XYZ:1:1:0:00") }
        assertFailsWith<BondsTransportException> { collector.accept("BTWVP1:anything") }
        val big = AnimatedQrTransport.Encoder(payload(8_000, 6))
        val small = AnimatedQrCollector(maxPayload = 1_000)
        assertFailsWith<BondsTransportException> { for (s in 0 until big.count) small.accept(big.frame(s)) }
    }
}
