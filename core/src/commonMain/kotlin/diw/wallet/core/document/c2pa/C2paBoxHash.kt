package diw.wallet.core.document.c2pa

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.c2pa.C2paBytes as B
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborInt
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tstr

/**
 * The general box hash (c2pa.hash.boxes, C2PA 9.2.3 and 15.12.3): the file split into the boxes of its format
 * (JPEG marker segments, PNG chunks, GIF blocks, JPEG XL boxes) named as the specification names them, with the
 * C2PA store as the box "C2PA" and bytes after the last box as "c2pa.after". Each entry hashes a run of boxes; the
 * C2PA box is skipped and every box of the file must be listed.
 */
object C2paBoxHash {
    const val C2PA = "C2PA"
    const val AFTER = "c2pa.after"

    class SourceBox(val name: String, val start: Long, val length: Long) {
        val end: Long get() = start + length
    }

    /** Formats whose box layout is defined. */
    fun supports(f: C2paFormat) = f in setOf(C2paFormat.JPEG, C2paFormat.PNG, C2paFormat.GIF, C2paFormat.JXL)

    /** The boxes of [b] in file order, then c2pa.after for trailing bytes. */
    fun boxes(b: ByteArray, f: C2paFormat): List<SourceBox> {
        val list = when (f) {
            C2paFormat.JPEG -> jpeg(b)
            C2paFormat.PNG -> listOf(SourceBox("PNGh", 0, 8)) + C2paContainers.Png.chunks(b).map { c ->
                SourceBox(if (c.first == "caBX") C2PA else c.first, c.second.toLong(), (c.third - c.second).toLong())
            }
            C2paFormat.GIF -> C2paContainers.Gif.blocks(b).map { SourceBox(it.kind, it.start.toLong(), (it.end - it.start).toLong()) }
            C2paFormat.JXL -> C2paContainers.Jxl.boxes(b).map { x ->
                SourceBox(if (C2paContainers.Jxl.isStoreBox(b, x)) C2PA else x.type, x.start.toLong(), (x.end - x.start).toLong())
            }
            else -> throw IllegalArgumentException("no box layout for $f")
        }
        val covered = list.maxOfOrNull { it.end } ?: 0L
        return if (b.size > covered) list + SourceBox(AFTER, covered, b.size - covered) else list
    }

    private val SEGMENT_NAMES: Map<Int, String> = buildMap {
        for (n in 0..15) put(0xE0 + n, "APP$n")
        for (n in 0..15) if (n != 4 && n != 8 && n != 12) put(0xC0 + n, "SOF$n")
        put(0xC4, "DHT"); put(0xC8, "JPG"); put(0xCC, "DAC"); put(0xDB, "DQT"); put(0xDD, "DRI"); put(0xDC, "DNL")
        put(0xDE, "DHP"); put(0xDF, "EXP"); put(0xFE, "COM"); put(0xD9, "EOI"); put(0xD8, "SOI"); put(0xDA, "SOS"); put(0x01, "TEM")
        for (n in 0..7) put(0xD0 + n, "RST$n")
        for (n in 0..13) put(0xF0 + n, "JPG$n")
    }

    /** JPEG segments (ISO/IEC 10918-1 symbols); a scan is the SOS segment and its entropy-coded data. */
    private fun jpeg(b: ByteArray): List<SourceBox> {
        val out = ArrayList<SourceBox>()
        out.add(SourceBox("SOI", 0, 2))
        var i = 2
        var c2pa: SourceBox? = null
        var c2paInstance = -1
        while (i + 2 <= b.size && B.u8(b, i) == 0xFF) {
            val marker = B.u8(b, i + 1)
            if (marker == 0xFF) { i++; continue }
            val name = SEGMENT_NAMES[marker] ?: "0x" + marker.toString(16)
            if (marker == 0xD9) { out.add(SourceBox("EOI", i.toLong(), 2)); i += 2; break }
            if (marker == 0x01 || marker in 0xD0..0xD7) { out.add(SourceBox(name, i.toLong(), 2)); i += 2; continue }
            if (i + 4 > b.size) break
            val len = B.u16(b, i + 2)
            if (len < 2 || i + 2 + len > b.size) C2paContainers.fail("JPEG segment at $i")
            var end = i + 2 + len
            if (marker == 0xEB && len > 16 && B.at(b, i + 4, "JP")) {
                val instance = B.u16(b, i + 6)
                val cur = c2pa
                if (cur != null && instance == c2paInstance && cur.end == i.toLong()) {
                    c2pa = SourceBox(C2PA, cur.start, end - cur.start)
                    out[out.size - 1] = c2pa
                    i = end
                    continue
                }
                if (C2paContainers.isStore(b, i + 12)) {
                    c2pa = SourceBox(C2PA, i.toLong(), (end - i).toLong())
                    c2paInstance = instance
                    out.add(c2pa)
                    i = end
                    continue
                }
            }
            if (marker == 0xDA) {
                // Entropy-coded data up to the next marker that is neither a stuffed zero nor a restart marker.
                var k = end
                while (k + 1 < b.size) {
                    if (B.u8(b, k) == 0xFF) {
                        val n = B.u8(b, k + 1)
                        if (n != 0x00 && n !in 0xD0..0xD7) break
                        k += 2
                    } else k++
                }
                end = if (k + 1 >= b.size) b.size else k
            }
            out.add(SourceBox(name, i.toLong(), (end - i).toLong()))
            i = end
        }
        return out
    }

    // ---------------------------------------------------------------- verification

    class Result(val status: String, val additionalExclusions: Boolean = false, val detail: String? = null)

    /** Checks the box hash [d] over [b]. [defaultAlg] is the claim's algorithm. */
    fun verify(b: ByteArray, f: C2paFormat, d: DataItem, defaultAlg: String?): Result {
        val entries = (d.getOrNullAny("boxes") as? CborArray)?.items ?: return Result("assertion.boxesHash.malformed")
        if (entries.isEmpty()) return Result("assertion.boxesHash.malformed")
        val source = boxes(b, f).toMutableList()
        val names = entries.map { e -> (e.getOrNullAny("names") as? CborArray)?.items?.mapNotNull { (it as? Tstr)?.value } ?: return Result("assertion.boxesHash.malformed") }
        if (names.none { it == listOf(C2PA) }) source.removeAll { it.name == C2PA && it.length == 0L }
        var index = 0
        if (source.firstOrNull()?.name == "PNGh" && names.first().firstOrNull() != "PNGh") index = 1
        var extra = false
        for ((k, e) in entries.withIndex()) {
            val ranges = ArrayList<SourceBox>()
            for (name in names[k]) {
                val s = source.getOrNull(index) ?: return Result("assertion.boxesHash.unknownBox")
                if (s.name != name) return Result("assertion.boxesHash.unknownBox", detail = name)
                ranges.add(s)
                index++
            }
            if (ranges.isEmpty()) return Result("assertion.boxesHash.malformed")
            val isC2pa = ranges.first().name == C2PA
            if (isC2pa && ranges.size != 1) return Result("assertion.boxesHash.malformed")
            val exclusions = e.getOrNullAny("exclusions")
            if (exclusions is CborArray && exclusions.items.isEmpty()) return Result("assertion.boxesHash.malformed")
            val excluded = e.getOrNullAny("excluded") == Simple.TRUE
            if (isC2pa || excluded) { if (excluded && !isC2pa) extra = true; continue }
            val start = ranges.first().start
            val end = ranges.last().end
            var included = listOf(C2paRange(start, end - start))
            if (exclusions is CborArray) {
                val cut = ArrayList<C2paRange>()
                for (x in exclusions.items) {
                    val xs = (x.getOrNullAny("start") as? CborInt)?.asNumber ?: return Result("assertion.boxesHash.malformed")
                    val xl = (x.getOrNullAny("length") as? CborInt)?.asNumber ?: return Result("assertion.boxesHash.malformed")
                    val bi = (x.getOrNullAny("boxIndex") as? CborInt)?.asNumber ?: if (ranges.size == 1) 0 else return Result("assertion.boxesHash.malformed")
                    val box = ranges.getOrNull(bi.toInt()) ?: return Result("assertion.boxesHash.malformed")
                    if (xs < 0 || xl < 0 || xs + xl > box.length) return Result("assertion.boxesHash.malformed")
                    cut.add(C2paRange(box.start + xs, xl))
                }
                included = subtract(included.first(), cut)
                extra = true
            }
            val alg = (e.getOrNullAny("alg") as? Tstr)?.value ?: (d.getOrNullAny("alg") as? Tstr)?.value ?: defaultAlg
                ?: return Result("assertion.boxesHash.malformed")
            val expected = (e.getOrNullAny("hash") as? Bstr)?.value ?: return Result("assertion.boxesHash.malformed")
            val data = C2paCbor.concat(included.map { b.copyOfRange(it.start.toInt(), it.end.toInt()) })
            if (!DocCrypto.digest(C2paManifests.jcaHash(alg), data).contentEquals(expected)) return Result("assertion.boxesHash.mismatch", detail = names[k].joinToString(","))
        }
        if (index != source.size) return Result("assertion.boxesHash.unknownBox", detail = source.getOrNull(index)?.name)
        return Result("assertion.boxesHash.match", extra)
    }

    private fun subtract(r: C2paRange, cut: List<C2paRange>): List<C2paRange> {
        val out = ArrayList<C2paRange>()
        var pos = r.start
        for (c in cut.sortedBy { it.start }) {
            if (c.start > pos) out.add(C2paRange(pos, c.start - pos))
            pos = maxOf(pos, c.end)
        }
        if (pos < r.end) out.add(C2paRange(pos, r.end - pos))
        return out
    }

    // ---------------------------------------------------------------- writing

    /**
     * The minimal box hash of a laid-out file: the boxes before the store, the store ("C2PA", hash 0x00), the boxes
     * after it. [zero] gives a placeholder of the same size.
     */
    fun assertionCbor(b: ByteArray, f: C2paFormat, alg: String = "sha256", zero: Boolean = false): ByteArray {
        val list = boxes(b, f)
        val at = list.indexOfFirst { it.name == C2PA }
        if (at < 0) throw IllegalArgumentException("no C2PA box")
        val groups = listOf(list.subList(0, at), list.subList(at + 1, list.size)).map { it.toList() }
        val size = DocCrypto.digest(C2paManifests.jcaHash(alg), ByteArray(0)).size
        fun entry(g: List<SourceBox>): ByteArray {
            val start = g.first().start
            val data = b.copyOfRange(start.toInt(), g.last().end.toInt())
            val hash = if (zero) ByteArray(size) else DocCrypto.digest(C2paManifests.jcaHash(alg), data)
            return C2paCbor.map(listOf(
                "names" to C2paCbor.array(g.map { C2paCbor.tstr(it.name) }),
                "alg" to C2paCbor.tstr(alg),
                "hash" to C2paCbor.bstr(hash),
                "pad" to C2paCbor.bstr(ByteArray(0)),
            ))
        }
        val c2pa = C2paCbor.map(listOf(
            "names" to C2paCbor.array(listOf(C2paCbor.tstr(C2PA))),
            "hash" to C2paCbor.bstr(byteArrayOf(0)),
            "pad" to C2paCbor.bstr(ByteArray(0)),
        ))
        val items = listOfNotNull(groups[0].takeIf { it.isNotEmpty() }?.let(::entry), c2pa, groups[1].takeIf { it.isNotEmpty() }?.let(::entry))
        return C2paCbor.map(listOf("boxes" to C2paCbor.array(items)))
    }
}
