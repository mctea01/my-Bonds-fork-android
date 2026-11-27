package diw.wallet.core.document.c2pa

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.c2pa.C2paBytes as B
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborInt
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tstr

/**
 * ISO BMFF (MP4, MOV, M4A, HEIF, HEIC, AVIF, 3GP) for C2PA (Appendix A.5 and 18.6): the manifest store in a uuid box
 * (D8FEC3D6-1B0E-483C-9297-5828877EC481, box_purpose "manifest") after ftyp, the absolute file offsets that moving
 * boxes changes (stco, co64, saio, iloc, tfhd, tfra), and the BMFF hash (c2pa.hash.bmff v1, v2 and v3) with its
 * exclusions, the 8-byte offsets v2 and later mix into the hash before each top-level box, and Merkle trees over
 * mdat blocks or over the fragments of a fragmented file.
 */
object C2paBmff {
    val UUID: ByteArray = DocCryptoUtil.unhex("d8fec3d61b0e483c92975828877ec481")
    private const val MAX_DEPTH = 32

    /** A box: its type, where it starts and ends, the header length (with the uuid user type), version and flags. */
    class Box(
        val type: String,
        val start: Long,
        val end: Long,
        val header: Int,
        val version: Int? = null,
        val flags: Int? = null,
        val children: List<Box> = emptyList(),
    ) {
        val size: Long get() = end - start
    }

    private val CONTAINERS = setOf("moov", "trak", "mdia", "minf", "stbl", "moof", "traf", "edts", "udta", "dinf", "tref", "treg", "mvex", "mfra", "meta", "schi")

    private val FULL_BOXES = setOf(
        "pdin", "mvhd", "tkhd", "mdhd", "hdlr", "nmhd", "elng", "stsd", "stdp", "stts", "ctts", "cslg", "stss", "stsh", "elst", "dref",
        "stsz", "stz2", "stsc", "stco", "co64", "padb", "subs", "saiz", "saio", "mehd", "trex", "mfhd", "tfhd", "trun", "tfra", "mfro",
        "tfdt", "leva", "trep", "assp", "sbgp", "sgpd", "csgp", "cprt", "tsel", "kind", "meta", "xml ", "bxml", "iloc", "pitm", "ipro",
        "infe", "iinf", "iref", "ipma", "schm", "fiin", "fpar", "fecr", "gitn", "fire", "stri", "stsg", "stvi", "csch", "sidx", "ssix",
        "prft", "srpp", "vmhd", "smhd", "srat", "chnl", "dmix", "txtC", "mime", "uri ", "uriI", "hmhd", "sthd", "vvhd", "medc",
    )

    private val TOP_TYPES = setOf("ftyp", "moov", "mdat", "free", "skip", "wide", "uuid", "meta", "moof", "mfra", "pnot", "styp", "sidx")

    /** True for a file that starts with an ftyp box, or (old QuickTime) with another top-level box of a valid size. */
    fun isBmff(b: ByteArray): Boolean {
        if (b.size < 16) return false
        val type = B.ascii(b, 4, 4)
        if (type == "ftyp") return true
        if (type !in TOP_TYPES) return false
        return runCatching { topLevel(b).isNotEmpty() && topLevel(b).last().end == b.size.toLong() }.getOrDefault(false)
    }

    fun mediaType(b: ByteArray): String {
        val brands = if (B.at(b, 4, "ftyp")) {
            val size = minOf(B.u32(b, 0), b.size.toLong()).toInt()
            listOf(B.ascii(b, 8, 4)) + (16 until size step 4).map { B.ascii(b, it, 4) }
        } else return "video/quicktime"
        val major = brands.first()
        return when {
            major in setOf("avif", "avis") -> "image/avif"
            major in setOf("heic", "heix", "heim", "heis") -> "image/heic"
            major in setOf("mif1", "msf1", "heif") -> if ("avif" in brands) "image/avif" else if ("heic" in brands) "image/heic" else "image/heif"
            major == "qt  " -> "video/quicktime"
            major in setOf("M4A ", "M4B ", "M4P ") -> "audio/mp4"
            major.startsWith("3gp") || major.startsWith("3gg") -> "video/3gpp"
            major.startsWith("3g2") -> "video/3gpp2"
            major == "M4V " -> "video/x-m4v"
            else -> "video/mp4"
        }
    }

    // ---------------------------------------------------------------- box structure

    private fun header(b: ByteArray, off: Long, limit: Long): Box? {
        if (off + 8 > limit) return null
        val o = off.toInt()
        var size = B.u32(b, o)
        val type = B.ascii(b, o + 4, 4)
        var h = 8
        if (size == 1L) {
            if (off + 16 > limit) C2paContainers.fail("BMFF box header past the end")
            size = B.u64(b, o + 8); h = 16
        } else if (size == 0L) size = limit - off
        if (type == "uuid") h += 16
        if (size < h || off + size > limit) C2paContainers.fail("BMFF box $type out of range")
        return Box(type, off, off + size, h)
    }

    /** The top-level boxes of [b]. */
    fun topLevel(b: ByteArray): List<Box> {
        val out = ArrayList<Box>()
        var off = 0L
        while (off < b.size) {
            val box = header(b, off, b.size.toLong()) ?: break
            out.add(box)
            off = box.end
        }
        return out
    }

    /** The box tree: containers with their children, version and flags of full boxes (QuickTime meta has none). */
    fun tree(b: ByteArray): List<Box> = children(b, 0, b.size.toLong(), 0)

    private fun children(b: ByteArray, from: Long, to: Long, depth: Int): List<Box> {
        if (depth > MAX_DEPTH) C2paContainers.fail("BMFF boxes nested too deep")
        val out = ArrayList<Box>()
        var off = from
        while (off + 8 <= to) {
            val h = header(b, off, to) ?: break
            out.add(full(b, h, depth))
            off = h.end
        }
        return out
    }

    private fun full(b: ByteArray, h: Box, depth: Int): Box {
        val dataAt = h.start + h.header
        var version: Int? = null
        var flags: Int? = null
        var childFrom = dataAt
        val quickTimeMeta = h.type == "meta" && dataAt + 8 <= h.end && B.at(b, (dataAt + 4).toInt(), "hdlr")
        if (h.type in FULL_BOXES && !quickTimeMeta && dataAt + 4 <= h.end) {
            version = B.u8(b, dataAt.toInt())
            flags = B.u24(b, dataAt.toInt() + 1)
            childFrom = dataAt + 4
        }
        val kids = if (h.type in CONTAINERS) children(b, childFrom, h.end, depth + 1) else emptyList()
        return Box(h.type, h.start, h.end, h.header, version, flags, kids)
    }

    /** Boxes an exclusion xpath selects (/a/b, b[n] the n-th from 1), in file order, as c2pa-rs selects them. */
    fun select(roots: List<Box>, xpath: String): List<Box> {
        var kids = roots
        var current = emptyList<Box>()
        for (part in xpath.trimStart('/').split('/')) {
            if (part.length < 4) return emptyList()
            if (kids.isEmpty()) return emptyList()
            if (part.contains('[')) {
                val name = part.substringBefore('[')
                val index = part.substringAfter('[').trimEnd(']').toIntOrNull() ?: return emptyList()
                if (name.length < 4 || index == 0) return emptyList()
                val child = kids.filter { it.type == name }.getOrNull(index - 1) ?: return emptyList()
                current = listOf(child)
                kids = child.children
            } else {
                current = kids.filter { it.type == part }
                kids = current.flatMap { it.children }
            }
        }
        return current
    }

    private fun all(roots: List<Box>): Sequence<Box> = roots.asSequence().flatMap { sequenceOf(it) + all(it.children) }

    // ---------------------------------------------------------------- the C2PA uuid boxes

    /** A C2PA uuid box: its purpose (manifest, original, update, merkle) and payload (store or Merkle map CBOR). */
    class C2paBox(val box: Box, val purpose: String, val payload: ByteArray)

    fun c2paBoxes(b: ByteArray): List<C2paBox> = topLevel(b).filter { it.type == "uuid" && isC2paUuid(b, it) }.mapNotNull { box ->
        val p = (box.start + box.header + 4).toInt()
        val end = box.end.toInt()
        val z = (p until end).firstOrNull { b[it] == 0.toByte() } ?: return@mapNotNull null
        val purpose = B.ascii(b, p, z - p)
        val data = z + 1
        when (purpose) {
            "merkle" -> C2paBox(box, purpose, b.copyOfRange(data, end))
            else -> if (data + 8 <= end) C2paBox(box, purpose, b.copyOfRange(data + 8, end)) else null
        }
    }

    private fun isC2paUuid(b: ByteArray, box: Box) = box.header >= 24 && b.copyOfRange((box.start + box.header - 16).toInt(), (box.start + box.header).toInt()).contentEquals(UUID)

    fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
        val boxes = c2paBoxes(b)
        val m = boxes.firstOrNull { it.purpose == "manifest" } ?: boxes.firstOrNull { it.purpose == "original" } ?: return null
        return m.payload to C2paRange(m.box.start, m.box.size)
    }

    /** The uuid box of a manifest store (box_purpose manifest, no Merkle proof boxes). */
    fun storeBox(store: ByteArray): ByteArray {
        val purpose = "manifest".encodeToByteArray() + 0
        val size = 8 + 16 + 4 + purpose.size + 8 + store.size
        return B.be32(size.toLong()) + "uuid".encodeToByteArray() + UUID + byteArrayOf(0, 0, 0, 0) + purpose + ByteArray(8) + store
    }

    fun strip(b: ByteArray): ByteArray {
        val drop = c2paBoxes(b).map { it.box }.sortedBy { it.start }
        if (drop.isEmpty()) return b
        val patched = b.copyOf()
        adjustOffsets(patched) { o -> o - drop.filter { it.end <= o }.sumOf { it.size } }
        var out = patched
        for (box in drop.sortedByDescending { it.start }) out = B.splice(out, box.start.toInt(), box.size.toInt(), ByteArray(0))
        return out
    }

    /** After ftyp (the start of a file without one), with the absolute offsets after that point moved. */
    fun embed(base: ByteArray, store: ByteArray): C2paLayout {
        val top = topLevel(base)
        val at = top.firstOrNull { it.type == "ftyp" }?.end ?: 0L
        val box = storeBox(store)
        val patched = base.copyOf()
        adjustOffsets(patched) { o -> if (o >= at) o + box.size else o }
        return C2paLayout(B.splice(patched, at.toInt(), 0, box), C2paRange(at, box.size.toLong()))
    }

    /**
     * Rewrites in place the absolute file offsets of [b] with [move]: chunk offsets (stco, co64), auxiliary
     * information offsets of sample tables (saio), item locations of file-offset construction (iloc), the base data
     * offsets of track fragments (tfhd flag 1) and the moof offsets of random access entries (tfra).
     */
    fun adjustOffsets(b: ByteArray, move: (Long) -> Long) {
        val roots = tree(b)
        fun patch(at: Long, n: Int) {
            val v = B.uN(b, at.toInt(), n)
            val nv = move(v)
            if (n == 4 && (nv < 0 || nv > 0xFFFFFFFFL)) C2paContainers.fail("BMFF 32-bit offset overflow")
            B.putN(b, at.toInt(), n, nv)
        }
        for (box in all(roots)) {
            val d = box.start + box.header + 4
            when (box.type) {
                "stco", "co64" -> {
                    val n = B.u32(b, d.toInt())
                    val w = if (box.type == "stco") 4 else 8
                    if (d + 4 + n * w > box.end) C2paContainers.fail("BMFF ${box.type} out of range")
                    for (k in 0 until n) patch(d + 4 + k * w, w)
                }
                "saio" -> if (isSampleTable(roots, box)) {
                    var p = d
                    if ((box.flags ?: 0) and 1 != 0) p += 8
                    val n = B.u32(b, p.toInt())
                    val w = if (box.version == 0) 4 else 8
                    for (k in 0 until n) patch(p + 4 + k * w, w)
                }
                "iloc" -> iloc(b, box, move)
                "tfhd" -> if ((box.flags ?: 0) and 1 != 0) patch(d + 4, 8)
                "tfra" -> {
                    val sizes = B.u32(b, (d + 4).toInt())
                    val n = B.u32(b, (d + 8).toInt())
                    val w = if (box.version == 1) 8 else 4
                    val rest = (((sizes ushr 4) and 3) + 1) + (((sizes ushr 2) and 3) + 1) + ((sizes and 3) + 1)
                    var p = d + 12
                    for (k in 0 until n) { patch(p + w, w); p += 2L * w + rest }
                }
            }
        }
    }

    private fun isSampleTable(roots: List<Box>, saio: Box): Boolean =
        select(roots, "/moov/trak/mdia/minf/stbl/saio").any { it.start == saio.start }

    /**
     * Item locations of file-offset construction: a non-zero base moves with [move], and each extent offset is
     * rewritten relative to the new base, so data on the other side of the moved point than its base stays found.
     */
    private fun iloc(b: ByteArray, box: Box, move: (Long) -> Long) {
        fun write(at: Long, n: Int, v: Long) {
            if (v < 0 || (n < 8 && v >= (1L shl (8 * n)))) C2paContainers.fail("BMFF iloc offset overflow")
            B.putN(b, at.toInt(), n, v)
        }
        val v = box.version ?: return
        var p = box.start + box.header + 4
        val s1 = B.u8(b, p.toInt()); val s2 = B.u8(b, p.toInt() + 1)
        p += 2
        val offsetSize = s1 ushr 4; val lengthSize = s1 and 0x0F
        val baseSize = s2 ushr 4; val indexSize = if (v == 1 || v == 2) s2 and 0x0F else 0
        val count = if (v < 2) B.u16(b, p.toInt()).toLong().also { p += 2 } else B.u32(b, p.toInt()).also { p += 4 }
        for (i in 0 until count) {
            p += if (v < 2) 2 else 4
            var method = 0
            if (v == 1 || v == 2) { method = B.u8(b, p.toInt() + 1) and 0x0F; p += 2 }
            val dataRef = B.u16(b, p.toInt()); p += 2
            val baseAt = p
            val base = if (baseSize > 0) B.uN(b, p.toInt(), baseSize) else 0L
            p += baseSize
            val extents = B.u16(b, p.toInt()); p += 2
            val fileOffsets = method == 0 && dataRef == 0
            val newBase = if (fileOffsets && base != 0L) move(base) else base
            if (newBase != base) write(baseAt, baseSize, newBase)
            for (e in 0 until extents) {
                p += indexSize
                val off = if (offsetSize > 0) B.uN(b, p.toInt(), offsetSize) else 0L
                if (fileOffsets && (base != 0L || off != 0L)) {
                    val newOff = move(base + off) - newBase
                    if (newOff != off) {
                        if (offsetSize == 0) C2paContainers.fail("BMFF iloc extent without an offset field")
                        write(p, offsetSize, newOff)
                    }
                }
                p += offsetSize + lengthSize
            }
            if (p > box.end) C2paContainers.fail("BMFF iloc out of range")
        }
    }

    // ---------------------------------------------------------------- BMFF hash

    class DataMatch(val offset: Long, val value: ByteArray)
    class Subset(val offset: Long, val length: Long)
    class Exclusion(
        val xpath: String,
        val length: Long? = null,
        val data: List<DataMatch> = emptyList(),
        val subset: List<Subset>? = null,
        val version: Int? = null,
        val flags: ByteArray? = null,
        val exact: Boolean? = null,
    )

    class MerkleMap(
        val uniqueId: Long,
        val localId: Long,
        val count: Int,
        val alg: String?,
        val initHash: ByteArray?,
        val hashes: List<ByteArray>,
        val fixedBlockSize: Long?,
        val variableBlockSizes: List<Long>?,
    )

    class Assertion(val exclusions: List<Exclusion>, val alg: String?, val hash: ByteArray?, val merkle: List<MerkleMap>, val name: String?)

    /** The standard exclusions (C2PA 18.6): the C2PA uuid boxes, ftyp and mfra. */
    val STANDARD: List<Exclusion> = listOf(Exclusion("/uuid", data = listOf(DataMatch(8, UUID))), Exclusion("/ftyp"), Exclusion("/mfra"))

    fun parse(d: DataItem): Assertion {
        fun long(x: DataItem?) = (x as? CborInt)?.asNumber
        val exclusions = (d.getOrNullAny("exclusions") as? CborArray)?.items.orEmpty().map { e ->
            Exclusion(
                xpath = (e.getOrNullAny("xpath") as? Tstr)?.value ?: throw IllegalArgumentException("exclusion without xpath"),
                length = long(e.getOrNullAny("length")),
                data = (e.getOrNullAny("data") as? CborArray)?.items.orEmpty().map { m ->
                    DataMatch(long(m.getOrNullAny("offset")) ?: 0, (m.getOrNullAny("value") as? Bstr)?.value ?: ByteArray(0))
                },
                subset = (e.getOrNullAny("subset") as? CborArray)?.items?.map { s -> Subset(long(s.getOrNullAny("offset")) ?: 0, long(s.getOrNullAny("length")) ?: 0) },
                version = long(e.getOrNullAny("version"))?.toInt(),
                flags = (e.getOrNullAny("flags") as? Bstr)?.value,
                exact = when (e.getOrNullAny("exact")) { Simple.TRUE -> true; Simple.FALSE -> false; else -> null },
            )
        }
        val merkle = (d.getOrNullAny("merkle") as? CborArray)?.items.orEmpty().map { m ->
            MerkleMap(
                uniqueId = long(m.getOrNullAny("uniqueId")) ?: 0,
                localId = long(m.getOrNullAny("localId")) ?: 0,
                count = long(m.getOrNullAny("count"))?.toInt() ?: 0,
                alg = (m.getOrNullAny("alg") as? Tstr)?.value,
                initHash = (m.getOrNullAny("initHash") as? Bstr)?.value,
                hashes = (m.getOrNullAny("hashes") as? CborArray)?.items.orEmpty().mapNotNull { (it as? Bstr)?.value },
                fixedBlockSize = long(m.getOrNullAny("fixedBlockSize")),
                variableBlockSizes = (m.getOrNullAny("variableBlockSizes") as? CborArray)?.items?.mapNotNull { long(it) },
            )
        }
        return Assertion(exclusions, (d.getOrNullAny("alg") as? Tstr)?.value, (d.getOrNullAny("hash") as? Bstr)?.value, merkle, (d.getOrNullAny("name") as? Tstr)?.value)
    }

    /** Excluded byte ranges and, for v2 and later, the offsets of the top-level boxes not excluded whole. */
    class Excluded(val ranges: List<C2paRange>, val offsets: List<Long>)

    fun excluded(b: ByteArray, exclusions: List<Exclusion>, v2: Boolean): Excluded {
        val roots = tree(b)
        val offsets = roots.map { it.start }.sorted().toMutableList()
        val ranges = ArrayList<C2paRange>()
        for (x in exclusions) for (box in select(roots, x.xpath)) {
            if (!matchesHeader(x, box) || !matchesData(b, x, box)) continue
            val subset = x.subset
            if (subset != null) {
                for (s in subset) {
                    if (s.offset > box.size) continue
                    val available = box.size - s.offset
                    ranges.add(C2paRange(box.start + s.offset, if (s.length == 0L) available else minOf(available, s.length)))
                }
            } else {
                ranges.add(C2paRange(box.start, box.size))
                offsets.remove(box.start)
            }
        }
        return Excluded(ranges, if (v2) offsets else emptyList())
    }

    private fun matchesHeader(x: Exclusion, box: Box): Boolean {
        if (x.length != null && x.length != box.size) return false
        if (x.version != null && box.version != null && x.version != box.version) return false
        val f = x.flags ?: return true
        val want = if (f.size >= 3) B.u24(f, 0) else 0
        val actual = box.flags ?: return true
        return if (x.exact ?: true) actual == want else (want or actual) == want
    }

    private fun matchesData(b: ByteArray, x: Exclusion, box: Box): Boolean = x.data.all { m ->
        val s = box.start + m.offset
        if (s + m.value.size > b.size) throw IllegalArgumentException("BMFF data map past the end")
        b.copyOfRange(s.toInt(), (s + m.value.size).toInt()).contentEquals(m.value)
    }

    /**
     * The hash of [b] without the [excluded] ranges, with the 8-byte big-endian offset of each top-level box mixed in
     * before its bytes (v2 and later), as c2pa-rs computes it: an offset inside a hashed range splits it, and an
     * offset outside every hashed range counts only between the first and the last hashed byte.
     */
    fun hash(b: ByteArray, excluded: Excluded, alg: String, extra: List<C2paRange> = emptyList()): ByteArray {
        val size = b.size.toLong()
        val all = (excluded.ranges + extra).filter { it.length > 0 }
        if (all.any { it.start < 0 || it.end > size }) throw IllegalArgumentException("BMFF exclusion past the end")
        // Included ranges as [start, end) after removing every exclusion.
        val included = ArrayList<C2paRange>()
        var pos = 0L
        for (r in all.sortedBy { it.start }) {
            if (r.start > pos) included.add(C2paRange(pos, r.start - pos))
            pos = maxOf(pos, r.end)
        }
        if (pos < size) included.add(C2paRange(pos, size - pos))
        class Piece(val start: Long, val end: Long, val marker: Boolean)
        val pieces = ArrayList<Piece>()
        val markers = excluded.offsets.sorted()
        for (r in included) {
            var curStart = r.start
            for (os in markers) {
                if (os in curStart until r.end) {
                    if (curStart == os) pieces.add(Piece(os, os, true))
                    else { pieces.add(Piece(curStart, os, false)); pieces.add(Piece(os, os, true)); curStart = os }
                }
            }
            pieces.add(Piece(curStart, r.end, false))
        }
        if (markers.isNotEmpty()) {
            val first = pieces.firstOrNull()?.start ?: 0L
            val last = pieces.lastOrNull()?.let { if (it.marker) it.end else it.end - 1 } ?: (size - 1)
            for (os in markers) {
                val inside = pieces.any { if (it.marker) it.start == os else os >= it.start && os < it.end }
                if (!inside && os > first && os < last) pieces.add(Piece(os, os, true))
            }
        }
        val ordered = pieces.withIndex().sortedWith(compareBy({ it.value.start }, { it.index })).map { it.value }
        val parts = ordered.map { if (it.marker) B.be64(it.start) else b.copyOfRange(it.start.toInt(), it.end.toInt()) }
        return DocCrypto.digest(C2paManifests.jcaHash(alg), C2paCbor.concat(parts))
    }

    /** The CBOR of a v3 BMFF hash with the standard exclusions. */
    fun assertionCbor(hash: ByteArray, alg: String = "sha256"): ByteArray = C2paCbor.map(listOf(
        "exclusions" to C2paCbor.array(STANDARD.map { x ->
            C2paCbor.map(listOfNotNull(
                "xpath" to C2paCbor.tstr(x.xpath),
                x.data.takeIf { it.isNotEmpty() }?.let { d -> "data" to C2paCbor.array(d.map { C2paCbor.map(listOf("offset" to C2paCbor.int(it.offset), "value" to C2paCbor.bstr(it.value))) }) },
            ))
        }),
        "alg" to C2paCbor.tstr(alg),
        "hash" to C2paCbor.bstr(hash),
        "name" to C2paCbor.tstr("jumbf manifest"),
    ))

    /** The v3 hash of a laid-out file with the standard exclusions. */
    fun standardHash(b: ByteArray, alg: String = "sha256"): ByteArray = hash(b, excluded(b, STANDARD, true), alg)

    // ---------------------------------------------------------------- Merkle trees

    /** The layer of the Merkle tree over [leaves] that has [size] nodes (an odd last node goes up unchanged). */
    fun merkleLayer(leaves: List<ByteArray>, size: Int, alg: String): List<ByteArray>? {
        var layer = leaves
        while (layer.size > size) {
            layer = layer.chunked(2).map { if (it.size == 2) DocCrypto.digest(C2paManifests.jcaHash(alg), it[0] + it[1]) else it[0] }
            if (layer.size == 1 && size != 1) return null
        }
        return layer.takeIf { it.size == size }
    }

    /** Fragments of a fragmented file: from each top-level moof to the box before the next moof. */
    fun fragments(top: List<Box>): List<List<Box>> {
        val first = top.indexOfFirst { it.type == "moof" }
        if (first <= 0) return emptyList()
        val out = ArrayList<List<Box>>()
        var cur = arrayListOf(top[first])
        for (x in top.drop(first + 1)) {
            if (x.type == "moof") { out.add(cur); cur = arrayListOf() }
            cur.add(x)
        }
        out.add(cur)
        return out
    }
}
