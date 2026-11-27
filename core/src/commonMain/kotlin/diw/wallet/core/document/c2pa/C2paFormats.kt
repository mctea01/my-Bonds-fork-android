package diw.wallet.core.document.c2pa

import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.c2pa.C2paBytes as B
import kotlin.io.encoding.Base64

/** The hard binding a container uses (C2PA 2.x, 9.2 and 18): data hash, box hash, BMFF hash or collection hash. */
enum class C2paBinding { DATA, BOXES, BMFF, COLLECTION }

/**
 * A file format that can carry a C2PA manifest store (C2PA 2.2 Appendix A), with the place the store goes, the
 * default media type and the hard binding the writer uses for it.
 */
enum class C2paFormat(val title: String, val mediaType: String, val binding: C2paBinding) {
    JPEG("JPEG APP11", "image/jpeg", C2paBinding.DATA),
    PNG("PNG caBX", "image/png", C2paBinding.DATA),
    WEBP("WebP C2PA", "image/webp", C2paBinding.DATA),
    WAV("WAV C2PA", "audio/wav", C2paBinding.DATA),
    AVI("AVI C2PA", "video/x-msvideo", C2paBinding.DATA),
    GIF("GIF C2PA_GIF", "image/gif", C2paBinding.DATA),
    TIFF("TIFF 0xCD41", "image/tiff", C2paBinding.DATA),
    DNG("DNG 0xCD41", "image/x-adobe-dng", C2paBinding.DATA),
    SVG("SVG c2pa:manifest", "image/svg+xml", C2paBinding.DATA),
    MP3("MP3 ID3 GEOB", "audio/mpeg", C2paBinding.DATA),
    FLAC("FLAC ID3 GEOB", "audio/flac", C2paBinding.DATA),
    JXL("JPEG XL jumb", "image/jxl", C2paBinding.BOXES),
    BMFF("BMFF uuid", "video/mp4", C2paBinding.BMFF),
    PDF("PDF C2PA_Manifest", "application/pdf", C2paBinding.DATA),
    ZIP("ZIP META-INF", "application/zip", C2paBinding.COLLECTION),
    SIDECAR("sidecar", "application/c2pa", C2paBinding.DATA),
}

/**
 * A manifest store found in a file: the JUMBF bytes and where they are stored. [region] is the store's location the
 * hard binding must exclude exactly (the c2pa-rs "C2PA object" of the format): the APP11 segments of JPEG, the
 * whole caBX chunk, the RIFF chunk without its pad byte, the whole GIF extension block, the TIFF tag's data, the
 * base64 text of SVG, the GEOB data of ID3, the jumb box of JPEG XL, the PDF stream content, the uuid box of BMFF
 * or the ZIP entry. Null for a sidecar.
 */
class C2paLocated(val format: C2paFormat, val jumbf: ByteArray, val region: C2paRange?, val mediaType: String)

/** A file with a store embedded and the store's [region] (as in [C2paLocated]). */
class C2paLayout(val bytes: ByteArray, val region: C2paRange)

/** Thrown when a file is not a well-formed instance of its container format, or cannot take a manifest store. */
class C2paContainerException(message: String) : Exception(message)

/**
 * Finds, removes and embeds C2PA manifest stores in every container of C2PA 2.2 Appendix A: JPEG, PNG, RIFF (WebP,
 * WAV, AVI), GIF, TIFF and DNG, SVG, MP3 and FLAC (ID3v2 GEOB), JPEG XL, ISO BMFF (MP4, MOV, HEIF, AVIF, M4A),
 * PDF and ZIP (including OOXML, ODF and EPUB). The layouts follow the specification and match where the c2pa-rs
 * SDK puts the store, so stores written here validate there and the other way round.
 */
object C2paContainers {
    internal const val STORE_UUID = "6332706100110010800000aa00389b71"

    /** The container format of [b], or null when it is none of the supported ones (a sidecar is not detected). */
    fun detect(b: ByteArray): C2paFormat? = when {
        b.size > 4 && B.u8(b, 0) == 0xFF && B.u8(b, 1) == 0xD8 -> C2paFormat.JPEG
        b.size > 8 && B.u8(b, 0) == 0x89 && B.at(b, 1, "PNG") -> C2paFormat.PNG
        b.size > 12 && B.at(b, 0, "RIFF") && B.at(b, 8, "WEBP") -> C2paFormat.WEBP
        b.size > 12 && B.at(b, 0, "RIFF") && B.at(b, 8, "WAVE") -> C2paFormat.WAV
        b.size > 12 && B.at(b, 0, "RIFF") && B.at(b, 8, "AVI ") -> C2paFormat.AVI
        b.size > 13 && (B.at(b, 0, "GIF87a") || B.at(b, 0, "GIF89a")) -> C2paFormat.GIF
        b.size > 8 && (B.at(b, 0, "II") || B.at(b, 0, "MM")) && Tiff.magic(b) -> if (Tiff.isDng(b)) C2paFormat.DNG else C2paFormat.TIFF
        b.size >= 12 && B.indexOf(b, JXL_SIGNATURE) == 0 -> C2paFormat.JXL
        b.size > 2 && B.u8(b, 0) == 0xFF && B.u8(b, 1) == 0x0A -> C2paFormat.JXL
        b.size > 4 && B.at(b, 0, "fLaC") -> C2paFormat.FLAC
        b.size > 10 && B.at(b, 0, "ID3") -> if (B.at(b, Id3.tagEnd(b), "fLaC")) C2paFormat.FLAC else C2paFormat.MP3
        b.size > 4 && B.u8(b, 0) == 0xFF && (B.u8(b, 1) and 0xE0) == 0xE0 && (B.u8(b, 1) and 0x06) != 0 -> C2paFormat.MP3
        b.size > 12 && C2paBmff.isBmff(b) -> C2paFormat.BMFF
        b.size > 8 && C2paPdf.isPdf(b) -> C2paFormat.PDF
        b.size > 22 && C2paZip.isZip(b) -> C2paFormat.ZIP
        b.size > 16 && Svg.isSvg(b) -> C2paFormat.SVG
        else -> null
    }

    /** True when [b] starts like a sidecar manifest store (a JUMBF superbox). */
    fun isSidecar(b: ByteArray): Boolean = b.size > 16 && B.at(b, 4, "jumb")

    /** The media type of [b] in format [f]: the BMFF brand and the ZIP document type refine the format's default. */
    fun mediaType(b: ByteArray, f: C2paFormat): String = when (f) {
        C2paFormat.BMFF -> C2paBmff.mediaType(b)
        C2paFormat.ZIP -> C2paZip.mediaType(b)
        else -> f.mediaType
    }

    /** The manifest store of [b] and where it is, or null when there is none. */
    fun locate(b: ByteArray): C2paLocated? {
        val f = detect(b) ?: return if (isSidecar(b)) C2paLocated(C2paFormat.SIDECAR, b, null, C2paFormat.SIDECAR.mediaType) else null
        val found = runCatching {
            when (f) {
                C2paFormat.JPEG -> Jpeg.locate(b)
                C2paFormat.PNG -> Png.locate(b)
                C2paFormat.WEBP, C2paFormat.WAV, C2paFormat.AVI -> Riff.locate(b)
                C2paFormat.GIF -> Gif.locate(b)
                C2paFormat.TIFF, C2paFormat.DNG -> Tiff.locate(b)
                C2paFormat.SVG -> Svg.locate(b)
                C2paFormat.MP3, C2paFormat.FLAC -> Id3.locate(b)
                C2paFormat.JXL -> Jxl.locate(b)
                C2paFormat.BMFF -> C2paBmff.locate(b)
                C2paFormat.PDF -> C2paPdf.locate(b)
                C2paFormat.ZIP -> C2paZip.locate(b)
                C2paFormat.SIDECAR -> null
            }
        }.getOrNull() ?: return null
        return C2paLocated(f, found.first, found.second, mediaType(b, f))
    }

    /** [b] without its manifest store (a PDF keeps it: a new store replaces it by incremental update). */
    fun strip(b: ByteArray, f: C2paFormat): ByteArray = when (f) {
        C2paFormat.JPEG -> Jpeg.strip(b)
        C2paFormat.PNG -> Png.strip(b)
        C2paFormat.WEBP, C2paFormat.WAV, C2paFormat.AVI -> Riff.strip(b)
        C2paFormat.GIF -> Gif.strip(b)
        C2paFormat.TIFF, C2paFormat.DNG -> Tiff.strip(b)
        C2paFormat.SVG -> Svg.strip(b)
        C2paFormat.MP3, C2paFormat.FLAC -> Id3.strip(b)
        C2paFormat.JXL -> Jxl.strip(b)
        C2paFormat.BMFF -> C2paBmff.strip(b)
        C2paFormat.ZIP -> C2paZip.strip(b)
        C2paFormat.PDF, C2paFormat.SIDECAR -> b
    }

    /**
     * Why [b] cannot take an embedded store (a sidecar is written instead), or null when it can: an encrypted or
     * certified PDF, an ID3 tag the writer would have to rewrite in another version, a ZIP64 archive.
     */
    fun cannotEmbed(b: ByteArray, f: C2paFormat): String? = when (f) {
        C2paFormat.PDF -> C2paPdf.cannotEmbed(b)
        C2paFormat.MP3, C2paFormat.FLAC -> Id3.cannotEmbed(b)
        C2paFormat.ZIP -> C2paZip.cannotEmbed(b)
        C2paFormat.SVG -> Svg.cannotEmbed(b)
        C2paFormat.TIFF, C2paFormat.DNG -> Tiff.cannotEmbed(b)
        else -> null
    }

    /**
     * [base] (without a store, as [strip] returns it) with [store] embedded. The layout depends only on the size of
     * the store, so a placeholder of the final size gives the final positions.
     */
    fun embed(base: ByteArray, f: C2paFormat, store: ByteArray): C2paLayout = when (f) {
        C2paFormat.JPEG -> Jpeg.embed(base, store)
        C2paFormat.PNG -> Png.embed(base, store)
        C2paFormat.WEBP, C2paFormat.WAV, C2paFormat.AVI -> Riff.embed(base, store)
        C2paFormat.GIF -> Gif.embed(base, store)
        C2paFormat.TIFF, C2paFormat.DNG -> Tiff.embed(base, store)
        C2paFormat.SVG -> Svg.embed(base, store)
        C2paFormat.MP3, C2paFormat.FLAC -> Id3.embed(base, store, f)
        C2paFormat.JXL -> Jxl.embed(base, store)
        C2paFormat.BMFF -> C2paBmff.embed(base, store)
        C2paFormat.PDF -> C2paPdf.embed(base, store)
        C2paFormat.ZIP -> C2paZip.embed(base, store)
        C2paFormat.SIDECAR -> C2paLayout(store, C2paRange(0, 0))
    }

    /** True when [jumbf] starts with a superbox whose description box has the C2PA store UUID (or the label c2pa). */
    internal fun isStore(jumbf: ByteArray, off: Int = 0): Boolean {
        if (off + 41 > jumbf.size || !B.at(jumbf, off + 4, "jumb") || !B.at(jumbf, off + 12, "jumd")) return false
        if (DocCryptoUtil.hex(jumbf.copyOfRange(off + 16, off + 32)).lowercase() == STORE_UUID) return true
        return B.u8(jumbf, off + 32) and 0x02 != 0 && B.at(jumbf, off + 33, "c2pa\u0000")
    }

    internal fun fail(message: String): Nothing = throw C2paContainerException(message)

    private val JXL_SIGNATURE = byteArrayOf(0, 0, 0, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87.toByte(), 0x0A)

    // ---------------------------------------------------------------- JPEG (APP11, ISO/IEC 18477-3 boxes)

    internal object Jpeg {
        private const val SEGMENT_DATA = 65525

        /** Marker segments up to the first scan: (marker, start, end). Standalone markers have no length. */
        fun segments(b: ByteArray): List<Triple<Int, Int, Int>> {
            val out = ArrayList<Triple<Int, Int, Int>>()
            var i = 2
            while (i + 4 <= b.size && B.u8(b, i) == 0xFF) {
                val marker = B.u8(b, i + 1)
                if (marker == 0xFF) { i++; continue }
                if (marker == 0x01 || marker in 0xD0..0xD7) { out.add(Triple(marker, i, i + 2)); i += 2; continue }
                if (marker == 0xDA || marker == 0xD9) break
                val len = B.u16(b, i + 2)
                if (len < 2 || i + 2 + len > b.size) break
                out.add(Triple(marker, i, i + 2 + len))
                i += 2 + len
            }
            return out
        }

        private fun isXt(b: ByteArray, s: Triple<Int, Int, Int>) = s.first == 0xEB && s.third - s.second > 16 && B.at(b, s.second + 4, "JP")

        /** Segments of the JPEG XT box instances that hold the C2PA store, by instance. */
        private fun storeSegments(b: ByteArray): List<Triple<Int, Int, Int>> {
            val byInstance = LinkedHashMap<Int, MutableList<Triple<Int, Int, Int>>>()
            for (s in segments(b)) if (isXt(b, s)) byInstance.getOrPut(B.u16(b, s.second + 6)) { ArrayList() }.add(s)
            return byInstance.values.firstOrNull { segs -> isStore(b, segs.first().second + 12) }.orEmpty()
        }

        fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
            val segs = storeSegments(b)
            if (segs.isEmpty()) return null
            val parts = segs.mapIndexed { k, s -> b.copyOfRange(s.second + 12 + if (k == 0) 0 else 8, s.third) }
            val start = segs.first().second
            return B.concat(*parts.toTypedArray()) to C2paRange(start.toLong(), (segs.last().third - start).toLong())
        }

        fun strip(b: ByteArray): ByteArray {
            val drop = storeSegments(b)
            if (drop.isEmpty()) return b
            val parts = ArrayList<ByteArray>()
            var pos = 0
            for (s in drop.sortedBy { it.second }) { parts.add(b.copyOfRange(pos, s.second)); pos = s.third }
            parts.add(b.copyOfRange(pos, b.size))
            return C2paCbor.concat(parts)
        }

        /** After SOI and the leading APP0 (JFIF) and APP1 (Exif, XMP) segments. */
        private fun insertAt(b: ByteArray): Int {
            var i = 2
            while (i + 4 <= b.size && B.u8(b, i) == 0xFF) {
                val marker = B.u8(b, i + 1)
                if (marker != 0xE0 && marker != 0xE1) break
                i += 2 + B.u16(b, i + 2)
            }
            return i
        }

        private fun instance(b: ByteArray): Int {
            val used = segments(b).filter { isXt(b, it) }.map { B.u16(b, it.second + 6) }.toSet()
            return (1..0xFFFF).first { it !in used }
        }

        /** APP11 segments: CI "JP", the box instance, a sequence number from 1, then the box (continued with its header). */
        fun app11(box: ByteArray, instance: Int): ByteArray {
            val parts = ArrayList<ByteArray>()
            var pos = 0
            var seq = 1L
            val head = box.copyOfRange(0, 8)
            while (pos < box.size) {
                val data = if (seq == 1L) {
                    val n = minOf(SEGMENT_DATA, box.size)
                    box.copyOfRange(0, n).also { pos = n }
                } else {
                    val n = minOf(SEGMENT_DATA - 8, box.size - pos)
                    (head + box.copyOfRange(pos, pos + n)).also { pos += n }
                }
                val lp = 2 + 2 + 2 + 4 + data.size
                parts.add(byteArrayOf(0xFF.toByte(), 0xEB.toByte()) + B.be16(lp) + byteArrayOf(0x4A, 0x50) + B.be16(instance) + B.be32(seq) + data)
                seq++
            }
            return C2paCbor.concat(parts)
        }

        fun embed(base: ByteArray, store: ByteArray): C2paLayout {
            val at = insertAt(base)
            val segs = app11(store, instance(base))
            return C2paLayout(B.splice(base, at, 0, segs), C2paRange(at.toLong(), segs.size.toLong()))
        }
    }

    // ---------------------------------------------------------------- PNG (caBX chunk)

    internal object Png {
        /** Chunks after the signature: (type, start, end) with end after the CRC. */
        fun chunks(b: ByteArray): List<Triple<String, Int, Int>> {
            val out = ArrayList<Triple<String, Int, Int>>()
            var i = 8
            while (i + 12 <= b.size) {
                val len = B.u32(b, i)
                if (len < 0 || i + 12 + len > b.size) break
                out.add(Triple(B.ascii(b, i + 4, 4), i, i + 12 + len.toInt()))
                i += 12 + len.toInt()
            }
            return out
        }

        fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
            val c = chunks(b).firstOrNull { it.first == "caBX" } ?: return null
            return b.copyOfRange(c.second + 8, c.third - 4) to C2paRange(c.second.toLong(), (c.third - c.second).toLong())
        }

        fun strip(b: ByteArray): ByteArray {
            val drop = chunks(b).filter { it.first == "caBX" }
            if (drop.isEmpty()) return b
            var out = b
            for (c in drop.sortedByDescending { it.second }) out = B.splice(out, c.second, c.third - c.second, ByteArray(0))
            return out
        }

        fun chunk(type: String, data: ByteArray): ByteArray {
            val t = type.encodeToByteArray()
            return B.be32(data.size.toLong()) + t + data + B.be32(Crc32.of(t + data).toLong() and 0xFFFFFFFFL)
        }

        fun embed(base: ByteArray, store: ByteArray): C2paLayout {
            val ihdr = chunks(base).firstOrNull() ?: fail("PNG without IHDR")
            val c = chunk("caBX", store)
            return C2paLayout(B.splice(base, ihdr.third, 0, c), C2paRange(ihdr.third.toLong(), c.size.toLong()))
        }
    }

    // ---------------------------------------------------------------- RIFF (WebP, WAV, AVI): C2PA chunk in the first RIFF

    internal object Riff {
        /** Chunks of the first RIFF: (id, start, data length). */
        fun chunks(b: ByteArray): List<Triple<String, Int, Int>> = walk(b).first

        /** The chunks of the first RIFF and where the last one ends with its pad byte. */
        private fun walk(b: ByteArray): Pair<List<Triple<String, Int, Int>>, Int> {
            val end = firstEnd(b)
            val out = ArrayList<Triple<String, Int, Int>>()
            var i = 12
            while (i + 8 <= end) {
                val len = B.le32(b, i + 4)
                if (len < 0 || i + 8 + len > end) break
                out.add(Triple(B.ascii(b, i, 4), i, len.toInt()))
                i = minOf(b.size, i + 8 + len.toInt() + (len.toInt() and 1))
            }
            return out to maxOf(i, minOf(end, b.size))
        }

        /** End of the first RIFF chunk (its size field plus the header, clamped to the file). */
        private fun firstEnd(b: ByteArray): Int = minOf(b.size.toLong(), 8 + B.le32(b, 4)).toInt()

        fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
            val c = chunks(b).firstOrNull { it.first == "C2PA" } ?: return null
            return b.copyOfRange(c.second + 8, c.second + 8 + c.third) to C2paRange(c.second.toLong(), (8 + c.third).toLong())
        }

        fun strip(b: ByteArray): ByteArray {
            val drop = chunks(b).filter { it.first == "C2PA" }
            if (drop.isEmpty()) return b
            var out = b
            for (c in drop.sortedByDescending { it.second }) {
                val n = minOf(8 + c.third + (c.third and 1), out.size - c.second)
                out = B.splice(out, c.second, n, ByteArray(0))
                B.putLe32(out, 4, B.le32(out, 4) - n)
            }
            return out
        }

        fun chunk(id: String, data: ByteArray): ByteArray =
            id.encodeToByteArray() + B.le32b(data.size.toLong()) + data + if (data.size and 1 == 1) byteArrayOf(0) else ByteArray(0)

        fun embed(base0: ByteArray, store: ByteArray): C2paLayout {
            val base = if (B.at(base0, 8, "WEBP")) webpExtended(base0) else base0
            // After the last chunk of the first RIFF and its pad byte (some writers leave the pad out of the size).
            val at = walk(base).second
            val c = chunk("C2PA", store)
            val out = B.splice(base, at, 0, c)
            B.putLe32(out, 4, (at - 8 + c.size).toLong())
            // The location is the chunk header and data without its pad byte, as c2pa-rs validators require.
            return C2paLayout(out, C2paRange(at.toLong(), (8 + store.size).toLong()))
        }

        /**
         * The WebP in the extended format (VP8X), which may carry other chunks: a simple lossy (VP8) or lossless (VP8L)
         * file gets a VP8X chunk with its canvas size (and the alpha flag of VP8L) in front of the image chunk.
         */
        private fun webpExtended(b: ByteArray): ByteArray {
            val first = B.ascii(b, 12, 4)
            if (first == "VP8X") return b
            val d = 20
            val (w, h, alpha) = when (first) {
                "VP8 " -> Triple(B.le16(b, d + 6) and 0x3FFF, B.le16(b, d + 8) and 0x3FFF, false)
                "VP8L" -> {
                    val bits = B.le32(b, d + 1)
                    Triple(((bits and 0x3FFF) + 1).toInt(), (((bits ushr 14) and 0x3FFF) + 1).toInt(), (bits ushr 28) and 1L == 1L)
                }
                else -> fail("WebP without a VP8, VP8L or VP8X chunk")
            }
            val vp8x = byteArrayOf((if (alpha) 0x10 else 0).toByte(), 0, 0, 0) + le24(w - 1) + le24(h - 1)
            val out = B.splice(b, 12, 0, chunk("VP8X", vp8x))
            B.putLe32(out, 4, B.le32(out, 4) + 18)
            return out
        }

        private fun le24(v: Int) = byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte())
    }

    // ---------------------------------------------------------------- GIF (Application Extension C2PA_GIF)

    internal object Gif {
        private val AUTH = byteArrayOf(0x01, 0x00, 0x00)

        /** One block: (kind, start, end). Kinds: header, LSD (with the global color table), 21xx, 2C (with LCT), TBID, 3B. */
        data class Block(val kind: String, val start: Int, val end: Int)

        fun preambleEnd(b: ByteArray): Int {
            val flags = B.u8(b, 10)
            return 13 + if (flags and 0x80 != 0) 3 * (1 shl ((flags and 0x07) + 1)) else 0
        }

        private fun subBlocksEnd(b: ByteArray, from: Int): Int {
            var i = from
            while (true) {
                if (i >= b.size) fail("GIF data sub-blocks run past the end")
                val n = B.u8(b, i)
                i += 1 + n
                if (n == 0) return i
            }
        }

        fun blocks(b: ByteArray): List<Block> {
            val out = ArrayList<Block>()
            out.add(Block("GIF89a", 0, 6))
            out.add(Block("LSD", 6, preambleEnd(b)))
            var i = preambleEnd(b)
            while (i < b.size) {
                when (B.u8(b, i)) {
                    0x21 -> {
                        val label = B.u8(b, i + 1)
                        val end = subBlocksEnd(b, i + 2)
                        val kind = when {
                            label == 0xFF && B.at(b, i + 3, "C2PA_GIF") && b.copyOfRange(i + 11, i + 14).contentEquals(AUTH) -> "C2PA"
                            else -> "21" + label.toString(16).uppercase().padStart(2, '0')
                        }
                        out.add(Block(kind, i, end))
                        i = end
                    }
                    0x2C -> {
                        val flags = B.u8(b, i + 9)
                        val descEnd = i + 10 + if (flags and 0x80 != 0) 3 * (1 shl ((flags and 0x07) + 1)) else 0
                        out.add(Block("2C", i, descEnd))
                        val end = subBlocksEnd(b, descEnd + 1)
                        out.add(Block("TBID", descEnd, end))
                        i = end
                    }
                    0x3B -> { out.add(Block("3B", i, i + 1)); i++; break }
                    else -> fail("GIF block ${B.u8(b, i)} at $i")
                }
            }
            return out
        }

        private fun data(b: ByteArray, block: Block): ByteArray {
            val parts = ArrayList<ByteArray>()
            var i = block.start + 14
            while (i < block.end) {
                val n = B.u8(b, i)
                if (n == 0) break
                parts.add(b.copyOfRange(i + 1, i + 1 + n))
                i += 1 + n
            }
            return B.concat(*parts.toTypedArray())
        }

        fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
            val block = blocks(b).firstOrNull { it.kind == "C2PA" } ?: return null
            return data(b, block) to C2paRange(block.start.toLong(), (block.end - block.start).toLong())
        }

        fun strip(b: ByteArray): ByteArray {
            var out = b
            for (block in blocks(b).filter { it.kind == "C2PA" }.sortedByDescending { it.start }) out = B.splice(out, block.start, block.end - block.start, ByteArray(0))
            return out
        }

        fun extension(store: ByteArray): ByteArray {
            val parts = ArrayList<ByteArray>()
            parts.add(byteArrayOf(0x21, 0xFF.toByte(), 0x0B) + "C2PA_GIF".encodeToByteArray() + AUTH)
            var pos = 0
            while (pos < store.size) {
                val n = minOf(255, store.size - pos)
                parts.add(byteArrayOf(n.toByte()) + store.copyOfRange(pos, pos + n))
                pos += n
            }
            parts.add(byteArrayOf(0))
            return C2paCbor.concat(parts)
        }

        fun embed(base: ByteArray, store: ByteArray): C2paLayout {
            val at = preambleEnd(base)
            val ext = extension(store)
            val out = B.splice(base, at, 0, ext)
            // GIF87a has no extension blocks: the file becomes GIF89a.
            out[4] = '9'.code.toByte()
            return C2paLayout(out, C2paRange(at.toLong(), ext.size.toLong()))
        }
    }

    // ---------------------------------------------------------------- TIFF and DNG (tag 0xCD41)

    internal object Tiff {
        const val TAG = 0xCD41
        private const val UNDEFINED = 7

        class Layout(val little: Boolean, val big: Boolean) {
            val entrySize get() = if (big) 20 else 12
            val countSize get() = if (big) 8 else 2
            val offsetSize get() = if (big) 8 else 4
        }

        class Ifd(val offset: Long, val entries: List<Entry>, val nextAt: Long, val next: Long)

        class Entry(val tag: Int, val type: Int, val count: Long, val value: Long, val raw: ByteArray)

        fun magic(b: ByteArray): Boolean = runCatching { layout(b) }.isSuccess

        fun layout(b: ByteArray): Layout {
            val little = when { B.at(b, 0, "II") -> true; B.at(b, 0, "MM") -> false; else -> fail("not TIFF") }
            val l = Layout(little, false)
            return when (u(b, l, 2, 2).toInt()) {
                42 -> l
                43 -> if (u(b, l, 4, 2) == 8L) Layout(little, true) else fail("BigTIFF offset size")
                else -> fail("not TIFF")
            }
        }

        fun u(b: ByteArray, l: Layout, o: Long, n: Int): Long {
            if (o < 0 || o + n > b.size) fail("TIFF field out of range")
            val i = o.toInt()
            return if (l.little) (0 until n).fold(0L) { acc, k -> acc or ((b[i + k].toLong() and 0xFF) shl (8 * k)) } else B.uN(b, i, n)
        }

        fun put(b: ByteArray, l: Layout, o: Long, n: Int, v: Long) {
            val i = o.toInt()
            if (l.little) for (k in 0 until n) b[i + k] = (v ushr (8 * k)).toByte() else B.putN(b, i, n, v)
        }

        fun bytes(l: Layout, n: Int, v: Long): ByteArray = ByteArray(n).also { put(it, l, 0, n, v) }

        private fun firstOffset(b: ByteArray, l: Layout) = u(b, l, if (l.big) 8 else 4, l.offsetSize)

        fun ifd(b: ByteArray, l: Layout, offset: Long): Ifd {
            val n = u(b, l, offset, l.countSize)
            if (n > 10000) fail("TIFF IFD too large")
            val entries = (0 until n.toInt()).map { k ->
                val e = offset + l.countSize + k.toLong() * l.entrySize
                val cs = if (l.big) 8 else 4
                Entry(u(b, l, e, 2).toInt(), u(b, l, e + 2, 2).toInt(), u(b, l, e + 4, cs), u(b, l, e + 4 + cs, l.offsetSize),
                    b.copyOfRange(e.toInt(), (e + l.entrySize).toInt()))
            }
            val nextAt = offset + l.countSize + n * l.entrySize
            return Ifd(offset, entries, nextAt, u(b, l, nextAt, l.offsetSize))
        }

        /** The IFD chain (pages), at most 4096 of them, without loops. */
        fun chain(b: ByteArray, l: Layout): List<Ifd> {
            val out = ArrayList<Ifd>()
            val seen = HashSet<Long>()
            var off = firstOffset(b, l)
            while (off != 0L && off < b.size && seen.add(off) && out.size < 4096) {
                val d = ifd(b, l, off)
                out.add(d)
                off = d.next
            }
            if (out.isEmpty()) fail("TIFF without IFD")
            return out
        }

        fun isDng(b: ByteArray): Boolean = runCatching { val l = layout(b); chain(b, l).first().entries.any { it.tag == 0xC612 } }.getOrDefault(false)

        /** The C2PA entry: in the last IFD (C2PA 2.4, multi-page), else in IFD0 (single page). */
        private fun c2pa(b: ByteArray, l: Layout): Pair<Ifd, Entry>? {
            val pages = chain(b, l)
            for (d in listOf(pages.last(), pages.first())) d.entries.firstOrNull { it.tag == TAG }?.let { return d to it }
            return null
        }

        fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
            val l = layout(b)
            val (_, e) = c2pa(b, l) ?: return null
            if (e.type != UNDEFINED || e.value < 0 || e.value + e.count > b.size) fail("TIFF C2PA tag")
            return b.copyOfRange(e.value.toInt(), (e.value + e.count).toInt()) to C2paRange(e.value, e.count)
        }

        fun cannotEmbed(b: ByteArray): String? = runCatching { val l = layout(b); chain(b, l); if (!l.big && b.size > 0xFFFF0000L) "TIFF over 4 GB" else null }.getOrElse { it.message }

        fun strip(b: ByteArray): ByteArray {
            val l = layout(b)
            val (d, e) = c2pa(b, l) ?: return b
            val pages = chain(b, l)
            val out = b.copyOf()
            if (d.entries.size == 1 && pages.size > 1 && d === pages.last()) {
                // A C2PA-only last IFD: the page before it ends the chain again.
                put(out, l, pages[pages.size - 2].nextAt, l.offsetSize, 0)
                // The IFD and its data at the end of the file, next to each other, are cut off.
                val ifdEnd = d.nextAt + l.offsetSize
                val tail = minOf(d.offset, e.value)
                val end = maxOf(ifdEnd, e.value + e.count)
                val adjacent = end - tail <= (ifdEnd - d.offset) + e.count + 1
                return if (end == b.size.toLong() && adjacent) out.copyOf(tail.toInt()) else out
            }
            // The entry removed from its IFD in place: the later entries and the next pointer move up.
            val kept = d.entries.filter { it.tag != TAG }
            var o = d.offset
            put(out, l, o, l.countSize, kept.size.toLong()); o += l.countSize
            for (k in kept) { k.raw.copyInto(out, o.toInt()); o += l.entrySize }
            put(out, l, o, l.offsetSize, d.next); o += l.offsetSize
            ByteArray(l.entrySize).copyInto(out, o.toInt())
            return if (e.value + e.count == b.size.toLong() && e.value > d.nextAt) out.copyOf(e.value.toInt()) else out
        }

        private fun entry(l: Layout, tag: Int, count: Long, value: Long): ByteArray =
            bytes(l, 2, tag.toLong()) + bytes(l, 2, UNDEFINED.toLong()) + bytes(l, if (l.big) 8 else 4, count) + bytes(l, l.offsetSize, value)

        /**
         * Single page: IFD0 copied to the end of the file with the C2PA entry, the header pointing to it. Several
         * pages: a new last IFD with only the C2PA entry (C2PA 2.4). The store follows the new IFD; the bytes of the
         * other entries keep their offsets.
         */
        fun embed(base: ByteArray, store: ByteArray): C2paLayout {
            val l = layout(base)
            val pages = chain(base, l)
            var out = base + if (base.size % 2 == 1) byteArrayOf(0) else ByteArray(0)
            val ifdAt = out.size.toLong()
            val single = pages.size == 1
            val others = if (single) pages.first().entries.map { it.tag to it.raw } else emptyList()
            val count = others.size + 1
            val ifdSize = l.countSize + count * l.entrySize + l.offsetSize
            val dataAt = ifdAt + ifdSize
            val c2pa = TAG to entry(l, TAG, store.size.toLong(), dataAt)
            val sorted = (others + c2pa).sortedBy { it.first }
            val ifd = bytes(l, l.countSize, count.toLong()) + C2paCbor.concat(sorted.map { it.second }) +
                bytes(l, l.offsetSize, if (single) pages.first().next else 0)
            out = out + ifd + store
            if (single) put(out, l, if (l.big) 8 else 4, l.offsetSize, ifdAt) else put(out, l, pages.last().nextAt, l.offsetSize, ifdAt)
            return C2paLayout(out, C2paRange(dataAt, store.size.toLong()))
        }
    }

    // ---------------------------------------------------------------- SVG (metadata/c2pa:manifest, base64)

    internal object Svg {
        const val NS = "http://c2pa.org/manifest"

        fun isSvg(b: ByteArray): Boolean {
            val head = b.copyOfRange(0, minOf(b.size, 4096)).decodeToString()
            return rootStart(head) != null
        }

        /** The root svg start tag: (start, end after '>', qualified name). */
        fun rootStart(text: String): Triple<Int, Int, String>? {
            var i = 0
            while (true) {
                i = text.indexOf('<', i)
                if (i < 0 || i + 1 >= text.length) return null
                when {
                    text.startsWith("<?", i) -> i = text.indexOf("?>", i).takeIf { it >= 0 }?.plus(2) ?: return null
                    text.startsWith("<!--", i) -> i = text.indexOf("-->", i).takeIf { it >= 0 }?.plus(3) ?: return null
                    text.startsWith("<!", i) -> i = doctypeEnd(text, i) ?: return null
                    else -> {
                        val nameEnd = (i + 1 until text.length).firstOrNull { text[it].isWhitespace() || text[it] == '>' || text[it] == '/' } ?: return null
                        val name = text.substring(i + 1, nameEnd)
                        if (name != "svg" && !name.endsWith(":svg")) return null
                        val end = tagEnd(text, nameEnd) ?: return null
                        return Triple(i, end, name)
                    }
                }
            }
        }

        private fun doctypeEnd(t: String, from: Int): Int? {
            var depth = 0
            for (k in from until t.length) when (t[k]) {
                '[' -> depth++
                ']' -> depth--
                '>' -> if (depth <= 0) return k + 1
            }
            return null
        }

        /** The index after the '>' that closes a tag, skipping quoted attribute values. */
        private fun tagEnd(t: String, from: Int): Int? {
            var q: Char? = null
            for (k in from until t.length) {
                val c = t[k]
                if (q != null) { if (c == q) q = null; continue }
                if (c == '"' || c == '\'') q = c else if (c == '>') return k + 1
            }
            return null
        }

        /** Prefixes bound to the C2PA manifest namespace in the document (c2pa is always accepted). */
        private fun prefixes(text: String): Set<String> {
            val out = HashSet<String>()
            out.add("c2pa")
            Regex("xmlns:([A-Za-z_][\\w.-]*)\\s*=\\s*([\"'])" + Regex.escape(NS) + "\\2").findAll(text).forEach { out.add(it.groupValues[1]) }
            return out
        }

        /** The manifest element: (element start, element end, text start, text end). */
        private fun element(text: String): IntArray? {
            for (p in prefixes(text)) {
                val open = "<$p:manifest>"
                val s = text.indexOf(open)
                if (s < 0) continue
                val close = "</$p:manifest>"
                val e = text.indexOf(close, s)
                if (e < 0) continue
                return intArrayOf(s, e + close.length, s + open.length, e)
            }
            return null
        }

        fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
            val text = b.decodeToString()
            val el = element(text) ?: return null
            val encoded = text.substring(el[2], el[3])
            val jumbf = Base64.Default.decode(encoded.trim())
            // Character offsets are byte offsets only up to the first non-ASCII character: count the UTF-8 bytes.
            val start = text.substring(0, el[2]).encodeToByteArray().size
            return jumbf to C2paRange(start.toLong(), encoded.encodeToByteArray().size.toLong())
        }

        fun cannotEmbed(b: ByteArray): String? {
            val r = rootStart(b.decodeToString()) ?: return "SVG without a root element"
            return if (b.decodeToString().substring(r.first, r.second).endsWith("/>")) "empty SVG" else null
        }

        fun strip(b: ByteArray): ByteArray {
            var text = b.decodeToString()
            val el = element(text) ?: return b
            text = text.removeRange(el[0], el[1])
            // An enclosing metadata element left empty goes too.
            val r = rootStart(text) ?: return text.encodeToByteArray()
            val prefix = r.third.substringBefore(":svg", "").let { if (it.isEmpty() || it == r.third) "" else "$it:" }
            val empty = "<${prefix}metadata></${prefix}metadata>"
            val at = text.indexOf(empty, r.second)
            if (at == r.second) text = text.removeRange(at, at + empty.length)
            return text.encodeToByteArray()
        }

        fun embed(base: ByteArray, store: ByteArray): C2paLayout {
            var text = base.decodeToString()
            val r = rootStart(text) ?: fail("SVG without a root element")
            var end = r.second
            if (!Regex("xmlns:c2pa\\s*=").containsMatchIn(text.substring(r.first, r.second))) {
                val insert = " xmlns:c2pa=\"$NS\""
                text = text.substring(0, end - 1) + insert + text.substring(end - 1)
                end += insert.length
            }
            val prefix = if (r.third.contains(':')) r.third.substringBefore(':') + ":" else ""
            val encoded = Base64.Default.encode(store)
            val head = "<${prefix}metadata><c2pa:manifest>"
            val element = head + encoded + "</c2pa:manifest></${prefix}metadata>"
            text = text.substring(0, end) + element + text.substring(end)
            val start = text.substring(0, end).encodeToByteArray().size + head.encodeToByteArray().size
            return C2paLayout(text.encodeToByteArray(), C2paRange(start.toLong(), encoded.length.toLong()))
        }
    }

    // ---------------------------------------------------------------- ID3v2 (MP3 and FLAC): GEOB application/c2pa

    internal object Id3 {
        private const val MIME = "application/c2pa"
        private const val MIME_OLD = "application/x-c2pa-manifest-store"

        class Frame(val id: String, val start: Int, val end: Int, val dataStart: Int)

        /** Where the ID3v2 tag at the start of [b] ends (0 when there is none). */
        fun tagEnd(b: ByteArray): Int = if (b.size >= 10 && B.at(b, 0, "ID3")) 10 + B.synchsafe(b, 6) + if (B.u8(b, 5) and 0x10 != 0) 10 else 0 else 0

        fun frames(b: ByteArray): List<Frame> {
            if (!B.at(b, 0, "ID3")) return emptyList()
            val version = B.u8(b, 3)
            val end = minOf(b.size, 10 + B.synchsafe(b, 6))
            var i = 10
            if (B.u8(b, 5) and 0x40 != 0) i += if (version == 4) B.synchsafe(b, 10) else (B.u32(b, 10).toInt() + 4)
            val out = ArrayList<Frame>()
            val header = if (version == 2) 6 else 10
            while (i + header <= end) {
                if (B.u8(b, i) == 0) break
                val id = B.ascii(b, i, if (version == 2) 3 else 4)
                val size = when (version) { 2 -> B.u24(b, i + 3); 3 -> B.u32(b, i + 4).toInt(); else -> B.synchsafe(b, i + 4) }
                if (size < 0 || i + header + size > end) break
                out.add(Frame(id, i, i + header + size, i + header))
                i += header + size
            }
            return out
        }

        /** The encapsulated object of a GEOB frame: (MIME type, offset of the object data). */
        private fun geob(b: ByteArray, f: Frame): Pair<String, Int>? {
            if (f.id != "GEOB" || f.dataStart >= f.end) return null
            val enc = B.u8(b, f.dataStart)
            var i = f.dataStart + 1
            val mimeEnd = (i until f.end).firstOrNull { b[it] == 0.toByte() } ?: return null
            val mime = B.ascii(b, i, mimeEnd - i)
            i = mimeEnd + 1
            repeat(2) { i = skipText(b, i, f.end, enc) ?: return null }
            return mime to i
        }

        private fun skipText(b: ByteArray, from: Int, end: Int, enc: Int): Int? {
            if (enc == 1 || enc == 2) {
                var i = from
                while (i + 1 < end) { if (b[i] == 0.toByte() && b[i + 1] == 0.toByte()) return i + 2; i += 2 }
                return null
            }
            return (from until end).firstOrNull { b[it] == 0.toByte() }?.plus(1)
        }

        private fun isC2pa(b: ByteArray, f: Frame): Int? {
            val (mime, data) = geob(b, f) ?: return null
            return if (mime == MIME || mime == MIME_OLD) data else null
        }

        fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
            val hits = frames(b).mapNotNull { f -> isC2pa(b, f)?.let { f to it } }
            if (hits.size != 1) return null
            val (f, data) = hits.first()
            return b.copyOfRange(data, f.end) to C2paRange(data.toLong(), (f.end - data).toLong())
        }

        fun cannotEmbed(b: ByteArray): String? {
            if (!B.at(b, 0, "ID3")) return null
            val version = B.u8(b, 3)
            return when {
                version != 3 && version != 4 -> "ID3v2.$version"
                B.u8(b, 5) and 0x80 != 0 -> "ID3 unsynchronisation"
                else -> null
            }
        }

        private fun frameBytes(version: Int, id: String, body: ByteArray): ByteArray =
            id.encodeToByteArray() + (if (version == 4) B.synchsafeBytes(body.size) else B.be32(body.size.toLong())) + byteArrayOf(0, 0) + body

        private fun tag(version: Int, frames: List<ByteArray>): ByteArray {
            val body = C2paCbor.concat(frames)
            return "ID3".encodeToByteArray() + byteArrayOf(version.toByte(), 0, 0) + B.synchsafeBytes(body.size) + body
        }

        /** The other frames of the tag, unchanged. */
        private fun kept(b: ByteArray): List<ByteArray> = frames(b).filter { isC2pa(b, it) == null }.map { b.copyOfRange(it.start, it.end) }

        fun strip(b: ByteArray): ByteArray {
            if (!B.at(b, 0, "ID3") || frames(b).none { isC2pa(b, it) != null }) return b
            val rest = kept(b)
            val audio = b.copyOfRange(tagEnd(b), b.size)
            return if (rest.isEmpty()) audio else tag(B.u8(b, 3), rest) + audio
        }

        /** A tag (the same version as before, v2.4 for a new one) with the other frames and the GEOB frame last. */
        fun embed(base: ByteArray, store: ByteArray, f: C2paFormat): C2paLayout {
            cannotEmbed(base)?.let { fail(it) }
            val version = if (B.at(base, 0, "ID3")) B.u8(base, 3) else 4
            val rest = if (B.at(base, 0, "ID3")) kept(base) else emptyList()
            val head = byteArrayOf(0) + "$MIME\u0000c2pa\u0000c2pa manifest store\u0000".encodeToByteArray()
            val frame = frameBytes(version, "GEOB", head + store)
            val t = tag(version, rest + frame)
            val audio = base.copyOfRange(tagEnd(base), base.size)
            if (f == C2paFormat.FLAC && !B.at(audio, 0, "fLaC")) fail("FLAC stream without fLaC marker")
            val dataAt = t.size - store.size
            return C2paLayout(t + audio, C2paRange(dataAt.toLong(), store.size.toLong()))
        }
    }

    // ---------------------------------------------------------------- JPEG XL (top-level jumb box)

    internal object Jxl {
        class Box(val type: String, val start: Int, val end: Int, val header: Int)

        fun boxes(b: ByteArray): List<Box> = C2paBmff.topLevel(b).map { Box(it.type, it.start.toInt(), it.end.toInt(), it.header) }

        fun isStoreBox(b: ByteArray, x: Box) = x.type == "jumb" && isStore(b, x.start)

        fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
            if (B.u8(b, 0) == 0xFF) return null
            val stores = boxes(b).filter { isStoreBox(b, it) }
            if (stores.size != 1) return null
            val x = stores.first()
            return b.copyOfRange(x.start, x.end) to C2paRange(x.start.toLong(), (x.end - x.start).toLong())
        }

        fun strip(b: ByteArray): ByteArray {
            if (B.u8(b, 0) == 0xFF) return b
            var out = b
            for (x in boxes(b).filter { isStoreBox(b, it) }.sortedByDescending { it.start }) out = B.splice(out, x.start, x.end - x.start, ByteArray(0))
            return out
        }

        /** A naked codestream wrapped in the container: signature, ftyp (brand jxl), jxlc with the codestream. */
        private fun container(b: ByteArray): ByteArray {
            if (B.u8(b, 0) != 0xFF) return b
            val sig = byteArrayOf(0, 0, 0, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87.toByte(), 0x0A)
            val ftyp = B.be32(20) + "ftypjxl ".encodeToByteArray() + B.be32(0) + "jxl ".encodeToByteArray()
            return sig + ftyp + B.be32((8 + b.size).toLong()) + "jxlc".encodeToByteArray() + b
        }

        fun embed(base0: ByteArray, store: ByteArray): C2paLayout {
            val base = container(base0)
            val list = boxes(base)
            val ftyp = list.indexOfFirst { it.type == "ftyp" }
            val codestream = list.indexOfFirst { it.type == "jxlc" || it.type == "jxlp" }
            val at = when {
                ftyp >= 0 && (codestream < 0 || ftyp < codestream) -> list.getOrNull(ftyp + 1)?.start ?: base.size
                codestream >= 0 -> list[codestream].start
                else -> 12
            }
            return C2paLayout(B.splice(base, at, 0, store), C2paRange(at.toLong(), store.size.toLong()))
        }
    }
}
