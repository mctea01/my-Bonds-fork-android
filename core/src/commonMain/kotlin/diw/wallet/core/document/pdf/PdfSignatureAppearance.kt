package diw.wallet.core.document.pdf

import diw.wallet.core.jose.PlatformCrypto
import kotlin.math.max
import kotlin.math.min

/** A picture shown in a visible signature, as straight (not premultiplied) ARGB pixels, row by row from the top. */
class PdfAppearanceImage(val width: Int, val height: Int, val argb: IntArray) {
    init {
        require(width in 1..MAX_SIDE && height in 1..MAX_SIDE) { "Image must be 1 to $MAX_SIDE pixels on each side" }
        require(argb.size == width * height) { "Pixel count does not match the size" }
    }

    companion object {
        const val MAX_SIDE = 1200
    }
}

/**
 * Where and how a signature appears on a page (ISO 32000-1 12.5.5 and 12.7.4.5). The box is given on the displayed
 * page (after /Rotate), with the origin at the top-left corner and every value a fraction of the page width or height,
 * the same convention as [PdfSignaturePlacement]. [page] is 0-based; a negative value counts from the end (-1 is the
 * last page).
 */
class PdfSignatureAppearance(
    val page: Int,
    val x: Double,
    val y: Double,
    val width: Double,
    val height: Double,
    /** Text lines, such as the signer name, the time and the reason. */
    val lines: List<String>,
    val image: PdfAppearanceImage? = null,
) {
    init {
        require(width > 0.0 && height > 0.0) { "The signature box must have an area" }
        require(x >= 0.0 && y >= 0.0 && x + width <= 1.0 + 1e-9 && y + height <= 1.0 + 1e-9) { "The signature box must lie on the page" }
        require(lines.isNotEmpty() || image != null) { "A visible signature needs text or a picture" }
    }

    companion object {
        /** Preset corners and the bottom centre, each a box of [w] by [h] page fractions with a small margin. */
        fun preset(position: Position, page: Int, lines: List<String>, image: PdfAppearanceImage? = null, w: Double = 0.36, h: Double = 0.09): PdfSignatureAppearance {
            val m = 0.04
            val (x, y) = when (position) {
                Position.TOP_LEFT -> m to m
                Position.TOP_RIGHT -> (1 - m - w) to m
                Position.BOTTOM_LEFT -> m to (1 - m - h)
                Position.BOTTOM_CENTER -> ((1 - w) / 2) to (1 - m - h)
                Position.BOTTOM_RIGHT -> (1 - m - w) to (1 - m - h)
            }
            return PdfSignatureAppearance(page, x, y, w, h, lines, image)
        }
    }

    enum class Position(val title: String) {
        BOTTOM_RIGHT("右下"), BOTTOM_CENTER("下方中央"), BOTTOM_LEFT("左下"), TOP_RIGHT("右上"), TOP_LEFT("左上"),
    }
}

/** A page of the page tree with its inherited box (CropBox, else MediaBox) and rotation. */
internal class PdfPageInfo(val ref: PdfRef, val dict: PdfDict, val box: FloatArray, val rotate: Int)

internal object PdfPages {
    /** Every page in document order (ISO 32000-1 7.7.3.3), with inherited attributes resolved. */
    fun list(pdf: PdfFile): List<PdfPageInfo> {
        val out = ArrayList<PdfPageInfo>()
        val seen = HashSet<Int>()
        fun box(d: PdfDict, key: String): FloatArray? {
            val a = pdf.array(d[key]) ?: return null
            if (a.size < 4) return null
            val v = a.map { (pdf.resolve(it) as? PdfNumber)?.double?.toFloat() ?: return null }
            return floatArrayOf(minOf(v[0], v[2]), minOf(v[1], v[3]), maxOf(v[0], v[2]), maxOf(v[1], v[3]))
        }
        fun walk(node: PdfObject?, media: FloatArray?, crop: FloatArray?, rotate: Int, depth: Int) {
            if (depth > 64) return
            if (node is PdfRef && !seen.add(node.num)) return
            val d = pdf.dict(node) ?: return
            val m = box(d, "MediaBox") ?: media
            val c = box(d, "CropBox") ?: crop
            val r = ((pdf.resolve(d["Rotate"]) as? PdfNumber)?.int ?: rotate).mod(360)
            val kids = pdf.array(d["Kids"])
            if (kids != null && d.name("Type") != "Page") {
                kids.forEach { walk(it, m, c, r, depth + 1) }
            } else if (node is PdfRef) {
                out.add(PdfPageInfo(node, d, c ?: m ?: floatArrayOf(0f, 0f, 612f, 792f), r))
            }
        }
        walk(pdf.catalog["Pages"], null, null, 0, 0)
        return out
    }
}

/**
 * Builds the widget rectangle and the normal appearance stream of a visible signature. Text uses the predefined
 * Adobe-CNS1 font MSung-Light with the UniCNS-UTF16-H CMap (ISO 32000-1 9.7.5.2, 9.10.2), which readers supply
 * without embedding, so Chinese names render without shipping a font file.
 */
internal object PdfAppearanceBuilder {
    class Objects(val rect: List<Double>, val form: PdfDict, val content: ByteArray, val image: Pair<PdfDict, ByteArray>?, val mask: Pair<PdfDict, ByteArray>?)

    fun build(a: PdfSignatureAppearance, page: PdfPageInfo): Objects {
        val b = page.box
        val pw = (b[2] - b[0]).toDouble().takeIf { it > 0 } ?: 612.0
        val ph = (b[3] - b[1]).toDouble().takeIf { it > 0 } ?: 792.0
        val rot = page.rotate
        val turned = rot == 90 || rot == 270
        // Box size in the displayed orientation, in points.
        val bw = a.width * (if (turned) ph else pw)
        val bh = a.height * (if (turned) pw else ph)
        // Displayed corners (top-left normalized) back to unrotated normalized, then to user space.
        val corners = listOf(a.x to a.y, a.x + a.width to a.y, a.x + a.width to a.y + a.height, a.x to a.y + a.height).map { (dx, dy) ->
            val (nx, ny) = when (rot) {
                90 -> dy to (1 - dx)
                180 -> (1 - dx) to (1 - dy)
                270 -> (1 - dy) to dx
                else -> dx to dy
            }
            (b[0] + nx * pw) to (b[3] - ny * ph)
        }
        val rect = listOf(corners.minOf { it.first }, corners.minOf { it.second }, corners.maxOf { it.first }, corners.maxOf { it.second })

        val pad = min(bw, bh) * 0.06
        val sb = StringBuilder()
        sb.append("q 0.2 0.25 0.6 RG 0.6 w ").append(n(0.3)).append(' ').append(n(0.3)).append(' ')
            .append(n(bw - 0.6)).append(' ').append(n(bh - 0.6)).append(" re S Q\n")
        var textLeft = pad
        val imageObj = a.image?.let { img ->
            // The picture takes the left part (up to 40 %, or the whole box without text), keeping its aspect ratio.
            val areaW = if (a.lines.isEmpty()) bw - 2 * pad else (bw - 2 * pad) * 0.4
            val areaH = bh - 2 * pad
            val scale = min(areaW / img.width, areaH / img.height)
            val iw = img.width * scale
            val ih = img.height * scale
            val ix = pad + (areaW - iw) / 2
            val iy = pad + (areaH - ih) / 2
            sb.append("q ").append(n(iw)).append(" 0 0 ").append(n(ih)).append(' ').append(n(ix)).append(' ').append(n(iy)).append(" cm /Im1 Do Q\n")
            textLeft = pad + areaW + pad
            img
        }
        if (a.lines.isNotEmpty()) {
            val availW = bw - textLeft - pad
            val availH = bh - 2 * pad
            val ems = a.lines.maxOf { em(it) }.coerceAtLeast(1.0)
            val size = min(availH / (a.lines.size * LEADING), availW / ems).coerceIn(2.0, 14.0)
            val block = a.lines.size * size * LEADING
            var baseline = pad + (availH + block) / 2 - size * ASCENT
            sb.append("BT /F1 ").append(n(size)).append(" Tf 0.1 0.1 0.1 rg\n")
            for (line in a.lines) {
                sb.append("1 0 0 1 ").append(n(textLeft)).append(' ').append(n(baseline)).append(" Tm ")
                PdfWriter.hex(utf16(line), sb)
                sb.append(" Tj\n")
                baseline -= size * LEADING
            }
            sb.append("ET\n")
        }

        val matrix = when (rot) {
            90 -> listOf(0, 1, -1, 0, 0, 0)
            180 -> listOf(-1, 0, 0, -1, 0, 0)
            270 -> listOf(0, -1, 1, 0, 0, 0)
            else -> listOf(1, 0, 0, 1, 0, 0)
        }
        val content = sb.toString().encodeToByteArray()
        val resources = LinkedHashMap<String, PdfObject>()
        if (a.lines.isNotEmpty()) resources["Font"] = PdfDict.of("F1" to font())
        val form = PdfDict.of(
            "Type" to PdfName("XObject"), "Subtype" to PdfName("Form"),
            "BBox" to PdfArray(listOf(PdfNumber.of(0), PdfNumber.of(0), num(bw), num(bh))),
            "Matrix" to PdfArray(matrix.map { PdfNumber.of(it) }),
            "Resources" to PdfDict(resources),
        )
        var image: Pair<PdfDict, ByteArray>? = null
        var mask: Pair<PdfDict, ByteArray>? = null
        imageObj?.let { img ->
            val rgb = ByteArray(img.width * img.height * 3)
            val alpha = ByteArray(img.width * img.height)
            var opaque = true
            for (i in img.argb.indices) {
                val p = img.argb[i]
                rgb[i * 3] = (p shr 16).toByte(); rgb[i * 3 + 1] = (p shr 8).toByte(); rgb[i * 3 + 2] = p.toByte()
                val al = (p ushr 24)
                alpha[i] = al.toByte()
                if (al != 0xFF) opaque = false
            }
            fun dict(cs: String) = PdfDict.of(
                "Type" to PdfName("XObject"), "Subtype" to PdfName("Image"), "Width" to PdfNumber.of(img.width), "Height" to PdfNumber.of(img.height),
                "ColorSpace" to PdfName(cs), "BitsPerComponent" to PdfNumber.of(8), "Filter" to PdfName("FlateDecode"),
            )
            image = dict("DeviceRGB") to PlatformCrypto.deflate(rgb)
            if (!opaque) mask = dict("DeviceGray") to PlatformCrypto.deflate(alpha)
        }
        return Objects(rect, form, content, image, mask)
    }

    /** The Type 0 font: MSung-Light, Adobe-CNS1, proportional Latin (CIDs 1 to 95) at half width. */
    private fun font(): PdfDict {
        val descriptor = PdfDict.of(
            "Type" to PdfName("FontDescriptor"), "FontName" to PdfName(FONT), "Flags" to PdfNumber.of(6),
            "FontBBox" to PdfArray(listOf(-160, -249, 1015, 1071).map { PdfNumber.of(it) }), "ItalicAngle" to PdfNumber.of(0),
            "Ascent" to PdfNumber.of(880), "Descent" to PdfNumber.of(-120), "CapHeight" to PdfNumber.of(880), "StemV" to PdfNumber.of(93),
        )
        val cid = PdfDict.of(
            "Type" to PdfName("Font"), "Subtype" to PdfName("CIDFontType0"), "BaseFont" to PdfName(FONT),
            "CIDSystemInfo" to PdfDict.of("Registry" to PdfString("Adobe".encodeToByteArray(), false), "Ordering" to PdfString("CNS1".encodeToByteArray(), false), "Supplement" to PdfNumber.of(4)),
            "FontDescriptor" to descriptor, "DW" to PdfNumber.of(1000),
            "W" to PdfArray(listOf(PdfNumber.of(1), PdfNumber.of(95), PdfNumber.of(500))),
        )
        return PdfDict.of(
            "Type" to PdfName("Font"), "Subtype" to PdfName("Type0"), "BaseFont" to PdfName(FONT),
            "Encoding" to PdfName("UniCNS-UTF16-H"), "DescendantFonts" to PdfArray(listOf(cid)),
        )
    }

    /** Width in ems: printable ASCII is half width, everything else full width. */
    internal fun em(s: String): Double = s.sumOf { c -> if (c.code in 0x20..0x7E) 0.5 else if (c.isLowSurrogate()) 0.0 else 1.0 }

    private fun utf16(s: String): ByteArray {
        val out = ByteArray(s.length * 2)
        s.forEachIndexed { i, c -> out[i * 2] = (c.code shr 8).toByte(); out[i * 2 + 1] = c.code.toByte() }
        return out
    }

    private fun num(v: Double) = PdfNumber(n(v))
    private fun n(v: Double): String {
        val r = kotlin.math.round(max(-1e7, min(1e7, v)) * 100) / 100
        return if (r == kotlin.math.floor(r)) r.toLong().toString() else r.toString()
    }

    private const val FONT = "MSung-Light"
    private const val LEADING = 1.25
    private const val ASCENT = 0.88
}
