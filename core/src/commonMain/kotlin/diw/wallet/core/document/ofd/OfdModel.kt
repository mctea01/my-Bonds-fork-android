package diw.wallet.core.document.ofd

import kotlin.math.abs
import kotlin.math.sqrt

/**
 * A 2D affine transform in the OFD (GB/T 33190) order, a row vector times the matrix:
 * x' = a x + c y + e, y' = b x + d y + f. Units are millimetres, y grows downwards.
 */
data class OfdMatrix(val a: Double, val b: Double, val c: Double, val d: Double, val e: Double, val f: Double) {
    /** This transform first, then [o]. */
    fun then(o: OfdMatrix) = OfdMatrix(
        a * o.a + b * o.c, a * o.b + b * o.d,
        c * o.a + d * o.c, c * o.b + d * o.d,
        e * o.a + f * o.c + o.e, e * o.b + f * o.d + o.f,
    )

    fun x(x: Double, y: Double) = a * x + c * y + e
    fun y(x: Double, y: Double) = b * x + d * y + f

    /** The factor lengths are scaled by (the square root of the determinant). */
    val scale: Double get() = sqrt(abs(a * d - b * c))

    /** True when the transform only scales and moves (no rotation or skew). */
    val axisAligned: Boolean get() = abs(b) < 1e-9 && abs(c) < 1e-9

    companion object {
        val IDENTITY = OfdMatrix(1.0, 0.0, 0.0, 1.0, 0.0, 0.0)
        fun translate(x: Double, y: Double) = OfdMatrix(1.0, 0.0, 0.0, 1.0, x, y)
        fun scale(sx: Double, sy: Double) = OfdMatrix(sx, 0.0, 0.0, sy, 0.0, 0.0)

        /** "a b c d e f"; anything else is the identity. */
        fun parse(s: String?): OfdMatrix {
            val n = OfdNumbers.list(s)
            return if (n.size == 6) OfdMatrix(n[0], n[1], n[2], n[3], n[4], n[5]) else IDENTITY
        }
    }
}

/** A rectangle "x y w h" in millimetres. */
data class OfdBox(val x: Double, val y: Double, val w: Double, val h: Double) {
    companion object {
        fun parse(s: String?): OfdBox? {
            val n = OfdNumbers.list(s)
            return if (n.size == 4 && n[2] > 0 && n[3] > 0) OfdBox(n[0], n[1], n[2], n[3]) else null
        }

        /** A4 portrait, the page size when a document gives none. */
        val A4 = OfdBox(0.0, 0.0, 210.0, 297.0)
    }
}

/** A colour as 8 bit sRGB with alpha (0 transparent, 255 opaque). */
data class OfdColor(val r: Int, val g: Int, val b: Int, val alpha: Int = 255) {
    /** 0xAARRGGBB. */
    val argb: Long get() = (alpha.toLong() shl 24) or (r.toLong() shl 16) or (g.toLong() shl 8) or b.toLong()

    fun withAlpha(a: Int) = copy(alpha = a.coerceIn(0, 255))

    companion object {
        val BLACK = OfdColor(0, 0, 0)
    }
}

/** One segment of a path, all coordinates in the object's own space. Arcs are already turned into cubic curves. */
sealed class OfdPathCommand {
    data class Move(val x: Double, val y: Double) : OfdPathCommand()
    data class Line(val x: Double, val y: Double) : OfdPathCommand()
    data class Quad(val x1: Double, val y1: Double, val x: Double, val y: Double) : OfdPathCommand()
    data class Cubic(val x1: Double, val y1: Double, val x2: Double, val y2: Double, val x: Double, val y: Double) : OfdPathCommand()
    data object Close : OfdPathCommand()
}

/** One TextCode: where it starts in the object's space (null to continue after the previous one), the offsets of the characters after the first, and the text. */
data class OfdTextCode(
    val x: Double?,
    val y: Double?,
    val deltaX: List<Double>,
    val deltaY: List<Double>,
    val text: String,
)

/** A character placed on the page (millimetres, page space): [x], [y] is the start of its baseline, [size] the font size there. */
data class OfdGlyph(val x: Double, val y: Double, val size: Double, val width: Double, val text: String, val objectId: String?)

/**
 * A drawable object of a page, in page space through [matrix] (the object's CTM, then its boundary's origin and
 * any enclosing appearance or composite unit). [clip] is the boundary in page space when the transform is axis aligned.
 */
sealed class OfdObject {
    abstract val id: String?
    abstract val matrix: OfdMatrix
    abstract val alpha: Int

    data class Text(
        override val id: String?,
        override val matrix: OfdMatrix,
        override val alpha: Int,
        val font: OfdFont?,
        val size: Double,
        val fill: OfdColor?,
        val stroke: OfdColor?,
        val hScale: Double,
        val weight: Int,
        val italic: Boolean,
        val readDirection: Int,
        val charDirection: Int,
        val codes: List<OfdTextCode>,
    ) : OfdObject() {
        /** Every character with its place on the page. */
        fun glyphs(): List<OfdGlyph> {
            val out = ArrayList<OfdGlyph>()
            var cx = 0.0
            var cy = 0.0
            val pageSize = size * matrix.scale
            for (code in codes) {
                if (code.x != null) cx = code.x
                if (code.y != null) cy = code.y
                val chars = OfdNumbers.codePoints(code.text)
                val vertical = readDirection == 90 || readDirection == 270
                for ((i, ch) in chars.withIndex()) {
                    // DeltaX and DeltaY give the offset to the next character; without them the font's advance applies.
                    val natural = (if (OfdNumbers.isWide(ch)) size else size * 0.55) * hScale
                    val dx = code.deltaX.getOrNull(i) ?: if (vertical) 0.0 else if (readDirection == 180) -natural else natural
                    val dy = code.deltaY.getOrNull(i) ?: if (!vertical) 0.0 else if (readDirection == 270) -size else size
                    val width = if (vertical || abs(dx) < 1e-9) natural else abs(dx)
                    out.add(OfdGlyph(matrix.x(cx, cy), matrix.y(cx, cy), pageSize, width * matrix.scale, ch, id))
                    // After the last character this is where a following TextCode without X or Y continues.
                    cx += dx
                    cy += dy
                }
            }
            return out
        }
    }

    data class Path(
        override val id: String?,
        override val matrix: OfdMatrix,
        override val alpha: Int,
        val commands: List<OfdPathCommand>,
        val fill: OfdColor?,
        val stroke: OfdColor?,
        val lineWidth: Double,
        val evenOdd: Boolean,
        val cap: String,
        val join: String,
        val dash: List<Double>,
    ) : OfdObject()

    data class Image(
        override val id: String?,
        override val matrix: OfdMatrix,
        override val alpha: Int,
        val media: OfdMedia?,
    ) : OfdObject()
}

/** A font resource; [file] is the embedded font program when the document carries one. */
data class OfdFont(
    val id: String,
    val name: String,
    val family: String?,
    val bold: Boolean,
    val italic: Boolean,
    val serif: Boolean,
    val fixedWidth: Boolean,
    val file: ByteArray?,
) {
    /** A generic family to draw with when the embedded font cannot be used: serif, sans-serif or monospace. */
    val generic: String get() {
        val n = (name + " " + family.orEmpty()).lowercase()
        return when {
            fixedWidth || "courier" in n || "mono" in n || "consol" in n -> "monospace"
            "hei" in n || "黑" in n || "sans" in n || "arial" in n || "helvetica" in n || "yahei" in n || "雅黑" in n || "gothic" in n -> "sans-serif"
            "song" in n || "宋" in n || "kai" in n || "楷" in n || "fang" in n || "仿" in n || "ming" in n || "明" in n || "times" in n || "serif" in n || serif -> "serif"
            else -> "serif"
        }
    }

    override fun equals(other: Any?) = other is OfdFont && other.id == id && other.name == name
    override fun hashCode() = id.hashCode() * 31 + name.hashCode()
}

/** A multimedia resource (an image); [format] as declared or detected (PNG, JPEG, BMP, GIF, TIFF, JB2, OFD). */
class OfdMedia(val id: String, val format: String, val bytes: ByteArray, val path: String)

/** A page: its size and everything drawn on it in order (templates, layers, then annotations). */
data class OfdPage(
    val id: String,
    val index: Int,
    val box: OfdBox,
    val objects: List<OfdObject>,
    /** The ID of each TextObject on the page with its text (for custom tags that point at objects). */
    val texts: Map<String, String>,
)

/** A file the document carries as an attachment (such as the XML of an invoice). */
data class OfdAttachment(
    val id: String?,
    val name: String,
    val format: String?,
    val creationDate: String?,
    val path: String,
    val bytes: ByteArray?,
)

/** A custom tag file (GB/T 33190 section 16): its namespace and the values it gives, by element name. */
data class OfdCustomTag(val namespace: String?, val path: String, val values: List<Pair<String, String>>)

/** Metadata of a document (DocInfo). */
data class OfdDocInfo(
    val docId: String?,
    val title: String?,
    val author: String?,
    val subject: String?,
    val creator: String?,
    val creationDate: String?,
    val custom: List<Pair<String, String>>,
)

/** One document of an OFD package. */
data class OfdDocument(
    val root: String,
    val info: OfdDocInfo,
    val pages: List<OfdPage>,
    val attachments: List<OfdAttachment>,
    val tags: List<OfdCustomTag>,
    /** Signatures.xml of this document, when it is signed. */
    val signatures: String?,
) {
    /** Values of every custom tag, by element name (the first value of each name). */
    fun tagValues(): Map<String, String> = LinkedHashMap<String, String>().also { m ->
        tags.forEach { t -> t.values.forEach { (k, v) -> if (k !in m) m[k] = v } }
    }
}

internal object OfdNumbers {
    private val split = Regex("[\\s,]+")

    fun list(s: String?): List<Double> = s?.trim()?.takeIf { it.isNotEmpty() }?.split(split)?.mapNotNull { it.toDoubleOrNull() }.orEmpty()

    /** DeltaX / DeltaY: numbers, where "g N v" stands for N times v. */
    fun deltas(s: String?): List<Double> {
        val t = s?.trim()?.takeIf { it.isNotEmpty() }?.split(split) ?: return emptyList()
        val out = ArrayList<Double>()
        var i = 0
        while (i < t.size) {
            if (t[i] == "g" && i + 2 < t.size) {
                val n = t[i + 1].toIntOrNull() ?: 0
                val v = t[i + 2].toDoubleOrNull() ?: 0.0
                repeat(n.coerceIn(0, 100_000)) { out.add(v) }
                i += 3
            } else {
                t[i].toDoubleOrNull()?.let { out.add(it) }
                i++
            }
        }
        return out
    }

    /** The characters of [s] (surrogate pairs kept together). */
    fun codePoints(s: String): List<String> {
        val out = ArrayList<String>()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate()) { out.add(s.substring(i, i + 2)); i += 2 }
            else { out.add(c.toString()); i++ }
        }
        return out
    }

    /** CJK, full-width forms and the like take a full em. */
    fun isWide(ch: String): Boolean {
        val c = ch.firstOrNull() ?: return false
        return c.code >= 0x2E80 || c.isHighSurrogate()
    }
}

/**
 * Where a signature's seal shows on a page (the StampAnnot of Signature.xml) with the seal picture from the
 * electronic seal: [pictureFormat] as the seal names it (png, jpg, gif, bmp, svg, ofd), null for a digital
 * signature without a seal picture. [label] is the label of the signature in the document report.
 */
class OfdStamp(
    val label: String,
    val pageId: String,
    val boundary: OfdBox,
    val clip: OfdBox?,
    val pictureFormat: String?,
    val picture: ByteArray?,
)
