package diw.wallet.core.document.ofd

import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Shadings of GB/T 33190 drawn into pixels, the same on every platform: axial and radial gradients (with their
 * extension, repetition, reflection and the elliptical radial form) and Gouraud triangles with colours interpolated
 * across each triangle. The pixels come out as a PNG so the platform's image decoder can take them.
 */
object OfdShading {
    /**
     * ARGB pixels of [shade] on a [width] by [height] grid; [toRaster] takes the object's space to the grid (pixel
     * centres at i + 0.5). Pixels the shading does not cover are transparent. Patterns are not drawn here.
     */
    fun raster(shade: OfdShade, width: Int, height: Int, toRaster: OfdMatrix): IntArray? {
        if (width <= 0 || height <= 0) return null
        val out = IntArray(width * height)
        when (shade) {
            is OfdShade.Axial -> {
                val inv = toRaster.inverse() ?: return null
                val dx = shade.x1 - shade.x0
                val dy = shade.y1 - shade.y0
                val len2 = dx * dx + dy * dy
                if (len2 < 1e-12) return null
                val len = sqrt(len2)
                for (j in 0 until height) for (i in 0 until width) {
                    val px = inv.x(i + 0.5, j + 0.5)
                    val py = inv.y(i + 0.5, j + 0.5)
                    val t = ((px - shade.x0) * dx + (py - shade.y0) * dy) / len2
                    val u = map(t, len, shade.mapType, shade.mapUnit, shade.extendStart, shade.extendEnd) ?: continue
                    out[j * width + i] = colorAt(shade.stops, u)
                }
            }
            is OfdShade.Radial -> {
                val inv = toRaster.inverse() ?: return null
                // An elliptical shading is a circular one in a space squeezed along its major axis.
                val k = sqrt(1 - shade.eccentricity * shade.eccentricity)
                val ang = shade.angle * kotlin.math.PI / 180
                val ca = cos(ang)
                val sa = sin(ang)
                fun ux(x: Double, y: Double) = x * ca + y * sa
                fun uy(x: Double, y: Double) = (-x * sa + y * ca) / k
                val c0x = ux(shade.x0, shade.y0); val c0y = uy(shade.x0, shade.y0)
                val c1x = ux(shade.x1, shade.y1); val c1y = uy(shade.x1, shade.y1)
                val cdx = c1x - c0x; val cdy = c1y - c0y
                val dr = shade.r1 - shade.r0
                val a = cdx * cdx + cdy * cdy - dr * dr
                val span = max(abs(dr), sqrt(cdx * cdx + cdy * cdy)).takeIf { it > 1e-9 } ?: shade.r1
                for (j in 0 until height) for (i in 0 until width) {
                    val ox = inv.x(i + 0.5, j + 0.5)
                    val oy = inv.y(i + 0.5, j + 0.5)
                    val pdx = ux(ox, oy) - c0x
                    val pdy = uy(ox, oy) - c0y
                    val b = pdx * cdx + pdy * cdy + shade.r0 * dr
                    val c = pdx * pdx + pdy * pdy - shade.r0 * shade.r0
                    val candidates = if (abs(a) < 1e-12) {
                        if (abs(b) < 1e-12) continue
                        doubleArrayOf(c / (2 * b))
                    } else {
                        val disc = b * b - a * c
                        if (disc < 0) continue
                        val r = sqrt(disc)
                        doubleArrayOf((b + r) / a, (b - r) / a).also { if (it[1] > it[0]) { val s = it[0]; it[0] = it[1]; it[1] = s } }
                    }
                    var u: Double? = null
                    for (t in candidates) {
                        if (shade.r0 + t * dr < 0) continue
                        u = map(t, span, shade.mapType, shade.mapUnit, shade.extendStart, shade.extendEnd)
                        if (u != null) break
                    }
                    out[j * width + i] = colorAt(shade.stops, u ?: continue)
                }
            }
            is OfdShade.Gouraud -> {
                if (shade.extend && shade.back != null) out.fill(shade.back.argb.toInt())
                for (tri in shade.triangles) {
                    if (tri.size < 3) continue
                    val xs = DoubleArray(3) { toRaster.x(tri[it].x, tri[it].y) }
                    val ys = DoubleArray(3) { toRaster.y(tri[it].x, tri[it].y) }
                    val area = (xs[1] - xs[0]) * (ys[2] - ys[0]) - (xs[2] - xs[0]) * (ys[1] - ys[0])
                    if (abs(area) < 1e-9) continue
                    val x0 = floor(min(xs[0], min(xs[1], xs[2]))).toInt().coerceIn(0, width - 1)
                    val x1 = floor(max(xs[0], max(xs[1], xs[2]))).toInt().coerceIn(0, width - 1)
                    val y0 = floor(min(ys[0], min(ys[1], ys[2]))).toInt().coerceIn(0, height - 1)
                    val y1 = floor(max(ys[0], max(ys[1], ys[2]))).toInt().coerceIn(0, height - 1)
                    for (j in y0..y1) for (i in x0..x1) {
                        val px = i + 0.5
                        val py = j + 0.5
                        val w0 = ((xs[1] - px) * (ys[2] - py) - (xs[2] - px) * (ys[1] - py)) / area
                        val w1 = ((xs[2] - px) * (ys[0] - py) - (xs[0] - px) * (ys[2] - py)) / area
                        val w2 = 1 - w0 - w1
                        if (w0 < -1e-6 || w1 < -1e-6 || w2 < -1e-6) continue
                        out[j * width + i] = mix3(tri[0].color, tri[1].color, tri[2].color, w0, w1, w2)
                    }
                }
            }
            is OfdShade.Pattern -> return null
        }
        return out
    }

    /** The colour parameter for [t] along a gradient [length] long, or null outside it when it does not extend. */
    private fun map(t: Double, length: Double, mapType: String, unit: Double, extendStart: Boolean, extendEnd: Boolean): Double? {
        val type = mapType.lowercase()
        if ((type == "repeat" || type == "reflect") && unit > 1e-9) {
            val v = t * length / unit
            return if (type == "repeat") v - floor(v) else { val m = v - 2 * floor(v / 2); if (m > 1) 2 - m else m }
        }
        return when {
            t < 0 -> if (extendStart) 0.0 else null
            t > 1 -> if (extendEnd) 1.0 else null
            else -> t
        }
    }

    private fun colorAt(stops: List<OfdColorStop>, t: Double): Int {
        if (stops.isEmpty()) return 0
        if (t <= stops.first().position) return stops.first().color.argb.toInt()
        for (k in 1 until stops.size) {
            val a = stops[k - 1]
            val b = stops[k]
            if (t <= b.position) {
                val span = b.position - a.position
                val f = if (span <= 1e-12) 1.0 else (t - a.position) / span
                return mix(a.color, b.color, f)
            }
        }
        return stops.last().color.argb.toInt()
    }

    private fun mix(a: OfdColor, b: OfdColor, f: Double): Int {
        fun ch(x: Int, y: Int) = (x + (y - x) * f + 0.5).toInt().coerceIn(0, 255)
        return OfdColor(ch(a.r, b.r), ch(a.g, b.g), ch(a.b, b.b), ch(a.alpha, b.alpha)).argb.toInt()
    }

    private fun mix3(a: OfdColor, b: OfdColor, c: OfdColor, wa: Double, wb: Double, wc: Double): Int {
        fun ch(x: Int, y: Int, z: Int) = (x * wa + y * wb + z * wc + 0.5).toInt().coerceIn(0, 255)
        return OfdColor(ch(a.r, b.r, c.r), ch(a.g, b.g, c.g), ch(a.b, b.b, c.b), ch(a.alpha, b.alpha, c.alpha)).argb.toInt()
    }

    // ---------------------------------------------------------------- PNG

    /** [argb] ([width] by [height]) as a PNG file: 8 bit RGBA, stored (uncompressed) deflate blocks. */
    fun png(width: Int, height: Int, argb: IntArray): ByteArray {
        val raw = ByteArray(height * (width * 4 + 1))
        var p = 0
        for (y in 0 until height) {
            raw[p++] = 0
            for (x in 0 until width) {
                val c = argb[y * width + x]
                raw[p++] = (c shr 16).toByte(); raw[p++] = (c shr 8).toByte(); raw[p++] = c.toByte(); raw[p++] = (c ushr 24).toByte()
            }
        }
        val z = Out()
        z.byte(0x78); z.byte(0x01)
        var off = 0
        while (off < raw.size || off == 0) {
            val n = min(65535, raw.size - off)
            val last = off + n >= raw.size
            z.byte(if (last) 1 else 0)
            z.byte(n and 0xFF); z.byte(n shr 8); z.byte(n.inv() and 0xFF); z.byte((n.inv() shr 8) and 0xFF)
            z.bytes(raw, off, n)
            off += n
            if (last) break
        }
        var s1 = 1L
        var s2 = 0L
        for (b in raw) { s1 = (s1 + (b.toInt() and 0xFF)) % 65521; s2 = (s2 + s1) % 65521 }
        z.int(((s2 shl 16) or s1).toInt())
        val out = Out()
        out.bytes(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A), 0, 8)
        val ihdr = Out().apply { int(width); int(height); byte(8); byte(6); byte(0); byte(0); byte(0) }
        chunk(out, "IHDR", ihdr.toByteArray())
        chunk(out, "IDAT", z.toByteArray())
        chunk(out, "IEND", ByteArray(0))
        return out.toByteArray()
    }

    private val CRC = IntArray(256) { n ->
        var c = n
        repeat(8) { c = if (c and 1 != 0) (c ushr 1) xor 0xEDB88320.toInt() else c ushr 1 }
        c
    }

    private fun chunk(out: Out, type: String, data: ByteArray) {
        out.int(data.size)
        val t = type.encodeToByteArray()
        out.bytes(t, 0, 4)
        out.bytes(data, 0, data.size)
        var c = -1
        for (b in t + data) c = CRC[(c xor b.toInt()) and 0xFF] xor (c ushr 8)
        out.int(c.inv())
    }

    private class Out {
        private var buf = ByteArray(1024)
        private var n = 0
        private fun room(k: Int) { if (n + k > buf.size) buf = buf.copyOf(max(buf.size * 2, n + k)) }
        fun byte(v: Int) { room(1); buf[n++] = v.toByte() }
        fun int(v: Int) { byte(v ushr 24); byte(v ushr 16); byte(v ushr 8); byte(v) }
        fun bytes(b: ByteArray, off: Int, len: Int) { room(len); b.copyInto(buf, n, off, off + len); n += len }
        fun toByteArray() = buf.copyOf(n)
    }
}
