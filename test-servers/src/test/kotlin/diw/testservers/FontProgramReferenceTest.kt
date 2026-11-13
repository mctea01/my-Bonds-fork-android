package diw.testservers

import diw.wallet.core.document.ofd.FontProgram
import diw.wallet.core.document.ofd.OfdPathCommand
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.double
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.math.abs
import kotlin.math.max
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Compares glyph outlines with reference values from another font library: DIW_FONT_REF names a JSON list of fonts
 * ({path, index, upem, count, cmap: {codePoint: glyph}, glyphs: [{id, bounds, area}]}). Skipped without it.
 */
class FontProgramReferenceTest {
    @Test
    fun matchesReferenceOutlines() {
        val ref = System.getenv("DIW_FONT_REF")?.let { File(it) } ?: return
        val failures = ArrayList<String>()
        var checked = 0
        for (font in Json.parseToJsonElement(ref.readText()).jsonArray) {
            val o = font.jsonObject
            val path = o["path"]!!.jsonPrimitive.content
            val p = FontProgram.parse(File(path).readBytes())
            if (p == null) { failures.add("$path: not parsed"); continue }
            if (p.unitsPerEm != o["upem"]!!.jsonPrimitive.int) failures.add("$path: upem ${p.unitsPerEm}")
            for ((cp, gid) in o["cmap"]!!.jsonObject) {
                val got = p.glyphId(cp.toInt())
                if (got != gid.jsonPrimitive.int) failures.add("$path: cmap $cp -> $got, expected $gid")
            }
            for (g in o["glyphs"]!!.jsonArray) {
                val e = g.jsonObject
                val id = e["id"]!!.jsonPrimitive.int
                val cmds = p.outline(id)
                val bounds = e["bounds"]
                checked++
                if (bounds == null || bounds is JsonNull) {
                    if (cmds.any { it !is OfdPathCommand.Close && it !is OfdPathCommand.Move }) failures.add("$path #$id: expected empty")
                    continue
                }
                val b = (bounds as JsonArray).map { it.jsonPrimitive.double }
                val (ours, area) = measure(cmds)
                if (ours == null) { failures.add("$path #$id: empty outline"); continue }
                val tol = max(1.5, (b[2] - b[0] + b[3] - b[1]) * 0.002)
                if ((0..3).any { abs(ours[it] - b[it]) > tol }) failures.add("$path #$id: bounds ${ours.toList()} vs $b")
                val expected = e["area"]!!.jsonPrimitive.double
                // AreaPen counts counter-clockwise as positive; the sign depends on the outline direction convention.
                if (abs(abs(area) - abs(expected)) > max(4.0, abs(expected) * 0.01)) failures.add("$path #$id: area $area vs $expected")
            }
        }
        println("font reference: $checked glyphs, ${failures.size} failures")
        failures.take(30).forEach { println(it) }
        assertTrue(failures.isEmpty(), failures.take(10).joinToString("\n"))
    }

    /** Exact-enough bounds and shoelace area of the flattened outline. */
    private fun measure(cmds: List<OfdPathCommand>): Pair<DoubleArray?, Double> {
        var minX = Double.MAX_VALUE; var minY = Double.MAX_VALUE; var maxX = -Double.MAX_VALUE; var maxY = -Double.MAX_VALUE
        var area = 0.0
        var sx = 0.0; var sy = 0.0; var cx = 0.0; var cy = 0.0
        var any = false
        fun point(x: Double, y: Double) {
            minX = minOf(minX, x); maxX = maxOf(maxX, x); minY = minOf(minY, y); maxY = maxOf(maxY, y); any = true
            area += cx * y - x * cy
            cx = x; cy = y
        }
        fun close() { area += cx * sy - sx * cy; cx = sx; cy = sy }
        val steps = 64
        for (c in cmds) when (c) {
            is OfdPathCommand.Move -> {
                close(); sx = c.x; sy = c.y; cx = c.x; cy = c.y
                minX = minOf(minX, c.x); maxX = maxOf(maxX, c.x); minY = minOf(minY, c.y); maxY = maxOf(maxY, c.y)
            }
            is OfdPathCommand.Line -> point(c.x, c.y)
            is OfdPathCommand.Quad -> {
                val x0 = cx; val y0 = cy
                for (i in 1..steps) {
                    val t = i.toDouble() / steps; val u = 1 - t
                    point(u * u * x0 + 2 * u * t * c.x1 + t * t * c.x, u * u * y0 + 2 * u * t * c.y1 + t * t * c.y)
                }
            }
            is OfdPathCommand.Cubic -> {
                val x0 = cx; val y0 = cy
                for (i in 1..steps) {
                    val t = i.toDouble() / steps; val u = 1 - t
                    point(
                        u * u * u * x0 + 3 * u * u * t * c.x1 + 3 * u * t * t * c.x2 + t * t * t * c.x,
                        u * u * u * y0 + 3 * u * u * t * c.y1 + 3 * u * t * t * c.y2 + t * t * t * c.y,
                    )
                }
            }
            OfdPathCommand.Close -> close()
        }
        close()
        return (if (any) doubleArrayOf(minX, minY, maxX, maxY) else null) to area / 2
    }
}
