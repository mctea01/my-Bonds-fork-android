package diw.wallet.app

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Canvas
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Matrix
import androidx.compose.ui.graphics.Paint
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.PathOperation
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.CanvasDrawScope
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.DrawStyle
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.sp
import diw.wallet.core.document.ofd.FontProgram
import diw.wallet.core.document.ofd.OfdClip
import diw.wallet.core.document.ofd.OfdColor
import diw.wallet.core.document.ofd.OfdGlyph
import diw.wallet.core.document.ofd.OfdMatrix
import diw.wallet.core.document.ofd.OfdMedia
import diw.wallet.core.document.ofd.OfdObject
import diw.wallet.core.document.ofd.OfdPage
import diw.wallet.core.document.ofd.OfdPathCommand
import diw.wallet.core.document.ofd.OfdShade
import diw.wallet.core.document.ofd.OfdShading
import kotlin.math.PI
import kotlin.math.atan2
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * Draws OFD pages (read by [diw.wallet.core.document.ofd.OfdPackage]) with Compose graphics, the same on Android
 * and the desktop: paths with their fill rule, line width, caps, joins, miter limit and dashes; shadings (axial,
 * radial, Gouraud) and patterns as fills and strokes; clipping areas (paths and text); images through the platform
 * decoder (JBIG2 and TIFF converted first); text with the document's embedded font (TrueType or CFF outlines,
 * CGTransform glyph indices), or with the system's serif, sans-serif or monospace family closest to the named font
 * when the document carries none. Seals are drawn by the caller through [Overlay].
 */
class OfdRenderer(
    /** Text without an embedded font is left out without a resolver (the platform gives one). */
    private val fonts: FontFamily.Resolver?,
    /** Decodes an image resource; null when it cannot be shown. */
    private val image: (OfdMedia) -> ImageBitmap?,
) {
    /** A picture drawn over the page at [x], [y] (millimetres, page space) [w] by [h], such as a seal. */
    class Overlay(val picture: ImageBitmap, val x: Double, val y: Double, val w: Double, val h: Double)

    private val measurer = fonts?.let { TextMeasurer(it, Density(1f), LayoutDirection.Ltr, CACHE) }
    private val layouts = HashMap<String, TextLayoutResult>()
    private val decoded = HashMap<String, ImageBitmap?>()
    private val programs = HashMap<String, FontProgram?>()
    private var canvasSize = Size.Zero

    /** [page] as an image [widthPx] wide, with [overlays] on top; on white, or transparent without [background]. */
    fun render(page: OfdPage, widthPx: Int, overlays: List<Overlay> = emptyList(), background: Boolean = true): ImageBitmap {
        val box = page.box
        val scale = widthPx / box.w
        val heightPx = (box.h * scale).roundToInt().coerceIn(1, widthPx * 4)
        val bitmap = ImageBitmap(widthPx, heightPx)
        val canvas = Canvas(bitmap)
        val device = OfdMatrix.scale(scale, scale)
        canvasSize = Size(widthPx.toFloat(), heightPx.toFloat())
        CanvasDrawScope().draw(Density(1f), LayoutDirection.Ltr, canvas, canvasSize) {
            if (background) drawRect(Color.White)
            for (o in page.objects) runCatching { draw(o, device, device, 0) }
            for (ov in overlays) {
                drawImage(
                    ov.picture, srcOffset = IntOffset.Zero, srcSize = IntSize(ov.picture.width, ov.picture.height),
                    dstOffset = IntOffset((ov.x * scale).roundToInt(), (ov.y * scale).roundToInt()),
                    dstSize = IntSize((ov.w * scale).roundToInt().coerceAtLeast(1), (ov.h * scale).roundToInt().coerceAtLeast(1)),
                    filterQuality = FilterQuality.Medium,
                )
            }
        }
        return bitmap
    }

    /** One object: [outer] takes its parent space (the page, or a pattern cell) to the device; [page] takes the page. */
    private fun DrawScope.draw(o: OfdObject, outer: OfdMatrix, page: OfdMatrix, depth: Int) {
        if (depth > 8) return
        val m = o.matrix.then(outer)
        withClips(o.clips, outer) {
            when (o) {
                is OfdObject.Path -> path(o, m, page, depth)
                is OfdObject.Image -> image(o, m)
                is OfdObject.Text -> text(o, m, page, depth)
            }
        }
    }

    private fun color(c: OfdColor, alpha: Int) = Color(
        red = c.r / 255f, green = c.g / 255f, blue = c.b / 255f,
        alpha = (c.alpha / 255f) * (alpha / 255f),
    )

    private fun build(commands: List<OfdPathCommand>, m: OfdMatrix, into: Path = Path()): Path {
        for (c in commands) when (c) {
            is OfdPathCommand.Move -> into.moveTo(m.x(c.x, c.y).toFloat(), m.y(c.x, c.y).toFloat())
            is OfdPathCommand.Line -> into.lineTo(m.x(c.x, c.y).toFloat(), m.y(c.x, c.y).toFloat())
            is OfdPathCommand.Quad -> into.quadraticTo(
                m.x(c.x1, c.y1).toFloat(), m.y(c.x1, c.y1).toFloat(), m.x(c.x, c.y).toFloat(), m.y(c.x, c.y).toFloat(),
            )
            is OfdPathCommand.Cubic -> into.cubicTo(
                m.x(c.x1, c.y1).toFloat(), m.y(c.x1, c.y1).toFloat(), m.x(c.x2, c.y2).toFloat(), m.y(c.x2, c.y2).toFloat(),
                m.x(c.x, c.y).toFloat(), m.y(c.x, c.y).toFloat(),
            )
            OfdPathCommand.Close -> into.close()
        }
        return into
    }

    // ---------------------------------------------------------------- clips

    /** Runs [block] inside every clip of an object (each the union of its areas); a clip that cannot be built is left out. */
    private fun DrawScope.withClips(clips: List<OfdClip>, outer: OfdMatrix, block: DrawScope.() -> Unit) {
        if (clips.isEmpty()) return block()
        val paths = clips.mapNotNull { clipPathOf(it, outer) }
        fun DrawScope.nest(i: Int) {
            if (i == paths.size) block() else clipPath(paths[i]) { nest(i + 1) }
        }
        nest(0)
    }

    private fun clipPathOf(clip: OfdClip, outer: OfdMatrix): Path? {
        var acc: Path? = null
        for (area in clip.areas) {
            val m = area.matrix.then(outer)
            val t = area.text
            val p = if (t != null) glyphPath(t, t.matrix.then(outer)) ?: continue
            else build(area.commands, m).also { it.fillType = if (area.evenOdd) PathFillType.EvenOdd else PathFillType.NonZero }
            acc = if (acc == null) p else Path().also { it.op(acc!!, p, PathOperation.Union) }
        }
        return acc
    }

    // ---------------------------------------------------------------- paths, shadings, patterns

    private fun DrawScope.path(o: OfdObject.Path, m: OfdMatrix, page: OfdMatrix, depth: Int) {
        val p = build(o.commands, m)
        p.fillType = if (o.evenOdd) PathFillType.EvenOdd else PathFillType.NonZero
        o.fill?.let { fill ->
            val shade = o.fillShade
            if (shade != null) shaded(p, Fill, 0f, shade, m, page, o.alpha, depth) else drawPath(p, color(fill, o.alpha), style = Fill)
        }
        o.stroke?.let { stroke ->
            val width = max(1f, (o.lineWidth * m.scale).toFloat())
            val dash = o.dash.takeIf { d -> d.size >= 2 && d.all { v -> v >= 0 } && d.any { v -> v > 0 } }
                ?.map { v -> max(0.01f, (v * m.scale).toFloat()) }?.let { if (it.size % 2 == 1) it + it else it }?.toFloatArray()
            val style = Stroke(
                width = width,
                miter = o.miterLimit.toFloat().coerceAtLeast(1f),
                cap = when (o.cap.lowercase()) { "round" -> StrokeCap.Round; "square" -> StrokeCap.Square; else -> StrokeCap.Butt },
                join = when (o.join.lowercase()) { "round" -> StrokeJoin.Round; "bevel" -> StrokeJoin.Bevel; else -> StrokeJoin.Miter },
                pathEffect = dash?.let { d -> PathEffect.dashPathEffect(d) },
            )
            val shade = o.strokeShade
            if (shade != null) shaded(p, style, width * o.miterLimit.toFloat(), shade, m, page, o.alpha, depth) else drawPath(p, color(stroke, o.alpha), style = style)
        }
    }

    /** Fills or strokes [mask] with [shade]: the shape is drawn into a layer, then the shading through it. */
    private fun DrawScope.shaded(mask: Path, style: DrawStyle, grow: Float, shade: OfdShade, m: OfdMatrix, page: OfdMatrix, alpha: Int, depth: Int) {
        val b = mask.getBounds().inflate(grow / 2 + 1f)
        val bounds = Rect(max(0f, b.left), max(0f, b.top), min(canvasSize.width, b.right), min(canvasSize.height, b.bottom))
        if (bounds.width <= 0f || bounds.height <= 0f) return
        drawIntoCanvas { canvas ->
            canvas.saveLayer(bounds, Paint())
            drawPath(mask, Color.Black, style = style)
            canvas.saveLayer(bounds, Paint().also { it.blendMode = BlendMode.SrcIn; it.alpha = alpha / 255f })
            if (shade is OfdShade.Pattern) pattern(shade, m, page, bounds, depth)
            else raster(shade, m, bounds)
            canvas.restore()
            canvas.restore()
        }
    }

    private fun DrawScope.raster(shade: OfdShade, m: OfdMatrix, bounds: Rect) {
        val w = ceil(bounds.width).toInt()
        val h = ceil(bounds.height).toInt()
        val f = max(1.0, max(w, h) / MAX_SHADE.toDouble())
        val rw = max(1, (w / f).toInt())
        val rh = max(1, (h / f).toInt())
        val toRaster = m.then(OfdMatrix.translate(-bounds.left.toDouble(), -bounds.top.toDouble())).then(OfdMatrix.scale(rw / bounds.width.toDouble(), rh / bounds.height.toDouble()))
        val pixels = OfdShading.raster(shade, rw, rh, toRaster) ?: return
        val bmp = image(OfdMedia("shade", "PNG", OfdShading.png(rw, rh, pixels), "")) ?: return
        drawImage(
            bmp, srcOffset = IntOffset.Zero, srcSize = IntSize(bmp.width, bmp.height),
            dstOffset = IntOffset(bounds.left.roundToInt(), bounds.top.roundToInt()), dstSize = IntSize(w, h), filterQuality = FilterQuality.Medium,
        )
    }

    /** Pattern cells over [bounds]: each cell's objects, clipped to the cell, mirrored as ReflectMethod says. */
    private fun DrawScope.pattern(p: OfdShade.Pattern, m: OfdMatrix, page: OfdMatrix, bounds: Rect, depth: Int) {
        val base = p.matrix.then(if (p.relativeToPage) page else m)
        val inv = base.inverse() ?: return
        val xs = listOf(bounds.left, bounds.right, bounds.right, bounds.left).map { it.toDouble() }
        val ys = listOf(bounds.top, bounds.top, bounds.bottom, bounds.bottom).map { it.toDouble() }
        val px = xs.indices.map { inv.x(xs[it], ys[it]) }
        val py = xs.indices.map { inv.y(xs[it], ys[it]) }
        val i0 = floor(px.min() / p.xStep).toInt() - 1
        val i1 = floor(px.max() / p.xStep).toInt() + 1
        val j0 = floor(py.min() / p.yStep).toInt() - 1
        val j1 = floor(py.max() / p.yStep).toInt() + 1
        if ((i1 - i0 + 1).toLong() * (j1 - j0 + 1) > MAX_TILES) return
        val cell = listOf(OfdPathCommand.Move(0.0, 0.0), OfdPathCommand.Line(p.width, 0.0), OfdPathCommand.Line(p.width, p.height), OfdPathCommand.Line(0.0, p.height), OfdPathCommand.Close)
        val r = p.reflect.lowercase()
        for (j in j0..j1) for (i in i0..i1) {
            var t = OfdMatrix.IDENTITY
            if ((r == "column" || r == "rowandcolumn") && i % 2 != 0) t = OfdMatrix(-1.0, 0.0, 0.0, 1.0, p.width, 0.0)
            if ((r == "row" || r == "rowandcolumn") && j % 2 != 0) t = t.then(OfdMatrix(1.0, 0.0, 0.0, -1.0, 0.0, p.height))
            val tile = t.then(OfdMatrix.translate(i * p.xStep, j * p.yStep)).then(base)
            clipPath(build(cell, OfdMatrix.translate(i * p.xStep, j * p.yStep).then(base))) {
                for (o in p.objects) runCatching { draw(o, tile, page, depth + 1) }
            }
        }
    }

    // ---------------------------------------------------------------- images

    /** An image fills the unit square of its CTM (scaled from its pixel size first). */
    private fun DrawScope.image(o: OfdObject.Image, m: OfdMatrix) {
        val media = o.media ?: return
        val bmp = decoded.getOrPut(media.id + "|" + media.path) { runCatching { image(media) }.getOrNull() } ?: return
        val unit = OfdMatrix.scale(1.0 / bmp.width, 1.0 / bmp.height).then(m)
        withTransform({ transform(matrix(unit)) }) {
            drawImage(
                bmp, srcOffset = IntOffset.Zero, srcSize = IntSize(bmp.width, bmp.height), dstOffset = IntOffset.Zero,
                dstSize = IntSize(bmp.width, bmp.height), alpha = o.alpha / 255f, filterQuality = FilterQuality.Medium,
            )
        }
    }

    // ---------------------------------------------------------------- text

    private fun program(o: OfdObject.Text): FontProgram? {
        val font = o.font ?: return null
        val file = font.file ?: return null
        return programs.getOrPut(font.id + "|" + font.name) { runCatching { FontProgram.parse(file) }.getOrNull() }
    }

    /** Font units of a glyph to the text object's space: size, horizontal scale, synthetic italic, character direction. */
    private fun glyphMatrix(o: OfdObject.Text, g: OfdGlyph, unitsPerEm: Int): OfdMatrix {
        val k = o.size / unitsPerEm
        var gm = OfdMatrix.IDENTITY
        if (o.italic && o.font?.italic != true) gm = OfdMatrix(1.0, 0.0, ITALIC_SKEW, 1.0, 0.0, 0.0)
        gm = gm.then(OfdMatrix.scale(k * o.hScale, -k))
        if (o.charDirection != 0) {
            val a = o.charDirection * PI / 180
            gm = gm.then(OfdMatrix(cos(a), sin(a), -sin(a), cos(a), 0.0, 0.0))
        }
        return gm.then(OfdMatrix.translate(g.ox, g.oy))
    }

    /** The glyph indices of [g] in [program]: CGTransform first, then the cmap; null when the font has no glyph for it. */
    private fun glyphIds(o: OfdObject.Text, g: OfdGlyph, program: FontProgram): List<Int>? {
        o.glyphIds(g.index)?.let { return it }
        val cp = codePoint(g.text) ?: return null
        return program.glyphId(cp).takeIf { it != 0 }?.let { listOf(it) }
    }

    private fun codePoint(s: String): Int? {
        if (s.isEmpty()) return null
        val c = s[0]
        return if (c.isHighSurrogate() && s.length > 1) ((c.code - 0xD800) shl 10) + (s[1].code - 0xDC00) + 0x10000 else c.code
    }

    /** The outline of all of [o]'s text in device space through [m]; null when its font cannot give every glyph. */
    private fun glyphPath(o: OfdObject.Text, m: OfdMatrix): Path? {
        val program = program(o) ?: return null
        val path = Path()
        for (g in o.glyphs()) {
            if (g.text.isBlank() && o.glyphIds(g.index) == null) continue
            val ids = glyphIds(o, g, program) ?: return null
            val gm = glyphMatrix(o, g, program.unitsPerEm).then(m)
            for (id in ids) build(program.outline(id), gm, path)
        }
        return path
    }

    private fun DrawScope.text(o: OfdObject.Text, m: OfdMatrix, page: OfdMatrix, depth: Int) {
        val paint = o.fill ?: o.stroke ?: return
        val c = color(paint, o.alpha)
        val program = program(o)
        val synthBold = o.weight >= 600 && o.font?.bold != true
        for (g in o.glyphs()) {
            if (program != null) {
                val ids = glyphIds(o, g, program)
                if (ids != null) {
                    if (ids.isEmpty()) continue
                    val gm = glyphMatrix(o, g, program.unitsPerEm).then(m)
                    val path = Path()
                    for (id in ids) build(program.outline(id), gm, path)
                    val sizePx = (o.size * m.scale).toFloat()
                    o.fill?.let { f ->
                        val shade = o.fillShade
                        if (shade != null) shaded(path, Fill, 0f, shade, m, page, o.alpha, depth) else drawPath(path, color(f, o.alpha), style = Fill)
                        if (synthBold) drawPath(path, color(f, o.alpha), style = Stroke(width = sizePx * BOLD_STROKE))
                    }
                    o.stroke?.let { s -> drawPath(path, color(s, o.alpha), style = Stroke(width = max(1f, (TEXT_STROKE * m.scale).toFloat()))) }
                    continue
                }
            }
            if (g.text.isBlank()) continue
            systemGlyph(o, g, m, c)
        }
    }

    /** A character drawn with the system family closest to the named font, at its place and rotation. */
    private fun DrawScope.systemGlyph(o: OfdObject.Text, g: OfdGlyph, m: OfdMatrix, c: Color) {
        val measurer = measurer ?: return
        val family = when (o.font?.generic) { "monospace" -> FontFamily.Monospace; "sans-serif" -> FontFamily.SansSerif; else -> FontFamily.Serif }
        val bold = o.weight >= 600 || o.font?.bold == true
        val italic = o.italic || o.font?.italic == true
        val sizePx = (o.size * m.scale).toFloat()
        if (sizePx < 1f) return
        val key = g.text + "|" + family + bold + italic + "|" + (sizePx * 2).roundToInt()
        val layout = layouts.getOrPut(key) {
            measurer.measure(
                g.text,
                TextStyle(
                    fontSize = ((sizePx * 2).roundToInt() / 2f).sp, fontFamily = family,
                    fontWeight = if (bold) FontWeight.Bold else FontWeight.Normal,
                    fontStyle = if (italic) FontStyle.Italic else FontStyle.Normal,
                ),
                softWrap = false,
            )
        }
        val x = m.x(g.ox, g.oy).toFloat()
        val y = m.y(g.ox, g.oy).toFloat()
        val origin = Offset(x, y)
        val angle = atan2(m.b, m.a) * 180.0 / PI + o.charDirection
        val draw: DrawScope.() -> Unit = { drawText(layout, color = c, topLeft = Offset(x, y - layout.firstBaseline)) }
        when {
            angle != 0.0 -> rotate(angle.toFloat(), origin) {
                if (o.hScale != 1.0) scale(o.hScale.toFloat(), 1f, origin) { draw() } else draw()
            }
            o.hScale != 1.0 -> scale(o.hScale.toFloat(), 1f, origin) { draw() }
            else -> draw()
        }
    }

    private fun matrix(m: OfdMatrix) = Matrix(
        floatArrayOf(
            m.a.toFloat(), m.b.toFloat(), 0f, 0f,
            m.c.toFloat(), m.d.toFloat(), 0f, 0f,
            0f, 0f, 1f, 0f,
            m.e.toFloat(), m.f.toFloat(), 0f, 1f,
        ),
    )

    companion object {
        private const val CACHE = 64
        /** Largest side of a shading drawn into pixels (it is scaled up from there). */
        private const val MAX_SHADE = 1024
        /** Pattern cells drawn at most for one fill. */
        private const val MAX_TILES = 4096L
        /** Slant of synthetic italic, as tan of about 11 degrees. */
        private const val ITALIC_SKEW = 0.2
        /** Width of the outline added for synthetic bold, as a fraction of the font size. */
        private const val BOLD_STROKE = 0.04f
        /** Line width (millimetres) of stroked text: the OFD default line width. */
        private const val TEXT_STROKE = 0.353
    }
}
