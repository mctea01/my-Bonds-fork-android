package diw.wallet.app

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Canvas
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Matrix
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.CanvasDrawScope
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.ui.graphics.drawscope.Stroke
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
import diw.wallet.core.document.ofd.OfdColor
import diw.wallet.core.document.ofd.OfdMatrix
import diw.wallet.core.document.ofd.OfdMedia
import diw.wallet.core.document.ofd.OfdObject
import diw.wallet.core.document.ofd.OfdPage
import diw.wallet.core.document.ofd.OfdPathCommand
import kotlin.math.PI
import kotlin.math.atan2
import kotlin.math.max
import kotlin.math.roundToInt

/**
 * Draws OFD pages (read by [diw.wallet.core.document.ofd.OfdPackage]) with Compose graphics, the same on Android
 * and the desktop: paths with their fill rule, line width, caps, joins and dashes; images through the platform
 * decoder; text character by character at the place the document gives each one. Embedded fonts are not loaded:
 * text is drawn with the system's serif, sans-serif or monospace family closest to the named font, so glyph shapes
 * can differ from the original while positions match. Clipping areas and shadings (drawn with their first colour)
 * are simplified. Seals are drawn by the caller through [Overlay].
 */
class OfdRenderer(
    /** Text is left out without a resolver (the platform gives one). */
    private val fonts: FontFamily.Resolver?,
    /** Decodes an image resource; null when it cannot be shown. */
    private val image: (OfdMedia) -> ImageBitmap?,
) {
    /** A picture drawn over the page at [x], [y] (millimetres, page space) [w] by [h], such as a seal. */
    class Overlay(val picture: ImageBitmap, val x: Double, val y: Double, val w: Double, val h: Double)

    private val measurer = fonts?.let { TextMeasurer(it, Density(1f), LayoutDirection.Ltr, CACHE) }
    private val layouts = HashMap<String, TextLayoutResult>()
    private val decoded = HashMap<String, ImageBitmap?>()

    /** [page] as an image [widthPx] wide, with [overlays] on top; on white, or transparent without [background]. */
    fun render(page: OfdPage, widthPx: Int, overlays: List<Overlay> = emptyList(), background: Boolean = true): ImageBitmap {
        val box = page.box
        val scale = widthPx / box.w
        val heightPx = (box.h * scale).roundToInt().coerceIn(1, widthPx * 4)
        val bitmap = ImageBitmap(widthPx, heightPx)
        val canvas = Canvas(bitmap)
        val device = OfdMatrix.scale(scale, scale)
        CanvasDrawScope().draw(Density(1f), LayoutDirection.Ltr, canvas, Size(widthPx.toFloat(), heightPx.toFloat())) {
            if (background) drawRect(Color.White)
            for (o in page.objects) runCatching {
                val m = o.matrix.then(device)
                when (o) {
                    is OfdObject.Path -> path(o, m)
                    is OfdObject.Image -> image(o, m)
                    is OfdObject.Text -> text(o, scale)
                }
            }
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

    private fun color(c: OfdColor, alpha: Int) = Color(
        red = c.r / 255f, green = c.g / 255f, blue = c.b / 255f,
        alpha = (c.alpha / 255f) * (alpha / 255f),
    )

    private fun DrawScope.path(o: OfdObject.Path, m: OfdMatrix) {
        val p = Path()
        for (c in o.commands) when (c) {
            is OfdPathCommand.Move -> p.moveTo(m.x(c.x, c.y).toFloat(), m.y(c.x, c.y).toFloat())
            is OfdPathCommand.Line -> p.lineTo(m.x(c.x, c.y).toFloat(), m.y(c.x, c.y).toFloat())
            is OfdPathCommand.Quad -> p.quadraticTo(
                m.x(c.x1, c.y1).toFloat(), m.y(c.x1, c.y1).toFloat(), m.x(c.x, c.y).toFloat(), m.y(c.x, c.y).toFloat(),
            )
            is OfdPathCommand.Cubic -> p.cubicTo(
                m.x(c.x1, c.y1).toFloat(), m.y(c.x1, c.y1).toFloat(), m.x(c.x2, c.y2).toFloat(), m.y(c.x2, c.y2).toFloat(),
                m.x(c.x, c.y).toFloat(), m.y(c.x, c.y).toFloat(),
            )
            OfdPathCommand.Close -> p.close()
        }
        p.fillType = if (o.evenOdd) PathFillType.EvenOdd else PathFillType.NonZero
        o.fill?.let { drawPath(p, color(it, o.alpha), style = Fill) }
        o.stroke?.let {
            val width = max(1f, (o.lineWidth * m.scale).toFloat())
            val dash = o.dash.takeIf { d -> d.size >= 2 && d.all { v -> v > 0 } }?.map { v -> (v * m.scale).toFloat() }?.toFloatArray()
            drawPath(
                p, color(it, o.alpha),
                style = Stroke(
                    width = width,
                    cap = when (o.cap.lowercase()) { "round" -> StrokeCap.Round; "square" -> StrokeCap.Square; else -> StrokeCap.Butt },
                    join = when (o.join.lowercase()) { "round" -> StrokeJoin.Round; "bevel" -> StrokeJoin.Bevel; else -> StrokeJoin.Miter },
                    pathEffect = dash?.let { d -> PathEffect.dashPathEffect(d) },
                ),
            )
        }
    }

    /** An image fills the unit square of its CTM (scaled from its pixel size first). */
    private fun DrawScope.image(o: OfdObject.Image, m: OfdMatrix) {
        val media = o.media ?: return
        val bmp = decoded.getOrPut(media.id) { runCatching { image(media) }.getOrNull() } ?: return
        val unit = OfdMatrix.scale(1.0 / bmp.width, 1.0 / bmp.height).then(m)
        withTransform({ transform(matrix(unit)) }) {
            drawImage(
                bmp, srcOffset = IntOffset.Zero, srcSize = IntSize(bmp.width, bmp.height), dstOffset = IntOffset.Zero,
                dstSize = IntSize(bmp.width, bmp.height), alpha = o.alpha / 255f, filterQuality = FilterQuality.Medium,
            )
        }
    }

    private fun DrawScope.text(o: OfdObject.Text, scale: Double) {
        val measurer = measurer ?: return
        val paint = o.fill ?: o.stroke ?: return
        val family = when (o.font?.generic) { "monospace" -> FontFamily.Monospace; "sans-serif" -> FontFamily.SansSerif; else -> FontFamily.Serif }
        val bold = o.weight >= 600 || o.font?.bold == true
        val italic = o.italic || o.font?.italic == true
        // Rotation of the text object (its CTM), applied around each character's baseline origin.
        val angle = atan2(o.matrix.b, o.matrix.a) * 180.0 / PI + o.charDirection
        val c = color(paint, o.alpha)
        for (g in o.glyphs()) {
            if (g.text.isBlank()) continue
            val sizePx = (g.size * scale).toFloat()
            if (sizePx < 1f) continue
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
            val x = (g.x * scale).toFloat()
            val y = (g.y * scale).toFloat()
            val origin = Offset(x, y)
            val draw: DrawScope.() -> Unit = { drawText(layout, color = c, topLeft = Offset(x, y - layout.firstBaseline)) }
            when {
                angle != 0.0 -> rotate(angle.toFloat(), origin) {
                    if (o.hScale != 1.0) scale(o.hScale.toFloat(), 1f, origin) { draw() } else draw()
                }
                o.hScale != 1.0 -> scale(o.hScale.toFloat(), 1f, origin) { draw() }
                else -> draw()
            }
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
    }
}
