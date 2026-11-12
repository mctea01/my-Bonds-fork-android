package diw.wallet.app

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Canvas
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.CanvasDrawScope
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.sp
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/**
 * The picture of an electronic seal the wallet makes, in seal red on a transparent ground: a round organisation seal
 * (the name along the upper rim, a star in the middle) or a square personal seal (the name in columns read from the
 * right, with 印 or 之印 added to short names as personal seals have).
 */
object SealPicture {
    private val RED = Color(0xFFD01818)

    fun draw(name: String, personal: Boolean, fonts: FontFamily.Resolver, size: Int = 480): ImageBitmap {
        val bitmap = ImageBitmap(size, size)
        val measurer = TextMeasurer(fonts, Density(1f), LayoutDirection.Ltr, 8)
        val chars = codePoints(name.trim()).take(if (personal) 8 else 24)
        CanvasDrawScope().draw(Density(1f), LayoutDirection.Ltr, Canvas(bitmap), Size(size.toFloat(), size.toFloat())) {
            if (personal) square(chars, measurer, size.toFloat()) else round(chars, measurer, size.toFloat())
        }
        return bitmap
    }

    private fun codePoints(s: String): List<String> {
        val out = ArrayList<String>()
        var i = 0
        while (i < s.length) {
            val n = if (s[i].isHighSurrogate() && i + 1 < s.length) 2 else 1
            out.add(s.substring(i, i + n))
            i += n
        }
        return out
    }

    private fun DrawScope.glyph(measurer: TextMeasurer, ch: String, px: Float, center: Offset) {
        val layout = measurer.measure(ch, TextStyle(color = RED, fontSize = px.sp, fontFamily = FontFamily.Serif, fontWeight = FontWeight.Bold))
        drawText(layout, topLeft = Offset(center.x - layout.size.width / 2f, center.y - layout.size.height / 2f))
    }

    private fun DrawScope.round(chars: List<String>, measurer: TextMeasurer, s: Float) {
        val c = Offset(s / 2, s / 2)
        val ring = s * 0.035f
        val r = s / 2 - ring
        drawCircle(RED, r, c, style = Stroke(ring))
        // A five-pointed star.
        val star = Path()
        val outer = s * 0.17f
        val inner = outer * 0.382f
        for (k in 0 until 10) {
            val a = -PI / 2 + k * PI / 5
            val rad = if (k % 2 == 0) outer else inner
            val x = c.x + (rad * cos(a)).toFloat()
            val y = c.y + (rad * sin(a)).toFloat()
            if (k == 0) star.moveTo(x, y) else star.lineTo(x, y)
        }
        star.close()
        drawPath(star, RED)
        if (chars.isEmpty()) return
        // The name along the rim, centred at the top, upright to the centre.
        val n = chars.size
        val span = min(250.0, 22.0 * n + 20)
        val step = if (n > 1) span / (n - 1) else 0.0
        val px = min(s * 0.12f, (2 * PI * r * 0.7 * (span / 360.0) / n.coerceAtLeast(1)).toFloat()).coerceAtLeast(s * 0.05f)
        val tr = r - ring * 1.5f - px * 0.8f
        for ((i, ch) in chars.withIndex()) {
            val deg = -span / 2 + i * step
            val a = (deg - 90) * PI / 180
            val p = Offset(c.x + (tr * cos(a)).toFloat(), c.y + (tr * sin(a)).toFloat())
            rotate(deg.toFloat(), pivot = p) { glyph(measurer, ch, px, p) }
        }
    }

    private fun DrawScope.square(name: List<String>, measurer: TextMeasurer, s: Float) {
        val border = s * 0.05f
        drawRect(RED, Offset(border / 2, border / 2), Size(s - border, s - border), style = Stroke(border))
        val chars = when (name.size) {
            0 -> return
            2 -> name + listOf("之", "印")
            3 -> name + listOf("印")
            else -> name
        }
        val n = chars.size
        val rows = if (n == 1) 1 else 2
        val cols = (n + rows - 1) / rows
        val inner = s - border * 3
        val cw = inner / cols
        val ch = inner / rows
        val px = min(cw, ch) * 0.86f
        // Columns from the right, each read top to bottom.
        for ((i, t) in chars.withIndex()) {
            val col = i / rows
            val row = i % rows
            val x = s - border * 1.5f - cw * (col + 0.5f)
            val y = border * 1.5f + ch * (row + 0.5f)
            glyph(measurer, t, px, Offset(x, y))
        }
    }
}
