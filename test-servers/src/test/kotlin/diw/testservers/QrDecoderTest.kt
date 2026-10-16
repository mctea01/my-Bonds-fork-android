package diw.testservers

import diw.wallet.core.util.QrDecoder
import diw.wallet.core.util.QrEncoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** QR Codes read from pictures: screenshots, dark mode (light code on dark) and pictures holding several codes. */
class QrDecoderTest {
    private val offer = "modadigitalwallet://credential_offer?credential_offer_uri=https%3A%2F%2Fissuer.mock.wallet.gov.tw%2Fapi%2F" +
        "credential-offer-object%3Fnonce%3D1a2b%26sub%3D3c4d"

    /** Draws [text] at [left],[top] in a white (or, [dark], black) picture of [width] by [height] pixels. */
    private class Picture(val width: Int, val height: Int, private val dark: Boolean = false) {
        private val light = 0xFFFFFFFF.toInt()
        private val black = 0xFF000000.toInt()
        val pixels = IntArray(width * height) { if (dark) black else light }

        fun draw(text: String, left: Int, top: Int, cell: Int) {
            val m = QrEncoder.encode(text, QrEncoder.Ecc.M)
            for (y in -4 until m.size + 4) for (x in -4 until m.size + 4) {
                val on = x in 0 until m.size && y in 0 until m.size && m[x, y]
                val colour = if (on != dark) black else light
                for (dy in 0 until cell) for (dx in 0 until cell) {
                    val px = left + (x + 4) * cell + dx
                    val py = top + (y + 4) * cell + dy
                    if (px in 0 until width && py in 0 until height) pixels[py * width + px] = colour
                }
            }
        }
    }

    @Test
    fun readsACodeInAScreenshot() {
        val p = Picture(720, 1600)
        p.draw(offer, 160, 500, 4)
        assertEquals(listOf(offer), QrDecoder.decode(p.width, p.height, p.pixels))
    }

    @Test
    fun readsALightCodeOnDark() {
        val p = Picture(600, 600, dark = true)
        p.draw(offer, 60, 60, 4)
        assertEquals(listOf(offer), QrDecoder.decode(p.width, p.height, p.pixels))
    }

    @Test
    fun mostCentralCodeFirstAndNothingInABlankPicture() {
        val p = Picture(1400, 1400)
        p.draw("https://example.org/corner", 20, 20, 4)
        p.draw(offer, 450, 450, 4)
        val found = QrDecoder.decode(p.width, p.height, p.pixels)
        assertEquals(offer, found.first())
        assertTrue("https://example.org/corner" in found, "found: $found")
        assertTrue(QrDecoder.decode(200, 200, IntArray(200 * 200) { 0xFFFFFFFF.toInt() }).isEmpty())
    }
}
