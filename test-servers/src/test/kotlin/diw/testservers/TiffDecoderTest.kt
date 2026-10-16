package diw.testservers

import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.image.ImageConversion
import diw.wallet.core.document.image.ImageKind
import diw.wallet.core.document.image.RasterImage
import diw.wallet.core.document.image.TiffDecoder
import java.awt.image.BufferedImage
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The pure Kotlin TIFF reader against samples written by Pillow with libtiff (images/generate.py): every compression
 * the page images of official documents use, and the common gray, RGB and palette layouts, pixel for pixel.
 */
class TiffDecoderTest {
    private fun resource(name: String): ByteArray = javaClass.getResourceAsStream("/images/$name")!!.readBytes()

    private fun expected(name: String): BufferedImage = ImageIO.read(resource(name).inputStream())

    private fun assertSame(want: BufferedImage, got: RasterImage, label: String) {
        assertEquals(want.width, got.width, "$label width")
        assertEquals(want.height, got.height, "$label height")
        var diff = 0
        for (y in 0 until want.height) for (x in 0 until want.width) {
            // getRGB would apply the gray colour space's gamma; the stored samples are compared instead.
            val w = if (want.raster.numBands == 1) IntArray(3) { want.raster.getSample(x, y, 0) * (if (want.raster.sampleModel.getSampleSize(0) == 1) 255 else 1) }
            else want.getRGB(x, y).let { rgb -> intArrayOf(rgb shr 16 and 0xFF, rgb shr 8 and 0xFF, rgb and 0xFF) }
            val i = (y * got.width + x) * got.channels
            val g = if (got.channels == 1) IntArray(3) { got.pixels[i].toInt() and 0xFF } else IntArray(3) { got.pixels[i + it].toInt() and 0xFF }
            if ((0 until 3).any { kotlin.math.abs(w[it] - g[it]) > 1 }) diff++
        }
        assertEquals(0, diff, "$label: pixels that differ")
    }

    @Test
    fun bilevelInEveryCompression() {
        val want = expected("bw-expected.png")
        for (c in listOf("group4", "group3", "tiff_ccitt", "packbits", "tiff_lzw", "tiff_adobe_deflate", "raw")) {
            val b = resource("bw-$c.tiff")
            assertTrue(TiffDecoder.isTiff(b))
            assertSame(want, TiffDecoder.decode(b), c)
        }
    }

    @Test
    fun grayRgbAndPalette() {
        assertSame(expected("gray-expected.png"), TiffDecoder.decode(resource("gray-lzw.tiff")), "gray LZW")
        assertSame(expected("rgb-expected.png"), TiffDecoder.decode(resource("rgb-lzw.tiff")), "RGB LZW")
        assertSame(expected("rgb-expected.png"), TiffDecoder.decode(resource("rgb-deflate.tiff")), "RGB Deflate")
        assertSame(expected("palette-expected.png"), TiffDecoder.decode(resource("palette-packbits.tiff")), "palette PackBits")
    }

    @Test
    fun pagesBecomePngs() {
        val b = resource("pages-group4.tiff")
        assertEquals(2, TiffDecoder.pageCount(b))
        val pages = ImageConversion.tiffPages(b)
        assertEquals(2, pages.size)
        val first = ImageIO.read(pages[0].inputStream())
        val want = expected("bw-expected.png")
        assertEquals(want.width, first.width)
        assertEquals(want.getRGB(40, 100), first.getRGB(40, 100))
        // Scaled down by a whole factor for a light preview: 301 pixels at most 150 wide is a third.
        val small = ImageIO.read(ImageConversion.tiffPages(b, 1, 150).single().inputStream())
        assertEquals(100, small.width)
        assertTrue(TiffDecoder.directories(b).first().describe().contains("CCITT Group 4"))
    }

    @Test
    fun imageKinds() {
        assertEquals(ImageKind.TIFF, ImageKind.of(resource("bw-group4.tiff")))
        assertEquals(ImageKind.PNG, ImageKind.of(resource("bw-expected.png")))
        assertEquals(ImageKind.HEIF, ImageKind.of(byteArrayOf(0, 0, 0, 24) + "ftypheic".encodeToByteArray() + ByteArray(8)))
        assertEquals(ImageKind.AVIF, ImageKind.of(byteArrayOf(0, 0, 0, 24) + "ftypavif".encodeToByteArray() + ByteArray(8)))
        assertEquals(ImageKind.JPEG2000, ImageKind.of(byteArrayOf(0, 0, 0, 12) + "jP  ".encodeToByteArray() + ByteArray(8)))
        assertEquals(DocumentFormat.IMAGE, DocumentInspector.sniff(resource("bw-group4.tiff"), "page.tif"))
    }
}
