package diw.wallet.app

import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asSkiaBitmap
import androidx.compose.ui.text.font.createFontFamilyResolver
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.ofd.OfdPackage
import diw.wallet.core.document.sign.DocumentSigning
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** OFD pages drawn with Compose graphics: text, paths, the seal picture where it was stamped. */
class OfdRenderTest {
    private val renderer = OfdRenderer(createFontFamilyResolver()) { decodeImageBytes(it.bytes) }

    private fun pixels(image: ImageBitmap): IntArray = IntArray(image.width * image.height).also { image.readPixels(it) }

    private fun save(name: String, image: ImageBitmap) {
        val dir = System.getenv("DIW_OFD_OUT") ?: return
        val data = org.jetbrains.skia.Image.makeFromBitmap(image.asSkiaBitmap()).encodeToData(org.jetbrains.skia.EncodedImageFormat.PNG)!!.bytes
        File(dir).apply { mkdirs() }.resolve("$name.png").writeBytes(data)
    }

    /** The share of pixels that are not white. */
    private fun ink(p: IntArray) = p.count { (it and 0xFFFFFF) != 0xFFFFFF }.toDouble() / p.size

    @Test
    fun drawsTextPathsAndSeal() {
        val bytes = File("../test-servers/src/test/resources/documents/signed-sesv4.ofd").readBytes()
        val pkg = assertNotNull(OfdPackage.read(DocumentSigning.unzip(bytes)))
        val page = pkg.pages.single()
        val plain = renderer.render(page, 800)
        assertEquals(800, plain.width)
        assertTrue(kotlin.math.abs((800 * page.box.h / page.box.w) - plain.height) <= 1.0, "page height")
        assertTrue(ink(pixels(plain)) > 0.001, "text drawn")

        val stamp = DocumentInspector.ofdStamps(bytes).single()
        val seal = assertNotNull(stamp.picture?.let { decodeImageBytes(it) }, "seal picture " + stamp.pictureFormat)
        val sealed = renderer.render(page, 800, listOf(OfdRenderer.Overlay(seal, stamp.boundary.x, stamp.boundary.y, stamp.boundary.w, stamp.boundary.h)))
        assertTrue(ink(pixels(sealed)) > ink(pixels(plain)), "seal drawn")
        save("ofd-seal", sealed)
    }

    /** A local file for a visual check: DIW_OFD_SAMPLE names it, DIW_OFD_OUT where its pages go. */
    @Test
    fun drawsLocalSample() {
        val path = System.getenv("DIW_OFD_SAMPLE") ?: return
        val bytes = File(path).readBytes()
        val pkg = assertNotNull(OfdPackage.read(DocumentSigning.unzip(bytes)))
        pkg.pages.take(3).forEachIndexed { i, p -> save("ofd-sample-$i", renderer.render(p, 1080)) }
    }
}
