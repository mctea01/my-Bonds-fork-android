package diw.testservers

import diw.wallet.core.credential.CardImages
import org.multipaz.util.toBase64
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNull

/** Card images from display metadata: data URIs, image bodies and the TWDIW text bodies carrying a data URI. */
class CardImagesTest {
    private val png = ByteArrayOutputStream().also { ImageIO.write(BufferedImage(8, 8, BufferedImage.TYPE_INT_RGB), "png", it) }.toByteArray()

    @Test
    fun dataUrisAndBodies() {
        val uri = "data:image/png;base64," + png.toBase64()
        assertContentEquals(png, CardImages.fromDataUri(uri))
        assertContentEquals(png, CardImages.fromBody(png))
        assertContentEquals(png, CardImages.fromBody(uri.encodeToByteArray()))
        assertContentEquals(png, CardImages.fromBody(("\"" + uri + "\"\n").encodeToByteArray()))
        // Base64 wrapped over lines still decodes.
        assertContentEquals(png, CardImages.fromDataUri("data:image/png;base64," + png.toBase64().chunked(40).joinToString("\n")))
    }

    @Test
    fun refusesWhatIsNotADrawableImage() {
        assertNull(CardImages.fromDataUri("data:image/svg+xml;base64," + "<svg/>".encodeToByteArray().toBase64()))
        assertNull(CardImages.fromDataUri("data:image/png," + png.toBase64()))
        assertNull(CardImages.fromDataUri("data:text/plain;base64," + png.toBase64()))
        assertNull(CardImages.fromDataUri("data:image/png;base64,!!!"))
        assertNull(CardImages.fromBody("<html>not found</html>".encodeToByteArray()))
        assertNull(CardImages.fromBody(ByteArray(0)))
        assertNull(CardImages.fromBody(ByteArray(CardImages.MAX_BODY_BYTES + 1)))
    }
}
