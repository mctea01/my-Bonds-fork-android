package diw.wallet.app

import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asSkiaBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import diw.wallet.core.document.image.ImageConversion
import diw.wallet.core.document.image.ImageKind
import diw.wallet.core.document.image.Jpeg2000
import org.jetbrains.skia.EncodedImageFormat
import org.jetbrains.skia.Image

/**
 * Skia reads JPEG, PNG, GIF, WebP, BMP and ICO; a TIFF (page images of official documents) goes through the wallet's
 * own TIFF reader, JPEG 2000 (chip portraits) the wallet's native decoder, and anything else ImageIO can read is
 * tried last.
 */
actual fun decodeImageBytes(bytes: ByteArray): ImageBitmap? =
    jpeg2000(bytes) ?: runCatching { Image.makeFromEncoded(bytes).toComposeImageBitmap() }.getOrNull()
        ?: ImageConversion.toPng(bytes)?.let { png -> runCatching { Image.makeFromEncoded(png).toComposeImageBitmap() }.getOrNull() }
        ?: runCatching {
            val img = javax.imageio.ImageIO.read(bytes.inputStream()) ?: return@runCatching null
            val out = java.io.ByteArrayOutputStream()
            javax.imageio.ImageIO.write(img, "png", out)
            Image.makeFromEncoded(out.toByteArray()).toComposeImageBitmap()
        }.getOrNull()

/** A JPEG 2000 picture through the native decoder, which [DesktopPlatform] loads first. */
private fun jpeg2000(bytes: ByteArray): ImageBitmap? {
    if (ImageKind.of(bytes) != ImageKind.JPEG2000) return null
    val p = Jpeg2000.decode(bytes) ?: return null
    return runCatching {
        val image = java.awt.image.BufferedImage(p.width, p.height, java.awt.image.BufferedImage.TYPE_INT_ARGB)
        image.setRGB(0, 0, p.width, p.height, p.argb, 0, p.width)
        val out = java.io.ByteArrayOutputStream()
        javax.imageio.ImageIO.write(image, "png", out)
        Image.makeFromEncoded(out.toByteArray()).toComposeImageBitmap()
    }.getOrNull()
}

actual fun encodePng(image: ImageBitmap): ByteArray? =
    runCatching { Image.makeFromBitmap(image.asSkiaBitmap()).encodeToData(EncodedImageFormat.PNG)?.bytes }.getOrNull()
