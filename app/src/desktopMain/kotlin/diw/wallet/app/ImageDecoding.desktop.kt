package diw.wallet.app

import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asSkiaBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import diw.wallet.core.document.image.ImageConversion
import org.jetbrains.skia.EncodedImageFormat
import org.jetbrains.skia.Image

/**
 * Skia reads JPEG, PNG, GIF, WebP, BMP and ICO; a TIFF (page images of official documents) goes through the wallet's
 * own TIFF reader, and anything else ImageIO can read is tried last.
 */
actual fun decodeImageBytes(bytes: ByteArray): ImageBitmap? =
    runCatching { Image.makeFromEncoded(bytes).toComposeImageBitmap() }.getOrNull()
        ?: ImageConversion.toPng(bytes)?.let { png -> runCatching { Image.makeFromEncoded(png).toComposeImageBitmap() }.getOrNull() }
        ?: runCatching {
            val img = javax.imageio.ImageIO.read(bytes.inputStream()) ?: return@runCatching null
            val out = java.io.ByteArrayOutputStream()
            javax.imageio.ImageIO.write(img, "png", out)
            Image.makeFromEncoded(out.toByteArray()).toComposeImageBitmap()
        }.getOrNull()

actual fun encodePng(image: ImageBitmap): ByteArray? =
    runCatching { Image.makeFromBitmap(image.asSkiaBitmap()).encodeToData(EncodedImageFormat.PNG)?.bytes }.getOrNull()
