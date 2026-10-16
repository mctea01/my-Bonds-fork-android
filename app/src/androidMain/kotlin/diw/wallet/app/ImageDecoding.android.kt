package diw.wallet.app

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.graphics.asImageBitmap
import diw.wallet.core.document.image.ImageConversion
import diw.wallet.core.document.image.ImageKind
import java.io.ByteArrayOutputStream

/**
 * The platform decoder reads JPEG, PNG, GIF, WebP, BMP and HEIF (AVIF on Android 12 and later); a TIFF, such as the
 * page images of official documents, goes through the wallet's own TIFF reader. Large pictures are sampled down so a
 * scan does not take a full size bitmap.
 */
actual fun decodeImageBytes(bytes: ByteArray): ImageBitmap? {
    val data = if (ImageKind.of(bytes) == ImageKind.TIFF) ImageConversion.toPng(bytes) ?: return null else bytes
    return runCatching {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(data, 0, data.size, bounds)
        var sample = 1
        while (bounds.outWidth / (sample * 2) >= 2048 || bounds.outHeight / (sample * 2) >= 4096) sample *= 2
        BitmapFactory.decodeByteArray(data, 0, data.size, BitmapFactory.Options().apply { inSampleSize = sample })?.asImageBitmap()
    }.getOrNull()
}

actual fun encodePng(image: ImageBitmap): ByteArray? = runCatching {
    ByteArrayOutputStream().also { image.asAndroidBitmap().compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
}.getOrNull()
