package diw.wallet.core.util

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.multi.qrcode.QRCodeMultiReader
import com.google.zxing.qrcode.QRCodeReader
import kotlin.math.hypot

actual object QrDecoder {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.CHARACTER_SET to "UTF-8",
    )

    actual fun decode(width: Int, height: Int, argb: IntArray): List<String> {
        require(width > 0 && height > 0 && argb.size >= width * height) { "invalid image" }
        val source = RGBLuminanceSource(width, height, argb)
        // Light codes on a dark background (dark mode screenshots) are read from the inverted image as well.
        for (candidate in listOf(source, source.invert())) {
            val bitmap = BinaryBitmap(HybridBinarizer(candidate))
            val found = try {
                QRCodeMultiReader().decodeMultiple(bitmap, hints).toList()
            } catch (_: NotFoundException) {
                try {
                    listOf(QRCodeReader().decode(bitmap, hints))
                } catch (_: ReaderException) {
                    emptyList()
                }
            } catch (_: ReaderException) {
                emptyList()
            }
            if (found.isEmpty()) continue
            val cx = width / 2.0
            val cy = height / 2.0
            return found
                .sortedBy { r ->
                    val points = r.resultPoints.orEmpty().filterNotNull()
                    if (points.isEmpty()) Double.MAX_VALUE
                    else hypot(points.map { it.x.toDouble() }.average() - cx, points.map { it.y.toDouble() }.average() - cy)
                }
                .mapNotNull { it.text?.takeIf { t -> t.isNotBlank() } }
                .distinct()
        }
        return emptyList()
    }
}
