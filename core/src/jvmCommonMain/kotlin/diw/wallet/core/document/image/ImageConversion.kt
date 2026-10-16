package diw.wallet.core.document.image

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream

/**
 * Images the platform decoder may not read, turned into PNG: every page of a TIFF (Android has no TIFF decoder).
 * Large pages are scaled down to [maxWidth] so a 300 dpi scan stays light to show.
 */
object ImageConversion {
    /** PNG of each page of the TIFF in [b], at most [maxPages]; empty when [b] is not a TIFF or cannot be read. */
    fun tiffPages(b: ByteArray, maxPages: Int = 10, maxWidth: Int = 1600): List<ByteArray> {
        if (!TiffDecoder.isTiff(b)) return emptyList()
        val count = TiffDecoder.pageCount(b).coerceAtMost(maxPages)
        return (0 until count).mapNotNull { runCatching { png(scaled(TiffDecoder.decode(b, it), maxWidth)) }.getOrNull() }
    }

    /** PNG of the first page or picture of [b] when the platform decoder needs help, else null. */
    fun toPng(b: ByteArray, maxWidth: Int = 2048): ByteArray? = tiffPages(b, 1, maxWidth).firstOrNull()

    /** [img] scaled down by a whole factor (box filter) so it is at most [maxWidth] wide. */
    fun scaled(img: RasterImage, maxWidth: Int): RasterImage {
        if (img.width <= maxWidth) return img
        val f = (img.width + maxWidth - 1) / maxWidth
        val w = img.width / f
        val h = maxOf(1, img.height / f)
        val ch = img.channels
        val out = ByteArray(w * h * ch)
        for (y in 0 until h) for (x in 0 until w) for (c in 0 until ch) {
            var sum = 0
            for (dy in 0 until f) for (dx in 0 until f) {
                sum += img.pixels[(((y * f + dy) * img.width) + x * f + dx) * ch + c].toInt() and 0xFF
            }
            out[(y * w + x) * ch + c] = (sum / (f * f)).toByte()
        }
        return RasterImage(w, h, ch, out)
    }

    /** [img] as a PNG file (8 bits per channel, no filtering). */
    fun png(img: RasterImage): ByteArray {
        val colorType = when (img.channels) { 1 -> 0; 2 -> 4; 3 -> 2; else -> 6 }
        val raw = ByteArrayOutputStream()
        DeflaterOutputStream(raw, Deflater(6)).use { z ->
            val row = img.width * img.channels
            for (y in 0 until img.height) {
                z.write(0)
                z.write(img.pixels, y * row, row)
            }
        }
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte(), 13, 10, 26, 10))
        val ihdr = ByteArrayOutputStream().also { s ->
            DataOutputStream(s).apply { writeInt(img.width); writeInt(img.height); writeByte(8); writeByte(colorType); writeByte(0); writeByte(0); writeByte(0) }
        }.toByteArray()
        chunk(out, "IHDR", ihdr)
        chunk(out, "IDAT", raw.toByteArray())
        chunk(out, "IEND", ByteArray(0))
        return out.toByteArray()
    }

    private fun chunk(out: ByteArrayOutputStream, type: String, data: ByteArray) {
        val d = DataOutputStream(out)
        d.writeInt(data.size)
        val t = type.encodeToByteArray()
        d.write(t)
        d.write(data)
        val crc = CRC32()
        crc.update(t)
        crc.update(data)
        d.writeInt(crc.value.toInt())
    }
}
