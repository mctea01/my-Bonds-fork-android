package diw.wallet.core.document.image

import diw.wallet.core.zk.native.bindings.jpeg2000Decode

/**
 * JPEG 2000 pictures (the portraits many electronic travel documents store) decoded by the wallet's native library
 * with hayro-jpeg2000, since neither Android nor Skia reads the format. On desktop the library must have been loaded
 * with [diw.wallet.core.zk.native.ZkNative.load] first; on Android it is found among the app's own libraries.
 */
object Jpeg2000 {
    /** Decoded pixels as packed ARGB, row by row. */
    class Pixels(val width: Int, val height: Int, val argb: IntArray)

    /** The pixels of a JP2 file or bare codestream; null when it is not one or the library is missing. */
    fun decode(bytes: ByteArray): Pixels? = try {
        if (ImageKind.of(bytes) != ImageKind.JPEG2000) null
        else {
            val image = jpeg2000Decode(bytes)
            val w = image.width.toInt()
            val h = image.height.toInt()
            val rgba = image.rgba
            if (w <= 0 || h <= 0 || rgba.size < w * h * 4) null
            else Pixels(w, h, IntArray(w * h) { i ->
                val p = i * 4
                ((rgba[p + 3].toInt() and 255) shl 24) or ((rgba[p].toInt() and 255) shl 16) or
                    ((rgba[p + 1].toInt() and 255) shl 8) or (rgba[p + 2].toInt() and 255)
            })
        }
    } catch (_: Exception) {
        null
    } catch (_: LinkageError) {
        null
    }
}
