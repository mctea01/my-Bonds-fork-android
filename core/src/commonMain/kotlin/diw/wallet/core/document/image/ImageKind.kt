package diw.wallet.core.document.image

/** Kinds of images the wallet recognises by their first bytes. */
enum class ImageKind(val title: String, val mediaType: String) {
    JPEG("JPEG", "image/jpeg"),
    PNG("PNG", "image/png"),
    GIF("GIF", "image/gif"),
    WEBP("WebP", "image/webp"),
    BMP("BMP", "image/bmp"),
    TIFF("TIFF", "image/tiff"),
    HEIF("HEIF／HEIC", "image/heif"),
    AVIF("AVIF", "image/avif"),
    JPEG2000("JPEG 2000", "image/jp2"),
    ICO("ICO", "image/x-icon");

    companion object {
        private fun at(b: ByteArray, offset: Int, ascii: String) =
            b.size >= offset + ascii.length && ascii.indices.all { b[offset + it] == ascii[it].code.toByte() }

        /** The kind of image [b] is, or null when it is none the wallet knows. */
        fun of(b: ByteArray): ImageKind? = when {
            b.size < 8 -> null
            b[0] == 0xFF.toByte() && b[1] == 0xD8.toByte() && b[2] == 0xFF.toByte() -> JPEG
            b[0] == 0x89.toByte() && at(b, 1, "PNG") -> PNG
            at(b, 0, "GIF8") -> GIF
            at(b, 0, "RIFF") && at(b, 8, "WEBP") -> WEBP
            (at(b, 0, "II") && b[2] == 42.toByte() && b[3] == 0.toByte()) || (at(b, 0, "MM") && b[2] == 0.toByte() && b[3] == 42.toByte()) -> TIFF
            at(b, 4, "ftyp") && (at(b, 8, "avif") || at(b, 8, "avis")) -> AVIF
            at(b, 4, "ftyp") && listOf("heic", "heix", "hevc", "heim", "heis", "mif1", "msf1").any { at(b, 8, it) } -> HEIF
            at(b, 4, "jP  ") || (b[0] == 0xFF.toByte() && b[1] == 0x4F.toByte() && b[2] == 0xFF.toByte() && b[3] == 0x51.toByte()) -> JPEG2000
            at(b, 0, "BM") && b.size > 26 -> BMP
            b[0] == 0.toByte() && b[1] == 0.toByte() && b[2] == 1.toByte() && b[3] == 0.toByte() && b.size > 22 -> ICO
            else -> null
        }

        /** The kind named by a file extension, for files whose bytes were not checked. */
        fun ofExtension(name: String): ImageKind? = when (name.substringAfterLast('.', "").lowercase()) {
            "jpg", "jpeg", "jfif" -> JPEG; "png" -> PNG; "gif" -> GIF; "webp" -> WEBP; "bmp" -> BMP; "tif", "tiff" -> TIFF
            "heic", "heif" -> HEIF; "avif" -> AVIF; "jp2", "j2k", "jpx" -> JPEG2000; "ico" -> ICO; else -> null
        }
    }
}
