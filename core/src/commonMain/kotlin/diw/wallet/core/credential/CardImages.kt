package diw.wallet.core.credential

import org.multipaz.util.fromBase64

/**
 * Card images from credential display metadata (logo, background_image). A URI is either a data: URI or an https URL
 * whose body is the image. TWDIW answers its background_image URL with a data URI as text/plain instead of the image
 * bytes, so a body that is not an image but a base64 image data URI is decoded as well.
 */
object CardImages {
    /** Largest decoded image the wallet keeps. */
    const val MAX_IMAGE_BYTES = 3 * 1024 * 1024

    /** Largest response body read for an image (a base64 data URI is a third larger than the image). */
    const val MAX_BODY_BYTES = 4 * 1024 * 1024 + 64

    /** Image bytes of a data: URI with a base64 image payload, or null. */
    fun fromDataUri(uri: String): ByteArray? {
        val text = uri.trim()
        if (!text.startsWith("data:image/", ignoreCase = true)) return null
        val header = text.substringBefore(',', "")
        if (!header.endsWith(";base64", ignoreCase = true)) return null
        val payload = text.substringAfter(',').filterNot { it.isWhitespace() }
        if (payload.isEmpty() || payload.length > MAX_BODY_BYTES) return null
        return runCatching { payload.fromBase64() }.getOrNull()?.takeIf { it.isNotEmpty() && it.size <= MAX_IMAGE_BYTES && isImage(it) }
    }

    /** Image bytes of an HTTP response body: the body itself when it is an image, or the data URI it carries. */
    fun fromBody(body: ByteArray): ByteArray? {
        if (body.isEmpty() || body.size > MAX_BODY_BYTES) return null
        if (isImage(body)) return body.takeIf { it.size <= MAX_IMAGE_BYTES }
        val text = body.decodeToString().trim().removeSurrounding("\"")
        return fromDataUri(text)
    }

    /** True for PNG, JPEG, GIF, WebP and BMP signatures; SVG and other formats are not drawn. */
    fun isImage(b: ByteArray): Boolean {
        fun at(i: Int, vararg v: Int) = b.size >= i + v.size && v.indices.all { (b[i + it].toInt() and 0xFF) == v[it] }
        return at(0, 0x89, 0x50, 0x4E, 0x47) ||
            at(0, 0xFF, 0xD8, 0xFF) ||
            at(0, 0x47, 0x49, 0x46, 0x38) ||
            (at(0, 0x52, 0x49, 0x46, 0x46) && at(8, 0x57, 0x45, 0x42, 0x50)) ||
            at(0, 0x42, 0x4D)
    }
}
