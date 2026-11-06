package diw.wallet.core.util

/**
 * Reads QR Codes from a picture (a screenshot or a photo the user picked) for platforms or screens without a camera
 * scanner. Pixels are ARGB, row by row.
 */
expect object QrDecoder {
    /** Texts of the QR Codes found, the most central first; empty when there is none. */
    fun decode(width: Int, height: Int, argb: IntArray): List<String>
}
