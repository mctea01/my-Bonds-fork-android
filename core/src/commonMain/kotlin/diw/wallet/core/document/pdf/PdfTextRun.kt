package diw.wallet.core.document.pdf

/** One text-showing operator in stream order. [op] is its zero-based text-operator ordinal. */
data class PdfTextRun(val op: Int, val font: String, val raw: ByteArray, val literal: Boolean,
    val text: String, val x: Double, val y: Double) {
    // The frozen public fields do not include glyph advances or font sizes.
    // Retain the interpreter's geometry so layoutRuns can use exactly the P3 layout algorithm.
    internal var glyphs: List<PdfTextExtractor.Glyph>? = null

    override fun toString(): String = "PdfTextRun(op=$op)"
}
