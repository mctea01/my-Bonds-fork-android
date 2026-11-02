package diw.wallet.core.document.zkpdf

import diw.wallet.core.document.pdf.PdfException

/**
 * One text-showing operator of a page content stream, in the v2 record form the zkPDF lexical circuit commits to
 * (p4-circuits.md 3.4.4): the font resource name, the string kind (0 literal, 1 hex) and every string operand as its
 * raw source bytes between the delimiters, escapes and nesting kept.
 */
class ZkPdfTextRecord(val font: ByteArray, val kind: Int, val strings: List<ByteArray>) {
    /** len(font) || font || kind || count || (u16 length || bytes)*, as the circuit and the Rust prover encode it. */
    fun encoded(): ByteArray {
        val out = ArrayList<Byte>(font.size + 3 + strings.sumOf { it.size + 2 })
        out += font.size.toByte()
        font.forEach { out += it }
        out += kind.toByte()
        out += strings.size.toByte()
        for (s in strings) {
            out += (s.size ushr 8).toByte()
            out += s.size.toByte()
            s.forEach { out += it }
        }
        return out.toByteArray()
    }

    override fun equals(other: Any?): Boolean =
        other is ZkPdfTextRecord && encoded().contentEquals(other.encoded())

    override fun hashCode(): Int = encoded().contentHashCode()
}

/**
 * The record view of a decompressed content stream that the zkPDF lexical circuit (pdf_lex_seg_v1) takes: the same
 * tokenizer and the same Word-like rules (one font per BT, no inline images, no marked content dictionaries, string
 * operands only in Tj, TJ, ' and "). A stream the circuit would reject is rejected here with a fixed message, so
 * the planner can explain it before any proof is attempted. Never echoes content bytes.
 */
object ZkPdfLexer {
    private const val MAX_RECORDS = 512
    private const val MAX_FONT = 16

    fun records(content: ByteArray): List<ZkPdfTextRecord> = State().run {
        for (b in content) step(b.toInt() and 255)
        eof()
        records
    }

    private class State {
        val records = ArrayList<ZkPdfTextRecord>()
        private var mode = 0
        private var depth = 0
        private var escaped = false
        private var dict = 0
        private var array = false
        private var closed = false
        private var bt = false
        private var font: ByteArray? = null
        private var name = ArrayList<Byte>()
        private var word = 0
        private var wordLength = 0
        private var longWord = false
        private var pending = false
        private var kind = 0
        private val raw = ArrayList<Byte>()
        private val strings = ArrayList<ByteArray>()

        private fun fail(): Nothing = throw PdfException("The page text is outside the zkPDF profile")
        private fun check(ok: Boolean) { if (!ok) fail() }

        private fun begin(k: Int) {
            check(bt && dict == 0 && !closed)
            if (pending) check(kind == k)
            kind = k
            pending = true
        }

        private fun rawByte(b: Int) {
            raw += b.toByte()
            check(raw.size <= 65535)
        }

        private fun endString() {
            strings += raw.toByteArray()
            raw.clear()
            check(strings.size <= 255)
        }

        private fun word() {
            val w = if (longWord) 0 else word
            val show = w == 0x546a || w == 0x544a || w == 39 || w == 34
            check(w != 0x4249)
            if (pending) check(show)
            if (show) {
                val f = font
                check(bt && f != null && pending && !array && dict == 0)
                check((w == 0x544a) == closed)
                check(records.size < MAX_RECORDS)
                records += ZkPdfTextRecord(f!!, kind, strings.toList())
                pending = false
                closed = false
                kind = 0
                strings.clear()
            } else {
                check(!array && !closed)
                when (w) {
                    0x4254 -> { check(!bt && dict == 0); bt = true; font = null }
                    0x4554 -> { check(bt && dict == 0); bt = false }
                    0x5466 -> { check(bt && dict == 0 && name.isNotEmpty()); font = name.toByteArray() }
                }
            }
            word = 0
            wordLength = 0
            longWord = false
            mode = 0
        }

        fun step(b: Int) {
            val white = b == 0 || b == 9 || b == 10 || b == 12 || b == 13 || b == 32
            val end = white || b in DELIMITERS
            if (mode in 4..6 && end) {
                if (mode == 6) word() else mode = 0
            }
            when (mode) {
                1 -> if (b == 10 || b == 13) mode = 0
                2 -> when {
                    escaped -> { rawByte(b); escaped = false }
                    b == 92 -> { rawByte(b); escaped = true }
                    b == 40 -> { depth++; rawByte(b) }
                    b == 41 -> {
                        depth--
                        if (depth == 0) { mode = 0; endString() } else rawByte(b)
                    }
                    else -> rawByte(b)
                }
                3 -> if (b == 62) { mode = 0; endString() } else { check(white || isHex(b)); rawByte(b) }
                7 -> if (b == 60) {
                    check(!pending && !array)
                    dict++
                    mode = 0
                } else {
                    begin(1)
                    mode = 3
                    if (b == 62) { mode = 0; endString() } else { check(white || isHex(b)); rawByte(b) }
                }
                8 -> { check(b == 62 && dict > 0); dict--; mode = 0 }
                4 -> { check(name.size < MAX_FONT); name += b.toByte() }
                5 -> check(b in NUMBER)
                6 -> if (wordLength < 3) { word = word * 256 + b; wordLength++ } else longWord = true
                else -> when {
                    white -> Unit
                    b == 37 -> mode = 1
                    b == 40 -> { begin(0); mode = 2; depth = 1 }
                    b == 60 -> mode = 7
                    b == 62 -> mode = 8
                    b == 91 -> { check(!array && !closed && !pending && dict == 0); array = true }
                    b == 93 -> { check(array && dict == 0); array = false; closed = true }
                    b == 47 -> { check(!pending && !closed); mode = 4; name = ArrayList() }
                    b == 41 -> fail()
                    b in NUMBER -> mode = 5
                    else -> { mode = 6; word = b; wordLength = 1; longWord = false }
                }
            }
        }

        fun eof() {
            if (mode == 1 || mode in 4..6) step(10)
            check(mode == 0 && !pending && !bt && !array && !closed && dict == 0)
        }

        private fun isHex(b: Int) = b in 48..57 || b in 65..70 || b in 97..102
    }

    private val DELIMITERS = "%()<>[]/".map { it.code }.toSet()
    private val NUMBER = "+-.0123456789".map { it.code }.toSet()
}
