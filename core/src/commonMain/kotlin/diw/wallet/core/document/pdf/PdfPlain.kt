package diw.wallet.core.document.pdf

/**
 * A copy of an encrypted PDF without its encryption, for page rendering where the platform renderer cannot take a
 * password (Android's PdfRenderer before API 35). Every object is written decrypted as a plain object (object streams
 * are expanded, cross-reference streams and the encryption dictionary left out) with a new cross-reference table.
 * Signatures no longer verify on the copy; it is never stored or exported.
 */
object PdfPlain {
    /** [bytes] opened with [password]; the bytes themselves when the file is not encrypted. */
    fun of(bytes: ByteArray, password: String = ""): ByteArray {
        val pdf = PdfFile(bytes, password)
        if (!pdf.encrypted) return bytes
        if (pdf.passwordRequired) throw PdfPasswordException("需要開啟密碼")
        pdf.encryptionProblem?.let { throw PdfException(it) }
        return of(pdf)
    }

    fun of(pdf: PdfFile): ByteArray {
        val out = PdfOutput(byteArrayOf('%'.code.toByte(), 'P'.code.toByte(), 'D'.code.toByte(), 'F'.code.toByte(), '-'.code.toByte(),
            '1'.code.toByte(), '.'.code.toByte(), '7'.code.toByte(), '\n'.code.toByte(), '%'.code.toByte(),
            0xE2.toByte(), 0xE3.toByte(), 0xCF.toByte(), 0xD3.toByte(), '\n'.code.toByte()))
        val encrypt = (pdf.trailer["Encrypt"] as? PdfRef)?.num
        for (num in 1 until pdf.size) {
            if (num == encrypt) continue
            val o = try { pdf.getObject(num) } catch (e: PdfException) { continue }
            when (o) {
                is PdfNull -> continue
                is PdfStream -> {
                    val type = o.dict.name("Type")
                    if (type == "XRef" || type == "ObjStm") continue
                    out.stream(num, pdf.generation(num), o.dict, o.data)
                }
                else -> out.obj(num, pdf.generation(num), PdfWriter.serialize(o))
            }
        }
        val trailer = PdfDict(LinkedHashMap<String, PdfObject>().apply {
            put("Size", PdfNumber.of(pdf.size))
            pdf.trailer["Root"]?.let { put("Root", it) }
            pdf.trailer["Info"]?.let { put("Info", it) }
            pdf.trailer["ID"]?.let { put("ID", it) }
        })
        out.xrefTable(trailer, includeFreeHead = true)
        return out.bytes()
    }
}
