package diw.wallet.core.document.c2pa

import diw.wallet.core.i18n.ct
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.pdf.PdfArray
import diw.wallet.core.document.pdf.PdfDict
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfName
import diw.wallet.core.document.pdf.PdfNumber
import diw.wallet.core.document.pdf.PdfObject
import diw.wallet.core.document.pdf.PdfOutput
import diw.wallet.core.document.pdf.PdfParser
import diw.wallet.core.document.pdf.PdfRef
import diw.wallet.core.document.pdf.PdfStream
import diw.wallet.core.document.pdf.PdfString
import diw.wallet.core.document.pdf.PdfWriter

/**
 * PDF (C2PA Appendix A.4): the manifest store is an embedded file stream whose file specification the catalog's
 * associated files (/AF) list with /AFRelationship /C2PA_Manifest, also named in the EmbeddedFiles name tree. A new
 * store is added by incremental update, so earlier PDF signatures stay valid; the data hash excludes the stream's
 * content, as c2pa-rs locates it. Encrypted and certified (DocMDP) documents get a sidecar instead.
 */
object C2paPdf {
    const val NAME = "Content Credentials"
    private const val MIME = "application/c2pa"

    fun isPdf(b: ByteArray): Boolean = PdfFile.isPdf(b)

    /** The file specifications in the catalog's /AF whose relationship is C2PA_Manifest. */
    private fun c2paSpecs(pdf: PdfFile): List<PdfRef> =
        pdf.array(pdf.catalog["AF"]).orEmpty().filterIsInstance<PdfRef>().filter { pdf.dict(it)?.name("AFRelationship") == "C2PA_Manifest" }

    /**
     * The store and the stream content in the file. An encrypted PDF that opens with the empty password is read too
     * (as c2pa-rs does): the store is the decrypted stream, the excluded range its encrypted content (/Length bytes).
     */
    fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
        val pdf = PdfFile(b)
        if (pdf.encrypted && pdf.encryptionProblem != null) return null
        val spec = c2paSpecs(pdf).firstOrNull() ?: return null
        val ef = pdf.dict(pdf.dict(spec)?.get("EF")) ?: return null
        val ref = ef["F"] as? PdfRef ?: ef["UF"] as? PdfRef ?: return null
        val stream = pdf.getObject(ref.num) as? PdfStream ?: return null
        val jumbf = if (stream.dict["Filter"] == null) stream.data else pdf.decode(stream)
        val offset = pdf.offsetOf(ref.num) ?: return null
        val extent = rawExtent(pdf, ref.num, offset) ?: return null
        val start = extent.first
        val length = if (pdf.encrypted) (pdf.resolve(stream.dict["Length"]) as? PdfNumber)?.int ?: return null else extent.count()
        if (length < 0 || start + length > b.size) return null
        if (!pdf.encrypted && !b.copyOfRange(start, start + length).contentEquals(stream.data)) return null
        return jumbf to C2paRange(start.toLong(), length.toLong())
    }

    /**
     * The raw content of stream object [num] stored at [offset], as the PDF parser finds it: comments and strings in
     * the stream dictionary that contain the word "stream" are skipped, unlike a byte search.
     */
    private fun rawExtent(pdf: PdfFile, num: Int, offset: Int): IntRange? = runCatching {
        val parser = PdfParser(pdf.bytes, offset) { (pdf.resolve(it["Length"]) as? PdfNumber)?.int }
        val (actual, _, value) = parser.parseIndirect()
        if (actual != num || value !is PdfStream) null else parser.lastStreamExtent
    }.getOrNull()

    fun cannotEmbed(b: ByteArray): String? = runCatching {
        val pdf = PdfFile(b)
        when {
            pdf.encrypted -> ct("core_c2pa_sidecar_pdf_encrypted")
            pdf.reconstructed -> ct("core_c2pa_sidecar_pdf_xref")
            pdf.dict(pdf.catalog["Perms"])?.has("DocMDP") == true -> ct("core_c2pa_sidecar_pdf_certified")
            else -> null
        }
    }.getOrElse { ct("core_c2pa_sidecar_unreadable", it.message ?: "") }

    /**
     * [base] with an incremental update holding [store]: the embedded file stream, its file specification, the
     * catalog with the new /AF (earlier C2PA manifests dropped from it) and the name tree entry. The update is the
     * same for every store of one size, so the data hash can be computed over a placeholder.
     */
    fun embed(base: ByteArray, store: ByteArray): C2paLayout {
        val pdf = PdfFile(base)
        cannotEmbed(base)?.let { C2paContainers.fail(it) }
        val catalogRef = pdf.trailer["Root"] as? PdfRef ?: C2paContainers.fail("PDF without a catalog")
        var catalog = pdf.catalog
        val old = c2paSpecs(pdf).toSet()
        var next = pdf.size
        val out = PdfOutput(base)
        if (base.isNotEmpty() && base.last() != '\n'.code.toByte()) out.append("\n")

        val streamNum = next++
        val dict = PdfDict.of(
            "Type" to PdfName("EmbeddedFile"),
            "Subtype" to PdfName(MIME),
            "Length" to PdfNumber.of(store.size),
        )
        out.offsets[streamNum] = out.size to 0
        out.append("$streamNum 0 obj\n" + PdfWriter.serialize(dict) + "\nstream\n")
        val contentAt = out.size
        out.append(store)
        out.append("\nendstream\nendobj\n")

        val specNum = next++
        val spec = PdfDict.of(
            "Type" to PdfName("Filespec"),
            "F" to PdfString(NAME.encodeToByteArray(), true),
            "UF" to PdfString(NAME.encodeToByteArray(), true),
            "Desc" to PdfString(NAME.encodeToByteArray(), true),
            "AFRelationship" to PdfName("C2PA_Manifest"),
            "Subtype" to PdfName(MIME),
            "EF" to PdfDict.of("F" to PdfRef(streamNum, 0)),
        )
        out.obj(specNum, 0, PdfWriter.serialize(spec))
        val specRef = PdfRef(specNum, 0)

        val af = pdf.array(catalog["AF"]).orEmpty().filter { it !in old } + specRef
        catalog = catalog.with("AF", PdfArray(af))

        // The name tree: a flat /Names array gets the entry (kept in key order); a tree with /Kids is left alone.
        val namesObj = catalog["Names"]
        val names = pdf.dict(namesObj) ?: PdfDict.of()
        val efObj = names["EmbeddedFiles"]
        val ef = pdf.dict(efObj)
        val newEf: PdfDict? = when {
            ef == null -> PdfDict.of("Names" to PdfArray(listOf(PdfString(NAME.encodeToByteArray(), true), specRef)))
            ef.has("Kids") -> null
            else -> {
                val pairs = pdf.array(ef["Names"]).orEmpty().chunked(2).filter { it.size == 2 && it[1] !in old }
                val all = (pairs + listOf(listOf(PdfString(NAME.encodeToByteArray(), true), specRef)))
                    .sortedWith { a, b -> C2paCbor.compareBytes(key(pdf, a[0]), key(pdf, b[0])) }
                ef.with("Names", PdfArray(all.flatten()))
            }
        }
        if (newEf != null) {
            if (efObj is PdfRef) out.obj(efObj.num, pdf.generation(efObj.num), PdfWriter.serialize(newEf))
            else {
                val newNames = names.with("EmbeddedFiles", newEf)
                if (namesObj is PdfRef) out.obj(namesObj.num, pdf.generation(namesObj.num), PdfWriter.serialize(newNames))
                else catalog = catalog.with("Names", newNames)
            }
        }
        out.obj(catalogRef.num, pdf.generation(catalogRef.num), PdfWriter.serialize(catalog))

        val trailer = LinkedHashMap<String, PdfObject>()
        val xrefStream = pdf.revisions.first().usesXrefStream
        trailer["Size"] = PdfNumber.of(next + if (xrefStream) 1 else 0)
        trailer["Root"] = catalogRef
        pdf.trailer["Info"]?.let { trailer["Info"] = it }
        // The second identifier is derived from the file, so the update is the same for the placeholder and the store.
        val id0 = (pdf.trailer["ID"] as? PdfArray)?.firstOrNull() as? PdfString
        val derived = DocCrypto.digest("SHA-256", base).copyOfRange(0, 16)
        trailer["ID"] = PdfArray(listOf(PdfString((id0?.bytes ?: derived), true), PdfString(derived, true)))
        trailer["Prev"] = PdfNumber.of(pdf.revisions.first().xrefOffset)
        if (xrefStream) out.xrefStream(next, PdfDict(trailer)) else out.xrefTable(PdfDict(trailer), includeFreeHead = false)
        return C2paLayout(out.bytes(), C2paRange(contentAt.toLong(), store.size.toLong()))
    }

    private fun key(pdf: PdfFile, o: PdfObject): ByteArray = (pdf.resolve(o) as? PdfString)?.bytes ?: ByteArray(0)
}
