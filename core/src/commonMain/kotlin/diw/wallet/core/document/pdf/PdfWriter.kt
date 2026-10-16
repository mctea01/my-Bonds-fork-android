package diw.wallet.core.document.pdf

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.sign.HttpFetch
import diw.wallet.core.document.sign.SigningException
import kotlin.time.Clock
import kotlin.time.Instant

/** PDF object serialization (ISO 32000-1 7.3). Strings are written in hex so no escaping is needed. */
object PdfWriter {
    fun serialize(o: PdfObject): String = StringBuilder().also { write(o, it) }.toString()

    fun write(o: PdfObject, b: StringBuilder) {
        when (o) {
            is PdfNull -> b.append("null")
            is PdfBool -> b.append(if (o.value) "true" else "false")
            is PdfNumber -> b.append(o.text)
            is PdfString -> hex(o.bytes, b)
            is PdfName -> name(o.name, b)
            is PdfArray -> {
                b.append('[')
                o.items.forEachIndexed { i, it -> if (i > 0) b.append(' '); write(it, b) }
                b.append(']')
            }
            is PdfDict -> {
                b.append("<<")
                for ((k, v) in o.entries) { name(k, b); b.append(' '); write(v, b) }
                b.append(">>")
            }
            is PdfRef -> b.append(o.num).append(' ').append(o.gen).append(" R")
            is PdfStream -> throw PdfException("Streams are written with their data")
        }
    }

    fun hex(bytes: ByteArray, b: StringBuilder) {
        b.append('<')
        for (x in bytes) { val v = x.toInt() and 0xFF; b.append(HEX[v shr 4]).append(HEX[v and 15]) }
        b.append('>')
    }

    fun name(n: String, b: StringBuilder) {
        b.append('/')
        for (x in n.encodeToByteArray()) {
            val c = x.toInt() and 0xFF
            if (c < 0x21 || c > 0x7E || c == '#'.code || PdfParser.isDelimiter(c)) {
                b.append('#').append(HEX[c shr 4]).append(HEX[c and 15])
            } else b.append(c.toChar())
        }
    }

    fun text(s: String) = PdfString(PdfText.encode(s), hex = true)

    private const val HEX = "0123456789ABCDEF"
}

/** Builds a file by appending bytes and records object offsets for the cross-reference data. */
class PdfOutput(initial: ByteArray = ByteArray(0)) {
    private var buf = initial.copyOf(maxOf(initial.size * 2, 4096))
    var size = initial.size
        private set
    val offsets = LinkedHashMap<Int, Pair<Int, Int>>() // num -> (offset, gen)

    fun append(bytes: ByteArray) {
        if (size + bytes.size > buf.size) buf = buf.copyOf(maxOf(buf.size * 2, size + bytes.size))
        bytes.copyInto(buf, size)
        size += bytes.size
    }

    fun append(s: String) = append(s.encodeToByteArray())

    fun obj(num: Int, gen: Int, body: String) {
        offsets[num] = size to gen
        append("$num $gen obj\n$body\nendobj\n")
    }

    fun stream(num: Int, gen: Int, dict: PdfDict, data: ByteArray) {
        offsets[num] = size to gen
        append("$num $gen obj\n" + PdfWriter.serialize(dict.with("Length", PdfNumber.of(data.size))) + "\nstream\n")
        append(data)
        append("\nendstream\nendobj\n")
    }

    fun bytes(): ByteArray = buf.copyOf(size)

    /** A classic cross-reference table for [offsets] and its trailer. */
    fun xrefTable(trailer: PdfDict, includeFreeHead: Boolean) {
        val start = size
        val nums = offsets.keys.sorted().toMutableList()
        val sb = StringBuilder("xref\n")
        if (includeFreeHead) {
            sb.append("0 1\n0000000000 65535 f\r\n")
        }
        var i = 0
        while (i < nums.size) {
            var j = i
            while (j + 1 < nums.size && nums[j + 1] == nums[j] + 1) j++
            sb.append(nums[i]).append(' ').append(j - i + 1).append('\n')
            for (k in i..j) {
                val (off, gen) = offsets[nums[k]]!!
                sb.append(off.toString().padStart(10, '0')).append(' ').append(gen.toString().padStart(5, '0')).append(" n\r\n")
            }
            i = j + 1
        }
        sb.append("trailer\n").append(PdfWriter.serialize(trailer)).append("\nstartxref\n").append(start).append("\n%%EOF\n")
        append(sb.toString())
    }

    /** A cross-reference stream (uncompressed, W [1 4 2]) as object [num] with [trailer] entries. */
    fun xrefStream(num: Int, trailer: PdfDict) {
        val start = size
        offsets[num] = start to 0
        val nums = offsets.keys.sorted()
        val index = ArrayList<PdfObject>()
        var i = 0
        val data = ArrayList<Byte>()
        while (i < nums.size) {
            var j = i
            while (j + 1 < nums.size && nums[j + 1] == nums[j] + 1) j++
            index.add(PdfNumber.of(nums[i])); index.add(PdfNumber.of(j - i + 1))
            for (k in i..j) {
                val (off, gen) = offsets[nums[k]]!!
                data.add(1)
                for (s in 24 downTo 0 step 8) data.add((off ushr s).toByte())
                data.add((gen shr 8).toByte()); data.add(gen.toByte())
            }
            i = j + 1
        }
        val dict = PdfDict(LinkedHashMap(trailer.entries).apply {
            put("Type", PdfName("XRef"))
            put("W", PdfArray(listOf(PdfNumber.of(1), PdfNumber.of(4), PdfNumber.of(2))))
            put("Index", PdfArray(index))
        })
        val bytes = data.toByteArray()
        append("$num 0 obj\n" + PdfWriter.serialize(dict.with("Length", PdfNumber.of(bytes.size))) + "\nstream\n")
        append(bytes)
        append("\nendstream\nendobj\nstartxref\n$start\n%%EOF\n")
    }
}

/** What a signature dictionary says besides the signature itself. */
class PdfSignOptions(
    val reason: String? = null,
    val location: String? = null,
    val contactInfo: String? = null,
    val signerName: String? = null,
    /** ETSI.CAdES.detached (PAdES) or adbe.pkcs7.detached. */
    val subFilter: String = "ETSI.CAdES.detached",
    /** Bytes reserved for the CMS signature (hex doubles it in the file). */
    val reserve: Int = 32 * 1024,
    val time: Instant = Clock.System.now(),
    /**
     * Sign even though a certification signature allows no changes (DocMDP P=1). The new revision then breaks that
     * certification; only for a user who confirmed the consequence.
     */
    val allowBreakingCertification: Boolean = false,
    /** B-LT: fetch the validation data of the signer and the time-stamp authority and add it to the DSS. */
    val validation: HttpFetch? = null,
    /** Fail instead of signing without any revocation data when [validation] is set. */
    val requireValidation: Boolean = false,
    /** B-LTA: a document time stamp after the DSS (needs the time-stamp authority). */
    val documentTimestamp: Boolean = false,
)

/**
 * Adds an invisible signature field to a PDF by incremental update (ISO 32000-1 7.5.6 and 12.8): the original bytes
 * stay as they are, so existing signatures remain valid. [prepare] writes the update with a placeholder for the
 * signature value; [Prepared.finish] fills in the CMS signature over [Prepared.signedData].
 */
object PdfIncrementalSigner {
    class Prepared internal constructor(private val bytes: ByteArray, private val contentsStart: Int, private val contentsEnd: Int) {
        /** The bytes the signature covers: everything except the /Contents hex string. */
        fun signedData(): ByteArray = bytes.copyOfRange(0, contentsStart) + bytes.copyOfRange(contentsEnd, bytes.size)

        fun finish(cms: ByteArray): ByteArray {
            val room = (contentsEnd - contentsStart - 2) / 2
            if (cms.size > room) throw SigningException("簽章資料（${cms.size} 位元組）超過預留空間（$room 位元組）")
            val out = bytes.copyOf()
            val hex = StringBuilder()
            for (x in cms) { val v = x.toInt() and 0xFF; hex.append("0123456789ABCDEF"[v shr 4]).append("0123456789ABCDEF"[v and 15]) }
            hex.toString().encodeToByteArray().copyInto(out, contentsStart + 1)
            return out
        }
    }

    fun prepare(original: ByteArray, options: PdfSignOptions, fieldName: String? = null): Prepared {
        val pdf = try { PdfFile(original) } catch (e: PdfException) { throw SigningException("PDF 結構無法讀取：" + e.message, e) }
        if (pdf.encrypted) throw SigningException("加密的 PDF 無法加簽；請先另存為未加密的檔案")
        if (pdf.reconstructed) throw SigningException("PDF 的交互參照表損壞，無法以增量方式加簽")
        val sigs = PdfSignatures(pdf)
        if (!options.allowBreakingCertification && sigs.fields().any { it.docMdpPermission == 1 }) throw SigningException("此文件有不允許任何修改的認證簽章，無法再加簽")

        val catalogRef = pdf.trailer["Root"] as? PdfRef ?: throw SigningException("PDF 沒有文件目錄")
        val catalog = pdf.catalog
        var next = pdf.size
        val sigNum = next++
        val fieldNum = next++
        val fieldRef = PdfRef(fieldNum, 0)
        val (pageRef, page) = firstPage(pdf) ?: throw SigningException("PDF 沒有頁面")
        val updates = LinkedHashMap<Int, PdfObject>()

        // AcroForm with the new field.
        val existingNames = sigs.fields().mapNotNull { it.fieldName }.toSet()
        val prefix = if (options.subFilter == "ETSI.RFC3161") "DocTimeStamp" else "Signature"
        val name = fieldName ?: generateSequence(1) { it + 1 }.map { "$prefix$it" }.first { it !in existingNames }
        fun withField(acro: PdfDict): PdfDict {
            val fieldsObj = acro["Fields"]
            val fields = if (fieldsObj is PdfRef) {
                val arr = pdf.array(fieldsObj).orEmpty()
                updates[fieldsObj.num] = PdfArray(arr + fieldRef)
                fieldsObj
            } else PdfArray((fieldsObj as? PdfArray).orEmpty() + fieldRef)
            return acro.with("Fields", fields).with("SigFlags", PdfNumber.of(3))
        }
        when (val acroObj = catalog["AcroForm"]) {
            is PdfRef -> updates[acroObj.num] = withField(pdf.dict(acroObj) ?: PdfDict.of())
            is PdfDict -> updates[catalogRef.num] = catalog.with("AcroForm", withField(acroObj))
            else -> {
                val acroNum = next++
                updates[acroNum] = withField(PdfDict.of())
                updates[catalogRef.num] = catalog.with("AcroForm", PdfRef(acroNum, 0))
            }
        }
        // The widget goes on the first page.
        when (val annots = page["Annots"]) {
            is PdfRef -> updates[annots.num] = PdfArray(pdf.array(annots).orEmpty() + fieldRef)
            else -> updates[pageRef.num] = page.with("Annots", PdfArray((annots as? PdfArray).orEmpty() + fieldRef))
        }
        val field = PdfDict.of(
            "Type" to PdfName("Annot"), "Subtype" to PdfName("Widget"), "FT" to PdfName("Sig"),
            "T" to PdfWriter.text(name), "V" to PdfRef(sigNum, 0), "F" to PdfNumber.of(132),
            "Rect" to PdfArray(List(4) { PdfNumber.of(0) }), "P" to pageRef,
        )

        val out = PdfOutput(original)
        if (original.isNotEmpty() && original.last() != '\n'.code.toByte()) out.append("\n")
        // Signature dictionary with placeholders.
        // A document time stamp (ETSI.RFC3161) is a /DocTimeStamp; its time is in the token, not in /M.
        val docTimeStamp = options.subFilter == "ETSI.RFC3161"
        val sb = StringBuilder(if (docTimeStamp) "<</Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter " else "<</Type /Sig /Filter /Adobe.PPKLite /SubFilter ")
        PdfWriter.name(options.subFilter, sb)
        if (!docTimeStamp) sb.append(" /M ").also { PdfWriter.write(PdfWriter.text(PdfDates.format(options.time)), sb) }
        options.signerName?.takeIf { !docTimeStamp }?.let { sb.append(" /Name "); PdfWriter.write(PdfWriter.text(it), sb) }
        options.reason?.let { sb.append(" /Reason "); PdfWriter.write(PdfWriter.text(it), sb) }
        options.location?.let { sb.append(" /Location "); PdfWriter.write(PdfWriter.text(it), sb) }
        options.contactInfo?.let { sb.append(" /ContactInfo "); PdfWriter.write(PdfWriter.text(it), sb) }
        sb.append(" /ByteRange ")
        val brPlaceholder = "[0 0000000000 0000000000 0000000000]"
        val brAt = sb.length
        sb.append(brPlaceholder)
        sb.append(" /Contents ")
        val contentsAt = sb.length
        sb.append('<').append("0".repeat(options.reserve * 2)).append('>')
        sb.append(">>")
        val sigOffset = out.size
        out.obj(sigNum, 0, sb.toString())
        val header = "$sigNum 0 obj\n".length
        val brStart = sigOffset + header + brAt
        val contentsStart = sigOffset + header + contentsAt
        val contentsEnd = contentsStart + options.reserve * 2 + 2
        out.obj(fieldNum, 0, PdfWriter.serialize(field))
        for ((num, obj) in updates) out.obj(num, pdf.generation(num), PdfWriter.serialize(obj))

        val trailer = LinkedHashMap<String, PdfObject>()
        trailer["Size"] = PdfNumber.of(next + if (pdf.revisions.first().usesXrefStream) 1 else 0)
        trailer["Root"] = catalogRef
        pdf.trailer["Info"]?.let { trailer["Info"] = it }
        val id0 = (pdf.trailer["ID"] as? PdfArray)?.firstOrNull() as? PdfString ?: PdfString(DocCrypto.randomBytes(16), true)
        trailer["ID"] = PdfArray(listOf(PdfString(id0.bytes, true), PdfString(DocCrypto.randomBytes(16), true)))
        trailer["Prev"] = PdfNumber.of(pdf.revisions.first().xrefOffset)
        if (pdf.revisions.first().usesXrefStream) out.xrefStream(next, PdfDict(trailer))
        else out.xrefTable(PdfDict(trailer), includeFreeHead = false)

        val bytes = out.bytes()
        val range = "[0 $contentsStart $contentsEnd ${bytes.size - contentsEnd}]"
        if (range.length > brPlaceholder.length) throw SigningException("檔案太大，無法加簽")
        (range.dropLast(1) + " ".repeat(brPlaceholder.length - range.length) + "]").encodeToByteArray().copyInto(bytes, brStart)
        return Prepared(bytes, contentsStart, contentsEnd)
    }

    /**
     * Adds validation data to the document security store (/DSS, ETSI EN 319 142-1 5.4) by incremental update:
     * certificates, OCSP responses and CRLs not stored yet, and a VRI entry for each signature in [vriKeys]
     * (upper-case hex SHA-1 of the signature's CMS). Earlier DSS content is kept; signatures stay valid because only
     * the catalog's /DSS changes.
     */
    fun addValidationData(original: ByteArray, certs: List<ByteArray>, ocsps: List<ByteArray>, crls: List<ByteArray>, vriKeys: List<String>): ByteArray {
        val pdf = try { PdfFile(original) } catch (e: PdfException) { throw SigningException("PDF 結構無法讀取：" + e.message, e) }
        if (pdf.encrypted) throw SigningException("加密的 PDF 無法加入長期驗證資料")
        val catalogRef = pdf.trailer["Root"] as? PdfRef ?: throw SigningException("PDF 沒有文件目錄")
        val catalog = pdf.catalog
        val stored = PdfSignatures(pdf).dss()
        val dssObj = catalog["DSS"]
        val dss = pdf.dict(dssObj) ?: PdfDict.of()
        var next = pdf.size
        val out = PdfOutput(original)
        if (original.isNotEmpty() && original.last() != '\n'.code.toByte()) out.append("\n")
        fun streams(items: List<ByteArray>, have: List<ByteArray>): List<PdfRef> = items
            .filter { item -> have.none { it.contentEquals(item) } }
            .distinctBy { it.contentHashCode() }
            .map { data -> val num = next++; out.stream(num, 0, PdfDict.of(), data); PdfRef(num, 0) }
        val newCerts = streams(certs, stored?.certificates.orEmpty())
        val newOcsps = streams(ocsps, stored?.ocsps.orEmpty())
        val newCrls = streams(crls, stored?.crls.orEmpty())
        fun merged(key: String, added: List<PdfRef>): PdfArray? {
            val have = pdf.array(dss[key]).orEmpty()
            return if (have.isEmpty() && added.isEmpty()) null else PdfArray(have + added)
        }
        val vri = LinkedHashMap((pdf.dict(dss["VRI"]) ?: PdfDict.of()).entries)
        for (key in vriKeys) {
            val entry = LinkedHashMap<String, PdfObject>()
            if (newCerts.isNotEmpty()) entry["Cert"] = PdfArray(newCerts)
            if (newOcsps.isNotEmpty()) entry["OCSP"] = PdfArray(newOcsps)
            if (newCrls.isNotEmpty()) entry["CRL"] = PdfArray(newCrls)
            if (entry.isNotEmpty()) vri[key.uppercase()] = PdfDict(entry)
        }
        var updated = dss.with("Type", PdfName("DSS"))
        merged("Certs", newCerts)?.let { updated = updated.with("Certs", it) }
        merged("OCSPs", newOcsps)?.let { updated = updated.with("OCSPs", it) }
        merged("CRLs", newCrls)?.let { updated = updated.with("CRLs", it) }
        if (vri.isNotEmpty()) updated = updated.with("VRI", PdfDict(vri))
        if (dssObj is PdfRef) {
            out.obj(dssObj.num, pdf.generation(dssObj.num), PdfWriter.serialize(updated))
        } else {
            val dssNum = next++
            out.obj(dssNum, 0, PdfWriter.serialize(updated))
            out.obj(catalogRef.num, pdf.generation(catalogRef.num), PdfWriter.serialize(catalog.with("DSS", PdfRef(dssNum, 0))))
        }
        val trailer = LinkedHashMap<String, PdfObject>()
        trailer["Size"] = PdfNumber.of(next + if (pdf.revisions.first().usesXrefStream) 1 else 0)
        trailer["Root"] = catalogRef
        pdf.trailer["Info"]?.let { trailer["Info"] = it }
        val id0 = (pdf.trailer["ID"] as? PdfArray)?.firstOrNull() as? PdfString ?: PdfString(DocCrypto.randomBytes(16), true)
        trailer["ID"] = PdfArray(listOf(PdfString(id0.bytes, true), PdfString(DocCrypto.randomBytes(16), true)))
        trailer["Prev"] = PdfNumber.of(pdf.revisions.first().xrefOffset)
        if (pdf.revisions.first().usesXrefStream) out.xrefStream(next, PdfDict(trailer))
        else out.xrefTable(PdfDict(trailer), includeFreeHead = false)
        return out.bytes()
    }

    private fun firstPage(pdf: PdfFile): Pair<PdfRef, PdfDict>? {
        var ref = pdf.catalog["Pages"] as? PdfRef ?: return null
        repeat(64) {
            val d = pdf.dict(ref) ?: return null
            if (d.name("Type") == "Page" || d["Kids"] == null) return ref to d
            ref = pdf.array(d["Kids"])?.firstOrNull() as? PdfRef ?: return null
        }
        return null
    }
}
