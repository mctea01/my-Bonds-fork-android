package diw.wallet.core.document.pdf

import diw.wallet.core.document.LaterChanges

/** A signature dictionary found in a PDF (ISO 32000-1 12.8.1, ETSI EN 319 142-1). */
class PdfSignatureField(
    val fieldName: String?,
    /** Sig or DocTimeStamp. */
    val type: String?,
    val filter: String?,
    val subFilter: String?,
    val byteRange: List<Long>,
    /** The signature value read from the file bytes between the two signed ranges (hex decoded). */
    val contents: ByteArray,
    /** The unsigned gap holds exactly the /Contents hex string and nothing else. */
    val gapIsContentsOnly: Boolean,
    val claimedTime: String?,
    val name: String?,
    val reason: String?,
    val location: String?,
    val contactInfo: String?,
    /** adbe.x509.rsa_sha1: the signer certificate(s) in /Cert. */
    val certificates: List<ByteArray>,
    /** DocMDP permission (1 no changes, 2 form filling and signing, 3 also annotations) of a certification signature. */
    val docMdpPermission: Int?,
) {
    /** End of the signed revision (offset of the last signed byte plus one). */
    val signedLength: Long get() = if (byteRange.size == 4) byteRange[2] + byteRange[3] else 0

    fun signedData(file: ByteArray): ByteArray {
        if (byteRange.size % 2 != 0) throw PdfException("Malformed /ByteRange")
        var total = 0L
        for (i in byteRange.indices step 2) total += byteRange[i + 1]
        if (total > Int.MAX_VALUE) throw PdfException("Signed range too large")
        val out = ByteArray(total.toInt())
        var p = 0
        for (i in byteRange.indices step 2) {
            val start = byteRange[i]; val len = byteRange[i + 1]
            if (start < 0 || len < 0 || start + len > file.size) throw PdfException("/ByteRange outside the file")
            file.copyInto(out, p, start.toInt(), (start + len).toInt())
            p += len.toInt()
        }
        return out
    }
}

/** Long-term validation data of the document security store (ETSI EN 319 142-1 5.4). */
class PdfDss(val certificates: List<ByteArray>, val ocsps: List<ByteArray>, val crls: List<ByteArray>)

/**
 * Where a signature's widget sits on a page, normalized to the page's CropBox (or MediaBox) with the origin at the
 * top-left and the page's /Rotate applied, so a viewer can frame it over a rendered page image. [visible] is false
 * for the zero-sized or hidden widget of an invisible signature (ISO 32000-1 12.7.4.5).
 */
class PdfSignaturePlacement(
    val fieldName: String?,
    /** 0-based page index in reading order. */
    val page: Int,
    val x0: Float,
    val y0: Float,
    val x1: Float,
    val y1: Float,
    val visible: Boolean,
)

/** Signature fields, validation data and change analysis of a PDF. */
class PdfSignatures(private val pdf: PdfFile) {
    private val bytes = pdf.bytes

    /** Every signature in the file: the AcroForm signature fields, then signature dictionaries found only by scanning. */
    fun fields(): List<PdfSignatureField> {
        val found = ArrayList<PdfSignatureField>()
        val seen = HashSet<List<Long>>()
        runCatching {
            val acro = pdf.dict(pdf.catalog["AcroForm"])
            val fields = pdf.array(acro?.get("Fields")).orEmpty()
            val visited = HashSet<Int>()
            fun walk(o: PdfObject, parentName: String?, inheritedFt: String?, depth: Int) {
                if (depth > 32) return
                if (o is PdfRef && !visited.add(o.num)) return
                val d = pdf.dict(o) ?: return
                val partial = (d["T"] as? PdfString)?.text()
                val name = listOfNotNull(parentName, partial).joinToString(".").ifEmpty { null }
                val ft = d.name("FT") ?: inheritedFt
                val kids = pdf.array(d["Kids"])
                if (kids != null && kids.any { pdf.dict(it)?.has("T") == true }) {
                    kids.forEach { walk(it, name, ft, depth + 1) }
                    return
                }
                if (ft == "Sig") {
                    val v = pdf.dict(d["V"]) ?: return
                    fromDict(v, name)?.let { if (seen.add(it.byteRange)) found.add(it) }
                }
            }
            fields.forEach { walk(it, null, null, 0) }
        }
        // Signature dictionaries the form does not reach (broken forms, or objects this reader could not resolve).
        val br = "/ByteRange".encodeToByteArray()
        var i = 0
        while (true) {
            val k = PdfParser.indexOf(bytes, br, i)
            if (k < 0) break
            i = k + br.size
            val start = dictStart(k) ?: continue
            val dict = runCatching { PdfParser(bytes, start).parseObject() as? PdfDict }.getOrNull() ?: continue
            val f = fromDict(dict, null) ?: continue
            if (seen.add(f.byteRange)) found.add(f)
        }
        return found.sortedBy { it.signedLength }
    }

    /** The "<<" that opens the dictionary containing [at], skipping nested dictionaries. */
    private fun dictStart(at: Int): Int? {
        var depth = 0
        var p = at
        while (p > 0 && at - p < 65536) {
            p--
            if (bytes[p] == '>'.code.toByte() && p > 0 && bytes[p - 1] == '>'.code.toByte()) { depth++; p--; continue }
            if (bytes[p] == '<'.code.toByte() && p > 0 && bytes[p - 1] == '<'.code.toByte()) {
                if (depth == 0) return p - 1
                depth--; p--
            }
        }
        return null
    }

    private fun fromDict(v: PdfDict, fieldName: String?): PdfSignatureField? {
        val range = (v["ByteRange"] as? PdfArray)?.mapNotNull { (pdf.resolve(it) as? PdfNumber)?.long } ?: return null
        if (range.size < 4 || range.size % 2 != 0) return null
        val gapStart = (range[0] + range[1]).toInt()
        val gapEnd = range[2].toInt()
        if (gapStart < 0 || gapEnd > bytes.size || gapEnd <= gapStart) return null
        var gapOk = range.size == 4 && range[0] == 0L && bytes[gapStart] == '<'.code.toByte() && bytes[gapEnd - 1] == '>'.code.toByte()
        val hex = StringBuilder()
        for (p in gapStart + 1 until gapEnd - 1) {
            val c = bytes[p].toInt() and 0xFF
            when {
                PdfParser.hexVal(c) >= 0 -> hex.append(c.toChar())
                PdfParser.isWhite(c) -> {}
                else -> gapOk = false
            }
        }
        if (hex.length % 2 == 1) hex.append('0')
        val contents = ByteArray(hex.length / 2) { ((PdfParser.hexVal(hex[it * 2].code) shl 4) or PdfParser.hexVal(hex[it * 2 + 1].code)).toByte() }
        fun text(key: String) = (pdf.resolve(v[key]) as? PdfString)?.text()
        val certs = when (val c = pdf.resolve(v["Cert"])) {
            is PdfString -> listOf(c.bytes)
            is PdfArray -> c.mapNotNull { (pdf.resolve(it) as? PdfString)?.bytes }
            else -> emptyList()
        }
        val mdp = pdf.array(v["Reference"])?.firstNotNullOfOrNull { r ->
            val ref = pdf.dict(r) ?: return@firstNotNullOfOrNull null
            if (ref.name("TransformMethod") != "DocMDP") return@firstNotNullOfOrNull null
            (pdf.dict(ref["TransformParams"])?.get("P") as? PdfNumber)?.int ?: 2
        }
        return PdfSignatureField(
            fieldName = fieldName,
            type = v.name("Type"),
            filter = v.name("Filter"),
            subFilter = v.name("SubFilter"),
            byteRange = range,
            contents = contents,
            gapIsContentsOnly = gapOk,
            claimedTime = text("M"),
            name = text("Name"),
            reason = text("Reason"),
            location = text("Location"),
            contactInfo = text("ContactInfo"),
            certificates = certs,
            docMdpPermission = mdp,
        )
    }

    /**
     * The on-page position of every signature widget (ISO 32000-1 12.7.4.5): walks the page tree for each page's box
     * and rotation, then the AcroForm signature fields for their widgets' /P and /Rect. A field whose widget has no
     * page, a zero-area /Rect or the Hidden/NoView flag is reported as not visible.
     */
    fun placements(): List<PdfSignaturePlacement> = runCatching {
        val pageIndex = HashMap<Int, Int>()
        val pageBox = HashMap<Int, Pair<FloatArray, Int>>() // page num -> (cropOrMediaBox llx,lly,urx,ury, rotate)
        PdfPages.list(pdf).forEachIndexed { i, p ->
            pageIndex[p.ref.num] = i
            pageBox[p.ref.num] = p.box to p.rotate
        }

        val out = ArrayList<PdfSignaturePlacement>()
        val acro = pdf.dict(pdf.catalog["AcroForm"])
        val fields = pdf.array(acro?.get("Fields")).orEmpty()
        val visited = HashSet<Int>()
        fun field(o: PdfObject, parentName: String?, inheritedFt: String?, depth: Int) {
            if (depth > 32) return
            if (o is PdfRef && !visited.add(o.num)) return
            val d = pdf.dict(o) ?: return
            val name = listOfNotNull(parentName, (d["T"] as? PdfString)?.text()).joinToString(".").ifEmpty { null }
            val ft = d.name("FT") ?: inheritedFt
            val kids = pdf.array(d["Kids"])
            if (kids != null && kids.any { pdf.dict(it)?.has("T") == true }) {
                kids.forEach { field(it, name, ft, depth + 1) }
                return
            }
            if (ft != "Sig") return
            // The widget is this dictionary, or its single widget kid (a field merged with its widget, or split out).
            val widgets = if (kids != null) kids.mapNotNull { pdf.dict(it) to (it as? PdfRef) } else listOf(d to (o as? PdfRef))
            for ((w, _) in widgets) {
                if (w == null) continue
                val pageRef = w["P"] as? PdfRef
                val idx = pageRef?.let { pageIndex[it.num] }
                val box = pageRef?.let { pageBox[it.num] }
                val rect = pdf.array(w["Rect"])?.mapNotNull { (pdf.resolve(it) as? PdfNumber)?.double }
                val flags = (pdf.resolve(w["F"]) as? PdfNumber)?.int ?: 0
                val hidden = (flags and 0x2) != 0 || (flags and 0x20) != 0 // Hidden or NoView
                if (idx == null || box == null || rect == null || rect.size < 4) {
                    out.add(PdfSignaturePlacement(name, idx ?: 0, 0f, 0f, 0f, 0f, false))
                    continue
                }
                out.add(place(name, idx, box.first, box.second, rect, hidden))
            }
        }
        fields.forEach { field(it, null, null, 0) }
        out
    }.getOrDefault(emptyList())

    /** Maps a widget /Rect in PDF user space to a top-left normalized box on the displayed (rotated) page. */
    private fun place(name: String?, page: Int, b: FloatArray, rotate: Int, rect: List<Double>, hidden: Boolean): PdfSignaturePlacement {
        val w = (b[2] - b[0]).takeIf { it > 0 } ?: 1f
        val h = (b[3] - b[1]).takeIf { it > 0 } ?: 1f
        val rx0 = minOf(rect[0], rect[2]).toFloat(); val rx1 = maxOf(rect[0], rect[2]).toFloat()
        val ry0 = minOf(rect[1], rect[3]).toFloat(); val ry1 = maxOf(rect[1], rect[3]).toFloat()
        // Unrotated, top-left origin.
        var nx0 = (rx0 - b[0]) / w; var nx1 = (rx1 - b[0]) / w
        var ny0 = (b[3] - ry1) / h; var ny1 = (b[3] - ry0) / h
        // Apply the page /Rotate (clockwise) to the four corners, then take the bounding box.
        val corners = listOf(nx0 to ny0, nx1 to ny0, nx1 to ny1, nx0 to ny1).map { (x, y) ->
            when (rotate) {
                90 -> (1f - y) to x
                180 -> (1f - x) to (1f - y)
                270 -> y to (1f - x)
                else -> x to y
            }
        }
        nx0 = corners.minOf { it.first }; nx1 = corners.maxOf { it.first }
        ny0 = corners.minOf { it.second }; ny1 = corners.maxOf { it.second }
        val area = (rx1 - rx0) * (ry1 - ry0)
        val visible = !hidden && area > 1f
        return PdfSignaturePlacement(name, page, nx0.coerceIn(0f, 1f), ny0.coerceIn(0f, 1f), nx1.coerceIn(0f, 1f), ny1.coerceIn(0f, 1f), visible)
    }

    /** Certificates, OCSP responses and CRLs of the /DSS dictionary. */
    fun dss(): PdfDss? = runCatching {
        val dss = pdf.dict(pdf.catalog["DSS"]) ?: return null
        fun streams(key: String) = pdf.array(dss[key]).orEmpty().mapNotNull { (pdf.resolve(it) as? PdfStream)?.let { s -> pdf.decode(s) } }
        PdfDss(streams("Certs"), streams("OCSPs"), streams("CRLs"))
    }.getOrNull()

    /** Number of pages per the page tree root. */
    fun pageCount(): Int? = runCatching { (pdf.dict(pdf.catalog["Pages"])?.get("Count")?.let { pdf.resolve(it) } as? PdfNumber)?.int }.getOrNull()

    /**
     * The document title from the Info dictionary, when it decodes to readable text. An encrypted PDF whose password
     * we do not have leaves the title string as ciphertext (encryptionProblem set), and a few files carry a title in a
     * broken encoding, so both are rejected here and the caller falls back to the file name instead of showing garble.
     */
    fun title(): String? = runCatching {
        if (pdf.encryptionProblem != null) return@runCatching null
        (pdf.resolve(pdf.dict(pdf.trailer["Info"])?.get("Title")) as? PdfString)?.text()?.trim()
            ?.takeIf { s -> s.isNotEmpty() && s.none { c -> c == '�' || (c.isISOControl() && c != '\t' && c != '\n' && c != '\r') } }
    }.getOrNull()

    /**
     * What changed after the revision ending at [signedLength]: nothing, only signatures and validation data (new
     * signature fields and widgets, DSS, document time stamps), or anything else (page content, resources,
     * annotations other than signature widgets, the catalog beyond AcroForm, DSS and extensions).
     */
    fun changesAfter(signedLength: Long): Pair<LaterChanges, List<String>> {
        if (signedLength >= bytes.size) return LaterChanges.NONE to emptyList()
        val tail = bytes.copyOfRange(signedLength.toInt(), bytes.size)
        if (tail.all { PdfParser.isWhite(it.toInt() and 0xFF) || it == 0.toByte() }) return LaterChanges.NONE to emptyList()
        val later = pdf.revisions.filter { it.xrefOffset >= signedLength }
        if (later.isEmpty()) return LaterChanges.OTHER to listOf("簽署範圍之後有無法解析的資料")
        val before = runCatching { PdfFile(bytes.copyOfRange(0, signedLength.toInt())) }.getOrNull()
            ?: return LaterChanges.OTHER to listOf("無法讀取簽署當時的文件版本")
        val pageObjects = HashSet<Int>()
        val pageContent = HashSet<Int>()
        runCatching {
            fun collect(o: PdfObject?, depth: Int) {
                if (depth > 64) return
                val ref = o as? PdfRef
                val d = before.dict(o) ?: return
                if (d.name("Type") == "Pages" || d["Kids"] != null) {
                    before.array(d["Kids"]).orEmpty().forEach { collect(it, depth + 1) }
                    return
                }
                ref?.let { pageObjects.add(it.num) }
                when (val c = d["Contents"]) {
                    is PdfRef -> { pageContent.add(c.num); before.array(c)?.forEach { (it as? PdfRef)?.let { r -> pageContent.add(r.num) } } }
                    is PdfArray -> c.forEach { (it as? PdfRef)?.let { r -> pageContent.add(r.num) } }
                    else -> {}
                }
                val res = before.dict(d["Resources"])
                (d["Resources"] as? PdfRef)?.let { pageContent.add(it.num) }
                listOf("XObject", "Font", "ExtGState", "ColorSpace", "Pattern", "Shading").forEach { k ->
                    (res?.get(k) as? PdfRef)?.let { pageContent.add(it.num) }
                    before.dict(res?.get(k))?.entries?.values?.forEach { (it as? PdfRef)?.let { r -> pageContent.add(r.num) } }
                }
            }
            collect(before.catalog["Pages"], 0)
        }
        val catalogNum = (before.trailer["Root"] as? PdfRef)?.num
        val problems = ArrayList<String>()
        val changed = later.flatMap { it.objects }.toSet()
        for (num in changed) {
            val now = runCatching { pdf.getObject(num) }.getOrNull() ?: continue
            val then = runCatching { before.getObject(num) }.getOrNull() ?: PdfNull
            if (then is PdfNull) {
                // A new object matters only through what refers to it; those referrers are checked below.
                continue
            }
            if (sameObject(now, then)) continue
            when {
                num == catalogNum -> {
                    val keys = changedKeys(now as? PdfDict, then as? PdfDict)
                    val extra = keys - setOf("AcroForm", "DSS", "Extensions", "Version", "Perms")
                    if (extra.isNotEmpty()) problems.add("文件目錄的 ${extra.joinToString("、")} 被修改")
                }
                num in pageContent -> problems.add("頁面內容或資源（物件 $num）被修改")
                num in pageObjects -> {
                    val keys = changedKeys(now as? PdfDict, then as? PdfDict)
                    val extra = keys - setOf("Annots")
                    if (extra.isNotEmpty()) problems.add("頁面的 ${extra.joinToString("、")} 被修改")
                    if ("Annots" in keys) annotationProblems(pdf.array((now as PdfDict)["Annots"]), before.array((then as? PdfDict)?.get("Annots")))?.let { problems.add(it) }
                }
                then is PdfArray && now is PdfArray -> {
                    annotationProblems(now, then)?.let { problems.add(it) }
                }
                then is PdfDict && now is PdfDict -> {
                    val type = now.name("Type")
                    val ft = now.name("FT") ?: pdf.dict(now["Parent"])?.name("FT")
                    val ok = type in setOf("Sig", "DocTimeStamp", "DSS", "VRI", "XRef", "ObjStm") || ft == "Sig" ||
                        now.has("Fields") || now.has("SigFlags")
                    if (!ok) problems.add("物件 $num（${type ?: now.name("Subtype") ?: "字典"}）被修改")
                }
                then is PdfStream && now is PdfStream -> {
                    if (now.dict.name("Type") !in setOf("XRef", "ObjStm", "Metadata")) problems.add("資料流物件 $num 被修改")
                }
                else -> problems.add("物件 $num 被修改")
            }
        }
        return if (problems.isEmpty()) LaterChanges.SIGNATURES_ONLY to emptyList() else LaterChanges.OTHER to problems.distinct()
    }

    private fun annotationProblems(now: PdfArray?, then: PdfArray?): String? {
        val old = then.orEmpty().toSet()
        val added = now.orEmpty().filter { it !in old }
        val bad = added.filter { a ->
            val d = pdf.dict(a) ?: return@filter true
            val ft = d.name("FT") ?: pdf.dict(d["Parent"])?.name("FT")
            !(d.name("Subtype") == "Widget" && ft == "Sig")
        }
        val removed = old.filter { it !in now.orEmpty().toSet() }
        return when {
            bad.isNotEmpty() -> "簽署後加入了簽章以外的註解（${bad.size} 個）"
            removed.isNotEmpty() -> "簽署後移除了註解（${removed.size} 個）"
            else -> null
        }
    }

    private fun changedKeys(a: PdfDict?, b: PdfDict?): Set<String> {
        if (a == null || b == null) return setOf("*")
        return (a.keys + b.keys).filter { !sameObject(a[it] ?: PdfNull, b[it] ?: PdfNull) }.toSet()
    }

    private fun sameObject(a: PdfObject, b: PdfObject): Boolean = when {
        a is PdfStream && b is PdfStream -> a.dict == b.dict && a.data.contentEquals(b.data)
        else -> a == b
    }
}
