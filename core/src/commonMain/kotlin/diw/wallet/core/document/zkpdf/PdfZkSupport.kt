package diw.wallet.core.document.zkpdf

import diw.wallet.core.document.pdf.*

/** PDF structure and decoding helpers for the public side of zkPDF. */
object PdfZkSupport {
    fun signedRevision(pdf: ByteArray, byteRange: IntArray, password: String = ""): PdfFile = zkPdfInput {
        val end = byteRangeEnd(pdf.size, byteRange)
        val covered = pdf.copyOf(end)
        val eof = PdfParser.lastIndexOf(covered, "%%EOF".encodeToByteArray())
        require(eof >= 0 && (eof + 5 until end).all { PdfParser.isWhite(covered[it].toInt() and 255) })
        PdfFile(covered, password).also {
            require(!it.reconstructed && it.revisions.first().xrefOffset < eof)
            require(it.encryptionProblem == null)
        }
    }

    fun pageContentObject(pdf: PdfFile, index: Int): Int = zkPdfInput {
        require(!pdf.reconstructed)
        val page = PdfTextExtractor.pages(pdf).getOrNull(index) ?: error("Page unavailable")
        val ref = page["Contents"] as? PdfRef ?: error("Content must be an indirect stream")
        require(ref.gen == pdf.generation(ref.num) && pdf.getObject(ref.num) is PdfStream)
        ref.num
    }

    /**
     * Object numbers of the streams that [page] shows besides its fonts, in the order they are found: its content
     * streams, thumbnail and metadata, every stream that its resources lead to (XObjects with their masks, patterns,
     * shadings, soft mask groups, colour spaces and functions, through the resources of forms, patterns and groups
     * in turn), and the appearance streams of its annotations with what they lead to, except those of signature
     * fields (the signature itself stays public). Fonts stay public and are not followed. These are the streams whose
     * data a masked file must not keep for a page that is not proven (p4-circuits.md 3.13). Only object structure is
     * read, so it works on the masked file as well.
     */
    fun drawnStreams(pdf: PdfFile, page: PdfDict): List<Int> = zkPdfInput { walkDrawn(pdf, page) {} }

    /** The thumbnail of [page] and every stream it leads to (masks, colour space and lookup streams). */
    fun thumbnailStreams(pdf: PdfFile, page: PdfDict): List<Int> = zkPdfInput {
        val thumb = page["Thumb"] as? PdfRef ?: return@zkPdfInput emptyList()
        walkDrawn(pdf, PdfDict.of("Thumb" to thumb)) {}
    }

    /** Keys that lead away from what a page draws: fonts (public), other pages, structure and navigation. */
    private val NOT_DRAWN = setOf("Font", "Parent", "P", "Pg", "Dest", "A", "AA", "Next", "Prev", "First", "Last", "Popup", "IRT", "StructParent", "StructParents")

    /**
     * Walks what [page] draws (see [drawnStreams]) and returns the streams; [onDict] sees every dictionary reached,
     * including stream dictionaries, so that callers can look for text kept outside streams.
     */
    private fun walkDrawn(pdf: PdfFile, page: PdfDict, onDict: (PdfDict) -> Unit): List<Int> {
        val out = LinkedHashSet<Int>()
        val visited = HashSet<Int>()
        var budget = 200_000
        fun visit(o: PdfObject?, depth: Int) {
            require(depth <= 64 && budget-- > 0) { "Resources nested too deeply" }
            when (o) {
                is PdfRef -> {
                    val target = pdf.getObject(o.num)
                    if (target is PdfStream) {
                        if (out.add(o.num)) visit(target.dict, depth + 1)
                    } else if (visited.add(o.num)) visit(target, depth + 1)
                }
                is PdfStream -> visit(o.dict, depth + 1)
                is PdfDict -> {
                    if (o.name("Type") in setOf("Page", "Pages", "Catalog")) return
                    onDict(o)
                    o.entries.forEach { (key, value) -> if (key !in NOT_DRAWN) visit(value, depth + 1) }
                }
                is PdfArray -> o.forEach { visit(it, depth + 1) }
                else -> {}
            }
        }
        when (val contents = page["Contents"]) {
            is PdfRef -> if (pdf.getObject(contents.num) is PdfStream) visit(contents, 0) else pdf.array(contents)?.forEach { visit(it, 0) }
            is PdfArray -> contents.forEach { visit(it, 0) }
            else -> {}
        }
        visit(page["Thumb"], 0)
        visit(page["Metadata"], 0)
        visit(page["Resources"], 0)
        pdf.array(page["Annots"])?.forEach { a ->
            val annotation = pdf.dict(a) ?: return@forEach
            // A signature field shows the signature, which the masked file keeps public anyway.
            if (isSignatureWidget(pdf, annotation)) return@forEach
            visit(annotation["AP"], 0)
        }
        return out.toList()
    }

    /**
     * Whether a stream can show page content (an image, form, pattern or shading), as opposed to a colour profile,
     * function or metadata that only describes how content is shown.
     */
    fun showsContent(stream: PdfStream): Boolean =
        stream.dict.name("Subtype") in setOf("Image", "Form") || stream.dict["PatternType"] != null || stream.dict["ShadingType"] != null

    private fun isSignatureWidget(pdf: PdfFile, annotation: PdfDict) = annotation.name("Subtype") == "Widget" &&
        (annotation.name("FT") ?: pdf.dict(annotation["Parent"])?.name("FT")) == "Sig"

    /** Annotation keys that only place, style or link an annotation, or hold text that is checked on its own. */
    private val ANNOTATION_KEYS = setOf(
        "Type", "Subtype", "Rect", "AP", "AS", "F", "P", "NM", "M", "CreationDate", "Border", "BS", "BE", "C", "IC",
        "CA", "ca", "BM", "StructParent", "OC", "DA", "DS", "Q", "Popup", "Open", "RD", "IT", "Lang", "Parent",
        "Contents", "RC", "T", "Subj",
    )

    /** Further keys of a form field widget: the field type, flags and design, and the value (checked on its own). */
    private val WIDGET_KEYS = setOf("FT", "Ff", "Kids", "H", "MK", "MaxLen", "DR", "TU", "TM", "Opt", "DV", "V", "RV")

    /** Strings of an annotation that only style or identify it: appearance and style strings, unique name, dates. */
    private val STYLE_STRINGS = setOf("DA", "DS", "NM", "M", "CreationDate")

    /** Entries that lead to other objects, checked on their own or public: fields above, page, appearance, resources. */
    private val NOT_OWN = setOf("Parent", "Kids", "P", "AP", "Popup", "DR")

    /**
     * Whether annotation or field dictionary [d] holds a non-empty string anywhere in its own entries (also inside
     * dictionaries and arrays such as `/MK` captions), apart from style strings and, for a form field, its name `/T`.
     */
    private fun keepsStrings(pdf: PdfFile, d: PdfDict, field: Boolean): Boolean {
        var budget = 10_000
        val seen = HashSet<Int>()
        fun scan(o: PdfObject?, depth: Int): Boolean {
            require(depth <= 32 && budget-- > 0) { "Annotation too large" }
            if (o is PdfRef && !seen.add(o.num)) return false
            return when (val v = pdf.resolve(o)) {
                is PdfString -> v.bytes.isNotEmpty()
                is PdfArray -> v.any { scan(it, depth + 1) }
                is PdfDict -> v.entries.any { (key, value) -> key !in STYLE_STRINGS && key !in NOT_OWN && scan(value, depth + 1) }
                else -> false
            }
        }
        return d.entries.any { (key, value) ->
            key !in STYLE_STRINGS && key !in NOT_OWN && !(field && key == "T") && scan(value, 0)
        }
    }

    /** Field entries that hold what a form field shows or offers: its value, default value and options. */
    private val FIELD_CONTENT = listOf("V", "RV", "DV", "Opt", "I")

    /** Page keys that only describe its boxes, resources and the objects that [drawnStreams] hides. */
    private val PAGE_KEYS = setOf(
        "Type", "Parent", "LastModified", "Resources", "MediaBox", "CropBox", "BleedBox", "TrimBox", "ArtBox",
        "BoxColorInfo", "Contents", "Rotate", "Group", "Thumb", "Annots", "Metadata", "StructParents", "Tabs",
        "UserUnit", "Trans", "Dur",
    )

    private fun present(pdf: PdfFile, o: PdfObject?): Boolean = when (val v = pdf.resolve(o)) {
        null, PdfNull -> false
        is PdfString -> v.bytes.isNotEmpty()
        is PdfName -> v.name != "Off"
        is PdfArray -> v.isNotEmpty()
        else -> true
    }

    /**
     * Whether [page] keeps content outside any stream: a page entry other than its boxes, resources and drawn objects
     * (for example page piece data, actions, article beads or viewports), or an annotation that does. For annotations
     * that is the text of a note or free-text annotation (`/Contents`, `/RC`), its author and subject (`/T`, `/Subj`),
     * the value, default value or options of a form field (`/V`, `/RV`, `/DV`, `/Opt`, `/I`, on the widget or a
     * parent field), any other string such as a caption in `/MK` or a tooltip (only style strings, dates, the unique
     * name and field names may stay), or any entry beyond placement, style and
     * appearance: ink and polygon coordinates, quad points, attached files, sounds, movies, link targets, actions and
     * replies all keep what a page shows or points to in dictionaries. Masking clears stream data only, so a page
     * that is not proven must not have any; signature fields are left out as in [drawnStreams]. Only object
     * structure is read, so it works on the masked file as well.
     */
    fun keepsAnnotationText(pdf: PdfFile, page: PdfDict): Boolean = zkPdfInput {
        fun present(o: PdfObject?) = present(pdf, o)
        if (page.entries.any { (key, value) -> key !in PAGE_KEYS && present(value) }) return@zkPdfInput true
        pdf.array(page["Annots"])?.any { a ->
            val annotation = pdf.dict(a) ?: return@any false
            if (isSignatureWidget(pdf, annotation)) return@any false
            val widget = annotation.name("Subtype") == "Widget"
            val allowed = if (widget) ANNOTATION_KEYS + WIDGET_KEYS else ANNOTATION_KEYS
            if (annotation.entries.any { (key, value) -> key !in allowed && present(value) }) return@any true
            if (keepsStrings(pdf, annotation, widget)) return@any true
            if (!widget) return@any false
            // A field value may sit on the widget or on any field above it.
            var field: PdfDict? = annotation
            var depth = 0
            while (field != null && depth++ < 16) {
                if (FIELD_CONTENT.any { present(field[it]) } || keepsStrings(pdf, field, true)) return@any true
                field = pdf.dict(field["Parent"])
            }
            false
        } ?: false
    }

    /**
     * Whether the signed revision keeps content that masking would not reach: an earlier version of an object (one
     * written again by a later update; found as an object header outside the newest streams at an offset the
     * cross-reference data no longer points to, or in an object stream that no longer holds its newest version) that
     * holds stream data, or text and coordinates that the newest version dropped or changed, or an object that nothing
     * in the document refers to and that holds either. Masking clears only the newest streams that pages draw, so such
     * bytes would reach the verifier. Numbers, names, booleans and references of earlier versions only place, style
     * or link, and array items that remain are kept anyway. Cross-reference and object streams are part of the
     * structure, and document metadata (XMP `/Type /Metadata` and the document information dictionary of any revision)
     * is public; signing tools often rewrite both.
     */
    fun keepsUnreachableStreams(pdf: PdfFile): Boolean = zkPdfInput {
        fun structural(s: PdfStream) = s.dict.name("Type") in setOf("XRef", "ObjStm", "Metadata")
        val infos = pdf.revisions.mapNotNull { (it.trailer["Info"] as? PdfRef)?.num }.toSet()
        var budget = 2_000_000
        // Whether earlier version [old] keeps nothing that the newest version [new] dropped or changed.
        fun kept(old: PdfObject, new: PdfObject?, depth: Int): Boolean {
            require(depth <= 64 && budget-- > 0) { "Document too large" }
            if (old == new) return true
            val resolved = if (new is PdfRef) pdf.resolveOrNull(new) else new
            if (old == resolved) return true
            return when (old) {
                is PdfString -> old.bytes.isEmpty()
                is PdfArray -> {
                    val items = (resolved as? PdfArray)?.items?.toSet().orEmpty()
                    old.items.all { it in items || it is PdfRef || it is PdfName || it is PdfNull }
                }
                is PdfDict -> {
                    val current = resolved as? PdfDict
                    old.entries.all { (key, value) -> kept(value, current?.get(key), depth + 1) }
                }
                is PdfStream -> structural(old)
                else -> true
            }
        }
        fun current(num: Int): PdfObject? = runCatching { pdf.getObject(num) }.getOrNull()
        fun contents(s: PdfStream): Map<Int, PdfObject>? = runCatching { pdf.objectStreamContents(s) }.getOrNull()
        val bytes = pdf.bytes
        val stored = pdf.storedObjects.associateWith { current(it) }
        val extents = stored.filterValues { it is PdfStream }.keys
            .mapNotNull { runCatching { streamExtent(pdf, it) }.getOrNull() }.sortedBy { it.first }
        val starts = extents.map { it.first }
        fun insideStream(position: Int): Boolean {
            val i = starts.binarySearch(position).let { if (it >= 0) it else -it - 2 }
            return i >= 0 && position in extents[i]
        }
        val text = String(CharArray(bytes.size) { (bytes[it].toInt() and 255).toChar() })
        for (m in Regex("(?<![0-9])([0-9]{1,10})\\s+([0-9]{1,5})\\s+obj(?![A-Za-z])").findAll(text)) {
            val position = m.range.first
            if (insideStream(position)) continue
            val num = m.groupValues[1].toIntOrNull() ?: continue
            if (pdf.offsetOf(num) == position) continue
            val (found, old) = runCatching { pdf.objectAt(position) }.getOrNull() ?: return@zkPdfInput true
            if (found != num) return@zkPdfInput true
            if (num in infos) continue
            if (old is PdfStream && old.dict.name("Type") == "ObjStm") {
                val held = contents(old) ?: return@zkPdfInput true
                if (held.any { (n, o) -> n !in infos && !kept(o, current(n), 0) }) return@zkPdfInput true
            } else if (!kept(old, current(num), 0)) return@zkPdfInput true
        }
        // Earlier versions kept in object streams that are still listed, and the objects they still hold.
        val compressed = HashMap<Int, PdfObject>()
        for ((num, s) in stored) {
            if (s !is PdfStream || s.dict.name("Type") != "ObjStm") continue
            val held = contents(s) ?: return@zkPdfInput true
            for ((n, o) in held) {
                if (pdf.containerOf(n) == num) compressed[n] = o
                else if (n !in infos && !kept(o, current(n), 0)) return@zkPdfInput true
            }
        }
        val reached = HashSet<Int>()
        val pending = ArrayList<PdfObject>(pdf.trailer.entries.values)
        while (pending.isNotEmpty()) {
            require(budget-- > 0) { "Document too large" }
            when (val o = pending.removeAt(pending.size - 1)) {
                is PdfRef -> if (reached.add(o.num)) current(o.num)?.let { pending.add(it) }
                is PdfDict -> pending.addAll(o.entries.values)
                is PdfArray -> pending.addAll(o.items)
                is PdfStream -> pending.addAll(o.dict.entries.values)
                else -> {}
            }
        }
        (stored + compressed).any { (num, o) ->
            num !in reached && num !in infos && o != null && !(o is PdfStream && structural(o)) && !kept(o, null, 0)
        }
    }

    /** Object numbers of the page objects, in the order of [PdfTextExtractor.pages]. */
    fun pageObjects(pdf: PdfFile): List<Int> = zkPdfInput {
        val out = ArrayList<Int>()
        val seen = HashSet<PdfObject>()
        fun walk(node: PdfObject?, depth: Int) {
            if (depth > 64 || (node is PdfRef && !seen.add(node))) return
            val d = pdf.dict(node) ?: return
            val kids = pdf.array(d["Kids"])
            if (kids != null && d.name("Type") != "Page") kids.forEach { walk(it, depth + 1) }
            else out += (node as? PdfRef)?.num ?: error("Page stored directly")
        }
        walk(pdf.catalog["Pages"], 0)
        out
    }

    /**
     * Whether text that masking cannot clear (it is not stream data) would stay in the file: page or annotation
     * entries of one of the [hidden] pages that keep content ([keepsAnnotationText]), an outline item that leads to one of them, or alternate or actual text
     * anywhere in the structure tree (it repeats page content, so it would expose proven pages as well). Outline items
     * whose destination is not an explicit page count as leading to a hidden page.
     */
    fun keepsTextOutsideStreams(pdf: PdfFile, hidden: List<Int>): Boolean = zkPdfInput {
        val pages = PdfTextExtractor.pages(pdf)
        if (hidden.any { keepsAnnotationText(pdf, pages[it]) }) return@zkPdfInput true
        // Marked-content properties and the dictionaries of what a hidden page draws may carry its text as well.
        val textKeys = listOf("ActualText", "Alt", "E")
        for (index in hidden) {
            var found = false
            walkDrawn(pdf, pages[index]) { d ->
                if (!found) found = textKeys.any { (pdf.resolve(d[it]) as? PdfString)?.bytes?.isNotEmpty() == true }
            }
            if (found) return@zkPdfInput true
        }
        var budget = 200_000
        val seen = HashSet<Int>()
        fun hasText(d: PdfDict) = listOf("Alt", "ActualText", "E").any { (pdf.resolve(d[it]) as? PdfString)?.bytes?.isNotEmpty() == true }
        fun structure(o: PdfObject?, depth: Int): Boolean {
            require(depth <= 128 && budget-- > 0) { "Structure tree too large" }
            if (o is PdfRef && !seen.add(o.num)) return false
            return when (val v = pdf.resolve(o)) {
                is PdfArray -> v.any { structure(it, depth + 1) }
                is PdfDict -> hasText(v) || structure(v["K"], depth + 1)
                else -> false
            }
        }
        if (structure(pdf.dict(pdf.catalog["StructTreeRoot"])?.get("K"), 0)) return@zkPdfInput true
        if (hidden.isEmpty()) return@zkPdfInput false
        val numbers = pageObjects(pdf)
        require(numbers.size == pages.size)
        val private = hidden.map { numbers[it] }.toSet()
        fun leadsToHidden(item: PdfDict): Boolean {
            val destination = item["Dest"] ?: pdf.dict(item["A"])?.takeIf { it.name("S") == "GoTo" }?.get("D") ?: return false
            val page = pdf.array(destination)?.firstOrNull() as? PdfRef ?: return true
            return page.num in private
        }
        val visited = HashSet<Int>()
        val stack = ArrayList<PdfObject>()
        pdf.dict(pdf.catalog["Outlines"])?.get("First")?.let { stack += it }
        while (stack.isNotEmpty()) {
            val node = stack.removeAt(stack.size - 1)
            require(budget-- > 0) { "Outlines too large" }
            if (node is PdfRef && !visited.add(node.num)) continue
            val item = pdf.dict(node) ?: continue
            if (leadsToHidden(item) && (pdf.resolve(item["Title"]) as? PdfString)?.bytes?.isNotEmpty() == true) return@zkPdfInput true
            item["Next"]?.let { stack += it }
            item["First"]?.let { stack += it }
        }
        false
    }

    /**
     * Object numbers of the streams that [page] really draws: the XObjects its content streams name with `Do` and the
     * patterns and graphics states they name with `scn`/`SCN` and `gs` (its soft mask group), recursively through the forms and tiling patterns drawn, the masks of the
     * images drawn, and the appearance streams of its annotations with what they draw. Unlike [drawnStreams] it reads
     * stream data, so it is for the holder, on the file before masking.
     */
    fun usedStreams(pdf: PdfFile, page: PdfDict): Set<Int> = zkPdfInput {
        val out = HashSet<Int>()
        lateinit var draw: (ByteArray, PdfDict?, Int) -> Unit
        fun named(resources: PdfDict?, category: String, name: String, depth: Int) {
            val o = pdf.dict(resources?.get(category))?.get(name) ?: return
            val value = pdf.resolve(o)
            // A shading pattern is a dictionary; what it shows is its shading.
            if (category == "Pattern" && value is PdfDict) {
                (value["Shading"] as? PdfRef)?.num?.takeIf { pdf.getObject(it) is PdfStream }?.let { out.add(it) }
                return
            }
            val stream = value as? PdfStream ?: return
            val num = (o as? PdfRef)?.num
            if (num != null && !out.add(num)) return
            when {
                category == "Shading" -> return
                category == "XObject" && stream.dict.name("Subtype") == "Image" -> {
                    listOf("SMask", "Mask").forEach { key -> (stream.dict[key] as? PdfRef)?.num?.let { out.add(it) } }
                    return
                }
                category == "XObject" && stream.dict.name("Subtype") != "Form" -> return
            }
            draw(pdf.decode(stream), pdf.dict(stream.dict["Resources"]) ?: resources, depth + 1)
        }
        fun graphicsState(resources: PdfDict?, name: String, depth: Int) {
            val state = pdf.dict(pdf.dict(resources?.get("ExtGState"))?.get(name)) ?: return
            val group = pdf.dict(state["SMask"])?.get("G") as? PdfRef ?: return
            val stream = pdf.getObject(group.num) as? PdfStream ?: return
            if (!out.add(group.num)) return
            draw(pdf.decode(stream), pdf.dict(stream.dict["Resources"]) ?: resources, depth + 1)
        }
        draw = fun(data: ByteArray, resources: PdfDict?, depth: Int) {
            require(depth <= 16) { "Resources nested too deeply" }
            val operands = ArrayList<Any>()
            for (token in PdfTextExtractor.tokens(data)) {
                if (token !is PdfTextExtractor.Keyword) { operands += token; continue }
                val name = (operands.lastOrNull() as? PdfName)?.name
                if (name != null) when (token.word) {
                    "Do" -> named(resources, "XObject", name, depth)
                    "scn", "SCN" -> named(resources, "Pattern", name, depth)
                    "gs" -> graphicsState(resources, name, depth)
                    "sh" -> named(resources, "Shading", name, depth)
                }
                operands.clear()
            }
        }
        val resources = pdf.dict(page["Resources"])
        val contents = when (val c = page["Contents"]) {
            is PdfRef -> (pdf.getObject(c.num) as? PdfStream)?.let { listOf(it) }
                ?: pdf.array(c)?.mapNotNull { pdf.resolve(it) as? PdfStream }.orEmpty()
            is PdfArray -> c.mapNotNull { pdf.resolve(it) as? PdfStream }
            else -> emptyList()
        }
        contents.forEach { draw(pdf.decode(it), resources, 0) }
        fun appearance(o: PdfObject?) {
            val num = (o as? PdfRef)?.num ?: return
            val stream = pdf.getObject(num) as? PdfStream ?: return
            if (!out.add(num)) return
            draw(pdf.decode(stream), pdf.dict(stream.dict["Resources"]), 1)
        }
        pdf.array(page["Annots"])?.forEach { a ->
            val annotation = pdf.dict(a) ?: return@forEach
            if (isSignatureWidget(pdf, annotation)) return@forEach
            val ap = pdf.dict(annotation["AP"]) ?: return@forEach
            listOf("N", "R", "D").forEach { key ->
                val entry = ap[key]
                if (pdf.resolve(entry) is PdfStream) appearance(entry)
                else pdf.dict(entry)?.entries?.values?.forEach { appearance(it) }
            }
        }
        out
    }

    fun streamExtent(pdf: PdfFile, num: Int): IntRange = zkPdfInput {
        require(!pdf.reconstructed)
        val offset = pdf.offsetOf(num) ?: error("Stream must be stored directly")
        val parser = PdfParser(pdf.bytes, offset) { dictionary ->
            val length = (pdf.resolve(dictionary["Length"]) as? PdfNumber)?.long
                ?: error("Stream length unavailable")
            require(length in 0..pdf.bytes.size.toLong())
            length.toInt()
        }
        val (actual, generation, value) = parser.parseIndirect()
        require(actual == num && generation == pdf.generation(num) && value is PdfStream)
        val range = parser.lastStreamExtent ?: error("Stream extent unavailable")
        val declared = (pdf.resolve(value.dict["Length"]) as? PdfNumber)?.long
        require(declared == range.count().toLong())
        range
    }

    /** Null for unencrypted files, unsupported handlers, or a non-empty user password. */
    fun rc4KeyStream(pdf: PdfFile, num: Int, length: Int): ByteArray? = zkPdfInput {
        require(length >= 0)
        if (!pdf.encrypted) return@zkPdfInput null
        // The encryption dictionary itself is never encrypted. Read its raw
        // object instead of passing /O and /U through normal object decryption.
        val enc = when (val reference = pdf.trailer["Encrypt"]) {
            is PdfDict -> reference
            is PdfRef -> {
                val offset = pdf.offsetOf(reference.num) ?: return@zkPdfInput null
                val (number, generation, value) = PdfParser(pdf.bytes, offset).parseIndirect()
                require(number == reference.num && generation == reference.gen)
                value as? PdfDict ?: return@zkPdfInput null
            }
            else -> return@zkPdfInput null
        }
        if (enc.name("Filter") != "Standard" || (enc["V"] as? PdfNumber)?.int != 2 ||
            (enc["R"] as? PdfNumber)?.int != 3) return@zkPdfInput null
        val bits = (enc["Length"] as? PdfNumber)?.int ?: 40
        if (bits !in 40..128 || bits % 8 != 0) return@zkPdfInput null
        val handler = try { StandardSecurity.open(enc, pdf.firstId(), "") } catch (_: PdfException) {
            return@zkPdfInput null
        }
        require(length <= streamExtent(pdf, num).count())
        handler.decryptStream(ByteArray(length), num, pdf.generation(num))
    }

    fun fontDecoders(pdf: PdfFile, index: Int): Map<String, ZkFontDecoder> = zkPdfInput {
        val page = PdfTextExtractor.pages(pdf).getOrNull(index) ?: error("Page unavailable")
        val resources = pdf.dict(page["Resources"])
        val fonts = pdf.dict(resources?.get("Font")) ?: return@zkPdfInput emptyMap()
        fonts.entries.mapValues { (_, reference) ->
            val dictionary = pdf.dict(reference) ?: error("Font unavailable")
            val kind = if (dictionary.name("Subtype") == "Type0") {
                require(dictionary.name("Encoding") == "Identity-H" && pdf.resolve(dictionary["ToUnicode"]) is PdfStream)
                2
            } else {
                require(dictionary.name("Subtype") in setOf("Type1", "MMType1", "TrueType", "Type3"))
                1
            }
            FontDecoder(PdfFont.of(pdf, dictionary), kind)
        }
    }

    private class FontDecoder(private val font: PdfFont, override val kind: Int) : ZkFontDecoder {
        override fun decode(raw: ByteArray, literal: Boolean): String = zkPdfInput {
            val decoded = decodeZkString(raw, literal)
            require(kind != 2 || decoded.size % 2 == 0)
            font.codes(decoded).joinToString("") { (code, _) -> font.unicode(code) ?: error("Unmapped font code") }
        }

        override fun digitCodes(): IntArray? {
            val codes = IntArray(10) { -1 }
            for (code in 0 until if (kind == 1) 256 else 65536) {
                val text = font.unicode(code) ?: continue
                if (text.length != 1 || text[0] !in '0'..'9') continue
                val digit = text[0] - '0'
                if (codes[digit] != -1) return null
                codes[digit] = code
            }
            return codes.takeIf { it.all { code -> code >= 0 } }
        }
    }
}

interface ZkFontDecoder {
    val kind: Int
    /** Raw source bytes without delimiters; false denotes ASCII hex source, not already decoded bytes. */
    fun decode(raw: ByteArray, literal: Boolean): String
    fun digitCodes(): IntArray?
}

/** Reuses the existing PDF string parser, including octal escapes, nested parentheses and odd hex nibbles. */
internal fun decodeZkString(raw: ByteArray, literal: Boolean): ByteArray {
    val source = byteArrayOf(if (literal) 40 else 60) + raw + byteArrayOf(if (literal) 41 else 62)
    val parser = PdfParser(source)
    val string = parser.parseObject() as? PdfString ?: error("Invalid PDF string")
    require(parser.pos == source.size)
    return string.bytes
}

/** Never propagate parser diagnostics that might quote document bytes or a password. */
internal inline fun <T> zkPdfInput(block: () -> T): T = try {
    block()
} catch (_: Exception) {
    throw PdfException("Unsupported or malformed zkPDF input")
}
