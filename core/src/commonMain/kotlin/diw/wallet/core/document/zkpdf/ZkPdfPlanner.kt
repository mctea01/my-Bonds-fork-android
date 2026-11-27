package diw.wallet.core.document.zkpdf

import diw.wallet.core.i18n.ct
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.pdf.*

/** A private byte range of the signed message and the public SHA-256 context around it (p4-circuits.md 3.2). */
class ZkPdfWindowPlan(
    /** content or opaque. */
    val role: String,
    /** Object number of the stream whose data this is. */
    val objectNumber: Int,
    /** Position of the stream data in the file. */
    val fileOffset: Int,
    val length: Int,
    /** First SHA-256 block of the window within the signed message. */
    val firstBlock: Int,
    val blocks: Int,
    /** SHA-256 state before the first block. */
    val midIn: ByteArray,
    /** Public bytes of the first block before the stream data, and of the last block after it. */
    val head: ByteArray,
    val tail: ByteArray,
    /** RC4 key stream of the content window (null when the file is not encrypted, and for opaque windows). */
    val keyStream: ByteArray?,
)

class ZkPdfAnchorPlan(val label: String, val record: ZkPdfTextRecord, val ordinal: Int, val total: Int)

/** A proven field: its slot and anchors on its page (0-based [page]) and its normalized value. */
class ZkPdfSlotPlan(val claim: String, val slot: Int, val beforeAnchor: Int, val afterAnchor: Int, val value: String, val page: Int = 0)

class ZkPdfDigitPlan(val font: ByteArray, val width: Int, val codes: IntArray)

/** DATE_LE (0) or DATE_GE (1) against a YYYYMMDD cutoff, on the date of [claim]. */
class ZkPdfPredicate(val kind: Int, val claim: String, val cutoff: Int) {
    init {
        require(kind == DATE_LE || kind == DATE_GE) { "Unknown zkPDF predicate" }
        require(cutoff in 10000101..99991231) { "Invalid cutoff" }
    }

    companion object {
        const val DATE_LE = 0
        const val DATE_GE = 1
        const val FORMAT_YMD = 0
    }
}

/** One proven page of a layout: its windows in statement order (its content window first) and its fonts. */
class ZkPdfPageLayout(
    /** Page index, 0-based. */
    val page: Int,
    /** Indices into [ZkPdfLayout.windows]: this page's content, its private images and the hidden windows it carries. */
    val windows: List<Int>,
    val digitTables: List<ZkPdfDigitPlan>,
    val decoders: Map<String, ZkFontDecoder>,
)

/** The public description of a signed PDF that both the holder and the verifier derive the same way. */
class ZkPdfLayout(
    val byteRange: IntArray,
    /** Every private window of the file: the windows of each proven page in page order, each page's after the last. */
    val windows: List<ZkPdfWindowPlan>,
    /** The proven pages in ascending order; each is one statement and one chain of segment proofs. */
    val pages: List<ZkPdfPageLayout>,
    /** Pages of the signed revision. */
    val pageCount: Int,
) {
    /** Fonts of the first proven page. */
    val decoders: Map<String, ZkFontDecoder> get() = pages.first().decoders
    val digitTables: List<ZkPdfDigitPlan> get() = pages.first().digitTables
}

/** The fields one proven page proves: its anchors, its slots (numbered from 0 on the page) and its predicates. */
class ZkPdfPartPlan(
    /** Page index, 0-based. */
    val page: Int,
    val anchors: List<ZkPdfAnchorPlan>,
    val slots: List<ZkPdfSlotPlan>,
    /** Each predicate with the slot (on this page) it applies to. */
    val predicates: List<Pair<ZkPdfPredicate, Int>>,
)

/** Everything the prover needs except the salts and the binding, which the caller adds. */
class ZkPdfPlan(
    val profile: ZkPdfProfile,
    val layout: ZkPdfLayout,
    /** Raw stream data (as stored in the file) of each window, in [ZkPdfLayout.windows] order. */
    val privateData: List<ByteArray>,
    /** One part per proven page, in [ZkPdfLayout.pages] order. */
    val parts: List<ZkPdfPartPlan>,
    /** Fields of the template that cannot be proven in this file, with the reason shown to the person. */
    val unavailable: Map<String, String>,
) {
    /** Every proven field, part by part; salts and openings follow this order. */
    val slots: List<ZkPdfSlotPlan> get() = parts.flatMap { it.slots }
    /** Anchors of the first proven page. */
    val anchors: List<ZkPdfAnchorPlan> get() = parts.firstOrNull()?.anchors.orEmpty()
    /** Predicates of every page, each with its slot on its page. */
    val predicates: List<Pair<ZkPdfPredicate, Int>> get() = parts.flatMap { it.predicates }
}

/**
 * Plans a zkPDF proof of a signed PDF (WP4): finds the signed revision, the pages the template proves, their
 * content and private image windows, the windows that keep every other page private, the anchors and fields of
 * the template, and the digit tables for date predicates. The verifier rebuilds the same [ZkPdfLayout] from the
 * masked file with [layout]. Errors never quote document content.
 */
object ZkPdfPlanner {
    const val MAX_COMPRESSED = 8192
    private const val CONTENT_BLOCKS = 130
    private const val OPAQUE_BLOCKS = 128
    private const val MAX_DIGIT_FONTS = 4
    /** Windows of one statement: the content window and at most 15 opaque ones (the native prover's limit). */
    const val MAX_STATEMENT_WINDOWS = 16
    /** Predicates of one statement (the predicate circuit). */
    const val MAX_PREDICATES = 2

    /** The single document signature: ByteRange [0, b, c, d] with only the signature value in the gap. */
    fun signature(file: PdfFile): PdfSignatureField = zkPdfInput {
        val fields = PdfSignatures(file).fields().filter { it.type != "DocTimeStamp" }
        val field = fields.singleOrNull() ?: error("One document signature is required")
        require(field.byteRange.size == 4 && field.byteRange[0] == 0L && field.gapIsContentsOnly)
        field
    }

    /**
     * The window layout of [pdf] for [profile] when [provenPages] (0-based, ascending, pages of the template) are
     * proven. Each proven page has a content window and windows for its private images; every stream that a page
     * outside [provenPages] shows (its content, images, forms and annotation appearances, [PdfZkSupport.drawnStreams])
     * and that no proven page shows publicly becomes opaque windows of at most 128 blocks each, as do the thumbnails of
     * proven pages. Reads only object structure and stream positions, so it works on the masked file too. The SHA-256
     * state entering a window depends on every earlier byte: the holder leaves [midOuts] null and hashes the real
     * windows; the verifier passes the claimed outgoing state of each window (in layout order) and later checks that
     * the proofs attest exactly those states (V3, V8).
     */
    fun layout(
        pdf: ByteArray,
        profile: ZkPdfProfile,
        password: String = "",
        midOuts: List<ByteArray>? = null,
        provenPages: List<Int> = profile.pages.map { it - 1 },
    ): ZkPdfLayout = zkPdfInput {
        val whole = PdfFile(pdf, password)
        val range = signature(whole).byteRange.map { it.toInt() }.toIntArray()
        val signed = PdfZkSupport.signedRevision(pdf, range, password)
        val pages = PdfTextExtractor.pages(signed)
        require(provenPages.isNotEmpty() && provenPages.zipWithNext().all { (a, b) -> a < b }) { "Invalid proven pages" }
        require(provenPages.all { it in pages.indices && it + 1 in profile.pages }) { "Page unavailable" }
        val message = Sha256Chain.message(pdf, range)
        // The private streams of each proven page: its content stream, then the private images of the template.
        val own = provenPages.map { index ->
            val content = PdfZkSupport.pageContentObject(signed, index)
            val xobjects = signed.dict(signed.dict(pages[index]["Resources"])?.get("XObject"))
            val images = profile.opaqueImages.filter { it.page == index + 1 }.map { image ->
                val ref = xobjects?.entries?.get(image.name) as? PdfRef ?: error("Private image unavailable")
                val stream = signed.getObject(ref.num) as? PdfStream ?: error("Private image unavailable")
                require(stream.dict.name("Subtype") == "Image" && ref.num != content)
                ref.num
            }
            content to images
        }
        val private = own.flatMap { (content, images) -> listOf(content) + images }.toSet()
        require(private.size == own.sumOf { 1 + it.second.size }) { "Private streams are shared" }
        // What proven pages show stays public as in a single-page proof, except their thumbnails (a picture of the page).
        val thumbs = provenPages.mapNotNull { (pages[it]["Thumb"] as? PdfRef)?.num?.takeIf { n -> signed.getObject(n) is PdfStream } }
        val shown = provenPages.flatMap { PdfZkSupport.drawnStreams(signed, pages[it]) }.toSet() - private - thumbs.toSet()
        val others = pages.indices.filter { it !in provenPages }
        // Masking clears stream data only: text kept in dictionaries (annotations, outlines, structure tree) would stay public.
        require(!PdfZkSupport.keepsTextOutsideStreams(signed, others)) { "Text outside streams" }
        // So are earlier versions of streams and streams nothing refers to, which masking does not reach.
        require(!PdfZkSupport.keepsUnreachableStreams(signed)) { "Unreachable stream data" }
        val hidden = (others.flatMap { PdfZkSupport.drawnStreams(signed, pages[it]) } + thumbs)
            .distinct().filter { it !in shown && it !in private && PdfZkSupport.streamExtent(signed, it).count() > 0 }
        val parts = own.map { (content, images) ->
            ArrayList(window(signed, message, range, "content", content) + images.flatMap { window(signed, message, range, "opaque", it) })
        }
        // Hidden windows fill the statements in page order, up to the native limit of each.
        for (w in hidden.flatMap { window(signed, message, range, "opaque", it) }) {
            val part = parts.firstOrNull { it.size < MAX_STATEMENT_WINDOWS } ?: error("Too much private data on other pages")
            part += w
        }
        val placed = parts.flatten()
        require(midOuts == null || midOuts.size == placed.size && midOuts.all { it.size == 32 })
        val midIns = arrayOfNulls<ByteArray>(placed.size)
        var state = Sha256State.INITIAL
        var position = 0
        for (i in placed.indices.sortedBy { placed[it].firstBlock }) {
            val w = placed[i]
            require(w.firstBlock >= position) { "Private windows overlap" }
            while (position < w.firstBlock) state = state.compress(message.block(position++))
            midIns[i] = state.toBytes()
            if (midOuts != null) {
                state = Sha256State.ofBytes(midOuts[i])
                position += w.blocks
            } else repeat(w.blocks) { state = state.compress(message.block(position++)) }
        }
        val windows = placed.mapIndexed { i, w ->
            ZkPdfWindowPlan(w.role, w.objectNumber, w.fileOffset, w.length, w.firstBlock, w.blocks, midIns[i]!!, w.head, w.tail, w.keyStream)
        }
        var next = 0
        val layouts = provenPages.mapIndexed { i, index ->
            val decoders = PdfZkSupport.fontDecoders(signed, index)
            val tables = decoders.entries.mapNotNull { (name, decoder) ->
                decoder.digitCodes()?.let { ZkPdfDigitPlan(name.encodeToByteArray(), decoder.kind, it) }
            }.take(MAX_DIGIT_FONTS)
            ZkPdfPageLayout(index, List(parts[i].size) { next++ }, tables, decoders)
        }
        ZkPdfLayout(range, windows, layouts, pages.size)
    }

    /**
     * The windows of stream [num]: one for a content stream, and for an opaque stream as many windows of at most 128
     * blocks as its data needs, back to back, so that only the first has a head and only the last a tail.
     */
    private fun window(pdf: PdfFile, message: Sha256Message, range: IntArray, role: String, num: Int): List<ZkPdfWindowPlan> {
        val extent = PdfZkSupport.streamExtent(pdf, num)
        val start = extent.first
        val length = extent.count()
        require(length > 0)
        val end = start + length
        val offset = when {
            end <= range[1] -> start
            start >= range[2] && end <= range[2] + range[3] -> start - (range[2] - range[1])
            else -> error("Stream crosses the signature value")
        }
        val left = offset / 64 * 64
        val right = (offset + length + 63) / 64 * 64
        require(right <= message.messageBytes / 64 * 64) { "Private window reaches the SHA-256 padding" }
        if (role == "content") {
            require((right - left) / 64 <= CONTENT_BLOCKS && length <= MAX_COMPRESSED)
            val stream = pdf.getObject(num) as PdfStream
            require(stream.dict.name("Filter") == "FlateDecode" && stream.dict["DecodeParms"] == null)
        }
        val limit = if (role == "content") CONTENT_BLOCKS * 64 else OPAQUE_BLOCKS * 64
        return (left until right step limit).map { chunk ->
            val chunkEnd = minOf(chunk + limit, right)
            val from = maxOf(chunk, offset)
            val to = minOf(chunkEnd, offset + length)
            val head = ByteArray(from - chunk) { message.block((chunk + it) / 64)[(chunk + it) % 64] }
            val tail = ByteArray(chunkEnd - to) { message.block((to + it) / 64)[(to + it) % 64] }
            ZkPdfWindowPlan(
                role, num, start + (from - offset), to - from, chunk / 64, (chunkEnd - chunk) / 64, ByteArray(32), head, tail,
                if (role == "content") PdfZkSupport.rc4KeyStream(pdf, num, length) else null,
            )
        }
    }

    /** Why the content stream of page [index] cannot be proven, or null when it can. */
    private fun contentProblem(signed: PdfFile, index: Int, pageCount: Int): String? {
        if (index >= pageCount) return ct("core_zkpdf_page_missing", index + 1)
        return try {
            val num = PdfZkSupport.pageContentObject(signed, index)
            val stream = signed.getObject(num) as PdfStream
            val length = PdfZkSupport.streamExtent(signed, num).count()
            if (length in 1..MAX_COMPRESSED && stream.dict.name("Filter") == "FlateDecode" && stream.dict["DecodeParms"] == null) null
            else ct("core_zkpdf_page_unsupported", index + 1)
        } catch (_: PdfException) {
            ct("core_zkpdf_page_unsupported", index + 1)
        }
    }

    /** Plans the fields of [profile] that this file supports; [predicates] name fields of the template. */
    fun plan(pdf: ByteArray, profile: ZkPdfProfile, predicates: List<ZkPdfPredicate> = emptyList(), password: String = ""): ZkPdfPlan =
        zkPdfInput {
            val range = signature(PdfFile(pdf, password)).byteRange.map { it.toInt() }.toIntArray()
            val signed = PdfZkSupport.signedRevision(pdf, range, password)
            val pageCount = PdfTextExtractor.pages(signed).size
            val unavailable = LinkedHashMap<String, String>()
            val parts = ArrayList<ZkPdfPartPlan>()
            for (page in profile.pages) {
                val index = page - 1
                val rules = profile.fields.filter { it.page == page }
                contentProblem(signed, index, pageCount)?.let { why -> rules.forEach { unavailable[it.claim] = why }; continue }
                val content = signed.decode(signed.getObject(PdfZkSupport.pageContentObject(signed, index)) as PdfStream)
                val part = planPage(index, rules, ZkPdfLexer.records(content), PdfZkSupport.fontDecoders(signed, index), unavailable)
                if (part.slots.isNotEmpty()) parts += part
            }
            val withPredicates = parts.map { part ->
                val on = predicates.mapNotNull { p -> part.slots.firstOrNull { it.claim == p.claim }?.let { p to it.slot } }
                require(on.size <= MAX_PREDICATES) { "Too many predicates on a page" }
                ZkPdfPartPlan(part.page, part.anchors, part.slots, on)
            }
            for (p in predicates) {
                require(parts.any { part -> part.slots.any { it.claim == p.claim } }) { "Predicate field unavailable" }
                require(profile.field(p.claim)?.normalize == ZkPdfNormalize.DATE)
            }
            if (withPredicates.isEmpty()) {
                return@zkPdfInput ZkPdfPlan(profile, ZkPdfLayout(range, emptyList(), emptyList(), pageCount), emptyList(), emptyList(), unavailable)
            }
            val layout = layout(pdf, profile, password, provenPages = withPredicates.map { it.page })
            sharedStreamsAreShown(signed, withPredicates.map { it.page }, layout)
            val private = layout.windows.map { pdf.copyOfRange(it.fileOffset, it.fileOffset + it.length) }
            ZkPdfPlan(profile, layout, private, withPredicates, unavailable)
        }

    /**
     * A stream that another page draws stays public when a proven page lists it in its resources (V5 cannot tell
     * what the masked content of a proven page really draws). Only the holder can check that: every such stream must
     * really be drawn by a proven page, or a private image or form of another page would reach the verifier.
     */
    private fun sharedStreamsAreShown(signed: PdfFile, proven: List<Int>, layout: ZkPdfLayout) {
        val pages = PdfTextExtractor.pages(signed)
        val others = pages.indices.filter { it !in proven }.flatMap { PdfZkSupport.drawnStreams(signed, pages[it]) }.toSet()
        if (others.isEmpty()) return
        val listed = proven.flatMap { PdfZkSupport.drawnStreams(signed, pages[it]) }.toSet()
        val shared = (others intersect listed) - layout.windows.map { it.objectNumber }.toSet()
        if (shared.isEmpty()) return
        val used = proven.flatMap { PdfZkSupport.usedStreams(signed, pages[it]) }.toSet()
        require(shared.all { it in used }) { "A stream of another page is only listed on a proven page" }
    }

    /** The anchors and slots of the fields [rules] of one page, from the text [records] of its content stream. */
    private fun planPage(
        page: Int,
        rules: List<ZkPdfFieldRule>,
        records: List<ZkPdfTextRecord>,
        decoders: Map<String, ZkFontDecoder>,
        unavailable: MutableMap<String, String>,
    ): ZkPdfPartPlan {
        val texts = records.map { decodeRecord(it, decoders) }
        val anchors = ArrayList<ZkPdfAnchorPlan>()
        val anchorAt = HashMap<Int, Int>()
        fun anchor(labels: List<String>, after: Int): Int? {
            val index = texts.indices.firstOrNull { it > after && texts[it] in labels } ?: return null
            anchorAt[index]?.let { return it }
            val same = records.indices.filter { records[it] == records[index] }
            if (same.size != 1) return null
            anchors += ZkPdfAnchorPlan(texts[index]!!, records[index], 1, 1)
            anchorAt[index] = anchors.size - 1
            return anchors.size - 1
        }
        val opOf = HashMap<Int, Int>()
        val slots = ArrayList<ZkPdfSlotPlan>()
        for (rule in rules) {
            val before = anchor(rule.before, -1)
            if (before == null) { unavailable[rule.claim] = ct("core_zkpdf_label_ambiguous", rule.before.first()); continue }
            val beforeOp = anchorAt.entries.first { it.value == before }.key
            val after = anchor(rule.after, beforeOp)
            if (after == null) { unavailable[rule.claim] = ct("core_zkpdf_label_ambiguous", rule.after.first()); continue }
            val afterOp = anchorAt.entries.first { it.value == after }.key
            val between = (beforeOp + 1 until afterOp).map { texts[it] }
            val value = if (between.isEmpty() || between.any { it == null }) null
            else rule.normalize.apply(between.joinToString(""))
            if (value == null) { unavailable[rule.claim] = ct("core_zkpdf_value_mismatch", rule.label); continue }
            opOf[before] = beforeOp
            opOf[after] = afterOp
            slots += ZkPdfSlotPlan(rule.claim, slots.size, before, after, value, page)
        }
        // Slots must follow the order of the content stream, as the lexical circuit fills them in one pass.
        val ordered = slots.sortedBy { opOf.getValue(it.beforeAnchor) }
            .mapIndexed { i, s -> ZkPdfSlotPlan(s.claim, i, s.beforeAnchor, s.afterAnchor, s.value, page) }
        for (i in 1 until ordered.size) {
            require(opOf.getValue(ordered[i - 1].afterAnchor) <= opOf.getValue(ordered[i].beforeAnchor)) {
                "Template fields overlap"
            }
        }
        // Anchors that only unusable fields found are not part of the statement.
        val used = ordered.flatMap { listOf(it.beforeAnchor, it.afterAnchor) }.distinct().sorted()
        val renumber = used.withIndex().associate { (i, old) -> old to i }
        return ZkPdfPartPlan(
            page,
            used.map { anchors[it] },
            ordered.map { ZkPdfSlotPlan(it.claim, it.slot, renumber.getValue(it.beforeAnchor), renumber.getValue(it.afterAnchor), it.value, page) },
            emptyList(),
        )
    }

    /** Text of a record with the page fonts, or null when a code has no Unicode mapping. */
    fun decodeRecord(record: ZkPdfTextRecord, decoders: Map<String, ZkFontDecoder>): String? = try {
        val decoder = decoders[record.font.decodeToString()] ?: return null
        record.strings.joinToString("") { decoder.decode(it, record.kind == 0) }
    } catch (_: PdfException) {
        null
    }

    /** Fresh 16-byte salts for the field commitments. */
    fun salts(count: Int): List<ByteArray> = List(count) { DocCrypto.randomBytes(16) }
}
