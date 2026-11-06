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

class ZkPdfSlotPlan(val claim: String, val slot: Int, val beforeAnchor: Int, val afterAnchor: Int, val value: String)

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

/** The public description of a signed PDF that both the holder and the verifier derive the same way. */
class ZkPdfLayout(
    val byteRange: IntArray,
    val windows: List<ZkPdfWindowPlan>,
    /** Records of the page content stream; only the holder (who has the private bytes) can list them. */
    val digitTables: List<ZkPdfDigitPlan>,
    val decoders: Map<String, ZkFontDecoder>,
)

/** Everything the prover needs except the salts and the binding, which the caller adds. */
class ZkPdfPlan(
    val profile: ZkPdfProfile,
    val layout: ZkPdfLayout,
    /** Raw stream data (as stored in the file) of each window, in [ZkPdfLayout.windows] order. */
    val privateData: List<ByteArray>,
    val anchors: List<ZkPdfAnchorPlan>,
    val slots: List<ZkPdfSlotPlan>,
    val predicates: List<Pair<ZkPdfPredicate, Int>>,
    /** Fields of the template that cannot be proven in this file, with the reason shown to the person. */
    val unavailable: Map<String, String>,
)

/**
 * Plans a zkPDF proof for page 1 of a signed PDF (WP4): finds the signed revision, the content and private image
 * windows, the anchors and fields of the template, and the digit tables for date predicates. The verifier rebuilds
 * the same [ZkPdfLayout] from the masked file with [layout]. Errors never quote document content.
 */
object ZkPdfPlanner {
    const val MAX_COMPRESSED = 8192
    private const val CONTENT_BLOCKS = 130
    private const val OPAQUE_BLOCKS = 128
    private const val MAX_DIGIT_FONTS = 4

    /** The single document signature: ByteRange [0, b, c, d] with only the signature value in the gap. */
    fun signature(file: PdfFile): PdfSignatureField = zkPdfInput {
        val fields = PdfSignatures(file).fields().filter { it.type != "DocTimeStamp" }
        val field = fields.singleOrNull() ?: error("One document signature is required")
        require(field.byteRange.size == 4 && field.byteRange[0] == 0L && field.gapIsContentsOnly)
        field
    }

    /**
     * The window layout of [pdf] for [profile]. Reads only object structure and stream positions, so it works on the
     * masked file too. The SHA-256 state entering a window depends on every earlier byte: the holder leaves [midOuts]
     * null and hashes the real windows; the verifier passes the claimed outgoing state of each window (in layout
     * order) and later checks that the proof attests exactly those states (V3, V8).
     */
    fun layout(pdf: ByteArray, profile: ZkPdfProfile, password: String = "", midOuts: List<ByteArray>? = null): ZkPdfLayout = zkPdfInput {
        val whole = PdfFile(pdf, password)
        val range = signature(whole).byteRange.map { it.toInt() }.toIntArray()
        val signed = PdfZkSupport.signedRevision(pdf, range, password)
        val content = PdfZkSupport.pageContentObject(signed, 0)
        val pages = PdfTextExtractor.pages(signed)
        // The masked file keeps every other page as it is, so a second page would be disclosed in full (v1 proves page 1).
        require(pages.size == 1) { "zkPDF v1 supports single-page documents" }
        val page = pages.first()
        val xobjects = signed.dict(signed.dict(page["Resources"])?.get("XObject"))
        val opaque = profile.opaqueImages.map { name ->
            val ref = xobjects?.entries?.get(name) as? PdfRef ?: error("Private image unavailable")
            val image = signed.getObject(ref.num) as? PdfStream ?: error("Private image unavailable")
            require(image.dict.name("Subtype") == "Image" && ref.num != content)
            ref.num
        }
        val message = Sha256Chain.message(pdf, range)
        val placed = listOf("content" to content).plus(opaque.map { "opaque" to it }).map { (role, num) ->
            window(signed, message, range, role, num)
        }
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
        val decoders = PdfZkSupport.fontDecoders(signed, 0)
        val tables = decoders.entries.mapNotNull { (name, decoder) ->
            decoder.digitCodes()?.let { ZkPdfDigitPlan(name.encodeToByteArray(), decoder.kind, it) }
        }.take(MAX_DIGIT_FONTS)
        ZkPdfLayout(range, windows, tables, decoders)
    }

    private fun window(pdf: PdfFile, message: Sha256Message, range: IntArray, role: String, num: Int): ZkPdfWindowPlan {
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
        val blocks = (right - left) / 64
        require(blocks <= if (role == "content") CONTENT_BLOCKS else OPAQUE_BLOCKS)
        if (role == "content") {
            require(length <= MAX_COMPRESSED)
            val stream = pdf.getObject(num) as PdfStream
            require(stream.dict.name("Filter") == "FlateDecode" && stream.dict["DecodeParms"] == null)
        }
        val head = ByteArray(offset - left) { message.block((left + it) / 64)[(left + it) % 64] }
        val tailStart = offset + length
        val tail = ByteArray(right - tailStart) { message.block((tailStart + it) / 64)[(tailStart + it) % 64] }
        return ZkPdfWindowPlan(
            role, num, start, length, left / 64, blocks, ByteArray(32), head, tail,
            if (role == "content") PdfZkSupport.rc4KeyStream(pdf, num, length) else null,
        )
    }

    /** Plans the fields of [profile] that this file supports; [predicates] name fields of the template. */
    fun plan(pdf: ByteArray, profile: ZkPdfProfile, predicates: List<ZkPdfPredicate> = emptyList(), password: String = ""): ZkPdfPlan =
        zkPdfInput {
            val layout = layout(pdf, profile, password)
            val signed = PdfZkSupport.signedRevision(pdf, layout.byteRange, password)
            val private = layout.windows.map { pdf.copyOfRange(it.fileOffset, it.fileOffset + it.length) }
            val content = signed.decode(signed.getObject(layout.windows.first().objectNumber) as PdfStream)
            val records = ZkPdfLexer.records(content)
            val texts = records.map { decodeRecord(it, layout.decoders) }
            val unavailable = LinkedHashMap<String, String>()
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
            for (rule in profile.fields) {
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
                slots += ZkPdfSlotPlan(rule.claim, slots.size, before, after, value)
            }
            // Slots must follow page order, as the lexical circuit fills them in one pass.
            val ordered = slots.sortedBy { opOf.getValue(it.beforeAnchor) }
                .mapIndexed { i, s -> ZkPdfSlotPlan(s.claim, i, s.beforeAnchor, s.afterAnchor, s.value) }
            for (i in 1 until ordered.size) {
                require(opOf.getValue(ordered[i - 1].afterAnchor) <= opOf.getValue(ordered[i].beforeAnchor)) {
                    "Template fields overlap"
                }
            }
            val predicatePlans = predicates.map { p ->
                val slot = ordered.firstOrNull { it.claim == p.claim } ?: error("Predicate field unavailable")
                require(profile.field(p.claim)?.normalize == ZkPdfNormalize.DATE)
                p to slot.slot
            }
            require(predicatePlans.size <= 2)
            ZkPdfPlan(profile, layout, private, anchors, ordered, predicatePlans, unavailable)
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
