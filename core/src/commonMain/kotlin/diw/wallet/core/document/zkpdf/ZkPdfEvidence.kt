package diw.wallet.core.document.zkpdf

import diw.wallet.core.i18n.ct
import diw.wallet.core.document.derived.DerivedClaim
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.jwkThumbprint
import diw.wallet.core.zk.ZkPdfEngine
import diw.wallet.core.zk.ZkPdfSegment
import diw.wallet.core.zk.ZkPdfStatement
import diw.wallet.core.zk.ZkPdfWitness
import diw.wallet.core.zk.ZkResult
import kotlinx.serialization.json.*
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Instant

/** One private window as the evidence lists it; the verifier recomputes everything but [midOut]. */
class ZkPdfEvidenceWindow(val role: String, val offset: Int, val length: Int, val blocks: Int, val midOut: ByteArray)

class ZkPdfEvidenceSlot(val claim: String, val slot: Int, val beforeAnchor: Int, val afterAnchor: Int)

/** A date predicate on a template field: DATE_LE or DATE_GE against [cutoff] (YYYYMMDD). */
class ZkPdfEvidencePredicate(val kind: Int, val claim: String, val cutoff: Int)

/**
 * The zkPDF evidence bundle (p4-zkp.md 5.1): the masked signed PDF, the template, the public anchors and slots and
 * the segment proofs. It is the value of the `zkPdf` disclosure of a document-derived credential. Field values are
 * separate disclosures, each opened by its `zkOpen:<claim>` disclosure ([ZkPdfOpening]).
 */
class ZkPdfEvidence(
    val profile: String,
    val composition: String,
    val binding: ByteArray,
    /** The signed file with every window's bytes set to 0. */
    val masked: ByteArray,
    val windows: List<ZkPdfEvidenceWindow>,
    val anchors: List<ZkPdfAnchorPlan>,
    val slots: List<ZkPdfEvidenceSlot>,
    val predicates: List<ZkPdfEvidencePredicate>,
    val segments: List<ZkPdfSegment>,
    val createdAt: Instant,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("v", VERSION)
        put("type", TYPE)
        put("profile", profile)
        put("composition", composition)
        put("binding", binding.toBase64Url())
        putJsonObject("document") {
            put("size", masked.size)
            put("zlib", PlatformCrypto.deflate(masked).toBase64Url())
        }
        putJsonArray("windows") {
            windows.forEach { w ->
                addJsonObject {
                    put("role", w.role); put("offset", w.offset); put("length", w.length); put("blocks", w.blocks)
                    put("midOut", hex(w.midOut))
                }
            }
        }
        putJsonArray("anchors") {
            anchors.forEach { a ->
                addJsonObject { put("record", a.record.encoded().toBase64Url()); put("ordinal", a.ordinal); put("total", a.total) }
            }
        }
        putJsonArray("slots") {
            slots.forEach { s ->
                addJsonObject { put("claim", s.claim); put("slot", s.slot); put("before", s.beforeAnchor); put("after", s.afterAnchor) }
            }
        }
        putJsonArray("predicates") {
            predicates.forEach { p ->
                addJsonObject { put("kind", PREDICATES.getValue(p.kind)); put("claim", p.claim); put("cutoff", p.cutoff) }
            }
        }
        putJsonArray("segments") {
            segments.forEach { s ->
                addJsonObject {
                    put("kind", s.kind); put("index", s.index)
                    put("proof", s.proof.toBase64Url()); put("publicInputs", s.publicInputs.toBase64Url())
                }
            }
        }
        put("createdAt", createdAt.toString())
    }

    companion object {
        const val VERSION = 1
        const val TYPE = "ZkPdfProof"
        /** The disclosure that carries the bundle, and the prefix of a field's opening disclosure. */
        const val CLAIM = "zkPdf"
        const val OPEN_PREFIX = "zkOpen:"
        /** Masked documents above this size are refused before inflating. */
        const val MAX_DOCUMENT = 16 * 1024 * 1024
        private const val MAX_SEGMENTS = 64
        private val PREDICATES = mapOf(ZkPdfPredicate.DATE_LE to "DATE_LE", ZkPdfPredicate.DATE_GE to "DATE_GE")

        /** Parses a bundle; throws IllegalArgumentException on any missing or malformed member. */
        fun parse(o: JsonObject): ZkPdfEvidence {
            fun bad(what: String): Nothing = throw IllegalArgumentException("Invalid zkPDF evidence: $what")
            fun JsonObject.text(key: String) = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: bad(key)
            fun JsonObject.int(key: String) = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull ?: bad(key)
            fun JsonObject.bytes(key: String) = runCatching { text(key).fromBase64Url() }.getOrElse { bad(key) }
            fun JsonObject.list(key: String) = (this[key] as? JsonArray ?: bad(key)).map { it as? JsonObject ?: bad(key) }
            if (o.int("v") != VERSION || o.text("type") != TYPE) bad("version")
            val composition = o.text("composition").takeIf { it in ZkPdfStatement.COMPOSITIONS } ?: bad("composition")
            val document = o["document"] as? JsonObject ?: bad("document")
            val size = document.int("size").takeIf { it in 1..MAX_DOCUMENT } ?: bad("size")
            val masked = runCatching { PlatformCrypto.inflate(document.bytes("zlib"), maxBytes = size) }.getOrElse { bad("document") }
            if (masked.size != size) bad("size")
            val segments = o.list("segments").map {
                ZkPdfSegment(it.text("kind"), it.int("index").takeIf { i -> i >= 0 } ?: bad("index"), it.bytes("proof"), it.bytes("publicInputs"))
            }
            if (segments.isEmpty() || segments.size > MAX_SEGMENTS) bad("segments")
            return ZkPdfEvidence(
                profile = o.text("profile"),
                composition = composition,
                binding = o.bytes("binding").takeIf { it.size == 32 } ?: bad("binding"),
                masked = masked,
                windows = o.list("windows").map {
                    ZkPdfEvidenceWindow(it.text("role"), it.int("offset"), it.int("length"), it.int("blocks"),
                        runCatching { unhex(it.text("midOut")) }.getOrNull()?.takeIf { m -> m.size == 32 } ?: bad("midOut"))
                },
                anchors = o.list("anchors").map {
                    val record = runCatching { ZkPdfTextRecord.parseAll(it.bytes("record")).single() }.getOrElse { bad("record") }
                    ZkPdfAnchorPlan("", record, it.int("ordinal"), it.int("total"))
                },
                slots = o.list("slots").map { ZkPdfEvidenceSlot(it.text("claim"), it.int("slot"), it.int("before"), it.int("after")) },
                predicates = o.list("predicates").map { p ->
                    val kind = PREDICATES.entries.firstOrNull { it.value == p.text("kind") }?.key ?: bad("predicate")
                    ZkPdfEvidencePredicate(kind, p.text("claim"), p.int("cutoff"))
                },
                segments = segments,
                createdAt = runCatching { Instant.parse(o.text("createdAt")) }.getOrElse { bad("createdAt") },
            )
        }

        internal fun hex(b: ByteArray) = b.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }

        internal fun unhex(s: String): ByteArray {
            require(s.length % 2 == 0 && s.all { it in '0'..'9' || it in 'a'..'f' })
            return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }
    }
}

/** The `zkOpen:<claim>` disclosure: the slot, its salt and the v2 records between its anchors. */
class ZkPdfOpening(val slot: Int, val salt: ByteArray, val source: ByteArray) {
    fun toJson(): JsonObject = buildJsonObject {
        put("slot", slot)
        put("salt", salt.toBase64Url())
        put("src", source.toBase64Url())
    }

    /** SHA-256("diw-zkpdf-claim-v1" || slot || salt || u16 length || source padded to 384), as the claim circuit commits. */
    fun commitment(): ByteArray {
        require(slot in 0 until ZkPdfProfile.MAX_SLOTS && salt.size == 16 && source.size <= MAX_SOURCE)
        val data = DOMAIN + byteArrayOf(slot.toByte()) + salt + byteArrayOf((source.size ushr 8).toByte(), source.size.toByte()) +
            source.copyOf(MAX_SOURCE)
        return PlatformCrypto.sha256(data)
    }

    companion object {
        const val MAX_SOURCE = 384
        private val DOMAIN = "diw-zkpdf-claim-v1".encodeToByteArray()

        fun parse(o: JsonObject): ZkPdfOpening {
            val slot = (o["slot"] as? JsonPrimitive)?.intOrNull ?: throw IllegalArgumentException("Invalid zkPDF opening")
            val salt = (o["salt"] as? JsonPrimitive)?.content?.let { runCatching { it.fromBase64Url() }.getOrNull() }
            val source = (o["src"] as? JsonPrimitive)?.content?.let { runCatching { it.fromBase64Url() }.getOrNull() }
            require(salt != null && salt.size == 16 && source != null && source.size <= MAX_SOURCE && slot in 0 until ZkPdfProfile.MAX_SLOTS) {
                "Invalid zkPDF opening"
            }
            return ZkPdfOpening(slot, salt, source)
        }
    }
}

/** What a finished proof adds to a derived credential: the field values, their openings and the bundle. */
class ZkPdfCreated(
    val evidence: ZkPdfEvidence,
    /** Normalized values of the proven fields, by template claim name, in slot order. */
    val values: List<DerivedClaim>,
    val openings: Map<String, ZkPdfOpening>,
    val proveMs: Long,
) {
    /** Disclosure name and value pairs: each field, its zkOpen and the bundle. */
    fun disclosures(): List<Pair<String, JsonElement>> = buildList {
        values.forEach { v ->
            add(v.name to JsonPrimitive(v.value))
            add(ZkPdfEvidence.OPEN_PREFIX + v.name to openings.getValue(v.name).toJson())
        }
        add(ZkPdfEvidence.CLAIM to evidence.toJson())
    }
}

/** Holder side of WP4: from a plan to a self-verified evidence bundle. */
object ZkPdfProofs {
    /** β: SHA-256 of the UTF-8 RFC 7638 thumbprint of the credential key. */
    fun binding(cnfJwk: JsonObject): ByteArray = PlatformCrypto.sha256(jwkThumbprint(cnfJwk).encodeToByteArray())

    fun statement(layout: ZkPdfLayout, anchors: List<ZkPdfAnchorPlan>, slots: List<Pair<Int, Int>>,
        predicates: List<Pair<ZkPdfPredicate, Int>>, composition: String, binding: ByteArray): ZkPdfStatement =
        ZkPdfStatement(
            composition, binding,
            layout.windows.map { ZkPdfStatement.Window(it.role, it.midIn, it.blocks, it.head, it.tail, it.keyStream) },
            anchors.map { ZkPdfStatement.Anchor(it.record, it.ordinal, it.total) },
            slots.mapIndexed { i, (before, after) -> ZkPdfStatement.Slot(i, before, after) },
            layout.digitTables.map { ZkPdfStatement.DigitTable(it.font, it.width, it.codes) },
            predicates.map { (p, slot) -> ZkPdfStatement.Predicate(p.kind, slot, ZkPdfPredicate.FORMAT_YMD, p.cutoff) },
        )

    /** [pdf] with the bytes of every window set to 0. */
    fun masked(pdf: ByteArray, layout: ZkPdfLayout): ByteArray = pdf.copyOf().also { m ->
        layout.windows.forEach { m.fill(0, it.fileOffset, it.fileOffset + it.length) }
    }

    fun statement(plan: ZkPdfPlan, composition: String, binding: ByteArray): ZkPdfStatement =
        statement(plan.layout, plan.anchors, plan.slots.map { it.beforeAnchor to it.afterAnchor }, plan.predicates, composition, binding)

    /**
     * Proves [plan] for the credential key [cnfJwk]. The engine verifies the bundle before it returns; the openings
     * are checked against the proven commitments here, so nothing unproven reaches the credential (Z14).
     */
    suspend fun create(
        pdf: ByteArray,
        plan: ZkPdfPlan,
        cnfJwk: JsonObject,
        composition: String,
        engine: ZkPdfEngine,
        progress: (String, Int, Int) -> Unit,
        now: Instant = Clock.System.now(),
        /** The field salts; fresh ones unless a proof made elsewhere for an earlier request is being imported. */
        salts: List<ByteArray> = ZkPdfPlanner.salts(plan.slots.size),
    ): ZkResult<ZkPdfCreated> {
        require(plan.slots.isNotEmpty()) { "No provable field" }
        require(salts.size == plan.slots.size) { "One salt per field" }
        val statement = statement(plan, composition, binding(cnfJwk))
        val proof = when (val r = engine.prove(statement, ZkPdfWitness(plan.privateData, salts), progress)) {
            is ZkResult.Ok -> r.value
            is ZkResult.Failed -> return r
            ZkResult.Cancelled -> return ZkResult.Cancelled
        }
        val openings = plan.slots.associate { s ->
            s.claim to ZkPdfOpening(s.slot, salts[s.slot], proof.claimRecords[s.slot])
        }
        val consistent = plan.slots.all { s ->
            openings.getValue(s.claim).commitment().contentEquals(proof.claimDigests[s.slot]) &&
                ZkPdfVerifier.decodeSource(proof.claimRecords[s.slot], plan.layout.decoders)
                    ?.let { plan.profile.field(s.claim)?.normalize?.apply(it) } == s.value
        }
        if (!consistent || proof.midOuts.size != plan.layout.windows.size) {
            return ZkResult.Failed(ct("core_zkpdf_inconsistent"), false)
        }
        val evidence = ZkPdfEvidence(
            profile = plan.profile.id,
            composition = composition,
            binding = statement.binding,
            masked = masked(pdf.copyOf(plan.layout.byteRange[2] + plan.layout.byteRange[3]), plan.layout),
            windows = plan.layout.windows.mapIndexed { i, w -> ZkPdfEvidenceWindow(w.role, w.fileOffset, w.length, w.blocks, proof.midOuts[i]) },
            anchors = plan.anchors,
            slots = plan.slots.map { ZkPdfEvidenceSlot(it.claim, it.slot, it.beforeAnchor, it.afterAnchor) },
            predicates = plan.predicates.map { (p, _) -> ZkPdfEvidencePredicate(p.kind, p.claim, p.cutoff) },
            segments = proof.segments,
            createdAt = now,
        )
        val values = plan.slots.map { s -> DerivedClaim(s.claim, s.value, plan.profile.field(s.claim)?.label) }
        return ZkResult.Ok(ZkPdfCreated(evidence, values, openings, proof.proveMs))
    }
}
