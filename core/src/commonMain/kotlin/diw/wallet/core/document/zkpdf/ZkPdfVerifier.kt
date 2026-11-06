package diw.wallet.core.document.zkpdf

import diw.wallet.core.i18n.ct
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.SignatureInfo
import diw.wallet.core.document.pdf.PdfException
import diw.wallet.core.zk.ZkPdfEngine
import diw.wallet.core.zk.ZkResult
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Clock
import kotlin.time.Instant

class ZkPdfFieldResult(val claim: String, val label: String, val value: String?, val check: Check, val detail: String)

class ZkPdfPredicateResult(val claim: String, val text: String)

/**
 * The outcome of checking a zkPDF bundle. [check] is PASS only when the proof, the document signature (valid and
 * trusted) and every disclosed field pass; WARN when the proof holds but the signer is not trusted or a disclosed
 * field has no opening; FAIL when anything does not match; NOT_CHECKED when this device cannot check it.
 */
class ZkPdfVerification(
    val check: Check,
    val summary: String,
    val profile: ZkPdfProfile?,
    val signature: SignatureInfo?,
    val fields: List<ZkPdfFieldResult>,
    val predicates: List<ZkPdfPredicateResult>,
    /** Template fields that are proven but not disclosed. */
    val hidden: List<String>,
)

/**
 * Verifier side of WP4 (p4-circuits.md 3.3, V1 to V10). Everything public is rebuilt from the masked file and the
 * template, never taken from the bundle: the window layout and RC4 key stream (V2, V5, V6), the SHA-256 chain into
 * the CMS check (V3, V4), the anchor texts and digit tables (V7), the binding (V9) and the field values (V10). The
 * bundle supplies only the anchor records, the slots, the outgoing SHA-256 states and the proofs, which the native
 * verifier then holds to that statement (V8).
 */
object ZkPdfVerifier {
    suspend fun verify(
        evidenceJson: JsonObject,
        /** Every disclosed claim of the presentation, by name. */
        disclosed: Map<String, JsonElement>,
        cnfJwk: JsonObject,
        /** The pinned templates by identifier (V1). */
        profiles: (String) -> ZkPdfProfile?,
        engine: ZkPdfEngine?,
        trust: DocumentTrustSource,
        now: Instant = Clock.System.now(),
    ): ZkPdfVerification {
        fun result(check: Check, summary: String, profile: ZkPdfProfile? = null, signature: SignatureInfo? = null) =
            ZkPdfVerification(check, summary, profile, signature, emptyList(), emptyList(), emptyList())
        fun fail(summary: String, profile: ZkPdfProfile? = null) = result(Check.FAIL, summary, profile)

        val evidence = try { ZkPdfEvidence.parse(evidenceJson) } catch (_: IllegalArgumentException) {
            return fail(ct("core_zkv_bad_evidence"))
        }
        // V1: a pinned template and the pinned circuits of the composition.
        val profile = profiles(evidence.profile) ?: return result(Check.NOT_CHECKED, ct("core_zkv_unknown_profile", evidence.profile))
        if (engine == null || !engine.ready(evidence.composition, false)) {
            return result(Check.NOT_CHECKED, ct("core_zkv_no_vk"), profile)
        }
        // V9: the proof is bound to this credential's key.
        if (!evidence.binding.contentEquals(runCatching { ZkPdfProofs.binding(cnfJwk) }.getOrNull())) {
            return fail(ct("core_zkv_wrong_key"), profile)
        }
        // V2, V5, V6: the layout of the masked file under this template, chained with the claimed window states.
        val layout = try {
            ZkPdfPlanner.layout(evidence.masked, profile, "", evidence.windows.map { it.midOut })
        } catch (_: PdfException) {
            return fail(ct("core_zkv_redacted_bad"), profile)
        } catch (_: IllegalArgumentException) {
            return fail(ct("core_zkv_redacted_bad"), profile)
        }
        val range = layout.byteRange
        val sameWindows = layout.windows.size == evidence.windows.size && layout.windows.zip(evidence.windows).all { (a, b) ->
            a.role == b.role && a.fileOffset == b.offset && a.length == b.length && a.blocks == b.blocks
        }
        if (!sameWindows || range[2] + range[3] != evidence.masked.size) return fail(ct("core_zkv_ranges"), profile)
        if (layout.windows.any { w -> (w.fileOffset until w.fileOffset + w.length).any { evidence.masked[it] != 0.toByte() } }) {
            return fail(ct("core_zkv_leak"), profile)
        }
        // V3: SHA-256 of the signed ranges, skipping each window with its claimed outgoing state.
        val digest = try {
            val message = Sha256Chain.message(evidence.masked, range)
            Sha256Chain.digestWithWindows(message, layout.windows.zip(evidence.windows).map { (w, e) ->
                HashWindow(w.firstBlock, w.blocks, Sha256State.ofBytes(w.midIn), Sha256State.ofBytes(e.midOut))
            })
        } catch (_: IllegalArgumentException) {
            return fail(ct("core_zkv_hash"), profile)
        }
        // V4: the CMS signature over that digest, with trust, validity and time stamps.
        val signature = DocumentInspector.inspectWithheldPdf(evidence.masked, range, digest, trust, now).signatures.singleOrNull()
            ?: return fail(ct("core_zkv_no_signature"), profile)
        if (signature.integrity != Check.PASS || signature.verdict == DocumentVerdict.INVALID) {
            return ZkPdfVerification(Check.FAIL, ct("core_zkv_signature_bad"), profile, signature, emptyList(), emptyList(), emptyList())
        }
        // V7: anchors decode to the template labels of the fields they bound; predicates name date fields.
        val anchorTexts = evidence.anchors.map { ZkPdfPlanner.decodeRecord(it.record, layout.decoders) }
        val slots = evidence.slots
        val structural = slots.size in 1..ZkPdfProfile.MAX_SLOTS && slots.withIndex().all { (i, s) -> s.slot == i } &&
            slots.map { it.claim }.toSet().size == slots.size &&
            evidence.anchors.size <= ZkPdfProfile.MAX_ANCHORS &&
            evidence.anchors.all { it.ordinal == 1 && it.total == 1 } &&
            slots.flatMap { listOf(it.beforeAnchor, it.afterAnchor) }.toSet() == evidence.anchors.indices.toSet() &&
            slots.all { s ->
                val rule = profile.field(s.claim)
                rule != null && s.beforeAnchor != s.afterAnchor &&
                    anchorTexts.getOrNull(s.beforeAnchor) in rule.before && anchorTexts.getOrNull(s.afterAnchor) in rule.after
            } &&
            evidence.predicates.size <= 2 &&
            evidence.predicates.all { p ->
                profile.field(p.claim)?.normalize == ZkPdfNormalize.DATE && slots.any { it.claim == p.claim } &&
                    p.cutoff in 10000101..99991231
            }
        if (!structural) return fail(ct("core_zkv_anchors"), profile)
        val predicates = evidence.predicates.map { p -> ZkPdfPredicate(p.kind, p.claim, p.cutoff) to slots.first { it.claim == p.claim }.slot }
        val statement = ZkPdfProofs.statement(layout, evidence.anchors, slots.map { it.beforeAnchor to it.afterAnchor }, predicates,
            evidence.composition, evidence.binding)
        // V8: every segment against the statement built here.
        val verified = when (val r = engine.verify(statement, evidence.segments)) {
            is ZkResult.Ok -> r.value ?: return fail(ct("core_zkv_invalid"), profile)
            is ZkResult.Failed -> return result(Check.NOT_CHECKED, ct("core_zkv_cannot_here", r.reason), profile, signature)
            ZkResult.Cancelled -> return result(Check.NOT_CHECKED, ct("core_zkv_cancelled"), profile, signature)
        }
        if (verified.midOuts.size != evidence.windows.size ||
            verified.midOuts.zip(evidence.windows).any { (a, b) -> !a.contentEquals(b.midOut) }) {
            return fail(ct("core_zkv_hash_mismatch"), profile)
        }
        // V10: each disclosed field against its commitment and the template's normalization.
        val fields = slots.mapNotNull { s ->
            val rule = profile.field(s.claim)!!
            val value = (disclosed[s.claim] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return@mapNotNull null
            val opening = (disclosed[ZkPdfEvidence.OPEN_PREFIX + s.claim] as? JsonObject)?.let { runCatching { ZkPdfOpening.parse(it) }.getOrNull() }
                ?: return@mapNotNull ZkPdfFieldResult(s.claim, rule.label, value, Check.NOT_CHECKED, ct("core_zkv_no_opening"))
            val committed = opening.slot == s.slot && verified.claimDigests.getOrNull(s.slot)?.contentEquals(opening.commitment()) == true
            val decoded = if (committed) decodeSource(opening.source, layout.decoders)?.let { rule.normalize.apply(it) } else null
            when {
                !committed -> ZkPdfFieldResult(s.claim, rule.label, value, Check.FAIL, ct("core_zkv_opening_mismatch"))
                decoded != value -> ZkPdfFieldResult(s.claim, rule.label, value, Check.FAIL, ct("core_zkv_value_mismatch"))
                else -> ZkPdfFieldResult(s.claim, rule.label, value, Check.PASS, ct("core_zkv_page_one"))
            }
        }
        val predicateResults = evidence.predicates.map { p ->
            val label = profile.field(p.claim)!!.label
            val date = p.cutoff.toString().let { "${it.substring(0, 4)}-${it.substring(4, 6)}-${it.substring(6, 8)}" }
            ZkPdfPredicateResult(p.claim, ct("core_zkv_predicate", label, if (p.kind == ZkPdfPredicate.DATE_LE) ct("core_zkv_not_after") else ct("core_zkv_not_before"), date))
        }
        val hidden = slots.filter { s -> fields.none { it.claim == s.claim } }.map { profile.field(it.claim)!!.label }
        val signer = signature.signer?.commonName ?: signature.signerName ?: ct("core_zkv_signer")
        val check = when {
            fields.any { it.check == Check.FAIL } -> Check.FAIL
            signature.verdict != DocumentVerdict.VALID || fields.any { it.check != Check.PASS } -> Check.WARN
            else -> Check.PASS
        }
        val summary = when {
            check == Check.FAIL -> ct("core_zkv_partial_mismatch")
            signature.verdict != DocumentVerdict.VALID -> ct("core_zkv_untrusted_signer", signer)
            fields.any { it.check != Check.PASS } -> ct("core_zkv_partial")
            else -> ct("core_zkv_proven", signer, profile.title)
        }
        // A test template (test environment only) was never reviewed against a real document; the summary says so.
        return ZkPdfVerification(check, (if (profile.test) ct("core_zkv_test_template") else "") + summary, profile, signature, fields, predicateResults, hidden)
    }

    /** Text of a field source (v2 records back to back) with the page fonts, or null when a record cannot be read. */
    fun decodeSource(source: ByteArray, decoders: Map<String, ZkFontDecoder>): String? = try {
        val records = ZkPdfTextRecord.parseAll(source)
        val texts = records.map { ZkPdfPlanner.decodeRecord(it, decoders) ?: return null }
        texts.joinToString("")
    } catch (_: PdfException) {
        null
    }
}
