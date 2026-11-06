package diw.wallet.core.document.zkpdf

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
            return fail("零知識證據的格式不正確")
        }
        // V1: a pinned template and the pinned circuits of the composition.
        val profile = profiles(evidence.profile) ?: return result(Check.NOT_CHECKED, "不認識文件版型「${evidence.profile}」，無法查驗")
        if (engine == null || !engine.ready(evidence.composition, false)) {
            return result(Check.NOT_CHECKED, "這台裝置尚未下載 zkPDF 驗證檔，無法查驗", profile)
        }
        // V9: the proof is bound to this credential's key.
        if (!evidence.binding.contentEquals(runCatching { ZkPdfProofs.binding(cnfJwk) }.getOrNull())) {
            return fail("證明綁定的不是這張憑證的金鑰", profile)
        }
        // V2, V5, V6: the layout of the masked file under this template, chained with the claimed window states.
        val layout = try {
            ZkPdfPlanner.layout(evidence.masked, profile, "", evidence.windows.map { it.midOut })
        } catch (_: PdfException) {
            return fail("遮蔽後的文件不符合版型或結構不正確", profile)
        } catch (_: IllegalArgumentException) {
            return fail("遮蔽後的文件不符合版型或結構不正確", profile)
        }
        val range = layout.byteRange
        val sameWindows = layout.windows.size == evidence.windows.size && layout.windows.zip(evidence.windows).all { (a, b) ->
            a.role == b.role && a.fileOffset == b.offset && a.length == b.length && a.blocks == b.blocks
        }
        if (!sameWindows || range[2] + range[3] != evidence.masked.size) return fail("證據的私密範圍與文件結構不符", profile)
        if (layout.windows.any { w -> (w.fileOffset until w.fileOffset + w.length).any { evidence.masked[it] != 0.toByte() } }) {
            return fail("遮蔽後的文件仍含私密範圍的內容", profile)
        }
        // V3: SHA-256 of the signed ranges, skipping each window with its claimed outgoing state.
        val digest = try {
            val message = Sha256Chain.message(evidence.masked, range)
            Sha256Chain.digestWithWindows(message, layout.windows.zip(evidence.windows).map { (w, e) ->
                HashWindow(w.firstBlock, w.blocks, Sha256State.ofBytes(w.midIn), Sha256State.ofBytes(e.midOut))
            })
        } catch (_: IllegalArgumentException) {
            return fail("文件雜湊無法重建", profile)
        }
        // V4: the CMS signature over that digest, with trust, validity and time stamps.
        val signature = DocumentInspector.inspectWithheldPdf(evidence.masked, range, digest, trust, now).signatures.singleOrNull()
            ?: return fail("找不到被證明的文件簽章", profile)
        if (signature.integrity != Check.PASS || signature.verdict == DocumentVerdict.INVALID) {
            return ZkPdfVerification(Check.FAIL, "文件簽章與證明的內容不符或無效", profile, signature, emptyList(), emptyList(), emptyList())
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
        if (!structural) return fail("證明的錨點或欄位與版型不符", profile)
        val predicates = evidence.predicates.map { p -> ZkPdfPredicate(p.kind, p.claim, p.cutoff) to slots.first { it.claim == p.claim }.slot }
        val statement = ZkPdfProofs.statement(layout, evidence.anchors, slots.map { it.beforeAnchor to it.afterAnchor }, predicates,
            evidence.composition, evidence.binding)
        // V8: every segment against the statement built here.
        val verified = when (val r = engine.verify(statement, evidence.segments)) {
            is ZkResult.Ok -> r.value ?: return fail("零知識證明無效", profile)
            is ZkResult.Failed -> return result(Check.NOT_CHECKED, "零知識證明無法在這台裝置查驗：${r.reason}", profile, signature)
            ZkResult.Cancelled -> return result(Check.NOT_CHECKED, "查驗已取消", profile, signature)
        }
        if (verified.midOuts.size != evidence.windows.size ||
            verified.midOuts.zip(evidence.windows).any { (a, b) -> !a.contentEquals(b.midOut) }) {
            return fail("證明的文件雜湊與證據不符", profile)
        }
        // V10: each disclosed field against its commitment and the template's normalization.
        val fields = slots.mapNotNull { s ->
            val rule = profile.field(s.claim)!!
            val value = (disclosed[s.claim] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return@mapNotNull null
            val opening = (disclosed[ZkPdfEvidence.OPEN_PREFIX + s.claim] as? JsonObject)?.let { runCatching { ZkPdfOpening.parse(it) }.getOrNull() }
                ?: return@mapNotNull ZkPdfFieldResult(s.claim, rule.label, value, Check.NOT_CHECKED, "沒有一併出示零知識開啟資料，無法確認來自文件")
            val committed = opening.slot == s.slot && verified.claimDigests.getOrNull(s.slot)?.contentEquals(opening.commitment()) == true
            val decoded = if (committed) decodeSource(opening.source, layout.decoders)?.let { rule.normalize.apply(it) } else null
            when {
                !committed -> ZkPdfFieldResult(s.claim, rule.label, value, Check.FAIL, "開啟資料與證明的承諾不符")
                decoded != value -> ZkPdfFieldResult(s.claim, rule.label, value, Check.FAIL, "出示的值與文件內容不符")
                else -> ZkPdfFieldResult(s.claim, rule.label, value, Check.PASS, "已證明出自簽章文件第 1 頁")
            }
        }
        val predicateResults = evidence.predicates.map { p ->
            val label = profile.field(p.claim)!!.label
            val date = p.cutoff.toString().let { "${it.substring(0, 4)}-${it.substring(4, 6)}-${it.substring(6, 8)}" }
            ZkPdfPredicateResult(p.claim, "$label${if (p.kind == ZkPdfPredicate.DATE_LE) "不晚於" else "不早於"} $date")
        }
        val hidden = slots.filter { s -> fields.none { it.claim == s.claim } }.map { profile.field(it.claim)!!.label }
        val signer = signature.signer?.commonName ?: signature.signerName ?: "簽署者"
        val check = when {
            fields.any { it.check == Check.FAIL } -> Check.FAIL
            signature.verdict != DocumentVerdict.VALID || fields.any { it.check != Check.PASS } -> Check.WARN
            else -> Check.PASS
        }
        val summary = when {
            check == Check.FAIL -> "部分出示的值與文件不符"
            signature.verdict != DocumentVerdict.VALID -> "證明成立，但簽署者 $signer 未通過信任檢查"
            fields.any { it.check != Check.PASS } -> "證明成立，部分欄位無法確認"
            else -> "已證明出自 $signer 簽章的「${profile.title}」"
        }
        // A test template (test environment only) was never reviewed against a real document; the summary says so.
        return ZkPdfVerification(check, (if (profile.test) "測試版型：" else "") + summary, profile, signature, fields, predicateResults, hidden)
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
