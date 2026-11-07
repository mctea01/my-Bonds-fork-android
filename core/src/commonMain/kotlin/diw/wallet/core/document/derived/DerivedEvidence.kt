package diw.wallet.core.document.derived

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.zkpdf.ZkPdfEvidence
import diw.wallet.core.document.zkpdf.ZkPdfProfile
import diw.wallet.core.document.zkpdf.ZkPdfVerifier
import diw.wallet.core.util.obj
import diw.wallet.core.zk.ZkPdfEngine
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.util.fromBase64
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * What checking a zkPDF bundle needs: the pinned templates by identifier (test templates only in the test
 * environment) and the engine with the verification keys, or null where this device has none.
 */
class ZkPdfContext(val profiles: (String) -> ZkPdfProfile?, val engine: suspend () -> ZkPdfEngine?)

/** One piece of evidence of a derived credential, as the verifier sees it. */
data class EvidenceResult(val type: String, val title: String, val check: Check, val detail: String)

/**
 * Verifier side of [DerivedCredentials]: checks each evidence entry of a derived credential. The time stamp is
 * verified here; the document signature check is the issuing wallet's statement, which a verifier without the
 * document cannot repeat.
 */
object DerivedEvidence {
    /**
     * [credential] is the issuer-signed SD-JWT VC payload, whose document object and evidence array are read.
     * [own] words the signature statement for the holder whose wallet made it, instead of for a verifier.
     */
    suspend fun verify(
        credential: JsonObject,
        trust: DocumentTrustSource?,
        own: Boolean = false,
        /** The disclosed claims of the presentation (or every claim, for the holder's own view), by name. */
        disclosed: Map<String, JsonElement> = emptyMap(),
        /** How to check a zkPDF bundle among [disclosed]; null leaves it unchecked. */
        zk: ZkPdfContext? = null,
        now: Instant = Clock.System.now(),
    ): List<EvidenceResult> {
        val document = credential.obj("document")
        val sha256 = document?.str("sha256")
        val evidence = (credential["evidence"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
        val listed = evidence.flatMap { e ->
            when (e.str("type")) {
                DerivedCredentials.EVIDENCE_TIMESTAMP -> listOf(timestamp(e, sha256, trust))
                DerivedCredentials.EVIDENCE_SIGNATURE -> listOf(signature(e, own))
                TravelDocumentFields.EVIDENCE -> TravelDocumentFields.verify(e, disclosed, trust, own, now)
                else -> listOf(EvidenceResult(e.str("type") ?: "", "其他證據", Check.NOT_CHECKED, "本錢包不認識這種證據"))
            }
        }
        val bundle = disclosed[ZkPdfEvidence.CLAIM] ?: return listed
        return listed + zkPdf(bundle, credential, disclosed, trust, zk, now)
    }

    /**
     * The zkPDF bundle of a derived credential (p4-zkp.md 5.1): the proof itself, then each disclosed field and date
     * condition it covers. The proof is bound to the credential's own key (cnf.jwk), so it cannot be moved to another
     * credential.
     */
    private suspend fun zkPdf(
        bundle: JsonElement,
        credential: JsonObject,
        disclosed: Map<String, JsonElement>,
        trust: DocumentTrustSource?,
        zk: ZkPdfContext?,
        now: Instant,
    ): List<EvidenceResult> {
        val title = "PDF 簽章零知識證明（zkPDF）"
        val evidence = bundle as? JsonObject ?: return listOf(EvidenceResult(ZkPdfEvidence.TYPE, title, Check.FAIL, "零知識證據的格式不正確"))
        val jwk = credential.obj("cnf")?.obj("jwk") ?: return listOf(EvidenceResult(ZkPdfEvidence.TYPE, title, Check.FAIL, "證件沒有綁定金鑰"))
        if (zk == null || trust == null) return listOf(EvidenceResult(ZkPdfEvidence.TYPE, title, Check.NOT_CHECKED, "此處無法查驗零知識證明"))
        val v = ZkPdfVerifier.verify(evidence, disclosed, jwk, zk.profiles, zk.engine(), trust, now)
        return buildList {
            add(EvidenceResult(ZkPdfEvidence.TYPE, title, v.check, v.summary + (v.profile?.let { "（版型 ${it.id}）" } ?: "")))
            v.fields.forEach { add(EvidenceResult(ZkPdfEvidence.TYPE, "zkPDF 欄位：${it.label}", it.check, it.detail)) }
            if (v.check != Check.FAIL && v.check != Check.NOT_CHECKED) {
                v.predicates.forEach { add(EvidenceResult(ZkPdfEvidence.TYPE, "zkPDF 條件", Check.PASS, "已證明${it.text}，不揭露實際日期")) }
                if (v.hidden.isNotEmpty()) {
                    add(EvidenceResult(ZkPdfEvidence.TYPE, "zkPDF 未揭露欄位", Check.NOT_CHECKED, "證明涵蓋但這次沒有出示：${v.hidden.joinToString("、")}"))
                }
            }
        }
    }

    private suspend fun timestamp(e: JsonObject, sha256: String?, trust: DocumentTrustSource?): EvidenceResult {
        val title = "文件時戳（RFC 3161）"
        val token = e.str("token")?.let { runCatching { it.fromBase64() }.getOrNull() }
            ?: return EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.FAIL, "時戳無法讀取")
        val digest = sha256?.let { runCatching { unhex(it) }.getOrNull() }?.takeIf { it.size == 32 }
            ?: return EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.FAIL, "證件沒有文件指紋")
        if (trust == null) return EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.NOT_CHECKED, "此處無法查驗時戳")
        val info = DocumentInspector.verifyTimestampDigest(token, digest, trust)
        val time = displayTime(Instant.fromEpochSeconds(info.time))
        return when {
            info.imprint == Check.FAIL -> EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.FAIL, "時戳涵蓋的不是這份文件")
            info.signature != Check.PASS -> EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.FAIL, "時戳簽章無效")
            info.trusted -> EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.PASS,
                "${info.tsa ?: "時戳機構"} 證明這份文件在 $time 已存在" + tierNote(info.trust?.tier))
            else -> EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.WARN,
                "時戳簽章正確，但時戳機構「${info.tsa ?: "未知"}」不在信任錨點；聲稱的時間為 $time")
        }
    }

    /** Taipei time, minute precision. */
    private fun displayTime(t: Instant): String {
        val local = t.toLocalDateTime(TimeZone.of("Asia/Taipei"))
        fun two(n: Int) = n.toString().padStart(2, '0')
        return "${local.year}-${two(local.month.ordinal + 1)}-${two(local.day)} ${two(local.hour)}:${two(local.minute)}（臺北時間）"
    }

    private fun tierNote(tier: String?): String = tier?.let { "（時戳機構 $it）" } ?: ""

    private fun signature(e: JsonObject, own: Boolean): EvidenceResult {
        val title = "文件簽章檢查"
        val verdict = e.str("verdict")
        val sigs = (e["signatures"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
        val tiers = sigs.mapNotNull { it.str("trustTier") }.distinct().sorted()
        val official = sigs.any { (it["official"] as? JsonPrimitive)?.content == "true" }
        val text = when (verdict) {
            "VALID" -> "簽章有效"
            "PARTIAL" -> "簽章部分通過"
            "INVALID" -> "簽章無效"
            else -> "文件未簽章"
        }
        val result = text + (if (tiers.isNotEmpty()) "，簽署者信任等級 ${tiers.joinToString("、")}" else "") + (if (official) "（官方）" else "")
        val checkedAt = e.str("checkedAt")?.let { runCatching { Instant.parse(it) }.getOrNull() }?.let { displayTime(it) } ?: "未知時間"
        val detail = if (own) {
            "產生憑證時（$checkedAt）檢查文件：$result。查驗方會看到這段聲明，但沒有文件原檔無法重新檢查。"
        } else {
            "出示者的錢包於 $checkedAt 檢查文件：$result。這是出示者錢包的聲明，查驗方沒有文件原檔無法重新檢查。"
        }
        return EvidenceResult(DerivedCredentials.EVIDENCE_SIGNATURE, title, Check.NOT_CHECKED, detail)
    }

    private fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0)
        return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
