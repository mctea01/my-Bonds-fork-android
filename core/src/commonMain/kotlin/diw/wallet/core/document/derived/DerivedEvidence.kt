package diw.wallet.core.document.derived

import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.profile.bonds.MoicaCa
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.util.Jcs
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.util.fromBase64
import org.multipaz.util.fromBase64Url
import kotlin.time.Clock
import kotlin.time.Instant

/** One piece of evidence of a derived credential, as the verifier sees it. */
data class EvidenceResult(val type: String, val title: String, val check: Check, val detail: String)

/**
 * Verifier side of [DerivedCredentials]: checks each evidence entry of a derived credential. The time stamp and the
 * citizen certificate signature are verified here; the document signature check is the issuing wallet's statement,
 * which a verifier without the document cannot repeat.
 */
object DerivedEvidence {
    /**
     * [credential] is the issuer-signed payload (SD-JWT VC payload with _sd, or the vc+moica credential), whose
     * document object and evidence array are read. [disclosed] are the claims the holder opened.
     */
    suspend fun verify(
        credential: JsonObject,
        disclosed: Map<String, String>,
        didResolver: DidResolver,
        trust: DocumentTrustSource?,
        now: Instant = Clock.System.now(),
        moicaCa: MoicaCa = MoicaCa.PRODUCTION,
    ): List<EvidenceResult> {
        val document = credential.obj("document")
        val sha256 = document?.str("sha256")
        val evidence = (credential["evidence"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
        return evidence.map { e ->
            when (e.str("type")) {
                DerivedCredentials.EVIDENCE_TIMESTAMP -> timestamp(e, sha256, trust)
                DerivedCredentials.EVIDENCE_CITIZEN -> citizen(e, credential, disclosed, didResolver, now, moicaCa)
                DerivedCredentials.EVIDENCE_SIGNATURE -> signature(e)
                else -> EvidenceResult(e.str("type") ?: "", "其他證據", Check.NOT_CHECKED, "本錢包不認識這種證據")
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
        val time = Instant.fromEpochSeconds(info.time).toString()
        return when {
            info.imprint == Check.FAIL -> EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.FAIL, "時戳涵蓋的不是這份文件")
            info.signature != Check.PASS -> EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.FAIL, "時戳簽章無效")
            info.trusted -> EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.PASS,
                "${info.tsa ?: "時戳機構"} 證明這份文件在 $time 已存在" + tierNote(info.trust?.tier))
            else -> EvidenceResult(DerivedCredentials.EVIDENCE_TIMESTAMP, title, Check.WARN,
                "時戳簽章正確，但時戳機構「${info.tsa ?: "未知"}」不在信任錨點；聲稱的時間為 $time")
        }
    }

    private fun tierNote(tier: String?): String = tier?.let { "（時戳機構 $it）" } ?: ""

    private suspend fun citizen(
        e: JsonObject,
        credential: JsonObject,
        disclosed: Map<String, String>,
        didResolver: DidResolver,
        now: Instant,
        moicaCa: MoicaCa,
    ): EvidenceResult {
        val title = "自然人憑證簽章"
        val type = DerivedCredentials.EVIDENCE_CITIZEN
        val payload = e.str("payload") ?: return EvidenceResult(type, title, Check.FAIL, "沒有簽署內容")
        // The card is verified without its issuer JWS (that key belongs to the holder's Bonds identity) and without
        // disclosures: what matters is that the cardholder signed the same commitments as this credential.
        val envelope = Jcs.canonicalize(buildJsonObject {
            put("disclosures", JsonArray(emptyList()))
            put("payload", payload)
            put("proof", buildJsonObject {
                put("certificate", e.str("certificate") ?: "")
                put("signature", e.str("signature") ?: "")
                put("tbsConstruction", e.str("tbsConstruction") ?: "")
            })
        })
        val result = try {
            MoicaSignedCredential.parse(envelope).verify(didResolver, now, moicaCa)
        } catch (ex: Exception) {
            return EvidenceResult(type, title, Check.FAIL, "自然人憑證簽章無效：" + (ex.message ?: ""))
        }
        val signed = runCatching { diw.wallet.core.util.DiwJson.parseToJsonElement(payload.fromBase64Url().decodeToString()) as JsonObject }.getOrNull()
            ?: return EvidenceResult(type, title, Check.FAIL, "簽署內容無法讀取")
        if (signed.strList("_sd").toSet() != credential.strList("_sd").toSet()) {
            return EvidenceResult(type, title, Check.FAIL, "自然人憑證簽署的欄位與這張證件不同")
        }
        if (signed.obj("document")?.str("sha256") != credential.obj("document")?.str("sha256")) {
            return EvidenceResult(type, title, Check.FAIL, "自然人憑證簽署的是另一份文件")
        }
        val name = disclosed[DerivedCredentials.CLAIM_NAME]
        if (name != null && name.trim() != result.cardholderName.trim()) {
            return EvidenceResult(type, title, Check.FAIL, "揭露的姓名與自然人憑證不符")
        }
        return EvidenceResult(type, title, Check.PASS, "${result.cardholderName} 以自然人憑證（MOICA G3）簽署這張證件的內容")
    }

    private fun signature(e: JsonObject): EvidenceResult {
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
        val detail = "出示者的錢包於 ${e.str("checkedAt") ?: "未知時間"} 檢查文件：$text" +
            (if (tiers.isNotEmpty()) "，簽署者信任等級 ${tiers.joinToString("、")}" else "") + (if (official) "（官方）" else "") +
            "。這是出示者錢包的聲明，查驗方沒有文件原檔無法重新檢查。"
        return EvidenceResult(DerivedCredentials.EVIDENCE_SIGNATURE, title, Check.NOT_CHECKED, detail)
    }

    private fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0)
        return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
