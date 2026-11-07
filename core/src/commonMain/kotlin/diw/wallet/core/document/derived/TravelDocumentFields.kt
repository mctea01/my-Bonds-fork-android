package diw.wallet.core.document.derived

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.mrtd.ChipCheck
import diw.wallet.core.document.mrtd.Lds
import diw.wallet.core.document.mrtd.LdsFile
import diw.wallet.core.document.mrtd.MrtdDump
import diw.wallet.core.document.mrtd.Mrz
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * A credential derived from an electronic passport or other ICAO 9303 travel document read from its chip
 * (docs/design/zkpassport.md 5.4): the claims come from DG1 alone, and the evidence is the passive authentication
 * the wallet did. The holder may add DG1 and the security object themselves, so a verifier that does not trust the
 * wallet's statement repeats passive authentication to the issuing state's CSCA (less private: DG1 holds the whole
 * zone). Shares the SD-JWT VC structure of [DerivedCredentials] under its own vct.
 */
object TravelDocumentFields {
    const val VCT = "urn:diw-wallet:vct:travel-document-derived:1"
    const val EVIDENCE = "TravelDocumentPassiveAuthentication"

    const val DOCUMENT_CODE = "documentCode"
    const val ISSUING_STATE = "issuingState"
    const val SURNAME = "surname"
    const val GIVEN_NAMES = "givenNames"
    const val DOCUMENT_NUMBER = "documentNumber"
    const val NATIONALITY = "nationality"
    const val BIRTH_DATE = "birthDate"
    const val SEX = "sex"
    const val EXPIRY_DATE = "expiryDate"

    /** DG1 and the security object as the chip returned them, base64. */
    const val CLAIM_DG1 = "travelDocumentDg1"
    const val CLAIM_SOD = "travelDocumentSod"

    /** Claims that carry chip files rather than values for people. */
    fun isRaw(name: String): Boolean = name == CLAIM_DG1 || name == CLAIM_SOD

    /** "YYMMDD" as YYYY-MM-DD, the century chosen so a birth date is in the past and an expiry date near now. */
    fun date(yymmdd: String, expiry: Boolean, currentYear: Int): String {
        if (yymmdd.length != 6 || !yymmdd.all { it.isDigit() }) return yymmdd.replace('<', '?')
        val yy = yymmdd.take(2).toInt()
        val pivot = currentYear % 100
        val century = if (expiry) (if (yy < pivot + 50) 2000 else 1900) else (if (yy <= pivot) 2000 else 1900)
        return "${century + yy}-${yymmdd.substring(2, 4)}-${yymmdd.substring(4, 6)}"
    }

    /** The claims of the zone, every given name kept. */
    fun claims(mrz: Mrz, currentYear: Int): List<DerivedClaim> = buildList {
        add(DerivedClaim(DOCUMENT_CODE, mrz.documentCode, "證件種類"))
        add(DerivedClaim(ISSUING_STATE, mrz.issuingState, "發證國"))
        mrz.primaryIdentifier.takeIf { it.isNotBlank() }?.let { add(DerivedClaim(SURNAME, it, "姓")) }
        mrz.secondaryIdentifier.takeIf { it.isNotBlank() }?.let { add(DerivedClaim(GIVEN_NAMES, it, "名")) }
        add(DerivedClaim(DOCUMENT_NUMBER, mrz.documentNumber, "證件號碼"))
        // Permit cards of mainland China state no nationality.
        mrz.nationality.takeIf { it.isNotBlank() }?.let { add(DerivedClaim(NATIONALITY, it, "國籍")) }
        add(DerivedClaim(BIRTH_DATE, date(mrz.birthDate, false, currentYear), "出生日期"))
        mrz.sex.takeIf { it.isNotBlank() }?.let { add(DerivedClaim(SEX, it, "性別")) }
        add(DerivedClaim(EXPIRY_DATE, date(mrz.expiryDate, true, currentYear), "效期截止日"))
    }

    /** The zone claims of [dump], then DG1 and the security object for verifiers that repeat the check; empty without DG1. */
    fun claims(dump: MrtdDump, currentYear: Int): List<DerivedClaim> {
        val dg1 = dump.file(LdsFile.DG1) ?: return emptyList()
        val mrz = Lds.dg1(dg1) ?: return emptyList()
        return claims(mrz, currentYear) + listOfNotNull(
            DerivedClaim(CLAIM_DG1, Base64.encode(dg1), "DG1 原文（供查驗方重做被動驗證）"),
            dump.file(LdsFile.SOD)?.let { DerivedClaim(CLAIM_SOD, Base64.encode(it), "安全物件 SOD 原文（供查驗方重做被動驗證）") },
        )
    }

    private fun hex(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    /** The wallet's passive authentication of [dump] as evidence, with fingerprints of the files a verifier may get. */
    fun evidence(report: DocumentReport, dump: MrtdDump): JsonObject? {
        val t = report.travelDocument ?: return null
        val sig = report.signatures.firstOrNull()
        return buildJsonObject {
            put("type", EVIDENCE)
            put("checkedAt", Instant.fromEpochSeconds(report.checkedAt).toString())
            put("verdict", report.verdict.name)
            sig?.trust?.let { put("trustTier", it.tier); put("official", it.official) }
            t.hashAlgorithm?.let { put("hashAlgorithm", it) }
            putJsonArray("matched") { t.matched.forEach { add(JsonPrimitive(it)) } }
            put("access", t.access)
            put("chipAuthentication", t.chipAuthentication.name)
            put("activeAuthentication", t.activeAuthentication.name)
            put("readAt", Instant.fromEpochSeconds(t.readAt).toString())
            dump.file(LdsFile.DG1)?.let { put("dg1Sha256", hex(PlatformCrypto.sha256(it))) }
            dump.file(LdsFile.SOD)?.let { put("sodSha256", hex(PlatformCrypto.sha256(it))) }
        }
    }

    private fun text(e: JsonElement?): String? = (e as? JsonPrimitive)?.takeIf { it.isString }?.content

    /**
     * Verifier side of [evidence]. Without DG1 and the security object the wallet's statement is all there is; with
     * them, passive authentication is repeated here and every disclosed zone claim must equal what DG1 says.
     */
    suspend fun verify(e: JsonObject, disclosed: Map<String, JsonElement>, trust: DocumentTrustSource?, own: Boolean, now: Instant = Clock.System.now()): List<EvidenceResult> {
        val title = "電子護照被動驗證"
        val statement = statement(e, own)
        val dg1 = text(disclosed[CLAIM_DG1])?.let { runCatching { Base64.decode(it) }.getOrNull() }
        val sod = text(disclosed[CLAIM_SOD])?.let { runCatching { Base64.decode(it) }.getOrNull() }
        if (dg1 == null || sod == null) {
            return listOf(EvidenceResult(EVIDENCE, title, Check.NOT_CHECKED, statement + if (own) "" else "。未附 DG1 與 SOD，查驗方無法重新驗證。"))
        }
        if (e.str("dg1Sha256") != hex(PlatformCrypto.sha256(dg1)) || e.str("sodSha256") != hex(PlatformCrypto.sha256(sod))) {
            return listOf(EvidenceResult(EVIDENCE, title, Check.FAIL, "附上的 DG1 或 SOD 不是產生憑證時檢查的檔案"))
        }
        if (trust == null) return listOf(EvidenceResult(EVIDENCE, title, Check.NOT_CHECKED, "$statement。此處無法重做被動驗證。"))
        val result = passiveAuthentication(title, dg1, sod, null, trust, now)
        if (result.check == Check.FAIL) return listOf(result)
        val mrz = Lds.dg1(dg1) ?: return listOf(EvidenceResult(EVIDENCE, title, Check.FAIL, "DG1 無法解讀"))
        val year = now.toString().take(4).toInt()
        val expected = claims(mrz, year).associate { it.name to it.value }
        val differing = expected.filter { (name, value) -> text(disclosed[name])?.let { it != value } == true }.keys
        val fields = if (differing.isEmpty()) EvidenceResult(EVIDENCE, "電子護照欄位", Check.PASS, "出示的機讀區欄位與 DG1 相符")
        else EvidenceResult(EVIDENCE, "電子護照欄位", Check.FAIL, "出示的欄位與 DG1 不符：" + differing.joinToString("、"))
        return listOf(result, fields)
    }

    /**
     * Passive authentication of chip files a verifier received ([dg2] optional): the security object's signature,
     * the hashes of the given files, and the chain of its document signer to a trusted CSCA.
     */
    suspend fun passiveAuthentication(title: String, dg1: ByteArray, sod: ByteArray, dg2: ByteArray?, trust: DocumentTrustSource, now: Instant): EvidenceResult {
        val files = buildMap {
            put(LdsFile.DG1.name, Base64.encode(dg1))
            put(LdsFile.SOD.name, Base64.encode(sod))
            dg2?.let { put(LdsFile.DG2.name, Base64.encode(it)) }
        }
        val dump = MrtdDump(files = files, access = "presented", readAt = now.epochSeconds)
        val report = DocumentInspector.inspect(dump.encode(), null, trust, now = now)
        val check = report.travelDocument
        val signature = report.signatures.firstOrNull()
        return when {
            report.format != DocumentFormat.EMRTD || check == null || signature == null ->
                EvidenceResult(EVIDENCE, title, Check.FAIL, "DG1 與 SOD 無法解讀")
            1 !in check.matched || (dg2 != null && 2 !in check.matched) || signature.integrity != Check.PASS ->
                EvidenceResult(EVIDENCE, title, Check.FAIL, "SOD 的簽章或資料群組雜湊不符")
            report.verdict == DocumentVerdict.VALID ->
                EvidenceResult(EVIDENCE, title, Check.PASS, "已重做被動驗證：SOD 由 ${check.signerCountry ?: "發證國"} 的文件簽發者簽署並連到信任的 CSCA" + (signature.trust?.let { "（${it.tier}）" } ?: ""))
            else ->
                EvidenceResult(EVIDENCE, title, Check.WARN, "已重做被動驗證：SOD 簽章與資料群組雜湊正確，但文件簽發者沒有連到本處信任的 CSCA")
        }
    }

    private fun statement(e: JsonObject, own: Boolean): String {
        val verdict = when (e.str("verdict")) {
            "VALID" -> "被動驗證通過"
            "PARTIAL" -> "被動驗證部分通過"
            "INVALID" -> "被動驗證失敗"
            else -> "沒有被動驗證結果"
        }
        val tier = e.str("trustTier")?.let { "，CSCA 信任等級 $it" } ?: ""
        val chip = buildList {
            if (e.str("chipAuthentication") == ChipCheck.PASS.name) add("晶片驗證")
            if (e.str("activeAuthentication") == ChipCheck.PASS.name) add("主動驗證")
        }.takeIf { it.isNotEmpty() }?.joinToString("與", prefix = "，", postfix = "通過（防複製）") ?: ""
        val at = e.str("readAt")?.take(10) ?: "未知日期"
        return (if (own) "讀取晶片時（$at）" else "出示者的錢包讀取晶片時（$at）") + verdict + tier + chip
    }

    /** Names of the zone claims, for the cards that list a derived credential's claims. */
    val labels: Map<String, String> = mapOf(
        DOCUMENT_CODE to "證件種類", ISSUING_STATE to "發證國", SURNAME to "姓", GIVEN_NAMES to "名",
        DOCUMENT_NUMBER to "證件號碼", NATIONALITY to "國籍", BIRTH_DATE to "出生日期", SEX to "性別", EXPIRY_DATE to "效期截止日",
        CLAIM_DG1 to "DG1 原文", CLAIM_SOD to "安全物件 SOD 原文",
    )
}
