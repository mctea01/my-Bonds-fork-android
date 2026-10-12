package diw.wallet.core.profile.bonds

import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfTextExtractor
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.w3c.SdJwtDisclosures
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.plus
import kotlinx.datetime.toLocalDateTime
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * The fields of the MyData national ID document (國民身分證資料, personal/detail/API.idPhotoRev), as Bonds reads them.
 * [nationality] is not in the document; Bonds writes it for every holder.
 */
data class NationalIdFields(
    val unifiedNo: String?,
    val name: String?,
    val birthdate: String?,
    val addressOfHousehold: String?,
    val nationality: String = BondsNationalId.NATIONALITY,
)

/** A Republic of China (民國) calendar date; year 1 is 1912. */
data class RocDate(val year: Int, val month: Int, val day: Int) {
    val gregorian: LocalDate? get() = runCatching { LocalDate(year + 1911, month, day) }.getOrNull()

    companion object {
        /**
         * Reads the form MyData writes ("民國 083年03月06日"): optional 民國 prefix, spaces and full-width digits
         * tolerated, the 年 / 月 / 日 markers required. Anything else (such as a bare "0700101") is null: an unknown
         * format must not be guessed at.
         */
        fun parse(raw: String): RocDate? {
            val s = raw.map { c -> if (c in '０'..'９') '0' + (c - '０') else c }.joinToString("")
                .filter { !it.isWhitespace() && it != '　' }
            val y = s.indexOf('年')
            val m = s.indexOf('月')
            val d = s.indexOf('日')
            if (y < 0 || m < 0 || d < 0 || y > m || m > d) return null
            val year = s.substring(0, y).removePrefix("民國").toIntOrNull() ?: return null
            val month = s.substring(y + 1, m).toIntOrNull() ?: return null
            val day = s.substring(m + 1, d).toIntOrNull() ?: return null
            if (year <= 0 || month !in 1..12 || day !in 1..31) return null
            return RocDate(year, month, day).takeIf { it.gregorian != null }
        }
    }
}

/**
 * The Bonds national ID card (NationalIDCredential): the fields of the MyData national ID PDF, which the holder
 * signs with the citizen digital certificate as a vc+moica card. The PDF is encrypted with the holder's ID number as
 * the user password. Issuer and subject are the holder's Bonds self-issued did:key; every field is a disclosure and
 * credentialSubject keeps only the id. The card states what the cardholder asserts from their MyData download, not
 * an endorsement by the household registration office.
 */
object BondsNationalId {
    const val TYPE = "NationalIDCredential"
    const val TERM_NAMESPACE = "https://bonds.tw/ns/credentials#"
    const val NATIONALITY = "中華民國（臺灣）"
    const val CLAIM_OVER_18 = "over18AtIssuance"
    const val MAJORITY = 18

    /** Display order of the claims (as in Bonds). */
    val claimOrder = listOf("nationality", "unifiedNo", "name", "birthdate", CLAIM_OVER_18, "addressOfHousehold")

    val claimLabels = mapOf(
        "nationality" to "國籍",
        "unifiedNo" to "身分證統一編號",
        "name" to "姓名",
        "birthdate" to "出生日期",
        CLAIM_OVER_18 to "簽發時年滿 18 歲",
        "addressOfHousehold" to "戶籍地址",
    )

    private val LABELS = listOf("統號", "姓名", "出生日期", "戶籍地址")
    private val ADDRESS_END = listOf("備註", "列印", "本資料")

    /** The ID number as a password: trimmed and upper case (Bonds tries the input as typed first, then this form). */
    fun normalizePassword(s: String): String = s.trim().uppercase()

    /** Opens the PDF with [idNumber] as the user password (as typed, then normalized) and reads its text. */
    fun readPdf(bytes: ByteArray, idNumber: String): String {
        var pdf = PdfFile(bytes, idNumber)
        if (pdf.passwordRequired && normalizePassword(idNumber) != idNumber) pdf = PdfFile(bytes, normalizePassword(idNumber))
        if (pdf.passwordRequired) throw BondsNationalIdException("身分證統一編號不正確，無法開啟這份 PDF")
        pdf.encryptionProblem?.let { throw BondsNationalIdException("無法開啟這份 PDF：$it") }
        return PdfTextExtractor.extract(pdf)
    }

    /**
     * Finds the fields by their labels, as Bonds does: full- or half-width colon, two fields may share a line, the
     * address may continue over the following lines. Null when none of 統號, 姓名 and 出生日期 is present (another
     * document opened with the same password).
     */
    fun parse(text: String): NationalIdFields? {
        val lines = text.split('\n').map { it.trim() }
        val unifiedNo = value("統號", lines)?.replace(" ", "")?.uppercase()
        val name = value("姓名", lines)?.replace(" ", "")
        val birthdate = value("出生日期", lines)
        if (unifiedNo == null && name == null && birthdate == null) return null
        return NationalIdFields(unifiedNo, name, birthdate, address(lines))
    }

    /** "label：value" in one line; the value ends at the next "label：" on the same line. */
    private fun valueIn(label: String, line: String): String? {
        val at = Regex(Regex.escape(label) + "\\s*[：:]").find(line) ?: return null
        val rest = line.substring(at.range.last + 1)
        val next = Regex("\\s(\\S{1,6})\\s*[：:]").find(rest)
        val value = (if (next != null) rest.substring(0, next.range.first) else rest).trim().trim('　')
        return value.ifEmpty { null }
    }

    private fun value(label: String, lines: List<String>): String? = lines.firstNotNullOfOrNull { valueIn(label, it) }

    private fun address(lines: List<String>): String? {
        val at = lines.indexOfFirst { l -> Regex("戶籍地址\\s*[：:]").containsMatchIn(l) }
        if (at < 0) return null
        val parts = ArrayList<String>()
        valueIn("戶籍地址", lines[at])?.let { parts.add(it) }
        // Continuation lines up to the next labelled line, a known trailer, or the last line of the text.
        for (i in at + 1 until lines.size - 1) {
            val l = lines[i]
            if (l.isEmpty()) continue
            if (l.contains('：') || l.contains(':') || LABELS.any { l.startsWith(it) } || ADDRESS_END.any { l.startsWith(it) }) break
            parts.add(l.replace(" ", ""))
        }
        return parts.joinToString("").ifEmpty { null }
    }

    /** "true" or "false" when the birthdate is readable, else null (unknown is not "under age"). */
    fun over18(birthdate: String?, at: Instant): String? {
        val born = birthdate?.let { RocDate.parse(it) }?.gregorian ?: return null
        val today = at.toLocalDateTime(TAIPEI).date
        // True on the 18th birthday itself, in Taipei time; a 29 February birthday is reached on 28 February.
        return if (born.plus(MAJORITY, DateTimeUnit.YEAR) <= today) "true" else "false"
    }

    /** The claims a card carries, sorted by name as Bonds commits them; absent fields are left out. */
    fun claims(fields: NationalIdFields, at: Instant): List<Pair<String, String>> = listOfNotNull(
        "nationality" to fields.nationality,
        fields.unifiedNo?.let { "unifiedNo" to it },
        fields.name?.let { "name" to it },
        fields.birthdate?.let { "birthdate" to it },
        fields.addressOfHousehold?.let { "addressOfHousehold" to it },
        over18(fields.birthdate, at)?.let { CLAIM_OVER_18 to it },
    ).sortedBy { it.first }

    /** Encoded disclosures [salt, name, value] with fresh 128 bit salts. */
    fun disclosures(claims: List<Pair<String, String>>): List<String> = claims.map { (name, value) ->
        JsonArray(listOf(JsonPrimitive(PlatformCrypto.randomBytes(16).toBase64Url()), JsonPrimitive(name), JsonPrimitive(value)))
            .toString().encodeToByteArray().toBase64Url()
    }

    /** The credential the citizen certificate signs: Bonds' NationalIDCredential with the sorted digests of [disclosures]. */
    fun payload(holderDid: String, disclosures: List<String>, at: Instant = Clock.System.now()): JsonObject = buildJsonObject {
        putJsonArray("@context") {
            add(JsonPrimitive(BondsOfflinePresentation.CREDENTIALS_V2))
            add(buildJsonObject {
                put("@protected", true)
                put(TYPE, TERM_NAMESPACE + TYPE)
                listOf("nationality", "unifiedNo", "birthdate", "addressOfHousehold", CLAIM_OVER_18).forEach { put(it, TERM_NAMESPACE + it) }
            })
        }
        putJsonArray("type") { add(JsonPrimitive("VerifiableCredential")); add(JsonPrimitive(TYPE)) }
        put("issuer", holderDid)
        put("validFrom", Instant.fromEpochSeconds(at.epochSeconds).toString())
        putJsonObject("credentialSubject") { put("id", holderDid) }
        putJsonArray("_sd") { disclosures.map { SdJwtDisclosures.digest(it) }.sorted().forEach { add(JsonPrimitive(it)) } }
    }

    /**
     * Signs the card with the citizen certificate [card] (vc+moica) for [holder], the Bonds self-issued key. The
     * certificate name must equal the name in [fields], since a verifier compares them.
     */
    suspend fun issue(fields: NationalIdFields, holder: HolderKey, card: DocumentSigner, at: Instant = Clock.System.now()): MoicaSignedCredential {
        val name = fields.name ?: throw BondsNationalIdException("讀不到姓名，無法製作身分證卡")
        if (fields.unifiedNo == null) throw BondsNationalIdException("讀不到身分證統一編號，無法製作身分證卡")
        val did = holder.did ?: throw BondsNationalIdException("持有者金鑰沒有 DID")
        val cn = PlatformCrypto.certificateSubjectCn(card.certificateChain.first())?.trim()
            ?: throw BondsNationalIdException("讀不到卡片憑證上的姓名")
        if (cn != name.trim()) throw BondsNationalIdException("自然人憑證上的姓名（$cn）與身分證資料的姓名（$name）不同，查驗方會拒絕這張卡")
        val disclosures = disclosures(claims(fields, at))
        return DerivedCredentials.signMoica(payload(did, disclosures, at), disclosures, holder, card)
    }

    /** True when a vc+moica card is a national ID card. */
    fun isNationalId(card: MoicaSignedCredential): Boolean =
        runCatching { (card.credential()["type"] as? JsonArray)?.any { (it as? JsonPrimitive)?.content == TYPE } == true }.getOrDefault(false)

    private val TAIPEI = TimeZone.of("Asia/Taipei")
}

class BondsNationalIdException(message: String) : Exception(message)
