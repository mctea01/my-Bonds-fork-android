package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.i18n.CoreText
import diw.wallet.core.document.official.BundleMatch
import diw.wallet.core.document.image.ImageConversion
import diw.wallet.core.util.TextEncodings
import diw.wallet.core.document.image.ImageKind
import diw.wallet.core.document.image.TiffDecoder
import diw.wallet.core.document.official.ApprovalFile
import diw.wallet.core.document.official.ApprovalPoint
import diw.wallet.core.document.sign.HttpFetch
import diw.wallet.core.document.sign.SignedDataFetch
import diw.wallet.core.document.sign.SignatureLevel
import diw.wallet.core.document.sign.ValidationData
import diw.wallet.core.profile.bonds.HouseholdTranscript
import diw.wallet.core.profile.bonds.HouseholdTranscripts
import diw.wallet.core.document.official.OfficialBundles
import diw.wallet.core.profile.bonds.MyDataText
import diw.wallet.core.document.sign.CscService
import androidx.compose.ui.graphics.ImageBitmap
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.card.GpkiTapSigner
import diw.wallet.core.document.card.NfcCardChannel
import diw.wallet.core.document.card.PivCard
import diw.wallet.core.document.card.PivTapSigner
import diw.wallet.core.document.card.OpenPgpKeySlot
import diw.wallet.core.document.pgp.OpenPgp
import diw.wallet.core.document.pgp.OpenPgpCards
import diw.wallet.core.document.pgp.OpenPgpKind
import diw.wallet.core.document.pgp.OpenPgpPackets
import diw.wallet.core.document.pgp.OpenPgpPlaintext
import diw.wallet.core.document.pgp.OpenPgpTapSigner
import diw.wallet.core.document.pgp.OpenPgpTrust
import diw.wallet.core.document.pgp.OpenPgpTrustedKey
import diw.wallet.core.document.pdf.PdfException
import diw.wallet.core.document.zkpdf.ZkPdfCreated
import diw.wallet.core.document.zkpdf.ZkPdfEvidence
import diw.wallet.core.document.zkpdf.ZkPdfPlan
import diw.wallet.core.document.zkpdf.ZkPdfPlanner
import diw.wallet.core.document.zkpdf.ZkPdfPredicate
import diw.wallet.core.document.zkpdf.ZkPdfProfile
import diw.wallet.core.document.zkpdf.ZkPdfProfiles
import diw.wallet.core.document.zkpdf.ZkPdfProofs
import diw.wallet.core.zk.RemoteZkPdfEngine
import diw.wallet.core.zk.ZkPdfRemote
import diw.wallet.core.zk.ZkPdfWitness
import diw.wallet.core.zk.ZkPdfEngine
import diw.wallet.core.zk.ZkPdfStatement
import diw.wallet.core.zk.ZkProverHost
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.document.derived.DerivedClaim
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.MovementRecord
import diw.wallet.core.document.derived.ParsedCertificate
import diw.wallet.core.document.derived.DerivedDocument
import diw.wallet.core.document.official.OfficialDocument
import diw.wallet.core.document.official.OfficialDocuments
import diw.wallet.core.document.opencerts.OaAttachment
import diw.wallet.core.document.opencerts.OpenAttestationDocument
import diw.wallet.core.document.opencerts.OpenAttestationOnline
import diw.wallet.core.document.opencerts.OpenCertOffline
import diw.wallet.core.document.opencerts.OpenCertRenderer
import diw.wallet.core.document.opencerts.OpenCertView
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfPlain
import diw.wallet.app.ui.compositionTitle
import diw.wallet.app.ui.localTime
import diw.wallet.core.document.pdf.PdfAppearanceImage
import diw.wallet.core.document.pdf.PdfSignOptions
import diw.wallet.core.document.pdf.PdfIncrementalSigner
import diw.wallet.core.document.sign.CscSigner
import diw.wallet.core.document.pdf.PdfSignatureAppearance
import diw.wallet.core.document.pdf.PdfTextExtractor
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.MobileMoicaCredentials
import diw.wallet.core.document.sign.MobileMoicaEnvironment
import diw.wallet.core.document.sign.MobileMoicaMode
import diw.wallet.core.document.sign.MobileMoicaService
import diw.wallet.core.document.sign.MobileMoicaSigner
import diw.wallet.core.document.sign.ServerMobileMoicaClient
import diw.wallet.core.document.sign.TwFidoClient
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.document.sign.Timestamper
import diw.wallet.core.document.sign.TsaClient
import diw.wallet.core.document.sign.TsaServices
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.oid4vci.CredentialDomains
import diw.wallet.core.oid4vci.IssuanceRecord
import diw.wallet.core.profile.bonds.BondsNationalId
import diw.wallet.core.profile.bonds.HolderDerivedException
import diw.wallet.core.profile.bonds.HolderDerivedSource
import diw.wallet.core.profile.bonds.HolderDerivedTypes
import diw.wallet.core.profile.bonds.HolderHint
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.profile.bonds.NationalIdFields
import diw.wallet.core.profile.bonds.TwPkiAnchors
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.crypto.EcPublicKey
import org.multipaz.securearea.SecureArea
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.X509Cert
import org.multipaz.sdjwt.credential.KeyBoundSdJwtVcCredential
import org.multipaz.storage.StorageTableSpec
import org.multipaz.util.fromBase64
import org.multipaz.util.toBase64

/** A time stamp the wallet obtained for a stored file (RFC 3161 over its SHA-256). */
@Serializable
data class StoredTimestamp(
    val token: String,
    val time: Long,
    val tsa: String? = null,
    val trusted: Boolean = false,
    /** The time-stamp authority's chain and revocation data (OCSP first), fetched when the stamp was made. */
    val validation: ValidationData? = null,
)

/** How a file came into the vault. */
@Serializable
enum class FileOrigin(private val titleRes: org.jetbrains.compose.resources.StringResource) {
    IMPORTED(Res.string.origin_imported),
    DOWNLOADED(Res.string.origin_downloaded),
    EXTRACTED(Res.string.origin_extracted),
    SIGNED(Res.string.origin_signed),
    COMPOSED(Res.string.origin_composed),
    LETTER(Res.string.origin_letter),
    ENCRYPTED(Res.string.origin_encrypted),
    DECRYPTED(Res.string.origin_decrypted),
    UNWRAPPED(Res.string.origin_unwrapped),
    /** Read from a document chip (an electronic passport) over NFC. */
    CHIP(Res.string.origin_chip),
    ;

    val title: String get() = tr(titleRes)
}

/** A file in the vault: its fingerprint, the last inspection, time stamps, and the credential derived from it. */
@Serializable
data class StoredFile(
    val id: String,
    val name: String,
    val mediaType: String,
    val size: Long,
    /** SHA-256 of the stored bytes, hex. */
    val sha256: String,
    val addedAt: Long,
    val origin: FileOrigin,
    /** Where it came from, short: "MyData・現戶全戶戶籍資料", a source site, the file it was signed from. */
    val source: String? = null,
    val report: DocumentReport? = null,
    val timestamps: List<StoredTimestamp> = emptyList(),
    /** The file a detached signature (.p7s) signs. */
    val contentId: String? = null,
    val parentId: String? = null,
    /** The derived SD-JWT VC (a document in the documents list); cleared when that credential is deleted. */
    val derivedDocumentId: String? = null,
    /** Web query results kept as evidence of this file (web-proof or web-record credentials in the documents list). */
    val webProofIds: List<String> = emptyList(),
    /** The Bonds national ID card (vc+moica NationalIDCredential) made from this MyData national ID PDF. */
    val nationalId: String? = null,
    /** The archive (ZIP) the file was unpacked from, by name; the archive itself may be gone. */
    val archive: String? = null,
    /** The official document whose container holds this file (an exchange form, approval file or attachment). */
    val bundleOf: String? = null,
    /** The period the content covers, read from it ("113 年度"), for telling yearly files apart. */
    val period: String? = null,
    /**
     * Chains and revocation data (OCSP first, else CRL) of the signers in the file and of their signature time-stamp
     * authorities, collected by the wallet so the signatures can be checked after the certificates expire.
     */
    val signatureValidation: ValidationData? = null,
    /** A zkPDF proof request exported for the desktop wallet, waiting for its proof file. */
    val zkPdfPending: ZkPdfPending? = null,
)

/**
 * What finishing a derived credential needs once the desktop wallet returns the zkPDF proof: the request it answers,
 * the credential key the proof is bound to (by its secure area and alias), the template, conditions, composition
 * and field salts the request was built with, and the choices made on the derive screen.
 */
@Serializable
data class ZkPdfPending(
    val requestId: String,
    val keyAlias: String,
    val secureArea: String,
    val profileId: String,
    val predicates: List<Predicate>,
    val composition: String,
    /** Field salts, base64url; they open the committed values, so they stay with the file. */
    val salts: List<String>,
    val claims: List<Claim>,
    val timestamp: Boolean,
    val validDays: Int? = null,
    val createdAt: Long,
) {
    @Serializable
    data class Predicate(val kind: Int, val claim: String, val cutoff: Int)

    @Serializable
    data class Claim(val name: String, val value: String, val label: String? = null)
}

/** What the file screen shows of a file's content. */
sealed class FilePreview {
    /**
     * Rendered pages (as many as [PREVIEW_PAGES]) of [total], the text layer when there is one, and the record read
     * from it when the PDF is an entry and exit certificate.
     */
    class Pages(
        val pages: List<ImageBitmap>, val total: Int, val text: String?, val entryExit: MovementRecord? = null,
        /** A household transcript read person by person, the holder first. */
        val household: HouseholdTranscript? = null,
        /** A certificate laid out as its parts (a proof of student status, a mainland permit association). */
        val certificate: ParsedCertificate? = null,
    ) : FilePreview()
    class Picture(val image: ImageBitmap) : FilePreview()
    /** A travel document read from its chip, laid out as its data page. */
    class Passport(val view: PassportView) : FilePreview()
    class Text(val text: String, val truncated: Boolean) : FilePreview()
    /** An official document (公文) laid out as a reader sees it; [source] is the XML, shown only on request. */
    class Official(val document: OfficialDocument, val source: String, val truncated: Boolean) : FilePreview()
    /** The PDF needs its open password; [wrong] after a password that did not open it. */
    class NeedsPassword(val wrong: Boolean) : FilePreview()
    class Unavailable(val reason: String) : FilePreview()
    data object Loading : FilePreview()

    companion object {
        const val PREVIEW_PAGES = 10
        const val TEXT_LIMIT = 20_000
    }
}

/** The fields read from a national ID PDF, shown for confirmation before the card signs them. */
data class NationalIdDraft(val fileId: String, val fields: NationalIdFields, val over18: String?)

/**
 * A site where a holder gets an official document (opened in the app on Android, downloads go to the vault).
 * [myData] marks MyData pages, whose ZIP downloads are unpacked at once; [nationalId] is the national ID item, whose
 * PDF goes straight to making the Bonds national ID card.
 */
class DocumentSource(
    val id: String,
    val name: String,
    val detail: String,
    val url: String,
    val myData: Boolean = false,
    val nationalId: Boolean = false,
)

object DocumentSources {
    private const val MYDATA = "https://mydata.nat.gov.tw/"

    /** MyData items, by the item paths Bonds uses (personal/detail/API.<code>). */
    val myData: List<DocumentSource> get() = listOf(
        DocumentSource("mydata-id", tr(Res.string.src_mydata_id), tr(Res.string.src_mydata_id_text), MYDATA + "personal/detail/API.idPhotoRev", myData = true, nationalId = true),
        DocumentSource("mydata", tr(Res.string.src_mydata), tr(Res.string.src_mydata_text), MYDATA + "signin", myData = true),
        DocumentSource("mydata-household", tr(Res.string.src_household), tr(Res.string.src_household_by), MYDATA + "personal/detail/API.UDauDOLyZg", myData = true),
        DocumentSource("mydata-income", tr(Res.string.src_income), tr(Res.string.src_income_by), MYDATA + "personal/detail/API.syWqjr4flJ", myData = true),
        DocumentSource("mydata-tax-cert", tr(Res.string.src_tax_cert), tr(Res.string.src_tax_cert_by), MYDATA + "personal/detail/API.TeV2Md7SIx", myData = true),
        DocumentSource("mydata-labor-insurance", tr(Res.string.src_labor), tr(Res.string.src_labor_by), MYDATA + "personal/detail/API.UZQkKbsOpz", myData = true),
        DocumentSource("mydata-labor-pension", tr(Res.string.src_pension), tr(Res.string.src_labor_by), MYDATA + "personal/detail/API.yqkllwwTYl", myData = true),
        DocumentSource("mydata-health-insurance", tr(Res.string.src_nhi), tr(Res.string.src_nhi_by), MYDATA + "personal/detail/API.zH584wn59r", myData = true),
        DocumentSource("mydata-nhi-premium", tr(Res.string.src_nhi_premium), tr(Res.string.src_nhi_by), MYDATA + "personal/detail/API.1qIr0nM0BT", myData = true),
        DocumentSource("mydata-land", tr(Res.string.src_land), tr(Res.string.src_land_by), MYDATA + "personal/detail/API.KvvyRZSc5K", myData = true),
    )

    val others: List<DocumentSource> get() = listOf(
        DocumentSource("mydoc", tr(Res.string.src_mydoc), tr(Res.string.src_mydoc_text), "https://mydoc.gov.taipei/"),
        DocumentSource("moe", tr(Res.string.src_moe), tr(Res.string.src_moe_text), "https://dcert.moe.gov.tw/"),
        DocumentSource("dcert", tr(Res.string.src_dcert), tr(Res.string.src_dcert_text), "https://dcmc.csie.ncku.edu.tw/"),
        DocumentSource("ris", tr(Res.string.src_ris), tr(Res.string.src_ris_text), "https://www.ris.gov.tw/app/portal/"),
        DocumentSource("land", tr(Res.string.src_land_transcript), tr(Res.string.src_land_transcript_text), "https://ep.land.nat.gov.tw/"),
        DocumentSource("etax", tr(Res.string.src_etax), tr(Res.string.src_etax_text), "https://www.etax.nat.gov.tw/etwmain"),
        DocumentSource("nia", tr(Res.string.src_nia), tr(Res.string.src_nia_text), "https://ncp.immigration.gov.tw/niaweb/entryExitQuery"),
    )

    val all = myData + others

    fun byId(id: String) = all.firstOrNull { it.id == id }
}

/** A MyData item recognised by the official file name of its download. */
class MyDataItem(val title: String, val nationalId: Boolean = false)

/**
 * MyData downloads by their official file names (as Bonds matches them): the national ID item, and the vault
 * documents. A name alone is not proof of origin; files recognised this way are labelled as such.
 */
object MyDataFiles {
    private val items = listOf(
        listOf("國民身分證資料", "idPhotoRev") to MyDataItem("國民身分證資料", nationalId = true),
        listOf("現戶全戶戶籍資料", "全戶戶籍", "UDauDOLyZg") to MyDataItem("現戶全戶戶籍資料"),
        listOf("個人所得資料", "所得資料表", "syWqjr4flJ") to MyDataItem("個人所得資料"),
        listOf("綜合所得稅納稅證明", "納稅證明", "TeV2Md7SIx") to MyDataItem("綜合所得稅納稅證明書"),
        listOf("被保險人投保資料", "勞保投保", "就保投保", "災保投保", "UZQkKbsOpz") to MyDataItem("被保險人投保資料"),
        listOf("勞工提繳異動資料", "勞退提繳", "提繳異動", "yqkllwwTYl") to MyDataItem("勞工提繳異動資料"),
        listOf("個人投退保資料", "健保投退保", "zH584wn59r") to MyDataItem("個人投退保資料（健保）"),
        listOf("保費繳納紀錄", "健保保費", "1qIr0nM0BT") to MyDataItem("保費繳納紀錄（健保）"),
        listOf("地籍及實價資料", "地籍資料", "實價資料", "KvvyRZSc5K") to MyDataItem("地籍及實價資料"),
        listOf("personal-data.zip", "MyData") to MyDataItem("MyData 個人文件"),
    )

    fun recognize(name: String): MyDataItem? = items.firstOrNull { (keys, _) -> keys.any { name.contains(it, ignoreCase = true) } }?.second

    /** Mark of a source known only from a file name. */
    const val BY_NAME = "（依檔名判斷）"

    /** The short source of a MyData file: "MyData・item", marked when only the file name says it is from MyData. */
    fun label(item: MyDataItem?, byName: Boolean): String =
        "MyData" + (item?.title?.takeIf { it != "MyData 個人文件" }?.let { "・$it" } ?: "") + if (byName) BY_NAME else ""

    fun isMyData(source: String?): Boolean = source?.startsWith("MyData") == true

    /** The Bonds holder-derived document type of a MyData item, when one is defined for it. */
    fun holderDerivedType(item: MyDataItem): String? = when (item.title) {
        "個人所得資料" -> HolderDerivedTypes.INCOME
        "被保險人投保資料" -> HolderDerivedTypes.LABOR_INSURANCE
        "現戶全戶戶籍資料" -> HolderDerivedTypes.HOUSEHOLD
        else -> null
    }

    /**
     * The source of a file stored before labels were shortened ("MyData（App 內下載：X）；解自 Y.zip（X）"), in the
     * short form, with the archive it named; null when it is not such a label.
     */
    fun legacy(source: String?, name: String): Pair<String, String?>? {
        if (source == null || !source.startsWith("MyData（")) return null
        val byName = "依檔名判斷" in source
        val item = recognize(name) ?: recognize(source.substringAfter("；解自", source))
        val archive = Regex("解自 (.+?\\.zip)").find(source)?.groupValues?.get(1)
        return label(item, byName) to archive
    }
}

/** Who signs a document. */
/**
 * A visible PDF signature chosen on the signing screen: the page (0-based, -1 for the last page), a preset position
 * and an optional picture such as a handwritten signature. The text lines are filled in at signing time.
 */
class VisibleSignature(val page: Int, val position: PdfSignatureAppearance.Position, val image: PdfAppearanceImage? = null)

sealed class SignerChoice {
    /** The citizen digital certificate (or another GPKI) card on [reader]; the PIN is used for this signing only. */
    class Card(val reader: NfcReaderOption, val pin: String) : SignerChoice()
    /**
     * A PIV card (NIST SP 800-73-4) on [reader]; [slot] chooses which key slot's certificate signs (null lets the
     * card's first usable slot answer). The PIN is used for this signing only.
     */
    class Piv(val reader: NfcReaderOption, val pin: String, val slot: Int? = null) : SignerChoice()
    /** A PKCS#12 file opened with its password. */
    class Pkcs12(val file: ByteArray, val password: String) : SignerChoice()
    /** The wallet's own key with a self-issued certificate in [name]. */
    class Wallet(val name: String) : SignerChoice()
    /** A key in the system store; [id] null opens the platform's own picker (Android KeyChain). */
    class System(val id: String?) : SignerChoice()
    /** A key on a PKCS#11 token loaded from [library]; the PIN is used for this signing only. */
    class Token(val library: String, val pin: String, val id: String) : SignerChoice()
    /**
     * The mobile citizen certificate, through [sp] (built in, or a licence holder's entered for this run) or, with
     * [server] set, through the SP account of that production server.
     */
    class MobileMoica(val sp: MobileMoicaSp?, val idNumber: String, val mode: MobileMoicaMode, val server: String? = null) : SignerChoice()
    /** A remote signing service (CSC API); the holder signs in and approves each signature with the service. */
    class Csc(val service: CscService) : SignerChoice()
    /**
     * The signature key of an OpenPGP card (OpenPGP card, YubiKey, Nitrokey) on [reader]; PW1 is used for this signing
     * only. Signs OpenPGP signatures, and the X.509 formats with an RSA or P-256 key.
     */
    class OpenPgp(val reader: NfcReaderOption, val pin: String) : SignerChoice()
}

/** An SP account entered for this run; kept in memory only, never stored. */
data class MobileMoicaSp(val environment: MobileMoicaEnvironment, val serviceId: String, val aesKeyBase64: String, val builtIn: Boolean = false)

/** The signature a file gets. */
enum class SignForm(private val titleRes: org.jetbrains.compose.resources.StringResource, private val detailRes: org.jetbrains.compose.resources.StringResource) {
    PADES(Res.string.sign_form_pades, Res.string.sign_form_pades_text),
    XADES(Res.string.sign_form_xades, Res.string.sign_form_xades_text),
    APPROVAL(Res.string.sign_form_approval, Res.string.sign_form_approval_text),
    CADES_DETACHED(Res.string.sign_form_detached, Res.string.sign_form_detached_text),
    CADES_ENVELOPING(Res.string.sign_form_enveloping, Res.string.sign_form_enveloping_text),
    ASIC(Res.string.sign_form_asic, Res.string.sign_form_asic_text),
    OPENPGP_DETACHED(Res.string.sign_form_pgp, Res.string.sign_form_pgp_text),
    ;

    val title: String get() = tr(titleRes)
    val detail: String get() = tr(detailRes)
}

/**
 * The document vault behind the Files tab: stored files with their inspection reports and time stamps, signing
 * (citizen certificate card, PKCS#12 or the wallet's own key), composing documents and official letters, and
 * deriving credentials from documents. Files never leave the device except when the user exports them; time
 * stamps send only the SHA-256 of a file.
 */
class FilesModel(private val model: WalletModel) {
    val files = MutableStateFlow<List<StoredFile>>(emptyList())
    /** What the vault is doing now, shown as a progress line; null when idle. */
    val busy = MutableStateFlow<String?>(null)
    /** The last failure of a vault action, shown on the screen it came from. */
    val error = MutableStateFlow<String?>(null)

    val trustSource = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision = model.trust.decide(role, chain, at)

        override suspend fun knownCertificates(): List<ByteArray> = model.trust.chainCertificates().map { it.encoded.toByteArray() }

        override suspend fun openPgpKeys(): List<OpenPgpTrustedKey> = model.openPgp.trustedKeys()

        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = try {
            if (!url.startsWith("http://") && !url.startsWith("https://")) emptyList()
            else {
                val r = model.signedDataHttp.exchange(url, null, null, null)
                val bytes = if (r.success) r.body else ByteArray(0)
                if (bytes.isEmpty() || bytes.size > MAX_AIA_BYTES) emptyList() else listOf(bytes)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            emptyList()
        }
    }

    suspend fun load() {
        val t = model.storage.getTable(metaTable)
        val loaded = t.enumerate().mapNotNull { key ->
            t.get(key)?.let { runCatching { DiwJson.decodeFromString(StoredFile.serializer(), it.decodeToString()) }.getOrNull() }
        }
        // Files stored before source labels were shortened get the short label and their archive name.
        files.value = loaded.map { f ->
            val (source, archive) = MyDataFiles.legacy(f.source, f.name) ?: return@map f
            f.copy(source = source, archive = f.archive ?: archive).also { t.update(it.id, DiwJson.encodeToString(StoredFile.serializer(), it).encodeToByteString()) }
        }.sortedByDescending { it.addedAt }
    }

    fun file(id: String): StoredFile? = files.value.firstOrNull { it.id == id }

    suspend fun data(id: String): ByteArray =
        Blobs.get(model.storage.getTable(dataTable), id) ?: throw IllegalStateException(tr(Res.string.msg_file_no_content))

    /** Serializes writes of file records, so [patch] never writes back a record older than one saved meanwhile. */
    private val saving = Mutex()

    internal suspend fun save(f: StoredFile) = saving.withLock { write(f) }

    private suspend fun write(f: StoredFile) {
        val t = model.storage.getTable(metaTable)
        val bytes = DiwJson.encodeToString(StoredFile.serializer(), f).encodeToByteString()
        if (t.get(f.id) == null) t.insert(f.id, bytes) else t.update(f.id, bytes)
        files.value = (files.value.filter { it.id != f.id } + f).sortedByDescending { it.addedAt }
    }

    /** Changes the current record of [id] (for work that finishes in the background); null when it is gone. */
    private suspend fun patch(id: String, change: (StoredFile) -> StoredFile): StoredFile? = saving.withLock {
        val current = file(id) ?: return@withLock null
        change(current).also { write(it) }
    }

    /** Inspects [bytes] and stores them; the same content stored before is returned instead. */
    suspend fun store(
        givenName: String,
        bytes: ByteArray,
        origin: FileOrigin,
        source: String? = null,
        parentId: String? = null,
        contentId: String? = null,
        archive: String? = null,
    ): StoredFile {
        // Names that went through the wrong decoder on the way (a server's raw header, a percent-encoded link) are repaired.
        val name = TextEncodings.repairName(givenName)
        if (bytes.isEmpty()) throw SigningException(tr(Res.string.msg_file_empty))
        if (bytes.size > MAX_FILE_BYTES) throw SigningException(tr(Res.string.msg_file_too_large, MAX_FILE_BYTES / 1024 / 1024))
        val detached = contentId?.let { data(it) }
        val report = DocumentInspector.inspect(bytes, name, trustSource, detached, related = relatedFor(bytes))
        files.value.firstOrNull { it.sha256 == report.sha256 }?.let { return it }
        val f = StoredFile(
            id = WalletModel.randomId(),
            name = name.ifBlank { tr(Res.string.msg_unnamed_file) },
            mediaType = mediaTypeOf(report, name),
            size = bytes.size.toLong(),
            sha256 = report.sha256,
            addedAt = Clock.System.now().epochSeconds,
            origin = origin,
            source = source,
            report = report,
            contentId = contentId,
            parentId = parentId,
            archive = archive,
        )
        Blobs.put(model.storage.getTable(dataTable), f.id, bytes)
        save(f)
        if (model.settings.timestampOnSave) runCatching { addTimestampNow(f) }
        if (model.settings.timestampRevocation && report.signatures.isNotEmpty()) {
            model.scope.launch { runCatching { storeSignatureValidation(f.id) } }
        }
        if (report.openCert != null) model.scope.launch { runCatching { verifyOpenCertNow(f, force = false) } }
        return file(f.id) ?: f
    }

    private fun run(progress: String, block: suspend () -> Unit) = model.scope.launch {
        busy.value = progress
        error.value = null
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            error.value = model.describe(e)
        } finally {
            busy.value = null
            model.endOperation()
        }
    }

    /** Lets the user pick a file and stores it. */
    fun pickAndImport() = run(tr(Res.string.step_read_check)) {
        val picked = model.platform.pickFiles()
        when (picked.size) {
            0 -> return@run
            1 -> importNow(picked.single(), FileOrigin.IMPORTED, null)
            else -> {
                val before = files.value.size
                val stored = ArrayList<StoredFile>()
                picked.forEachIndexed { i, p ->
                    busy.value = tr(Res.string.step_read_check_n, i + 1, picked.size)
                    stored.addAll(ingest(p, FileOrigin.IMPORTED, null))
                }
                val added = files.value.size - before
                model.message.value = tr(Res.string.msg_saved_files, added) + if (added < stored.size) tr(Res.string.msg_saved_before, stored.size - added) else ""
                if (proposeBundles(stored)) return@run
                model.showTab(HomeTab.FILES)
            }
        }
    }

    /**
     * Stores one incoming file without opening anything: a MyData ZIP and a ZIP of official document files are
     * unpacked at once (their files replace the archive). Returns the files that now stand for it.
     */
    private suspend fun ingest(picked: PickedFile, origin: FileOrigin, source: String?): List<StoredFile> {
        val item = MyDataFiles.recognize(picked.name)
        val f = store(picked.name, picked.bytes, origin, if (item != null) MyDataFiles.label(item, byName = true) else source)
        return when {
            f.report?.format != DocumentFormat.ZIP -> listOf(annotatePeriod(f))
            item != null -> extractNow(f).first
            hasExchangeFiles(f) -> extractNow(f, unpackOfficial = true).first
            else -> listOf(f)
        }
    }

    /**
     * Reads a travel document chip on [reader] with [secret] (the zone's access key or the card access number) and
     * stores what it read as a file; passive authentication runs as for any file, and the file screen opens.
     */
    fun readPassport(reader: NfcReaderOption, secret: diw.wallet.core.document.mrtd.AccessSecret) = run(tr(Res.string.mrtd_stage_access)) {
        val dump = Passports.read(reader, secret) { busy.value = it }
        busy.value = tr(Res.string.step_read_check)
        val f = store(Passports.fileName(dump), dump.encode(), FileOrigin.CHIP, tr(Res.string.mrtd_source))
        model.message.value = tr(Res.string.msg_saved_name, f.name)
        model.screen.value = Screen.FileDetail(f.id)
    }

    /** A file handed over by another app or downloaded from a source site. */
    fun import(picked: PickedFile, origin: FileOrigin, source: String?) = run(tr(Res.string.step_read_check)) { importNow(picked, origin, source) }

    private suspend fun importNow(picked: PickedFile, origin: FileOrigin, source: String?) = receive(picked, origin, source, null)

    /**
     * Stores a file that came in (picked, shared by another app, or downloaded from [site]) and carries on with it:
     * a MyData ZIP, whether downloaded here or recognised by its file name, is unpacked at once; the national ID PDF
     * opens the national ID card screen; anything else opens its detail screen. The recorded source is short
     * ("MyData・現戶全戶戶籍資料") and marked when only the file name says the file is from MyData. A MyData ZIP is
     * removed once its files are stored, as Bonds does.
     */
    private suspend fun receive(picked: PickedFile, origin: FileOrigin, source: String?, site: DocumentSource?) {
        val known = files.value.size
        val item = MyDataFiles.recognize(picked.name)
        val myData = site?.myData == true || item != null
        val label = when {
            site?.myData == true -> MyDataFiles.label(item ?: myDataItemOf(site), byName = false)
            site != null -> site.name
            item != null -> MyDataFiles.label(item, byName = true)
            else -> source
        }
        val f = store(picked.name, picked.bytes, origin, label)
        val children = when {
            f.report?.format != DocumentFormat.ZIP -> emptyList()
            myData -> {
                busy.value = tr(Res.string.step_extract_mydata)
                extractNow(f).first
            }
            hasExchangeFiles(f) -> {
                busy.value = tr(Res.string.step_extract_official)
                extractNow(f, unpackOfficial = true).first
            }
            else -> emptyList()
        }
        if (children.isEmpty()) annotatePeriod(f)
        val pdfs = children.ifEmpty { listOf(f) }.filter { it.report?.format == DocumentFormat.PDF }
        val nationalId = site?.nationalId == true || item?.nationalId == true || pdfs.any { MyDataFiles.recognize(it.name)?.nationalId == true }
        if (nationalId && pdfs.isNotEmpty()) {
            val pdf = pdfs.firstOrNull { MyDataFiles.recognize(it.name)?.nationalId == true } ?: pdfs.first()
            model.message.value = if (unlock(pdf, data(pdf.id), null) != null) tr(Res.string.msg_mydata_confirm_id) else tr(Res.string.msg_mydata_enter_id)
            model.screen.value = Screen.NationalIdCreate(pdf.id)
            return
        }
        model.message.value = null
        if (proposeBundles(children.ifEmpty { listOf(f) })) {
            if (children.isNotEmpty()) model.message.value = tr(Res.string.msg_extracted_n, children.size) + (model.message.value ?: tr(Res.string.msg_confirm_container))
            return
        }
        val target = when {
            children.size == 1 -> children.first()
            pdfs.size == 1 && children.isNotEmpty() -> pdfs.first()
            else -> f
        }
        model.message.value = when {
            children.isNotEmpty() && myData -> tr(Res.string.msg_extracted_mydata, children.size)
            children.isNotEmpty() -> tr(Res.string.msg_extracted_files, children.size)
            files.value.size == known -> tr(Res.string.msg_already_saved)
            else -> tr(Res.string.msg_saved_name, f.name)
        }
        model.screen.value = Screen.FileDetail(target.id)
    }

    /** Checks the file again with the current time and trust anchors and stores the new report. */
    suspend fun refreshed(f: StoredFile): StoredFile {
        val data = data(f.id)
        val report = DocumentInspector.inspect(data, f.name, trustSource, f.contentId?.let { data(it) }, related = relatedFor(data))
        // Apply the report to the latest copy so changes made meanwhile (a new time stamp) are kept; the time stamps
        // are checked again too, since the trusted authorities may have changed.
        val latest = file(f.id) ?: f
        val stamps = latest.timestamps.map { t ->
            runCatching { t.copy(trusted = DocumentInspector.verifyTimestamp(t.token.fromBase64(), data, trustSource).trusted) }.getOrDefault(t)
        }
        // The online check of an OpenCerts certificate is not part of the inspection; it stays until checked again.
        val online = latest.report?.openCert?.online
        val kept = report.openCert?.takeIf { online != null }?.let { report.copy(openCert = it.copy(online = online)) } ?: report
        return latest.copy(report = kept, timestamps = stamps).also { save(it) }
    }

    /** Re-checks a file when it is opened; the stored report stays if the check cannot run. */
    fun refresh(id: String) = model.scope.launch {
        val f = file(id) ?: return@launch
        try {
            val r = refreshed(f)
            if (r.report?.openCert != null) verifyOpenCertNow(r, force = false)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
        }
    }

    /**
     * ID numbers the holder's MyData PDFs open with, as Bonds asks for them: those on the holder's national ID cards
     * and the one saved for MyData sign-in, when the holder saved it.
     */
    private fun knownPasswords(): List<String> =
        (nationalIdCards().mapNotNull { (_, c) -> runCatching { TaiwanModel.nationalIdClaims(c).toMap()["unifiedNo"] }.getOrNull() } +
            listOfNotNull(savedMyDataId())).distinct()

    /** Open passwords of PDFs entered in this session, by file id; never stored. */
    private val passwords = HashMap<String, String>()
    val previews = MutableStateFlow<Map<String, FilePreview>>(emptyMap())

    /** The PDF opened with the password entered for it in this session (or none). */
    fun openPdf(f: StoredFile, bytes: ByteArray): PdfFile = PdfFile(bytes, passwords[f.id] ?: "")

    /**
     * Makes the preview of [f]: PDF pages (an encrypted PDF is decrypted in memory with [password], also tried
     * trimmed and in upper case, as MyData's ID number passwords are), images, and the text of text formats.
     */
    fun preview(f: StoredFile, password: String? = null) = model.scope.launch {
        previews.value = previews.value + (f.id to FilePreview.Loading)
        val result = try {
            withContext(Dispatchers.Default) { makePreview(f, password) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            FilePreview.Unavailable(tr(Res.string.msg_no_preview) + model.describe(e))
        }
        previews.value = previews.value + (f.id to result)
        (result as? FilePreview.Pages)?.text?.let { text -> runCatching { annotatePeriod(file(f.id) ?: f, text) } }
    }

    /**
     * [bytes] of the PDF [f] opened with [password] (also trimmed and in upper case), the password entered earlier in
     * this session, or none; null while it stays locked. A password that opens it is kept for this session.
     */
    private fun unlock(f: StoredFile, bytes: ByteArray, password: String?): PdfFile? {
        val tries = (listOfNotNull(password, password?.let { BondsNationalId.normalizePassword(it) }, passwords[f.id], "") + knownPasswords()).distinct()
        for (pw in tries) {
            val p = PdfFile(bytes, pw)
            if (!p.passwordRequired) {
                if (pw.isNotEmpty()) passwords[f.id] = pw
                return p
            }
        }
        return null
    }

    /**
     * The text of [f] for reading values out of it (a check number to fill in): a PDF's text layer when it opens
     * without asking (no password, or one already known), or a text or XML file. Null for anything else.
     */
    suspend fun documentText(f: StoredFile): String? = withContext(Dispatchers.Default) {
        when (f.report?.format) {
            DocumentFormat.PDF -> unlock(f, data(f.id), null)?.takeIf { it.encryptionProblem == null }?.let { pdf ->
                runCatching { PdfTextExtractor.extract(pdf, FilePreview.PREVIEW_PAGES) }.getOrNull()
            }
            DocumentFormat.TEXT, DocumentFormat.XML -> data(f.id).takeIf { it.size <= FilePreview.TEXT_LIMIT * 4 }?.decodeToString()
            else -> null
        }?.takeIf { it.isNotBlank() }
    }

    /** The first page of a PDF (opened with the session password) or the image of [f], for card art; null otherwise. */
    suspend fun firstPage(f: StoredFile): ImageBitmap? = withContext(Dispatchers.Default) {
        val bytes = data(f.id)
        when (f.report?.format) {
            DocumentFormat.PDF -> unlock(f, bytes, null)?.let { pdf ->
                if (pdf.encryptionProblem != null) null
                else model.platform.renderPdf(if (pdf.encrypted) PdfPlain.of(pdf) else bytes, 1, CardArtSpec.WIDTH).firstOrNull()
            }
            DocumentFormat.IMAGE -> model.platform.decodeImage(bytes)
            else -> null
        }
    }

    /** Claims a derived credential of [f] can carry, and whether the PDF's content stays locked without its password. */
    class DeriveFields(
        val claims: List<DerivedClaim>,
        val locked: Boolean,
        val notice: String? = null,
        /** The entry and exit record the PDF holds (Taiwan or mainland China), for claims about a day the holder picks. */
        val entryExit: MovementRecord? = null,
        /** zkPDF templates that fit the PDF, each with at least one field it can prove. */
        val zkPdf: List<ZkPdfMatch> = emptyList(),
    )

    /** A zkPDF template that fits a PDF: the values it can prove (read from page 1) and the fields it cannot, with why. */
    class ZkPdfMatch(val profile: ZkPdfProfile, val fields: List<DerivedClaim>, val unavailable: List<Pair<String, String>>)

    /**
     * A zkPDF proof to add to a derived credential: the template, the date conditions (at most two), the circuit
     * composition, and [extended] when the user chose to prove here against the device advice (longer time limit).
     * [selfHosted] proves on the self-hosted prover of the settings instead, in the largest composition it offers
     * that this device can verify.
     */
    class ZkPdfChoice(
        val profileId: String,
        val predicates: List<ZkPdfPredicate>,
        val composition: String,
        val extended: Boolean,
        val selfHosted: Boolean = false,
    )

    /** The templates that fit [pdf] (unencrypted, or encrypted with an empty open password; one document signature). */
    private fun zkPdfMatches(pdf: ByteArray): List<ZkPdfMatch> = ZkPdfProfiles.available(model.settings.testEnvironment).mapNotNull { profile ->
        val plan = try { ZkPdfPlanner.plan(pdf, profile) } catch (_: PdfException) { return@mapNotNull null }
        if (plan.slots.isEmpty()) return@mapNotNull null
        ZkPdfMatch(
            profile,
            plan.slots.map { DerivedClaim(it.claim, it.value, profile.field(it.claim)?.label) },
            plan.unavailable.map { (claim, why) -> (profile.field(claim)?.label ?: claim) to why },
        )
    }

    /**
     * The claims of a derived credential of [f], read from the document rather than typed: its report, its source,
     * the text layer of a PDF (opened with [password] when it is encrypted), an official letter or OpenCerts data.
     */
    suspend fun deriveFields(f: StoredFile, password: String? = null): DeriveFields = withContext(Dispatchers.Default) {
        val report = f.report ?: return@withContext DeriveFields(emptyList(), false)
        val bytes = data(f.id)
        var locked = false
        var text: String? = null
        var xml: String? = null
        when (report.format) {
            DocumentFormat.PDF -> {
                val pdf = unlock(f, bytes, password)
                if (pdf == null) locked = true
                else text = runCatching { PdfTextExtractor.extract(pdf, FilePreview.PREVIEW_PAGES) }.getOrNull()?.takeIf { it.isNotBlank() }
            }
            DocumentFormat.XML -> xml = bytes.decodeToString().removePrefix("\uFEFF").takeIf { OfficialDocuments.parse(bytes) != null }
            else -> {}
        }
        val suggested = DerivedCredentials.suggested(report, f.name, f.source, text, xml, holderHints())
        val zk = if (report.format == DocumentFormat.PDF) zkPdfMatches(bytes) else emptyList()
        DeriveFields(suggested.claims, locked, suggested.notice, text?.let { MovementRecord.parse(it) }, zk)
    }

    private suspend fun makePreview(f: StoredFile, password: String?): FilePreview {
        val bytes = data(f.id)
        return when (f.report?.format) {
            DocumentFormat.PDF -> {
                val pdf = unlock(f, bytes, password) ?: return FilePreview.NeedsPassword(wrong = password != null)
                pdf.encryptionProblem?.let { return FilePreview.Unavailable(tr(Res.string.msg_pdf_decrypt_failed, it)) }
                val plain = if (pdf.encrypted) PdfPlain.of(pdf) else bytes
                val pages = model.platform.renderPdf(plain, FilePreview.PREVIEW_PAGES, PREVIEW_WIDTH)
                val text = runCatching { PdfTextExtractor.extract(pdf, FilePreview.PREVIEW_PAGES) }.getOrNull()?.trim()?.ifEmpty { null }
                val total = runCatching { PdfTextExtractor.pages(pdf).size }.getOrDefault(pages.size)
                if (pages.isEmpty() && text == null) FilePreview.Unavailable(tr(Res.string.msg_pdf_no_render))
                else FilePreview.Pages(
                    pages, total, text, text?.let { MovementRecord.parse(it) },
                    text?.let { runCatching { HouseholdTranscripts.parse(it, holderHints()) }.getOrNull() },
                    text?.let { runCatching { ParsedCertificate.parse(it) }.getOrNull() },
                )
            }
            DocumentFormat.IMAGE -> when (val kind = ImageKind.of(bytes)) {
                // A TIFF can hold several pages (official document page images); each is shown like a PDF page.
                ImageKind.TIFF -> {
                    val pages = ImageConversion.tiffPages(bytes, FilePreview.PREVIEW_PAGES, PREVIEW_WIDTH).mapNotNull { model.platform.decodeImage(it) }
                    if (pages.isEmpty()) FilePreview.Unavailable(tr(Res.string.msg_tiff_unreadable))
                    else FilePreview.Pages(pages, TiffDecoder.pageCount(bytes), null)
                }
                else -> model.platform.decodeImage(bytes)?.let { FilePreview.Picture(it) }
                    ?: FilePreview.Unavailable(tr(Res.string.msg_image_no_render, kind?.title?.let { " $it " } ?: " "))
            }
            DocumentFormat.XML -> {
                val text = bytes.decodeToString().removePrefix("\uFEFF")
                val official = OfficialDocuments.parse(bytes)
                if (official != null) FilePreview.Official(official, text.take(FilePreview.TEXT_LIMIT), text.length > FilePreview.TEXT_LIMIT)
                else FilePreview.Text(text.take(FilePreview.TEXT_LIMIT), text.length > FilePreview.TEXT_LIMIT)
            }
            DocumentFormat.JSON, DocumentFormat.TEXT, DocumentFormat.OPENCERTS -> {
                val text = bytes.decodeToString()
                FilePreview.Text(text.take(FilePreview.TEXT_LIMIT), text.length > FilePreview.TEXT_LIMIT)
            }
            DocumentFormat.OPENPGP -> {
                val pgp = f.report?.openPgp
                val clear = pgp?.clearText
                when {
                    clear != null -> FilePreview.Text(clear.take(FilePreview.TEXT_LIMIT), clear.length > FilePreview.TEXT_LIMIT)
                    pgp?.kind == OpenPgpKind.ENCRYPTED -> FilePreview.Unavailable(tr(Res.string.msg_pgp_encrypted))
                    pgp?.kind == OpenPgpKind.SIGNED_MESSAGE || pgp?.kind == OpenPgpKind.LITERAL ->
                        FilePreview.Unavailable(tr(Res.string.msg_pgp_wrapped))
                    else -> FilePreview.Unavailable(tr(Res.string.msg_pgp_no_preview))
                }
            }
            DocumentFormat.EMRTD -> diw.wallet.core.document.mrtd.MrtdDump.decode(bytes)
                ?.let { FilePreview.Passport(Passports.view(it) { b -> model.platform.decodeImage(b) }) }
                ?: FilePreview.Unavailable(tr(Res.string.core_mrtd_unreadable))
            DocumentFormat.ZIP, DocumentFormat.ASIC_E, DocumentFormat.OFD -> FilePreview.Unavailable(tr(Res.string.msg_archive_preview))
            DocumentFormat.OFFICE -> FilePreview.Unavailable(tr(Res.string.msg_office_preview))
            DocumentFormat.CMS_ENVELOPED -> FilePreview.Unavailable(tr(Res.string.msg_envelope_preview))
            else -> {
                // A signature with its content inside (.p7m) previews the content when it is a known kind.
                val inner = runCatching { DocumentInspector.encapsulatedContent(bytes) }.getOrNull()
                when {
                    inner != null && PdfFile.isPdf(inner) -> model.platform.renderPdf(inner, FilePreview.PREVIEW_PAGES, PREVIEW_WIDTH)
                        .takeIf { it.isNotEmpty() }?.let { FilePreview.Pages(it, it.size, null) } ?: FilePreview.Unavailable(tr(Res.string.msg_wrapped_pdf))
                    inner != null && runCatching { inner.decodeToString(throwOnInvalidSequence = true) }.isSuccess ->
                        inner.decodeToString().let { FilePreview.Text(it.take(FilePreview.TEXT_LIMIT), it.length > FilePreview.TEXT_LIMIT) }
                    else -> FilePreview.Unavailable(tr(Res.string.msg_no_format_preview))
                }
            }
        }
    }

    /** Checks the file again with the current trust anchors. */
    fun reinspect(f: StoredFile) = run(tr(Res.string.step_recheck)) { refreshed(f) }

    /** Pairs a detached signature (.p7s) with the file it signs and checks it again. */
    fun attachContent(signature: StoredFile, content: StoredFile) = run(tr(Res.string.step_check_detached)) {
        val report = DocumentInspector.inspect(data(signature.id), signature.name, trustSource, data(content.id))
        save(signature.copy(report = report, contentId = content.id))
    }

    /** Stores every file of a ZIP archive as its own entry; a MyData archive is removed afterwards. */
    fun extract(f: StoredFile) = run(tr(Res.string.step_extract)) {
        val (stored, added) = extractNow(f)
        model.message.value = tr(Res.string.msg_extracted_files, added)
        if (file(f.id) == null) {
            val only = stored.singleOrNull()
            if (only != null) model.screen.value = Screen.FileDetail(only.id) else model.showTab(HomeTab.FILES)
        }
    }

    /**
     * Opens one file of a container (ASiC-E, OFD or ZIP) on its own: it is stored as a file taken from [f], which
     * keeps the container and its signatures as they are, and its detail screen opens.
     */
    fun openEntry(f: StoredFile, entry: String) = run(tr(Res.string.step_open_member)) {
        val files = DocumentSigning.unzip(data(f.id))
        val bytes = files[entry] ?: files.entries.firstOrNull { it.key.endsWith("/$entry") }?.value
            ?: throw SigningException(tr(Res.string.msg_member_missing, entry))
        val name = OfficialBundles.decodeZipName(entry.substringAfterLast('/'))
        val stored = store(name, bytes, FileOrigin.EXTRACTED, f.source ?: f.name, parentId = f.id, archive = f.name)
        model.screen.value = Screen.FileDetail(stored.id)
    }

    // ---------------------------------------------------------------- official document containers

    /** True when the ZIP [f] holds files of the official document exchange (.di, .sw, .si, .dm, .co). */
    private suspend fun hasExchangeFiles(f: StoredFile): Boolean = runCatching {
        DocumentSigning.unzip(data(f.id)).keys.any { OfficialBundles.isExchangeFile(OfficialBundles.decodeZipName(it)) }
    }.getOrDefault(false)

    private val mains = HashMap<String, Boolean>()

    /** True when [f] is an official document that can hold related files. */
    suspend fun isOfficialMain(f: StoredFile): Boolean = mains[f.id] ?: run {
        f.report?.format == DocumentFormat.XML && runCatching { OfficialBundles.isMain(f.name, data(f.id)) }.getOrDefault(false)
    }.also { mains[f.id] = it }

    /** The files in the container of the official document [main], its own and those [inherited] from what it was signed from. */
    fun members(main: StoredFile): List<StoredFile> = (files.value.filter { it.bundleOf == main.id } + inherited(main)).sortedBy { it.name }

    /**
     * A signed official document keeps the container of the document it was signed from: those members still count,
     * except the ones it holds a signed copy of. The original keeps its own container unchanged.
     */
    fun inherited(main: StoredFile, depth: Int = 0): List<StoredFile> {
        if (main.origin != FileOrigin.SIGNED || depth > 8) return emptyList()
        val parent = main.parentId?.let { file(it) }?.takeIf { it.id != main.id } ?: return emptyList()
        val own = files.value.filter { it.bundleOf == main.id }
        return (files.value.filter { it.bundleOf == parent.id } + inherited(parent, depth + 1))
            .filter { m -> own.none { it.parentId == m.id } }
    }

    /**
     * The files an online approval file (.si) in [bytes] signed, found in the vault by name or by content (its
     * SHA-256): for each name, the stored file with a digest the approval lists, else the latest one of that name.
     * Empty for any other file.
     */
    suspend fun relatedFor(bytes: ByteArray): Map<String, ByteArray> {
        val refs = runCatching { OfficialBundles.approvalReferences(bytes) }.getOrDefault(emptyList())
        if (refs.isEmpty()) return emptyMap()
        val out = HashMap<String, ByteArray>()
        for ((uri, group) in refs.groupBy { it.uri }) {
            val hashes = group.filter { it.algorithm == "SHA-256" }.map { DocCryptoUtil.hex(it.digest) }.toSet()
            val candidates = files.value.filter { it.name == uri || it.sha256 in hashes }.sortedByDescending { it.sha256 in hashes }
            var chosen: ByteArray? = null
            for (c in candidates) {
                val d = runCatching { data(c.id) }.getOrNull() ?: continue
                if (group.any { it.matches(d) }) { chosen = d; break }
                if (chosen == null && c.name == uri) chosen = d
            }
            chosen?.let { out[uri] = it }
        }
        return out
    }

    /** True when [f] is an online approval file (線上簽核, .si). */
    fun isApproval(f: StoredFile): Boolean = f.report?.format == DocumentFormat.XML &&
        (f.name.endsWith(".si", ignoreCase = true) || f.report.notes.any { n -> OFFICIAL_NOTES.any { n.startsWith(it) } && "線上簽核" in n })

    /** The start of the core note on an official document, in the app language and in Chinese (reports saved before). */
    private val OFFICIAL_NOTES: List<String>
        get() = listOf(CoreText.prefix("core_official_note"), CoreText.chinese("core_official_note").substringBefore("（"))

    /** True when [f] is a file of the official document exchange (公文, .sw, .si...), signed with an approval point. */
    fun isOfficialFile(f: StoredFile): Boolean = f.report?.format == DocumentFormat.XML &&
        (OfficialBundles.isExchangeFile(f.name) || f.report.notes.any { n -> OFFICIAL_NOTES.any { n.startsWith(it) } })

    /** What an approval point on [f] covers: the approval it is added to (null for a new one) and the case files. */
    class ApprovalCase(val main: StoredFile?, val approval: StoredFile?, val files: List<StoredFile>, val missing: List<String>)

    /**
     * The case of [f]: an official document (or a file in its container) takes the document and every file of its
     * container except the approval files, and the latest approval file in it; an approval file on its own takes
     * the files it names, found in the vault.
     */
    suspend fun approvalCase(f: StoredFile): ApprovalCase {
        val main = f.bundleOf?.let { file(it) } ?: f.takeIf { !isApproval(it) }
        if (main != null) {
            val members = members(main)
            val approvals = members.filter { isApproval(it) } + listOfNotNull(f.takeIf { isApproval(it) && it.bundleOf == main.id })
            val approval = approvals.distinctBy { it.id }.maxByOrNull { it.addedAt }
            return ApprovalCase(main, approval, listOf(main) + members.filter { !isApproval(it) }, emptyList())
        }
        val refs = OfficialBundles.approvalReferences(data(f.id)).map { it.uri }.distinct()
        val related = relatedFor(data(f.id))
        val found = refs.mapNotNull { uri -> files.value.firstOrNull { it.name == uri && related[uri]?.let { b -> DocCryptoUtil.hex(DocCrypto.digest("SHA-256", b)) } == it.sha256 } ?: files.value.firstOrNull { it.name == uri } }
        return ApprovalCase(null, f, found, refs.filter { r -> found.none { it.name == r } })
    }

    /**
     * One signing point of a container's online approval: the files it signed first ([files]), the ones an earlier
     * point already signed and this one signed again unchanged ([repeated]), names whose stored content differs
     * from what it signed ([changed]) and names not in the container ([missing]).
     */
    class ContainerPoint(
        val index: Int,
        val signer: String?,
        val action: String?,
        val time: Long?,
        val signature: diw.wallet.core.document.SignatureInfo?,
        val files: List<StoredFile>,
        val repeated: List<StoredFile>,
        val changed: List<String>,
        val missing: List<String>,
    ) {
        val title: String get() = tr(Res.string.approval_point_n, index + 1) + (signer?.let { tr(Res.string.colon_value, it) } ?: "") + (action?.let { tr(Res.string.parenthesized, it) } ?: "")
    }

    /** A container laid out by the signing points of its online approval [approval]; [others] are files it does not list. */
    class ContainerLayout(val approval: StoredFile, val points: List<ContainerPoint>, val others: List<StoredFile>) {
        val missing: Int get() = points.flatMap { it.missing }.distinct().size
        val changed: Int get() = points.flatMap { it.changed }.distinct().size
    }

    /**
     * The container of [main] in two levels, by the signing points of the approval file in it with the most points:
     * each file goes under the first point whose signature covers its content. Null when the container holds no
     * online approval listing files.
     */
    suspend fun containerLayout(main: StoredFile): ContainerLayout? = withContext(Dispatchers.Default) {
        val all = (listOf(main) + members(main)).distinctBy { it.id }
        val approvals = all.filter { isApproval(it) }
        val parsed = approvals.mapNotNull { a ->
            runCatching { OfficialBundles.approvalPoints(data(a.id)) }.getOrNull()?.takeIf { p -> p.any { it.references.isNotEmpty() } }?.let { a to it }
        }
        val (approval, points) = parsed.maxWithOrNull(compareBy({ it.second.size }, { it.first.addedAt })) ?: return@withContext null
        val content = all.filter { !isApproval(it) }
        val cache = HashMap<String, ByteArray>()
        suspend fun covers(f: StoredFile, refs: List<diw.wallet.core.document.official.ApprovalReference>): Boolean = refs.any { r ->
            if (r.algorithm == "SHA-256") DocCryptoUtil.hex(r.digest) == f.sha256
            else r.matches(cache.getOrPut(f.id) { runCatching { data(f.id) }.getOrDefault(ByteArray(0)) })
        }
        val placed = HashSet<String>()
        // The approval's check lists one signature per signed point, in order.
        var signedBefore = 0
        val out = points.map { p ->
            val first = ArrayList<StoredFile>()
            val again = ArrayList<StoredFile>()
            val changed = ArrayList<String>()
            val missing = ArrayList<String>()
            for (name in p.names) {
                val refs = p.references.filter { it.uri == name }
                val match = content.filter { covers(it, refs) }.let { m -> m.firstOrNull { it.name == name } ?: m.firstOrNull() }
                when {
                    match != null -> if (placed.add(match.id)) first.add(match) else again.add(match)
                    content.any { it.name == name } -> changed.add(name)
                    else -> missing.add(name)
                }
            }
            ContainerPoint(
                index = p.index, signer = p.signer, action = p.action,
                time = ApprovalPoint.parseRocTime(p.time)?.epochSeconds,
                signature = if (p.signed) approval.report?.signatures?.getOrNull(signedBefore++) else null,
                files = first, repeated = again, changed = changed, missing = missing,
            )
        }
        ContainerLayout(approval, out, content.filter { it.id !in placed } + approvals.filter { it.id != approval.id })
    }

    /** Re-checks the approval files in the container of [main] (after files joined it). */
    private suspend fun recheckApprovals(main: StoredFile) {
        members(main).filter { isApproval(it) }.forEach { runCatching { refreshed(it) } }
    }

    /**
     * After files came in together: when an official document is among them, opens the confirmation of which of the
     * other files go into its container. False when there is nothing to confirm.
     */
    private suspend fun proposeBundles(stored: List<StoredFile>): Boolean {
        val incoming = stored.distinctBy { it.id }
        // An online approval that came in decides the container first: the files it signed join it at once.
        placeByApproval(incoming)?.let { (main, placed) ->
            val left = incoming.filter { it.id != main.id && it.id !in placed && file(it.id)?.bundleOf == null && it.nationalId == null }
            recheckApprovals(main)
            if (left.isEmpty()) {
                model.message.value = tr(Res.string.msg_container_made, placed.size)
                model.screen.value = Screen.FileDetail(main.id)
            } else {
                model.message.value = tr(Res.string.msg_container_partial, placed.size, left.size)
                model.screen.value = Screen.OfficialBundle(main.id, left.map { it.id }, emptyList())
            }
            return true
        }
        // Files saved earlier that an online approval ties to these: an approval that came in brings the files it
        // names, and an approval saved earlier that names a file that came in joins with its files.
        val pool = files.value.filter { it.bundleOf == null && it.nationalId == null && incoming.none { s -> s.id == it.id } }
        val incomingApprovals = approvalsAmong(incoming)
        val savedApprovals = approvalsAmong(pool.filter { isApproval(it) }).filter { a -> incoming.any { a.lists(it.name, data(it.id)) == true } }
        val linked = (incomingApprovals + savedApprovals).let { approvals ->
            val names = approvals.flatMap { it.names }.toSet()
            pool.filter { p ->
                (isApproval(p) && savedApprovals.any { it.name == p.name }) ||
                    (p.name in names && approvals.any { it.lists(p.name, data(p.id)) == true })
            }
        }
        val distinct = incoming + linked
        val docs = distinct.filter { it.bundleOf == null && isOfficialMain(it) }
        val others = distinct.filter { it.bundleOf == null && it !in docs }
        if (docs.isEmpty() && others.isNotEmpty()) {
            // The approval names files already in a container: offer the new files to that container.
            val home = incomingApprovals.firstNotNullOfOrNull { a ->
                files.value.firstOrNull { m -> m.bundleOf != null && m.name in a.names && a.lists(m.name, data(m.id)) == true }?.bundleOf?.let { file(it) }
            } ?: return false
            model.screen.value = Screen.OfficialBundle(home.id, others.map { it.id }, emptyList())
            return true
        }
        if (docs.isEmpty() || others.isEmpty()) return false
        // An online approval that signed several documents (a case's incoming letter, drafts and their versions) puts
        // them in one container: the first document it lists holds it, the others are offered as its members.
        val approvals = incomingApprovals + savedApprovals
        val approved = approvals.flatMap { a ->
            a.names.mapNotNull { n -> docs.firstOrNull { it.name == n && a.lists(it.name, data(it.id)) == true } }
        }.distinctBy { it.id }
        val main = approved.firstOrNull { d -> files.value.any { it.bundleOf == d.id } } ?: approved.firstOrNull() ?: docs.first()
        val grouped = approved.filter { it != main }
        val rest = docs.filter { it != main && it !in grouped }
        model.screen.value = Screen.OfficialBundle(main.id, (grouped + others).map { it.id }, rest.map { it.id })
        return true
    }

    /**
     * Builds a container from the online approval among [incoming] that lists the most files: the official document
     * it lists first (with the content it signed) holds the container, and the approval and every other file it signed
     * (by name and digest, among the files that came in and those saved outside a container) join it without asking,
     * since the approval's signatures name them. Returns the document and the ids placed; null when no approval lists
     * an official document that is here.
     */
    private suspend fun placeByApproval(incoming: List<StoredFile>): Pair<StoredFile, Set<String>>? {
        val approvals = incoming.filter { isApproval(it) && it.bundleOf == null }.mapNotNull { f ->
            runCatching { ApprovalFile.of(f.name, data(f.id)) }.getOrNull()?.let { f to it }
        }
        if (approvals.isEmpty()) return null
        val (siFile, si) = approvals.maxBy { it.second.references.size }
        val pool = (incoming + files.value.filter { it.bundleOf == null && it.nationalId == null }).distinctBy { it.id }.filter { it.id != siFile.id }
        val found = LinkedHashMap<String, StoredFile>()
        for (name in si.names) {
            val refs = si.references.filter { it.uri == name }
            val hit = pool.filter { c ->
                refs.any { r -> if (r.algorithm == "SHA-256") DocCryptoUtil.hex(r.digest) == c.sha256 else r.matches(data(c.id)) }
            }.let { m -> m.firstOrNull { it.name == name && it in incoming } ?: m.firstOrNull { it.name == name } ?: m.firstOrNull() }
            if (hit != null && found.values.none { it.id == hit.id }) found[name] = hit
        }
        // A document already holding a container keeps it; otherwise the first official document the approval lists.
        val docs = found.values.filter { isOfficialMain(it) }
        val main = docs.firstOrNull { d -> files.value.any { it.bundleOf == d.id } } ?: docs.firstOrNull() ?: return null
        val placed = LinkedHashSet<String>()
        for (f in found.values + siFile) {
            if (f.id == main.id) continue
            val latest = file(f.id) ?: continue
            if (latest.bundleOf != null) continue
            save(latest.copy(bundleOf = main.id))
            placed.add(f.id)
        }
        return main to placed
    }

    /** The online approval files (.si) among [files], with the files their signatures cover. */
    private suspend fun approvalsAmong(files: List<StoredFile>): List<ApprovalFile> = files.mapNotNull { f ->
        if (f.report?.format != DocumentFormat.XML) null else runCatching { ApprovalFile.of(f.name, data(f.id)) }.getOrNull()
    }

    /** A file that may go into the container of [main], with the hints for and against it. */
    class BundleCandidate(val file: StoredFile, val match: BundleMatch)

    /**
     * Files that may go into the container of [main]: [only] when given (files that just came in), else every file
     * outside a container that is not an official document itself. Suggested files come first.
     */
    suspend fun bundleCandidates(main: StoredFile, only: List<String>?): List<BundleCandidate> = withContext(Dispatchers.Default) {
        val mainBytes = data(main.id)
        val pool = (only?.mapNotNull { file(it) } ?: files.value).filter { it.id != main.id && it.bundleOf == null && it.nationalId == null }
        // Approvals that came with the files or are already in the container.
        val approvals = approvalsAmong(pool + members(main))
        pool.filter { !isOfficialMain(it) || only != null }.map { f ->
            val bytes = runCatching { data(f.id) }.getOrDefault(ByteArray(0))
            BundleCandidate(f, OfficialBundles.match(main.name, mainBytes, f.name, bytes, approvals))
        }.sortedWith(compareByDescending<BundleCandidate> { it.match.suggested }.thenByDescending { it.match.supported }.thenBy { it.file.name })
    }

    /**
     * Puts [ids] into the container of [main] after the holder confirmed them, then goes on with the next document
     * of the same import, if any.
     */
    fun confirmBundle(main: StoredFile, ids: Collection<String>, only: List<String>?, next: List<String>) = run(tr(Res.string.step_put_container)) {
        ids.mapNotNull { file(it) }.forEach { save(it.copy(bundleOf = main.id)) }
        if (ids.isNotEmpty()) model.message.value = tr(Res.string.msg_put_container, ids.size, main.name)
        recheckApprovals(main)
        val following = next.firstNotNullOfOrNull { file(it) }
        if (following != null) {
            val left = only?.filter { it !in ids && it != following.id && file(it)?.bundleOf == null }
            model.screen.value = Screen.OfficialBundle(following.id, left, next.drop(next.indexOf(following.id) + 1))
        } else {
            model.screen.value = Screen.FileDetail(main.id)
        }
    }

    /** Takes [member] out of its container; it is listed on its own again. */
    fun leaveBundle(member: StoredFile) = run(tr(Res.string.step_move_out)) {
        save(member.copy(bundleOf = null))
        model.message.value = tr(Res.string.msg_moved_out, member.name)
    }

    /** Picks related files from the device for the container of [main]; the holder confirms them next. */
    fun importIntoBundle(main: StoredFile) = run(tr(Res.string.step_read_check)) {
        val picked = model.platform.pickFiles()
        if (picked.isEmpty()) return@run
        val stored = ArrayList<StoredFile>()
        picked.forEachIndexed { i, p ->
            busy.value = tr(Res.string.step_read_check_n, i + 1, picked.size)
            stored.addAll(ingest(p, FileOrigin.IMPORTED, null))
        }
        model.screen.value = Screen.OfficialBundle(main.id, stored.filter { it.id != main.id }.map { it.id }.distinct(), emptyList())
    }

    // ---------------------------------------------------------------- periods

    /**
     * Reads the period a MyData file covers ("113 年度" for income records) and puts it in the file's name, so files
     * of several years stand apart; files it cannot read (still locked) are returned as they are.
     */
    private suspend fun annotatePeriod(f: StoredFile, known: String? = null): StoredFile {
        if (f.period != null || !MyDataFiles.isMyData(f.source)) return f
        val text = known ?: runCatching { sourceText(f) }.getOrNull() ?: return f
        val period = periodOf(text) ?: return f
        val dot = f.name.lastIndexOf('.')
        val name = if (period in f.name) f.name else if (dot > 0) f.name.substring(0, dot) + "（$period）" + f.name.substring(dot) else "${f.name}（$period）"
        return f.copy(period = period, name = name).also { save(it) }
    }

    private fun periodOf(text: String): String? {
        val t = MyDataText.halfWidth(text)
        Regex("所得年度\\s*:?\\s*(\\d{2,4})").find(t)?.let { return it.groupValues[1] + " 年度" }
        Regex("(?<!\\d)(\\d{2,3})\\s*年度").find(t)?.let { return it.groupValues[1] + " 年度" }
        return null
    }

    /** The MyData item a source site downloads, by its name; null for the generic sign-in page. */
    private fun myDataItemOf(site: DocumentSource): MyDataItem? =
        if (site.nationalId) MyDataFiles.recognize("idPhotoRev") else if (site.id == "mydata") null else MyDataFiles.recognize(site.url) ?: MyDataItem(site.name)

    /**
     * The files of the archive [f] as stored (new or already there), and how many were new. A file of a MyData
     * archive is named after its item (MyData's own file names are opaque numbers and may carry the holder's name)
     * and has the archive's short source; once every file is stored the MyData archive itself is removed, keeping
     * only its name on the files.
     */
    private suspend fun extractNow(f: StoredFile, unpackOfficial: Boolean = false): Pair<List<StoredFile>, Int> {
        val entries = DocumentSigning.unzip(data(f.id)).filter { it.value.isNotEmpty() && !it.key.endsWith("/") }
        val myData = MyDataFiles.isMyData(f.source) || MyDataFiles.recognize(f.name) != null
        val replaces = myData || unpackOfficial
        val byName = f.source?.endsWith(MyDataFiles.BY_NAME) == true
        val stored = ArrayList<StoredFile>()
        val used = HashMap<String, Int>()
        var added = 0
        for ((path, bytes) in entries) {
            val before = files.value.size
            val original = OfficialBundles.decodeZipName(path.substringAfterLast('/'))
            val own = MyDataFiles.recognize(original)
            val item = own ?: MyDataFiles.recognize(f.name) ?: f.source?.let { MyDataFiles.recognize(it) }
            val name = if (myData && own == null && item != null) {
                val ext = original.substringAfterLast('.', "").let { if (it.isEmpty()) "" else ".$it" }
                val n = (used[ext] ?: 0) + 1
                used[ext] = n
                item.title + (if (n > 1) "-$n" else "") + ext
            } else original
            val label = if (myData) MyDataFiles.label(item, byName) else f.source
            val s = store(name, bytes, FileOrigin.EXTRACTED, label, parentId = if (replaces) null else f.id, archive = f.name)
            stored.add(if (myData) annotatePeriod(s) else s)
            if (files.value.size > before) added++
        }
        if (replaces && stored.size == entries.size && stored.isNotEmpty()) remove(f)
        return stored to added
    }

    private suspend fun remove(f: StoredFile) {
        Blobs.delete(model.storage.getTable(dataTable), f.id)
        model.storage.getTable(metaTable).delete(f.id)
        files.value = files.value.filter { it.id != f.id }
        previews.value = previews.value - f.id
    }

    /** A download from a source site in the app. */
    fun importDownload(picked: PickedFile, src: DocumentSource) = run(tr(Res.string.step_save_download)) {
        receive(picked, FileOrigin.DOWNLOADED, src.name, src)
    }

    fun timestamper(): Timestamper = TsaClient(model.signedDataHttp, TsaServices.byId(model.settings.tsaId).url)

    /** Gets an RFC 3161 time stamp over the file from the chosen authority (only the hash is sent). */
    fun addTimestamp(f: StoredFile) = run(tr(Res.string.step_get_timestamp)) { addTimestampNow(f) }

    private suspend fun addTimestampNow(f: StoredFile) {
        val data = data(f.id)
        val token = timestamper().timestamp(data)
        val info = DocumentInspector.verifyTimestamp(token, data, trustSource)
        // The authority's revocation data is kept with the stamp, so it can be checked after its certificate expires.
        val validation = if (model.settings.timestampRevocation) timestampValidation(token) else null
        val stamp = StoredTimestamp(token.toBase64(), info.time, info.tsa, info.trusted, validation)
        save((file(f.id) ?: f).let { it.copy(timestamps = it.timestamps + stamp) })
        model.message.value = (if (info.trusted) tr(Res.string.msg_timestamped, info.tsa ?: tr(Res.string.tsa_fallback)) else tr(Res.string.msg_timestamped_untrusted)) +
            (validation?.let { tr(Res.string.sep_semicolon) + it.summary() } ?: "")
    }

    /** Revocation data of the authority of [token]; null when nothing could be fetched at all. */
    private suspend fun timestampValidation(token: ByteArray): ValidationData? = runCatching {
        DocumentSigning.timestampValidation(token, revocationFetch, trustSource.knownCertificates())
    }.getOrNull()

    /** Fetches OCSP responses, CRLs and issuer certificates for long-term signatures and time stamps. */
    val revocationFetch: HttpFetch by lazy { SignedDataFetch(model.signedDataHttp) }

    /** Fetches the authority's revocation data for a stamp made before it was kept, or again. */
    fun refreshTimestampValidation(f: StoredFile, index: Int) = run(tr(Res.string.step_tsa_revocation)) {
        val t = f.timestamps.getOrNull(index) ?: return@run
        val v = timestampValidation(t.token.fromBase64()) ?: throw SigningException(tr(Res.string.msg_no_revocation))
        val latest = file(f.id) ?: f
        save(latest.copy(timestamps = latest.timestamps.mapIndexed { i, s -> if (i == index) s.copy(validation = v) else s }))
        model.message.value = v.summary()
    }

    /** Removes the time stamp at [index] of [f] (a stamp made without revocation data can be replaced by a new one). */
    fun removeTimestamp(f: StoredFile, index: Int) = run(tr(Res.string.step_remove_timestamp)) {
        val latest = file(f.id) ?: return@run
        if (index !in latest.timestamps.indices) return@run
        save(latest.copy(timestamps = latest.timestamps.filterIndexed { i, _ -> i != index }))
        model.message.value = tr(Res.string.msg_timestamp_removed)
    }

    /**
     * Chains and revocation data of every signature in [f] (the signer's chain and its signature time stamp's), OCSP
     * first; null when the file has no signature with a certificate.
     */
    private suspend fun signatureValidationOf(f: StoredFile): ValidationData? {
        val sigs = f.report?.signatures.orEmpty()
        val known = trustSource.knownCertificates()
        var out: ValidationData? = null
        for (s in sigs) {
            val chains = listOf(s.chain, s.timestamp?.chain.orEmpty())
            for (c in chains) {
                val der = c.mapNotNull { runCatching { it.der.fromBase64() }.getOrNull() }
                if (der.isEmpty()) continue
                val v = DocumentSigning.collectValidation(der, revocationFetch, known)
                out = out?.plus(v) ?: v
            }
        }
        return out
    }

    /** Collects and stores the revocation data of the signatures in the file [id]; null when it has none. */
    private suspend fun storeSignatureValidation(id: String): ValidationData? {
        val f = file(id) ?: return null
        val v = signatureValidationOf(f) ?: return null
        patch(id) { it.copy(signatureValidation = v) } ?: return null
        return v
    }

    /** Fetches and keeps the revocation data of the signatures in [f] (OCSP first, else CRL). */
    fun collectSignatureValidation(f: StoredFile) = run(tr(Res.string.step_signature_revocation)) {
        val v = storeSignatureValidation(f.id) ?: throw SigningException(tr(Res.string.msg_no_revocable))
        model.message.value = v.summary()
    }

    /**
     * Fetches and keeps revocation data for every file in the container of [main] that has signatures, and for their
     * time stamps that were made without it.
     */
    fun collectContainerValidation(main: StoredFile) = run(tr(Res.string.files_container_revocation)) {
        val all = (listOf(main) + members(main)).distinctBy { it.id }
        var done = 0
        var bad = 0
        all.forEachIndexed { i, m ->
            busy.value = tr(Res.string.step_container_revocation_n, i + 1, all.size)
            storeSignatureValidation(m.id)?.let { done++; if (!it.allGood) bad++ }
            val latest = file(m.id) ?: return@forEachIndexed
            if (latest.timestamps.any { it.validation == null }) {
                val stamps = latest.timestamps.map { t -> if (t.validation != null) t else t.copy(validation = timestampValidation(t.token.fromBase64())) }
                save(latest.copy(timestamps = stamps))
            }
        }
        model.message.value = if (done == 0) tr(Res.string.msg_container_no_signed) else tr(Res.string.msg_container_revocation_done, done) + if (bad > 0) tr(Res.string.msg_container_revocation_bad, bad) else ""
    }

    // ---------------------------------------------------------------- OpenCerts

    /** What the OpenCerts certificate [f] shows; null when the file is not one. */
    suspend fun openCertView(f: StoredFile): OpenCertView? = withContext(Dispatchers.Default) {
        runCatching { OpenAttestationDocument.parse(data(f.id))?.view() }.getOrNull()
    }

    /** The page that shows [f] with the issuer's own renderer; null when the certificate has no https renderer. */
    suspend fun openCertRendererPage(f: StoredFile): String? = withContext(Dispatchers.Default) {
        runCatching { OpenAttestationDocument.parse(data(f.id))?.let { OpenCertRenderer.hostPage(it) } }.getOrNull()
    }

    /** The page that shows [f] without the network (built-in demo templates, or the wallet's own layout). */
    suspend fun openCertOfflinePage(f: StoredFile): OpenCertOffline.Page? = withContext(Dispatchers.Default) {
        runCatching { OpenAttestationDocument.parse(data(f.id))?.let { OpenCertOffline.page(it) } }.getOrNull()
    }

    /**
     * Checks online whether the issuer published the certificate [f] and has not revoked it, and whether the issuer's
     * identity holds. Without [force] a result younger than [OPENCERT_RECHECK_SECONDS] is kept. When nothing can be
     * queried (offline), the last meaningful result stays; the return value is false then.
     */
    suspend fun verifyOpenCertNow(f: StoredFile, force: Boolean): Boolean {
        val previous = (file(f.id) ?: f).report?.openCert?.online
        val now = Clock.System.now().epochSeconds
        if (!force && previous != null && now - previous.checkedAt < OPENCERT_RECHECK_SECONDS) return true
        val doc = OpenAttestationDocument.parse(data(f.id)) ?: return false
        val result = OpenAttestationOnline(model.http).verify(doc)
        val unreachable = result.issuance == Check.NOT_CHECKED && result.identity == Check.NOT_CHECKED
        val meaningful = previous != null && (previous.issuance != Check.NOT_CHECKED || previous.identity != Check.NOT_CHECKED)
        if (unreachable && meaningful) return false
        val current = file(f.id) ?: return false
        val report = current.report ?: return false
        val info = report.openCert ?: return false
        save(current.copy(report = report.copy(openCert = info.copy(online = result))))
        return !unreachable
    }

    fun recheckOpenCert(f: StoredFile) = run(tr(Res.string.step_oa_check)) {
        if (!verifyOpenCertNow(f, force = true)) model.message.value = tr(Res.string.msg_oa_offline)
    }

    /** Stores an attachment of the certificate [f] as its own file in the vault. */
    fun storeOpenCertAttachment(f: StoredFile, a: OaAttachment) = run(tr(Res.string.step_save_attachment)) {
        val known = files.value.size
        val stored = store(a.name, a.bytes, FileOrigin.EXTRACTED, source = tr(Res.string.oa_attachment_source), parentId = f.id, archive = f.name)
        model.message.value = if (files.value.size == known) tr(Res.string.msg_attachment_saved) else tr(Res.string.msg_saved_name, stored.name)
        model.screen.value = Screen.FileDetail(stored.id)
    }

    fun exportOpenCertAttachment(a: OaAttachment, share: Boolean = false) = run(if (share) tr(Res.string.step_share_attachment) else tr(Res.string.step_export_attachment)) {
        deliver(a.name, a.type ?: "application/octet-stream", a.bytes, share)
    }

    fun export(f: StoredFile, share: Boolean = false) = run(if (share) tr(Res.string.step_share_file) else tr(Res.string.step_export_file)) {
        deliver(f.name, f.mediaType, data(f.id), share)
    }

    /** Saves [bytes] through the platform save dialog, or hands them to another app when [share]. */
    private suspend fun deliver(name: String, mediaType: String, bytes: ByteArray, share: Boolean): Boolean {
        val done = if (share) model.platform.shareFile(name, mediaType, bytes) else model.platform.saveFile(name, mediaType, bytes)
        if (!done) model.message.value = if (share) tr(Res.string.msg_not_shared) else tr(Res.string.msg_not_exported)
        return done
    }

    /** True when [f] has something to export besides the file: time stamps or collected revocation data. */
    fun hasEvidence(f: StoredFile): Boolean = f.timestamps.isNotEmpty() || f.signatureValidation != null

    /** Exports [f] with its time stamps and revocation data as a ZIP, for checking elsewhere. */
    fun exportWithEvidence(f: StoredFile, share: Boolean = false) = run(if (share) tr(Res.string.files_share_evidence) else tr(Res.string.files_export_evidence)) {
        val entries = ArrayList<Pair<String, ByteArray>>()
        entries.add(f.name to data(f.id))
        entries.addAll(evidenceEntries(f, ""))
        entries.add(tr(Res.string.export_readme_name) to evidenceReadme(listOf(f), null).encodeToByteArray())
        val name = f.name.substringBeforeLast('.').ifBlank { f.name } + tr(Res.string.export_evidence_suffix)
        deliver(name, "application/zip", DocumentSigning.zip(entries), share)
    }

    /**
     * Exports the container of [main] as a ZIP: every file under its own name at the top (as the online approval
     * names them, so other systems can check it), their evidence under 證據/, and a list of the files by signing
     * point with what the wallet found.
     */
    fun exportContainer(main: StoredFile, share: Boolean = false) = run(if (share) tr(Res.string.files_container_share) else tr(Res.string.files_container_export)) {
        val all = (listOf(main) + members(main)).distinctBy { it.id }
        val entries = ArrayList<Pair<String, ByteArray>>()
        val used = HashSet<String>()
        for (f in all) {
            // Two versions of one name (a file changed between signing points) cannot share it; the later one is kept
            // under the name and the other gets its digest added.
            val name = if (used.add(f.name)) f.name else f.name.substringBeforeLast('.') + "-" + f.sha256.take(8) +
                (f.name.substringAfterLast('.', "").let { if (it.isEmpty()) "" else ".$it" })
            used.add(name)
            entries.add(name to data(f.id))
            entries.addAll(evidenceEntries(f, tr(Res.string.export_evidence_dir, name)))
        }
        entries.add(tr(Res.string.export_readme_name) to evidenceReadme(all, containerLayout(main)).encodeToByteArray())
        val name = main.name.substringBeforeLast('.').ifBlank { main.name } + tr(Res.string.export_container_suffix)
        if (deliver(name, "application/zip", DocumentSigning.zip(entries), share)) {
            model.message.value = (if (share) tr(Res.string.msg_shared_prefix) else tr(Res.string.msg_exported_prefix)) + tr(Res.string.msg_files_with_evidence, all.size)
        }
    }

    /** Time stamps (.tsr) and validation data (certificates, OCSP responses, CRLs) of [f], under [dir]. */
    private fun evidenceEntries(f: StoredFile, dir: String): List<Pair<String, ByteArray>> = buildList {
        val prefix = dir.ifEmpty { f.name.substringBeforeLast('.').ifBlank { f.name } + "." }
        f.timestamps.forEachIndexed { i, t ->
            add(tr(Res.string.export_tsr_name, prefix, i + 1) to t.token.fromBase64())
            t.validation?.let { addAll(validationEntries(it, tr(Res.string.export_tsr_prefix, prefix, i + 1))) }
        }
        f.signatureValidation?.let { addAll(validationEntries(it, tr(Res.string.export_signature_prefix, prefix))) }
    }

    private fun validationEntries(v: ValidationData, prefix: String): List<Pair<String, ByteArray>> = buildList {
        v.certificates.forEachIndexed { i, c -> add(tr(Res.string.export_cert_name, prefix, i + 1) to c.fromBase64()) }
        v.ocsps.forEachIndexed { i, o -> add("${prefix}OCSP${i + 1}.der" to o.fromBase64()) }
        v.crls.forEachIndexed { i, c -> add("${prefix}CRL${i + 1}.crl" to c.fromBase64()) }
    }

    /** The text that goes with an export: each file's digest and check, its evidence and, for a container, the points. */
    private fun evidenceReadme(list: List<StoredFile>, layout: ContainerLayout?): String = buildString {
        append(tr(Res.string.export_readme_intro)).append(Instant.fromEpochSeconds(Clock.System.now().epochSeconds)).append(tr(Res.string.export_readme_utc))
        append(tr(Res.string.export_readme_formats))
        for (f in list) {
            append(tr(Res.string.export_readme_file)).append(f.name).append("\n")
            append(tr(Res.string.export_readme_sha)).append(f.sha256).append("\n")
            f.report?.let { r ->
                append(tr(Res.string.export_readme_check)).append(r.verdict.name).append(tr(Res.string.paren_open)).append(Instant.fromEpochSeconds(r.checkedAt)).append(tr(Res.string.export_readme_paren_close))
                r.signatures.forEach { sig -> append(tr(Res.string.export_readme_signature)).append(sig.label).append(tr(Res.string.sep_space)).append(sig.verdict.name).append("\n") }
            }
            f.timestamps.forEachIndexed { i, t ->
                append(tr(Res.string.export_readme_timestamp)).append(i + 1).append(tr(Res.string.label_colon_sep)).append(t.tsa ?: tr(Res.string.tsa_fallback)).append(tr(Res.string.sep_space)).append(Instant.fromEpochSeconds(t.time)).append("\n")
                t.validation?.let { append("    ").append(it.summary()).append("\n") }
            }
            f.signatureValidation?.let { append(tr(Res.string.export_readme_revocation)).append(it.summary()).append("\n") }
        }
        if (layout != null) {
            append(tr(Res.string.export_readme_approval)).append(layout.approval.name).append("\n")
            layout.points.forEach { p ->
                append(p.title).append(p.signature?.let { tr(Res.string.sep_space) + it.verdict.name } ?: "").append("\n")
                p.files.forEach { append("  ").append(it.name).append("\n") }
                p.changed.forEach { append("  ").append(it).append(tr(Res.string.export_readme_changed)) }
                p.missing.forEach { append("  ").append(it).append(tr(Res.string.export_readme_absent)) }
            }
            if (layout.others.isNotEmpty()) {
                append(tr(Res.string.export_readme_unlisted))
                layout.others.forEach { append("  ").append(it.name).append("\n") }
            }
        }
    }

    /**
     * Deletes [f]. The files in its container go back to being files of their own, or are deleted with it when
     * [withMembers] (files inherited from the document it was signed from stay with that document).
     */
    fun delete(f: StoredFile, withMembers: Boolean = false) = run(tr(Res.string.step_delete_file)) {
        val members = files.value.filter { it.bundleOf == f.id }
        if (withMembers) members.forEach { remove(it) } else members.forEach { save(it.copy(bundleOf = null)) }
        remove(f)
        if (withMembers && members.isNotEmpty()) model.message.value = tr(Res.string.msg_deleted_container, members.size)
        model.showTab(HomeTab.FILES)
    }

    // ---------------------------------------------------------------- signing

    /** Forms that apply to [f]: PAdES for PDF, XAdES for XML, and CAdES and ASiC-E for any file. */
    fun formsFor(f: StoredFile): List<SignForm> = buildList {
        when (f.report?.format) {
            DocumentFormat.PDF -> if (f.report.encrypted != true) add(SignForm.PADES)
            // Official documents are signed with an approval point (線上簽核); XAdES would change the files the
            // approval names by their digests.
            DocumentFormat.XML -> add(if (isOfficialFile(f)) SignForm.APPROVAL else SignForm.XADES)
            else -> if (f.bundleOf != null) add(SignForm.APPROVAL)
        }
        add(SignForm.CADES_DETACHED)
        add(SignForm.CADES_ENVELOPING)
        add(SignForm.ASIC)
        add(SignForm.OPENPGP_DETACHED)
    }

    /**
     * Signs [f] as [form]; the signed result is stored as a new file. An official document is signed with an
     * approval point ([point]) in its case's online approval file, which becomes a new version in the container.
     */
    fun sign(
        f: StoredFile, choice: SignerChoice, form: SignForm, reason: String, location: String, timestamp: Boolean,
        allowBreakingCertification: Boolean = false,
        point: ApprovalPoint? = null,
        /** The baseline level of a PAdES, CAdES, ASiC-E or XAdES signature; [timestamp] applies to approval files. */
        level: SignatureLevel = SignatureLevel.B_T,
        /** Make a PDF signature certify the document with this DocMDP permission (1 to 3); first signature only. */
        certification: Int? = null,
        /** Show the PDF signature on a page; null keeps it invisible. */
        visible: VisibleSignature? = null,
    ) = run(tr(Res.string.step_prepare_sign)) {
        if (form == SignForm.OPENPGP_DETACHED) {
            signOpenPgp(f, choice as? SignerChoice.OpenPgp ?: throw SigningException(tr(Res.string.msg_pgp_needs_card)))
            return@run
        }
        val case = if (form == SignForm.APPROVAL) approvalCase(f).also { c ->
            if (c.missing.isNotEmpty()) throw SigningException(tr(Res.string.msg_approval_missing) + c.missing.joinToString(tr(Res.string.sep_list)) + tr(Res.string.msg_approval_import))
            if (c.files.isEmpty()) throw SigningException(tr(Res.string.msg_approval_none))
        } else null
        val data = data(f.id)
        val signer = withContext(model.unlockProvider) { signer(choice, tr(Res.string.sign_reason_prefix) + f.name) }
        // A CSC service that offers signatures/timestamp time-stamps its own signatures (falling back to the chosen authority).
        val cscTs = (signer as? CscSigner)?.let { runCatching { it.timestamper() }.getOrNull() }
        val ts = if (form != SignForm.APPROVAL && level.timestamp) cscTs?.let { remote -> fallbackTimestamper(remote, timestamper()) } ?: timestamper() else null
        // A CSC service without signatures/signHash but with signatures/signDoc builds the PAdES CMS itself.
        val viaSignDoc = form == SignForm.PADES && signer is CscSigner && !signer.supportsSignHash() && signer.supportsSignDoc()
        if (signer is CscSigner && !viaSignDoc && !signer.supportsSignHash()) {
            throw SigningException(if (signer.supportsSignDoc()) tr(Res.string.msg_csc_signdoc_only) else tr(Res.string.msg_csc_no_sign))
        }
        val validation = if (form != SignForm.APPROVAL && level.revocation) revocationFetch else null
        val archive = form != SignForm.APPROVAL && level.archive
        if (form != SignForm.APPROVAL) model.updateSettings { it.copy(padesLevel = level.name) }
        busy.value = when (choice) {
            is SignerChoice.Card -> tr(Res.string.step_sign_moica)
            is SignerChoice.Piv -> tr(Res.string.step_sign_piv)
            is SignerChoice.OpenPgp -> if (choice.reader.external) tr(Res.string.step_sign_pgp_usb) else tr(Res.string.step_sign_pgp_nfc)
            is SignerChoice.MobileMoica -> tr(Res.string.step_sign_mobile)
            is SignerChoice.Csc -> tr(Res.string.step_sign_csc)
            else -> tr(Res.string.step_signing)
        }
        val signerName = DocumentSigning.certificateSummary(signer.certificateChain.first())?.first
        if (case != null) {
            signApprovalPoint(f, case, signer, (point ?: ApprovalPoint()).copy(time = Clock.System.now()), timestamp, signerName)
            return@run
        }
        val base = f.name.substringBeforeLast('.')
        val now = Clock.System.now()
        val appearance = visible?.let { v ->
            PdfSignatureAppearance.preset(v.position, v.page, appearanceLines(signerName ?: signer.source.title, now.epochSeconds, reason, location), v.image)
        }
        val (bytes, name) = withContext(model.unlockProvider) {
            when (form) {
                SignForm.PADES -> {
                    val options = PdfSignOptions(
                        reason = reason.ifBlank { null }, location = location.ifBlank { null }, signerName = signerName,
                        allowBreakingCertification = allowBreakingCertification,
                        validation = validation, requireValidation = level.revocation, documentTimestamp = archive,
                        certification = certification, time = now, appearance = appearance,
                    )
                    (if (viaSignDoc) signPdfViaSignDoc(data, signer as CscSigner, options, level, ts) else DocumentSigning.signPdf(data, signer, options, ts)) to "$base-signed.pdf"
                }
                SignForm.XADES -> DocumentSigning.signXml(data, signer, ts, validation, archive) to (base + "-signed." + f.name.substringAfterLast('.', "xml"))
                SignForm.CADES_DETACHED -> DocumentSigning.signCades(data, signer, true, ts, validation, archive) to "${f.name}.p7s"
                SignForm.CADES_ENVELOPING -> DocumentSigning.signCades(data, signer, false, ts, validation, archive) to "${f.name}.p7m"
                SignForm.ASIC -> DocumentSigning.buildAsic(listOf(f.name to data), signer, ts, validation, archive) to "$base.asice"
                SignForm.APPROVAL -> throw IllegalStateException("approval handled above")
                SignForm.OPENPGP_DETACHED -> throw IllegalStateException("OpenPGP handled above")
            }
        }
        busy.value = tr(Res.string.step_check_save_signed)
        val stored = store(name, bytes, FileOrigin.SIGNED, f.name, parentId = f.id, contentId = if (form == SignForm.CADES_DETACHED) f.id else null)
        // The level the inspection of the result reached, which can be lower than asked when revocation data was missing.
        val reached = reachedLevel(file(stored.id) ?: stored)
        val levelNote = tr(Res.string.sep_comma) + (reached ?: level.short) + (certification?.let { tr(Res.string.msg_certify_level, it) } ?: "")
        model.record(HistoryKind.SIGNED, signerName ?: signer.source.title, null, listOf(f.name), note = tr(Res.string.history_signed_note, form.title, levelNote, signer.source.title))
        val lower = SignatureLevel.entries.firstOrNull { it.short == reached?.substringAfterLast(' ') }?.let { it.ordinal < level.ordinal } == true
        model.message.value = tr(Res.string.msg_signed_saved, stored.name) + (reached?.let { tr(Res.string.msg_level_open, it) + if (lower) tr(Res.string.msg_level_lower, level.short) else tr(Res.string.paren_close) } ?: "")
        model.screen.value = Screen.FileDetail(stored.id)
    }

    /** Tries [first]; when it fails, [second], so a missing remote time stamp never stops a signature. */
    private fun fallbackTimestamper(first: Timestamper, second: Timestamper) = Timestamper { data ->
        try { first.timestamp(data) } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (e: Exception) { second.timestamp(data) }
    }

    /**
     * PAdES through CSC signatures/signDoc: the wallet prepares the incremental update, the service returns the CMS
     * for its digest at AdES-B-B or AdES-B-T, and B-LT and B-LTA are reached by extending the signed file locally
     * (DSS and a document time stamp, as 延長保存 does).
     */
    private suspend fun signPdfViaSignDoc(pdf: ByteArray, signer: CscSigner, options: PdfSignOptions, level: SignatureLevel, ts: Timestamper?): ByteArray {
        val prepared = PdfIncrementalSigner.prepare(pdf, PdfSignOptions(
            reason = options.reason, location = options.location, signerName = options.signerName,
            allowBreakingCertification = options.allowBreakingCertification, certification = options.certification,
            time = options.time, appearance = options.appearance, reserve = 64 * 1024,
        ))
        val cms = signer.signPadesDigest(prepared.signedData(), if (level.timestamp) "AdES-B-T" else "AdES-B-B")
        DocumentSigning.verifyDetached(cms, prepared.signedData(), signer.certificateChain.first())
        val signed = prepared.finish(cms)
        return if (level.revocation) DocumentSigning.extendPdf(signed, revocationFetch, ts ?: timestamper()).pdf else signed
    }

    /** The text of a visible signature: who signed, when (local time), and the reason and location when given. */
    fun appearanceLines(signerName: String, epochSeconds: Long, reason: String, location: String): List<String> = buildList {
        add(tr(Res.string.appearance_signed) + signerName.take(40))
        add(tr(Res.string.appearance_time) + localTime(epochSeconds))
        reason.trim().takeIf { it.isNotEmpty() }?.let { add(tr(Res.string.appearance_reason) + it.take(40)) }
        location.trim().takeIf { it.isNotEmpty() }?.let { add(tr(Res.string.appearance_location) + it.take(40)) }
    }

    /**
     * A picture for a visible signature from an image file (PNG, JPEG and what the platform decodes), reduced so the
     * longer side is at most [maxSide] pixels; transparency is kept. Null when the file is not a picture.
     */
    fun signatureImage(bytes: ByteArray, maxSide: Int = 480): PdfAppearanceImage? {
        val bitmap = model.platform.decodeImage(bytes) ?: return null
        val w = bitmap.width
        val h = bitmap.height
        if (w <= 0 || h <= 0) return null
        val pixels = IntArray(w * h)
        bitmap.readPixels(pixels)
        val scale = minOf(1.0, maxSide.toDouble() / maxOf(w, h))
        val tw = maxOf(1, (w * scale).toInt())
        val th = maxOf(1, (h * scale).toInt())
        if (tw == w && th == h) return PdfAppearanceImage(w, h, pixels)
        // Box filter: each target pixel averages the source pixels it covers (straight alpha weighted by alpha).
        val out = IntArray(tw * th)
        for (ty in 0 until th) {
            val y0 = ty * h / th; val y1 = maxOf(y0 + 1, (ty + 1) * h / th)
            for (tx in 0 until tw) {
                val x0 = tx * w / tw; val x1 = maxOf(x0 + 1, (tx + 1) * w / tw)
                var a = 0L; var r = 0L; var g = 0L; var b = 0L; var n = 0L
                for (y in y0 until y1) for (x in x0 until x1) {
                    val p = pixels[y * w + x]
                    val pa = (p ushr 24).toLong()
                    a += pa; r += ((p shr 16) and 0xFF) * pa; g += ((p shr 8) and 0xFF) * pa; b += (p and 0xFF) * pa; n++
                }
                out[ty * tw + tx] = if (a == 0L) 0 else
                    ((a / n).toInt() shl 24) or ((r / a).toInt() shl 16) or ((g / a).toInt() shl 8) or (b / a).toInt()
            }
        }
        return PdfAppearanceImage(tw, th, out)
    }

    /** The baseline level the inspection of [f] found, such as "PAdES B-LT"; null when the report does not say. */
    private fun reachedLevel(f: StoredFile): String? {
        val r = f.report ?: return null
        // Notes of either language ("PAdES 等級：B-LT", "PAdES level: B-LT"), so reports saved before a language change work.
        val level = Regex("([A-Z][A-Za-z]*AdES)[^B]*(B-(?:LTA|LT|T|B))")
        val match = (r.notes + r.signatures.lastOrNull()?.notes.orEmpty()).mapNotNull { level.find(it) }.lastOrNull() ?: return null
        return match.groupValues[1] + " " + match.groupValues[2]
    }

    /** A signed PDF whose signatures can be extended: it has a signature or time stamp and is not encrypted. */
    fun canExtend(f: StoredFile): Boolean =
        f.report?.format == DocumentFormat.PDF && f.report.encrypted != true && f.report.signatures.isNotEmpty()

    /**
     * Extends every signature of a signed PDF (延長保存): their chains and revocation data go into the DSS and a
     * document time stamp covers it all (PAdES B-LTA). The result is a new file; the original stays as it is.
     */
    fun extendPdf(f: StoredFile) = run(tr(Res.string.step_extend)) {
        val result = DocumentSigning.extendPdf(data(f.id), revocationFetch, timestamper())
        busy.value = tr(Res.string.step_check_save_extended)
        val stored = store(f.name.substringBeforeLast('.') + "-ltv.pdf", result.pdf, FileOrigin.SIGNED, f.name, parentId = f.id)
        val reached = reachedLevel(file(stored.id) ?: stored)
        model.record(HistoryKind.SIGNED, TsaServices.byId(model.settings.tsaId).name, null, listOf(f.name),
            note = tr(Res.string.history_extend_note, result.signatures) + (reached?.let { tr(Res.string.cert_path_len_sep, it) } ?: ""))
        model.message.value = tr(Res.string.msg_extended_saved, stored.name) + result.validation.summary()
        model.screen.value = Screen.FileDetail(stored.id)
    }

    /**
     * Adds an approval point to the case of [f] and stores the new approval file: in the official document's
     * container, replacing the earlier version there (which stays in the vault), with a file time stamp when
     * [timestamp] is set (the approval format has no place for one).
     */
    private suspend fun signApprovalPoint(f: StoredFile, case: ApprovalCase, signer: DocumentSigner, point: ApprovalPoint, timestamp: Boolean, signerName: String?) {
        val previous = case.approval
        val bytes = withContext(model.unlockProvider) {
            DocumentSigning.signApproval(previous?.let { data(it.id) }, case.files.map { it.name to data(it.id) }, signer, point)
        }
        busy.value = tr(Res.string.step_check_save_approval)
        val owner = case.main ?: f
        val name = previous?.name ?: (owner.name.substringBeforeLast('.') + tr(Res.string.approval_file_suffix))
        var stored = store(name, bytes, FileOrigin.SIGNED, previous?.name ?: owner.name, parentId = previous?.id ?: owner.id)
        case.main?.let { main ->
            stored = (file(stored.id) ?: stored).copy(bundleOf = main.id).also { save(it) }
            previous?.takeIf { it.bundleOf == main.id }?.let { old -> save((file(old.id) ?: old).copy(bundleOf = null)) }
        }
        if (timestamp) runCatching { addTimestampNow(file(stored.id) ?: stored) }
        model.record(HistoryKind.SIGNED, signerName ?: signer.source.title, null, case.files.map { it.name }, note = tr(Res.string.history_approval_note, SignForm.APPROVAL.title, point.action, signer.source.title))
        model.message.value = tr(Res.string.msg_approval_added, stored.name, case.files.size) + if (previous != null && case.main != null) tr(Res.string.msg_approval_previous) else ""
        model.screen.value = Screen.FileDetail(stored.id)
    }

    private suspend fun signer(choice: SignerChoice, hint: String = tr(Res.string.sign_default_reason)): DocumentSigner = when (choice) {
        is SignerChoice.Card -> cardSigner(choice)
        is SignerChoice.Piv -> pivSigner(choice)
        is SignerChoice.Pkcs12 -> DocumentSigning.pkcs12Signer(choice.file, choice.password)
        is SignerChoice.Wallet -> walletSigner(choice.name)
        is SignerChoice.System -> withMoicaChain(model.platform.externalKeys.systemSigner(choice.id))
        is SignerChoice.Token -> withMoicaChain(model.platform.externalKeys.tokenSigner(choice.library, choice.pin, choice.id))
        is SignerChoice.MobileMoica -> mobileMoicaSigner(choice, hint)
        is SignerChoice.Csc -> model.csc.signer(choice.service, hint.take(60)) { busy.value = it }
        is SignerChoice.OpenPgp -> openPgpSigner(choice, x509 = true)
    }

    /**
     * An OpenPGP card signer with the card read (first tap). For the X.509 formats the key gets the card's cardholder
     * certificate, the certificate the card signed for itself before, or a new self-issued one (kept for next time).
     */
    private suspend fun openPgpSigner(choice: SignerChoice.OpenPgp, x509: Boolean): OpenPgpTapSigner {
        busy.value = OpenPgpModel.tapMessage(choice.reader, tr(Res.string.step_read_card))
        val signer = OpenPgpTapSigner(
            choice.reader.reader, choice.pin, model.openPgp.knownBodies(), { model.openPgp.selfIssuedCertificate(it) },
            tapMessage = OpenPgpModel.tapMessage(choice.reader, tr(Res.string.step_read_card)),
            signMessage = OpenPgpModel.tapMessage(choice.reader, tr(Res.string.step_same_card)),
        )
        signer.load(x509)
        val made = signer.selfIssued
        val fpr = signer.signatureKey.fingerprint?.let { DocCryptoUtil.hex(it).uppercase() }
        if (made != null && fpr != null) model.openPgp.keepSelfIssued(fpr, made)
        return signer
    }

    /**
     * Signs [f] with an OpenPGP card as an armored detached signature and stores it beside [f]. The card read by this
     * wallet is the holder's own, so its keys join the OpenPGP list as such when they are not listed yet.
     */
    private suspend fun signOpenPgp(f: StoredFile, choice: SignerChoice.OpenPgp) {
        val data = data(f.id)
        val signer = openPgpSigner(choice, x509 = false)
        val info = signer.info ?: throw SigningException(tr(Res.string.msg_pgp_not_read))
        val key = signer.signatureKey
        val fpr = key.fingerprint?.let { DocCryptoUtil.hex(it).uppercase() }
        val listed = fpr?.let { model.openPgp.holder(it) }
        val added = if (listed == null || (listed.trust == OpenPgpTrust.UNVERIFIED)) runCatching { model.openPgp.addCard(info) }.isSuccess else false
        busy.value = OpenPgpModel.tapMessage(choice.reader, tr(Res.string.step_same_card))
        val bytes = signer.signDetached(data)
        busy.value = tr(Res.string.step_check_save_signed)
        val stored = store("${f.name}.asc", bytes, FileOrigin.SIGNED, f.name, parentId = f.id, contentId = f.id)
        val name = model.openPgp.holder(fpr ?: "")?.info?.name ?: info.cardholder ?: info.label
        model.record(HistoryKind.SIGNED, name, null, listOf(f.name), note = tr(Res.string.history_pgp_note, SignForm.OPENPGP_DETACHED.title, SignerSource.OPENPGP.title, key.algorithm))
        model.message.value = tr(Res.string.msg_signed_saved, stored.name) + if (added) tr(Res.string.msg_pgp_key_added) else ""
        model.screen.value = Screen.FileDetail(stored.id)
    }

    // ---------------------------------------------------------------- OpenPGP messages

    /** Checks the OpenPGP files again after the key list or the user's trust changed. */
    suspend fun reinspectOpenPgp() {
        files.value.filter { it.report?.format == DocumentFormat.OPENPGP }.forEach { runCatching { refreshed(it) } }
    }

    /** Decrypts the OpenPGP message [f] with the card on [reader] and stores the content (and the signatures inside). */
    fun decryptOpenPgp(f: StoredFile, reader: NfcReaderOption, pin: String) = run(tr(Res.string.pgp_decrypt)) {
        val bytes = data(f.id)
        busy.value = OpenPgpModel.tapMessage(reader, tr(Res.string.step_decrypt))
        val (info, session) = OpenPgpCards.sessionKey(
            reader.reader, OpenPgpModel.tapMessage(reader, tr(Res.string.step_decrypt)), pin, bytes, model.openPgp.knownBodies(),
        )
        busy.value = tr(Res.string.step_decrypt_check)
        val plain = withContext(Dispatchers.Default) { OpenPgp.decrypt(bytes, session.first, session.second) }
        val dec = info.key(OpenPgpKeySlot.DECRYPTION)?.fingerprint?.let { DocCryptoUtil.hex(it).uppercase() }
        if (dec != null && model.openPgp.holder(dec) == null) runCatching { model.openPgp.addCard(info) }
        val stored = storePlain(f, plain, FileOrigin.DECRYPTED)
        model.message.value = tr(Res.string.msg_decrypted_saved, stored.name) + if (plain.detachedSignature != null) tr(Res.string.msg_decrypted_sig) else ""
        model.screen.value = Screen.FileDetail(stored.id)
    }

    /** Takes the content out of a signed (or plain) OpenPGP message [f], keeping its signatures as a detached signature. */
    fun unwrapOpenPgp(f: StoredFile) = run(tr(Res.string.step_unwrap)) {
        val plain = withContext(Dispatchers.Default) { OpenPgp.literal(data(f.id)) } ?: throw SigningException(tr(Res.string.msg_unwrap_none))
        val stored = storePlain(f, plain, FileOrigin.UNWRAPPED)
        model.message.value = tr(Res.string.msg_unwrapped_saved, stored.name)
        model.screen.value = Screen.FileDetail(stored.id)
    }

    private suspend fun storePlain(f: StoredFile, plain: OpenPgpPlaintext, origin: FileOrigin): StoredFile {
        val fallback = f.name.removeSuffix(".gpg").removeSuffix(".pgp").removeSuffix(".asc").removeSuffix(".sig")
            .takeIf { it != f.name && it.isNotBlank() } ?: (f.name + ".out")
        val name = plain.fileName?.substringAfterLast('/')?.substringAfterLast('\\')?.let { safeName(it) } ?: fallback
        val stored = store(name, plain.data, origin, f.name, parentId = f.id)
        plain.detachedSignature?.let { sig ->
            store("${stored.name}.asc", OpenPgpPackets.armor("SIGNATURE", sig).encodeToByteArray(), origin, f.name, parentId = f.id, contentId = stored.id)
        }
        return stored
    }

    /**
     * Encrypts [f] to the listed keys [fingerprints] (AES-256 with integrity protection) and stores the message as
     * `.asc` when [armor], else `.gpg`.
     */
    fun encryptOpenPgp(f: StoredFile, fingerprints: List<String>, armor: Boolean) = run(tr(Res.string.pgp_encrypt_title)) {
        if (fingerprints.isEmpty()) throw SigningException(tr(Res.string.msg_choose_recipient))
        val entries = fingerprints.mapNotNull { model.openPgp.entry(it) }
        val certs = entries.map { it.certificate.fromBase64() }
        val cardKeys = entries.flatMap { it.cardKeySet }.toSet()
        val bytes = withContext(Dispatchers.Default) { OpenPgp.encrypt(data(f.id), f.name, certs, armor, cardKeys) }
        val stored = store(f.name + if (armor) ".asc" else ".gpg", bytes, FileOrigin.ENCRYPTED, f.name, parentId = f.id)
        model.message.value = tr(Res.string.msg_encrypted_saved, entries.size, stored.name)
        model.screen.value = Screen.FileDetail(stored.id)
    }

    /** SP account entered on the signing screen during this run (developer option); never written to storage. */
    var mobileMoicaSp: MobileMoicaSp? = null

    /** The SP account this build was made with, or null when the build has none. */
    val builtInMobileMoicaSp: MobileMoicaSp? = run {
        val id = BuiltInSp.serviceId ?: return@run null
        val key = BuiltInSp.aesKeyBase64 ?: return@run null
        MobileMoicaSp(MobileMoicaEnvironment.valueOf(BuiltInSp.ENVIRONMENT), id, key, builtIn = true)
    }

    /** Holder certificates already read through the mobile citizen certificate, so later signings need one approval. */
    private val mobileMoicaCerts = mutableMapOf<String, ByteArray>()

    private suspend fun mobileMoicaSigner(choice: SignerChoice.MobileMoica, hint: String): MobileMoicaSigner {
        if (!model.legal.enabled(diw.wallet.app.legal.Integration.MOBILE_MOICA)) {
            throw SigningException(model.legal.disabledMessage(diw.wallet.app.legal.Integration.MOBILE_MOICA))
        }
        val server = choice.server
        val sp = choice.sp
        val client: MobileMoicaService
        val cacheKey: String
        var fromServer: Pair<ServerMobileMoicaClient, MobileMoicaEnvironment>? = null
        if (server != null) {
            // Asked again right before the ID number goes out: the server must still say it holds an SP account.
            val environment = try {
                model.server.mobileMoica(server)
            } catch (e: Exception) {
                throw SigningException(tr(Res.string.moica_server_unknown) + model.describe(e), e)
            } ?: throw SigningException(tr(Res.string.msg_moica_server_none))
            val serverClient = ServerMobileMoicaClient(model.http, server, model.server.tokenFor(server))
            fromServer = serverClient to environment
            client = serverClient
            cacheKey = "server:" + server + ":" + choice.idNumber
        } else {
            if (sp == null) throw SigningException(tr(Res.string.msg_moica_no_sp))
            if (!sp.builtIn) mobileMoicaSp = sp
            client = TwFidoClient(model.http, sp.environment, MobileMoicaCredentials(sp.serviceId.trim(), sp.aesKeyBase64.trim()))
            cacheKey = sp.environment.name + ":" + sp.serviceId + ":" + choice.idNumber
        }
        val returnUrl = model.platform.mobileMoicaReturnUrl ?: ""
        val signer = MobileMoicaSigner(
            client, choice.idNumber, choice.mode, hint.take(60),
            openApp = { model.platform.openExternal(it) }, returnUrl = returnUrl,
            onStatus = { busy.value = it }, certificate = mobileMoicaCerts[cacheKey],
        )
        val moica = TwPkiAnchors.moicaG3.encoded.toByteArray()
        val cert = mobileMoicaCerts[cacheKey] ?: run {
            busy.value = tr(Res.string.step_moica_first)
            val c = signer.load()
            fromServer?.let { (serverClient, environment) -> checkServerCertificate(serverClient, environment, c, moica) }
            c.also { mobileMoicaCerts[cacheKey] = it }
        }
        return if (PlatformCrypto.certificateSignedBy(cert, moica)) signer.withIntermediates(listOf(moica)) else signer
    }

    /**
     * A server could answer with any key pair, so its first answer must show that the request really went through
     * the Ministry of the Interior: the environment the sign request ran in is the one `/info` named, and in the
     * production environment the certificate is issued by MOICA G3. Test-environment certificates come from the
     * UAT CA, which this app does not carry, so they are only marked.
     */
    private fun checkServerCertificate(client: ServerMobileMoicaClient, expected: MobileMoicaEnvironment, cert: ByteArray, moica: ByteArray) {
        val ran = client.environment
        if (ran != null && ran != expected) {
            throw SigningException(tr(Res.string.msg_moica_env_mismatch, ran.title, expected.title))
        }
        when (expected) {
            MobileMoicaEnvironment.PRODUCTION -> if (!PlatformCrypto.certificateSignedBy(cert, moica)) {
                throw SigningException(tr(Res.string.msg_moica_not_g3))
            }
            MobileMoicaEnvironment.UAT -> busy.value = tr(Res.string.msg_moica_uat)
        }
    }

    /** Adds MOICA G3 after a citizen certificate that a store or token returned without its issuer. */
    private fun withMoicaChain(signer: DocumentSigner): DocumentSigner {
        val chain = signer.certificateChain
        if (chain.size != 1) return signer
        val moica = TwPkiAnchors.moicaG3.encoded.toByteArray()
        if (!PlatformCrypto.certificateSignedBy(chain.first(), moica)) return signer
        return object : DocumentSigner by signer {
            override val certificateChain = chain + listOf(moica)
        }
    }

    /** A card signer with its certificate read (first tap); MOICA G3 is added to the chain when it issued the card. */
    private suspend fun cardSigner(choice: SignerChoice.Card): GpkiTapSigner {
        busy.value = if (choice.reader.external) tr(Res.string.step_insert_moica, choice.reader.name) else tr(Res.string.step_tap_moica)
        val moica = TwPkiAnchors.moicaG3.encoded.toByteArray()
        val probe = GpkiTapSigner(choice.reader.reader, choice.pin)
        val cert = probe.load()
        val intermediates = if (PlatformCrypto.certificateSignedBy(cert, moica)) listOf(moica) else emptyList()
        return if (intermediates.isEmpty()) probe else GpkiTapSigner(choice.reader.reader, choice.pin, intermediates).also { it.load() }
    }

    /**
     * A PIV card signer with its certificate read (first tap). A PIV card does not carry its issuer chain in a fixed
     * slot, so only the leaf certificate is used; the verifier builds the chain from its trust store.
     */
    private suspend fun pivSigner(choice: SignerChoice.Piv): PivTapSigner {
        busy.value = if (choice.reader.external) tr(Res.string.step_keep_piv, choice.reader.name) else tr(Res.string.step_tap_piv)
        val signer = PivTapSigner(choice.reader.reader, choice.pin, choice.slot)
        signer.load()
        return signer
    }

    /**
     * Reads every usable certificate on a PIV card in one tap (no PIN), so the signing screen can list all the
     * certificates and let the user pick a slot instead of the wallet choosing one.
     */
    suspend fun pivCertificates(reader: NfcReaderOption): List<PivCard.KeyInfo> {
        val message = if (reader.external) tr(Res.string.step_keep_piv_list, reader.name)
            else tr(Res.string.step_tap_piv_list)
        return reader.reader.scan(message, tagInteractionFunc = { tag ->
            val card = PivCard(NfcCardChannel(tag))
            card.connect()
            card.allSigningKeys()
        })
    }

    /** The wallet's own P-256 key (document-signer identity) with a self-issued certificate in [name]. */
    private suspend fun walletSigner(name: String): DocumentSigner {
        val key = identity(HolderIdentities.DOCUMENT_SIGNER)
        val subject = name.trim().ifEmpty { tr(Res.string.wallet_user) }
        val certKey = "wallet-cert:" + key.alias + ":" + subject
        val t = model.storage.getTable(metaTable)
        val cert = t.get(certKey)?.toByteArray() ?: DocumentSigning.selfIssuedCertificate(
            spki(key.publicKey), subject, { data -> key.signingKey("ES256").sign(data).toDerEncoded() }, SignerKeyType.EC_P256, 3650,
        ).also { t.insert(certKey, ByteString(it)) }
        return object : DocumentSigner {
            override val certificateChain = listOf(cert)
            override val keyType = SignerKeyType.EC_P256
            override val source = SignerSource.WALLET
            override suspend fun sign(data: ByteArray): ByteArray = key.signingKey("ES256").sign(data).toDerEncoded()
        }
    }

    private suspend fun identity(profile: String): HolderKey {
        val backend = model.backends.first()
        val userAuth = model.settings.requireUserAuth || !backend.protection.hardware
        return model.holderIdentities.getOrCreate(profile, "did:key", backend.secureArea, backend.settings(ByteString(PlatformCrypto.randomBytes(16)), userAuth))
    }

    // ---------------------------------------------------------------- derived credentials

    /**
     * Derives a credential from [f]: an SD-JWT VC with [claims] in the documents list, issued by the wallet's
     * document issuer key, with the document check and a time stamp as evidence. Signing the document itself is a
     * separate step (PAdES, CAdES, XAdES); a signature made before deriving is part of the document check.
     */
    fun derive(f: StoredFile, claims: List<DerivedClaim>, timestamp: Boolean, validDays: Int?, zk: ZkPdfChoice? = null) = run(tr(Res.string.step_derive)) {
        val data = data(f.id)
        // A zkPDF proof is planned first, so a file the template does not fit fails before anything is created.
        val zkPlan = zk?.let { choice ->
            val plan = zkPdfPlan(data, choice.profileId, choice.predicates)
            val local = model.zk.pdf() ?: throw SigningException(tr(Res.string.msg_no_zkpdf))
            if (choice.selfHosted) {
                val (remote, composition) = selfHostedProver(local)
                // A remote proof waits on the host's queue as well, so it gets the longer time limit.
                Triple(ZkPdfChoice(choice.profileId, choice.predicates, composition, extended = true, selfHosted = true), plan, remote)
            } else {
                if (!local.ready(choice.composition, true)) throw SigningException(tr(Res.string.msg_zkpdf_circuits))
                Triple(choice, plan, local)
            }
        }
        issueDerived(f, data, claims, timestamp, validDays, zkPlan?.second, key = null) { holderKey ->
            zkPlan?.let { (choice, plan, engine) -> provePdf(f, data, plan, holderKey, choice, engine) }
        }
    }

    /** The zkPDF plan of [data] for the template [profileId]; fails when the template does not fit or proves nothing. */
    private suspend fun zkPdfPlan(data: ByteArray, profileId: String, predicates: List<ZkPdfPredicate>): ZkPdfPlan {
        val profile = ZkPdfProfiles.find(profileId, model.settings.testEnvironment) ?: throw SigningException(tr(Res.string.msg_no_layout))
        val plan = withContext(Dispatchers.Default) {
            try { ZkPdfPlanner.plan(data, profile, predicates) } catch (_: PdfException) { null }
        } ?: throw SigningException(tr(Res.string.msg_layout_mismatch, profile.title))
        if (plan.slots.isEmpty()) throw SigningException(tr(Res.string.msg_layout_no_fields, profile.title))
        return plan
    }

    /** A credential key made before its credential: the desktop route binds the proof to it before anything is issued. */
    private class HeldKey(val secureArea: SecureArea, val alias: String)

    /**
     * Issues the derived credential of [f] and stores it. [prove] runs once the credential key exists (a key in
     * [key] when the proof was made for it earlier) and before signing, so a proof is always bound to the key of the
     * credential that carries it.
     */
    private suspend fun issueDerived(
        f: StoredFile,
        data: ByteArray,
        claims: List<DerivedClaim>,
        timestamp: Boolean,
        validDays: Int?,
        plan: ZkPdfPlan?,
        key: HeldKey?,
        prove: suspend (EcPublicKey) -> ZkPdfCreated?,
    ) {
        val zkNames = plan?.slots?.map { it.claim }.orEmpty().toSet()
        // A proven field replaces a field of the same name read from the text layer.
        val textClaims = claims.filter { it.name !in zkNames && !DerivedCredentials.isProofClaim(it.name) }
        if (textClaims.isEmpty() && plan == null) throw SigningException(tr(Res.string.derive_choose_one))
        // The evidence states the result as of now, never a report cached from an earlier check.
        val report = refreshed(f).report ?: DocumentInspector.inspect(data, f.name, trustSource)
        val now = Clock.System.now()
        val validUntil = validDays?.let { now + it.days }
        val document = DerivedDocument(f.sha256, f.mediaType, f.size)
        val evidence = buildList {
            add(DerivedCredentials.signatureEvidence(report))
            val stamp = f.timestamps.lastOrNull { it.trusted }?.let { it.token.fromBase64() }
                ?: if (timestamp) { busy.value = tr(Res.string.step_get_timestamp); timestamper().timestamp(data) } else null
            stamp?.let { add(DerivedCredentials.timestampEvidence(it, DocumentInspector.verifyTimestamp(it, data, trustSource))) }
        }
        val zkLabels = plan?.let { p ->
            p.slots.associate { s -> s.claim to (p.profile.field(s.claim)?.label ?: s.claim) } +
                p.slots.associate { s -> ZkPdfEvidence.OPEN_PREFIX + s.claim to tr(Res.string.derive_zk_opening, p.profile.field(s.claim)?.label ?: s.claim) } +
                (ZkPdfEvidence.CLAIM to tr(Res.string.derive_zk_claim))
        }.orEmpty()
        val doc = withContext(model.unlockProvider) {
            busy.value = tr(Res.string.step_derive)
            val issuer = identity(HolderIdentities.DOCUMENT_ISSUER)
            val keys = model.keyRequest()
            val title = textClaims.firstOrNull { it.name == DerivedCredentials.CLAIM_TITLE }?.value ?: plan?.profile?.title ?: f.name
            val record = IssuanceRecord(
                credentialIssuer = issuer.did!!,
                configurationId = CONFIGURATION,
                format = "dc+sd-jwt",
                vct = DerivedCredentials.VCT,
                tier = TrustTier.T3.name,
                environment = TrustEnvironment.USER.id,
                official = false,
                anchorName = tr(Res.string.derive_issuer_name),
                labels = listOf(TrustLabel.SELF_ISSUED.name),
                issuedAt = now.epochSeconds,
                keyStorage = keys.keyStorage,
                specs = listOf("IETF SD-JWT VC"),
                claimNames = DerivedCredentials.claimLabels + textClaims.filter { it.label != null }.associate { it.name to it.label!! } + zkLabels,
                profile = PROFILE,
            )
            val created = model.documentStore.createDocument(displayName = title, typeDisplayName = tr(Res.string.files_derived), appData = record.encode())
            try {
                val credential = if (key != null) {
                    KeyBoundSdJwtVcCredential.createForExistingAlias(created, null, CredentialDomains.SD_JWT, key.secureArea, DerivedCredentials.VCT, key.alias)
                } else {
                    KeyBoundSdJwtVcCredential.create(
                        created, null, CredentialDomains.SD_JWT, keys.secureArea, DerivedCredentials.VCT,
                        keys.createKeySettings(ByteString(PlatformCrypto.randomBytes(16))),
                    )
                }
                val holderKey = credential.secureArea.getKeyInfo(credential.alias).ecPublicKey
                val proven = prove(holderKey)
                val disclosures = DerivedCredentials.jsonDisclosures(
                    textClaims.map { it.name to JsonPrimitive(it.value) } + proven?.disclosures().orEmpty(),
                )
                val compact = DerivedCredentials.sdJwtVc(issuer, holderKey, document, evidence, disclosures, now, validUntil)
                credential.certify(compact.encodeToByteString())
                created.edit { provisioned = true }
            } catch (e: Exception) {
                model.documentStore.deleteDocument(created.identifier)
                throw e
            }
            // A credential derived earlier from the same file is replaced, and a request waiting for the desktop is done.
            (file(f.id) ?: f).derivedDocumentId?.let { old -> runCatching { model.documentStore.deleteDocument(old) } }
            save((file(f.id) ?: f).copy(derivedDocumentId = created.identifier, zkPdfPending = null))
            created
        }
        model.documents.value = model.documentStore.listDocuments()
        model.platform.registerDigitalCredentials(model)
        val labels = textClaims.map { DerivedCredentials.labelOf(it) } +
            plan?.let { p -> p.slots.map { s -> (p.profile.field(s.claim)?.label ?: s.claim) + tr(Res.string.derive_zk_suffix) } }.orEmpty()
        model.record(HistoryKind.ISSUED, tr(Res.string.derive_issuer_name), null, listOf(doc.displayName ?: f.name), labels)
        model.message.value = if (plan != null) tr(Res.string.msg_derived_zk) else tr(Res.string.msg_derived)
        model.screen.value = Screen.FileDetail(f.id)
    }

    /**
     * Runs the zkPDF proof of [plan] for the credential key [holderKey] as a background proof (one at a time, with a
     * time limit and cancellation from the screen), showing the segment progress. Nothing unproven is returned.
     */
    private suspend fun provePdf(
        f: StoredFile,
        pdf: ByteArray,
        plan: ZkPdfPlan,
        holderKey: EcPublicKey,
        choice: ZkPdfChoice,
        engine: ZkPdfEngine,
    ): ZkPdfCreated {
        val jwk = holderKey.toJwk()
        val job = model.zk.prove(zkJobId(f.id), ZkProofKind.PDF, choice.extended, if (choice.selfHosted) tr(Res.string.zk_job_self_host, compositionTitle(choice.composition)) else compositionTitle(choice.composition)) { step ->
            step(tr(Res.string.step_prepare))
            ZkPdfProofs.create(pdf, plan, jwk, choice.composition, engine, { kind, done, total ->
                val text = tr(Res.string.step_zkpdf_progress, segmentName(kind), done, total)
                step(text)
                busy.value = text
            })
        }
        return proofResult(job)
    }

    private suspend fun <T> proofResult(job: kotlinx.coroutines.Deferred<ZkResult<T>>): T {
        val result = try {
            job.await()
        } catch (e: CancellationException) {
            currentCoroutineContext().ensureActive()
            ZkResult.Cancelled
        }
        return when (result) {
            is ZkResult.Ok -> result.value
            is ZkResult.Failed -> throw SigningException(result.reason)
            ZkResult.Cancelled -> throw SigningException(tr(Res.string.msg_zkpdf_cancelled))
        }
    }

    // ---------------------------------------------------------------- zkPDF made by the desktop wallet

    /**
     * Prepares a zkPDF proof of [f] for the desktop wallet: creates the credential key the proof binds to, keeps
     * what finishing needs with the file ([StoredFile.zkPdfPending]) and saves the proof request (page 1 content, the
     * private image and the field salts, never the whole PDF) for the holder to open in the desktop wallet. The
     * request is made for the desktop composition; an earlier request of the file is replaced.
     */
    fun exportZkPdfRequest(f: StoredFile, claims: List<DerivedClaim>, timestamp: Boolean, validDays: Int?, choice: ZkPdfChoice) =
        run(tr(Res.string.step_prepare_desktop)) {
            val data = data(f.id)
            val plan = zkPdfPlan(data, choice.profileId, choice.predicates)
            val local = model.zk.pdf() ?: throw SigningException(tr(Res.string.msg_no_zkpdf_verify))
            val composition = ZkPdfStatement.DESKTOP
            if (!local.ready(composition, false)) throw SigningException(tr(Res.string.msg_download_vk))
            val keys = model.keyRequest()
            val info = withContext(model.unlockProvider) {
                keys.secureArea.createKey(null, keys.createKeySettings(ByteString(PlatformCrypto.randomBytes(16))))
            }
            val salts = ZkPdfPlanner.salts(plan.slots.size)
            val statement = ZkPdfProofs.statement(plan, composition, ZkPdfProofs.binding(info.ecPublicKey.toJwk()))
            val request = ZkPdfRemote.Request(ZkPdfRemote.newId(), statement, ZkPdfWitness(plan.privateData, salts))
            val bytes = ZkPdfRemote.encodeRequest(request).toString().encodeToByteArray()
            val name = f.name.substringBeforeLast('.') + ZkPdfRemote.REQUEST_EXTENSION
            val saved = if (model.platform.canShareFiles) model.platform.shareFile(name, ZkPdfRemote.MEDIA_TYPE, bytes)
                else model.platform.saveFile(name, ZkPdfRemote.MEDIA_TYPE, bytes)
            if (!saved) {
                runCatching { keys.secureArea.deleteKey(info.alias) }
                throw SigningException(tr(Res.string.msg_request_not_saved))
            }
            val current = file(f.id) ?: f
            current.zkPdfPending?.let { old -> dropPendingKey(old) }
            save(current.copy(zkPdfPending = ZkPdfPending(
                requestId = request.id,
                keyAlias = info.alias,
                secureArea = keys.secureArea.identifier,
                profileId = choice.profileId,
                predicates = choice.predicates.map { ZkPdfPending.Predicate(it.kind, it.claim, it.cutoff) },
                composition = composition,
                salts = salts.map { it.toBase64Url() },
                claims = claims.map { ZkPdfPending.Claim(it.name, it.value, it.label) },
                timestamp = timestamp,
                validDays = validDays,
                createdAt = Clock.System.now().epochSeconds,
            )))
            model.message.value = tr(Res.string.msg_request_saved, ZkPdfRemote.RESPONSE_EXTENSION)
        }

    /**
     * Finishes the request waiting on [f] with a proof file the desktop wallet made: the proof must answer that
     * request, every segment must verify here against the statement this device builds again from the PDF and the
     * waiting key, and the field openings must match; only then is the credential issued with that key.
     */
    fun importZkPdfProof(f: StoredFile) = run(tr(Res.string.step_import_desktop)) {
        val pending = (file(f.id) ?: f).zkPdfPending ?: throw SigningException(tr(Res.string.msg_no_pending))
        val picked = model.platform.pickFile() ?: return@run
        if (picked.bytes.size > ZkPdfRemote.MAX_BYTES) throw SigningException(tr(Res.string.msg_proof_too_large))
        val response = try {
            ZkPdfRemote.parseResponse(ZkPdfRemote.parse(picked.bytes))
        } catch (_: IllegalArgumentException) {
            throw SigningException(tr(Res.string.msg_not_proof))
        }
        if (response.requestId != pending.requestId) throw SigningException(tr(Res.string.msg_proof_other_request))
        val secureArea = model.backends.map { it.secureArea }.firstOrNull { it.identifier == pending.secureArea }
            ?: throw SigningException(tr(Res.string.msg_request_key_missing))
        val holderKey = try {
            secureArea.getKeyInfo(pending.keyAlias).ecPublicKey
        } catch (_: Exception) {
            throw SigningException(tr(Res.string.msg_request_key_missing))
        }
        val data = data(f.id)
        val plan = zkPdfPlan(data, pending.profileId, pending.predicates.map { ZkPdfPredicate(it.kind, it.claim, it.cutoff) })
        val local = model.zk.pdf() ?: throw SigningException(tr(Res.string.msg_no_zkpdf))
        if (!local.ready(pending.composition, false)) throw SigningException(tr(Res.string.msg_download_vk_settings))
        val salts = pending.salts.map { it.fromBase64Url() }
        // The imported output stands in for a prover: it is accepted only when it verifies against this statement.
        val imported = object : ZkPdfEngine by local {
            override suspend fun prove(statement: ZkPdfStatement, witness: ZkPdfWitness, progress: (String, Int, Int) -> Unit) =
                RemoteZkPdfEngine.accept(statement, response.output, local)
        }
        busy.value = tr(Res.string.step_verify_desktop)
        val job = model.zk.prove(zkJobId(f.id), ZkProofKind.PDF, true, tr(Res.string.zk_job_desktop_import, compositionTitle(pending.composition))) { step ->
            step(tr(Res.string.step_verify_proof))
            ZkPdfProofs.create(data, plan, holderKey.toJwk(), pending.composition, imported, { _, _, _ -> }, salts = salts)
        }
        val created = proofResult(job)
        issueDerived(f, data, pending.claims.map { DerivedClaim(it.name, it.value, it.label) }, pending.timestamp, pending.validDays,
            plan, HeldKey(secureArea, pending.keyAlias)) { key ->
            if (!ZkPdfProofs.binding(key.toJwk()).contentEquals(created.evidence.binding)) throw SigningException(tr(Res.string.msg_proof_key_mismatch))
            created
        }
    }

    /** Drops the request waiting on [f] and its key. */
    fun cancelZkPdfRequest(f: StoredFile) = run(tr(Res.string.step_cancel_request)) {
        val current = file(f.id) ?: f
        current.zkPdfPending?.let { dropPendingKey(it) }
        save(current.copy(zkPdfPending = null))
    }

    private suspend fun dropPendingKey(p: ZkPdfPending) {
        model.backends.map { it.secureArea }.firstOrNull { it.identifier == p.secureArea }?.let { area ->
            runCatching { area.deleteKey(p.keyAlias) }
        }
    }

    /**
     * Proves a request a phone wallet exported (desktop wallet): checks it, proves it here with the local prover in
     * the background, checks the result like the phone will, and saves the proof file for the phone to import. The
     * request holds private page content; it is never stored, only proved and dropped.
     */
    fun proveForPhone() = run(tr(Res.string.zk_phone_requests)) {
        val picked = model.platform.pickFile() ?: return@run
        if (picked.bytes.size > ZkPdfRemote.MAX_BYTES) throw SigningException(tr(Res.string.msg_request_too_large))
        val request = try {
            ZkPdfRemote.parseRequest(ZkPdfRemote.parse(picked.bytes))
        } catch (_: IllegalArgumentException) {
            throw SigningException(tr(Res.string.msg_not_request))
        }
        val engine = model.zk.pdf() ?: throw SigningException(tr(Res.string.msg_no_zkpdf))
        val composition = request.statement.composition
        if (!engine.ready(composition, true)) {
            throw SigningException(tr(Res.string.msg_circuits_missing, if (composition == ZkPdfStatement.DESKTOP) tr(Res.string.zk_desktop_spaced) else tr(Res.string.zk_phone_spaced)))
        }
        val job = model.zk.prove(PHONE_JOB, ZkProofKind.PDF, true, tr(Res.string.zk_job_for_phone, compositionTitle(composition))) { step ->
            step(tr(Res.string.step_prepare))
            when (val r = engine.prove(request.statement, request.witness) { kind, done, total ->
                val text = tr(Res.string.step_for_phone_progress, segmentName(kind), done, total)
                step(text)
                busy.value = text
            }) {
                is ZkResult.Ok -> RemoteZkPdfEngine.accept(request.statement, r.value, engine)
                else -> r
            }
        }
        val output = proofResult(job)
        val bytes = ZkPdfRemote.encodeResponse(ZkPdfRemote.Response(request.id, output)).toString().encodeToByteArray()
        val name = picked.name.substringBeforeLast('.') + ZkPdfRemote.RESPONSE_EXTENSION
        if (!model.platform.saveFile(name, ZkPdfRemote.MEDIA_TYPE, bytes)) throw SigningException(tr(Res.string.msg_proof_not_saved))
        model.message.value = tr(Res.string.msg_proof_saved, name)
    }

    /**
     * The self-hosted prover of the settings over [local], and the composition to prove in: the desktop one when the
     * host has it (fewer, larger segments), else the phone one; either only when this device can verify it.
     */
    private suspend fun selfHostedProver(local: ZkPdfEngine): Pair<RemoteZkPdfEngine, String> {
        val s = model.settings
        if (s.zkProverUrl.isEmpty()) throw SigningException(tr(Res.string.msg_no_self_host))
        ZkProverHost.problem(s.zkProverUrl, model.platform::cleartextPermitted)?.let { throw SigningException(tr(Res.string.msg_self_host_bad, it)) }
        val remote = RemoteZkPdfEngine(ZkProverHost(tr(Res.string.zk_self_host), s.zkProverUrl, s.zkProverToken), local, model.http)
        busy.value = tr(Res.string.step_connect_host)
        val offered = when (val r = remote.compositions()) {
            is ZkResult.Ok -> r.value
            is ZkResult.Failed -> throw SigningException(r.reason)
            ZkResult.Cancelled -> throw SigningException(tr(Res.string.msg_zkpdf_cancelled))
        }
        if (offered.isEmpty()) throw SigningException(tr(Res.string.zk_prover_no_circuits_short))
        val composition = SELF_HOST_COMPOSITIONS.firstOrNull { it in offered && local.ready(it, false) }
            ?: throw SigningException(tr(Res.string.msg_self_host_vk))
        return remote to composition
    }

    /** Stops the zkPDF proof running for the file [fileId]. */
    fun cancelZkPdf(fileId: String) = model.zk.cancel(zkJobId(fileId))

    fun zkJobId(fileId: String) = "zkpdf:$fileId"

    private fun segmentName(kind: String): String = when (kind) {
        "sha_content", "sha_opaque" -> tr(Res.string.zk_segment_hash)
        "inflate0", "inflate" -> tr(Res.string.zk_segment_inflate)
        "lex" -> tr(Res.string.zk_segment_text)
        "claim" -> tr(Res.string.zk_segment_commit)
        "pred" -> tr(Res.string.zk_segment_dates)
        else -> tr(Res.string.zk_segment_proof)
    }

    /** Clears the link of every file to the derived credential [documentId], after that credential was deleted. */
    suspend fun forgetDerived(documentId: String) {
        files.value.filter { it.derivedDocumentId == documentId }.forEach { save(it.copy(derivedDocumentId = null)) }
        files.value.filter { documentId in it.webProofIds }.forEach { save(it.copy(webProofIds = it.webProofIds - documentId)) }
    }

    /** Clears links to derived credentials and web query results that no longer exist (deleted while the link was not updated). */
    suspend fun reconcileDerived(existing: Set<String>) {
        files.value.filter { it.derivedDocumentId != null && it.derivedDocumentId !in existing }.forEach { save(it.copy(derivedDocumentId = null)) }
        files.value.filter { f -> f.webProofIds.any { it !in existing } }.forEach { f -> save(f.copy(webProofIds = f.webProofIds.filter { it in existing })) }
    }

    /** Links the kept web query result [documentId] (ZkTlsKeep) to the file [fileId] as its evidence. */
    suspend fun attachWebProof(fileId: String, documentId: String) {
        val f = file(fileId) ?: return
        save(f.copy(webProofIds = (f.webProofIds + documentId).distinct()))
    }

    // ---------------------------------------------------------------- Bonds holder-derived credentials

    /**
     * Vault documents a Bonds holder-derived credential can be computed from at presentation time: MyData PDFs and
     * text exports, typed by their MyData item when the vault knows it. The text is read only for the document the
     * request selects; encrypted MyData PDFs open with the holder's ID number as for the preview.
     */
    fun holderDerivedSources(): List<HolderDerivedSource> = files.value.filter { f ->
        f.report?.format == DocumentFormat.PDF || f.mediaType.startsWith("text/")
    }.sortedByDescending { it.addedAt }.map { f ->
        val item = MyDataFiles.recognize(f.name) ?: f.source?.let { s -> MyDataFiles.recognize(s.substringAfter("・")) }
        HolderDerivedSource(
            id = f.id,
            name = f.name,
            documentType = item?.let { MyDataFiles.holderDerivedType(it) },
            sha256Hex = f.sha256,
            text = { sourceText(f) },
        )
    }

    /** The holder's ID number and name from the national ID cards, and the ID number saved for MyData. */
    fun holderHints(): List<HolderHint> =
        nationalIdCards().mapNotNull { (_, c) ->
            runCatching { TaiwanModel.nationalIdClaims(c).toMap() }.getOrNull()?.let { HolderHint(it["unifiedNo"], it["name"]) }
        } + listOfNotNull(savedMyDataId()?.let { HolderHint(it, null) })

    /** The ID number saved for MyData, used only while the MyData statement is accepted. */
    private fun savedMyDataId(): String? =
        model.settings.myDataIdNumber?.takeIf { model.legal.enabled(diw.wallet.app.legal.Integration.MYDATA) }

    private suspend fun sourceText(f: StoredFile): String = withContext(Dispatchers.Default) {
        val bytes = data(f.id)
        if (f.report?.format == DocumentFormat.PDF) {
            val pdf = unlock(f, bytes, null) ?: throw HolderDerivedException(tr(Res.string.msg_pdf_needs_id, f.name))
            PdfTextExtractor.extract(pdf, 50).takeIf { it.isNotBlank() } ?: throw HolderDerivedException(tr(Res.string.msg_pdf_no_text, f.name))
        } else bytes.decodeToString()
    }

    // ---------------------------------------------------------------- Bonds national ID card

    /** Fields read from a national ID PDF, waiting for the holder to confirm and sign them. */
    val nationalIdDraft = MutableStateFlow<NationalIdDraft?>(null)

    /** Vault files with a Bonds national ID card; the newest card first. */
    fun nationalIdCards(): List<Pair<StoredFile, MoicaSignedCredential>> =
        files.value.mapNotNull { f -> f.nationalId?.let { m -> runCatching { MoicaSignedCredential.parse(m) }.getOrNull()?.let { f to it } } }

    /**
     * Opens the MyData national ID PDF [f] with the holder's ID number (its user password) and reads the fields, as
     * Bonds does; [idNumber] is used for this only and never stored.
     */
    fun readNationalId(f: StoredFile, idNumber: String) = run(tr(Res.string.step_open_id)) {
        nationalIdDraft.value = null
        val bytes = data(f.id)
        val text = withContext(Dispatchers.Default) { BondsNationalId.readPdf(bytes, idNumber) }
        passwords[f.id] = listOf(idNumber, BondsNationalId.normalizePassword(idNumber)).first { !PdfFile(bytes, it).passwordRequired }
        val fields = BondsNationalId.parse(text) ?: throw SigningException(tr(Res.string.msg_not_id_pdf))
        if (fields.unifiedNo == null || fields.name == null) throw SigningException(tr(Res.string.msg_id_unreadable))
        nationalIdDraft.value = NationalIdDraft(f.id, fields, BondsNationalId.over18(fields.birthdate, Clock.System.now()))
    }

    /** Reads the national ID PDF [f] at once when an ID number the wallet knows opens it. */
    fun readNationalIdIfKnown(f: StoredFile) = model.scope.launch {
        if (nationalIdDraft.value?.fileId == f.id || busy.value != null) return@launch
        val bytes = data(f.id)
        val opened = withContext(Dispatchers.Default) { unlock(f, bytes, null) } ?: return@launch
        if (!opened.encrypted) return@launch
        passwords[f.id]?.let { readNationalId(f, it) }
    }

    /** Signs the confirmed fields with the citizen certificate card and stores the card with the file. */
    fun issueNationalId(draft: NationalIdDraft, card: SignerChoice.Card) =
        issueNationalId(draft, if (card.reader.external) tr(Res.string.step_signing) else tr(Res.string.step_sign_tap_again)) { cardSigner(card) }

    /** Signs with the RSA certificate [signer] gives (the card, read with its first tap); tests pass their own. */
    internal fun issueNationalId(draft: NationalIdDraft, signing: String, signer: suspend () -> DocumentSigner) = run(tr(Res.string.step_make_national_id)) {
        val f = file(draft.fileId) ?: throw SigningException(tr(Res.string.msg_id_file_missing))
        val cardSigner = signer()
        val issued = withContext(model.unlockProvider) {
            val self = identity(HolderIdentities.BONDS_SELF_ISSUED)
            busy.value = signing
            BondsNationalId.issue(draft.fields, self, cardSigner)
        }
        save((file(f.id) ?: f).copy(nationalId = issued.serialized()))
        nationalIdDraft.value = null
        model.record(
            HistoryKind.ISSUED, tr(Res.string.national_id_holder_self), null, listOf(tr(Res.string.national_id_bonds)),
            BondsNationalId.claims(draft.fields, Clock.System.now()).map { BondsNationalId.claimLabels[it.first] ?: it.first },
        )
        model.message.value = tr(Res.string.msg_id_made)
        model.screen.value = Screen.NationalId(f.id)
    }

    /** Exports the national ID card as Bonds vc+moica JSON. */
    fun exportNationalId(f: StoredFile, share: Boolean = false) = run(if (share) tr(Res.string.step_share_id) else tr(Res.string.step_export_id)) {
        val card = f.nationalId ?: throw SigningException(tr(Res.string.msg_no_id_card))
        deliver("national-id.vc-moica.json", "application/vc+moica", card.encodeToByteArray(), share)
    }

    /** Removes the national ID card; the PDF it was made from stays in the vault. */
    fun deleteNationalId(f: StoredFile) = run(tr(Res.string.national_id_delete)) {
        save((file(f.id) ?: f).copy(nationalId = null))
        model.showTab(HomeTab.DOCUMENTS)
    }

    companion object {
        const val PROFILE = "document"
        const val CONFIGURATION = "document-derived"
        const val MAX_FILE_BYTES = 64 * 1024 * 1024
        /** Width of rendered PDF pages, in pixels. */
        const val PREVIEW_WIDTH = 1080
        private const val MAX_AIA_BYTES = 256 * 1024

        /** An OpenCerts certificate is checked online again when opened after this long. */
        const val OPENCERT_RECHECK_SECONDS = 12 * 3600L

        /** The background proof a desktop wallet runs for a phone's request. */
        const val PHONE_JOB = "zkpdf:phone-request"

        /** Compositions a self-hosted prover is asked for, the preferred first. */
        val SELF_HOST_COMPOSITIONS = listOf(ZkPdfStatement.DESKTOP, ZkPdfStatement.PHONE)

        /** What checking a proof from a self-hosted prover needs on this device, in either composition. */
        val SELF_HOST_ASSETS: List<String> =
            SELF_HOST_COMPOSITIONS.flatMap { diw.wallet.core.zk.ZkPdfAssets.required(it, prover = false) }.distinct()
        private val metaTable = StorageTableSpec(name = "DiwFiles", supportPartitions = false, supportExpiration = false)
        private val dataTable = StorageTableSpec(name = "DiwFileData", supportPartitions = false, supportExpiration = false)

        fun mediaTypeOf(report: DocumentReport, name: String): String = when (report.format) {
            DocumentFormat.IMAGE -> ImageKind.ofExtension(name)?.mediaType ?: "image/*"
            DocumentFormat.OFFICE -> when (name.substringAfterLast('.', "").lowercase()) {
                "doc" -> "application/msword"
                "docx" -> "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                "xls" -> "application/vnd.ms-excel"
                "xlsx" -> "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                "ppt" -> "application/vnd.ms-powerpoint"
                "pptx" -> "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                "odt" -> "application/vnd.oasis.opendocument.text"
                "ods" -> "application/vnd.oasis.opendocument.spreadsheet"
                "odp" -> "application/vnd.oasis.opendocument.presentation"
                else -> report.format.mediaType
            }
            else -> report.format.mediaType
        }

        fun safeName(s: String): String = s.map { if (it in "\\/:*?\"<>|" || it.code < 0x20) '_' else it }.joinToString("").trim().ifEmpty { "document" }

        /** SubjectPublicKeyInfo DER of a P-256 public key. */
        fun spki(key: EcPublicKey): ByteArray {
            val k = key as? EcPublicKeyDoubleCoordinate ?: throw SigningException(tr(Res.string.msg_wallet_key_not_p256))
            val prefix = "3059301306072a8648ce3d020106082a8648ce3d030107034200"
            val head = ByteArray(prefix.length / 2) { prefix.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            return head + byteArrayOf(0x04) + k.x + k.y
        }
    }
}
