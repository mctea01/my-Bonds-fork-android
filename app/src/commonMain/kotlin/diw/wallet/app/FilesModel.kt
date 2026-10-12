package diw.wallet.app

import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.card.GpkiTapSigner
import diw.wallet.core.document.derived.DerivedClaim
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.DerivedDocument
import diw.wallet.core.document.official.OfficialLetter
import diw.wallet.core.document.pdf.PdfComposer
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfPlain
import diw.wallet.core.document.pdf.PdfTextExtractor
import diw.wallet.core.document.pdf.PdfSignOptions
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.DocumentSigning
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
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.profile.bonds.NationalIdFields
import diw.wallet.core.profile.bonds.TwPkiAnchors
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.isSuccess
import androidx.compose.ui.graphics.ImageBitmap
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.X509Cert
import org.multipaz.sdjwt.credential.KeyBoundSdJwtVcCredential
import org.multipaz.storage.StorageTableSpec
import org.multipaz.util.fromBase64
import org.multipaz.util.toBase64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/** A time stamp the wallet obtained for a stored file (RFC 3161 over its SHA-256). */
@Serializable
data class StoredTimestamp(val token: String, val time: Long, val tsa: String? = null, val trusted: Boolean = false)

/** How a file came into the vault. */
@Serializable
enum class FileOrigin(val title: String) {
    IMPORTED("匯入"),
    DOWNLOADED("從來源網站下載"),
    EXTRACTED("從壓縮檔解出"),
    SIGNED("本錢包簽署"),
    COMPOSED("本錢包製作"),
    LETTER("本錢包製作的公文"),
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
    /** Where it came from: a source site, the file it was signed or extracted from. */
    val source: String? = null,
    val report: DocumentReport? = null,
    val timestamps: List<StoredTimestamp> = emptyList(),
    /** The file a detached signature (.p7s) signs. */
    val contentId: String? = null,
    val parentId: String? = null,
    /** The derived SD-JWT VC (a document in the documents list). */
    val derivedDocumentId: String? = null,
    /** The vc+moica form of the derived credential, when signed with the citizen certificate card. */
    val moica: String? = null,
    /** The Bonds national ID card (vc+moica NationalIDCredential) made from this MyData national ID PDF. */
    val nationalId: String? = null,
)

/** What the file screen shows of a file's content. */
sealed class FilePreview {
    /** Rendered pages (as many as [PREVIEW_PAGES]) of [total], and the text layer when there is one. */
    class Pages(val pages: List<ImageBitmap>, val total: Int, val text: String?) : FilePreview()
    class Picture(val image: ImageBitmap) : FilePreview()
    class Text(val text: String, val truncated: Boolean) : FilePreview()
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
    val myData = listOf(
        DocumentSource("mydata-id", "國民身分證資料（製作身分證卡）", "下載後輸入身分證統一編號開啟 PDF，再以自然人憑證簽成 Bonds 身分證卡", MYDATA + "personal/detail/API.idPhotoRev", myData = true, nationalId = true),
        DocumentSource("mydata", "MyData 個人文件", "登入後在「個人專區／個人文件」下載已完成的文件，可連續下載多份", MYDATA + "signin", myData = true),
        DocumentSource("mydata-household", "現戶全戶戶籍資料", "內政部戶政司", MYDATA + "personal/detail/API.UDauDOLyZg", myData = true),
        DocumentSource("mydata-income", "個人所得資料", "財政部財政資訊中心；MyData 約需兩小時產生，完成後到個人文件下載", MYDATA + "personal/detail/API.syWqjr4flJ", myData = true),
        DocumentSource("mydata-tax-cert", "綜合所得稅納稅證明書", "財政部財政資訊中心", MYDATA + "personal/detail/API.TeV2Md7SIx", myData = true),
        DocumentSource("mydata-labor-insurance", "被保險人投保資料（勞保、就保、災保）", "勞動部勞工保險局", MYDATA + "personal/detail/API.UZQkKbsOpz", myData = true),
        DocumentSource("mydata-labor-pension", "勞工提繳異動資料", "勞動部勞工保險局", MYDATA + "personal/detail/API.yqkllwwTYl", myData = true),
        DocumentSource("mydata-health-insurance", "個人投退保資料（健保）", "衛生福利部中央健康保險署", MYDATA + "personal/detail/API.zH584wn59r", myData = true),
        DocumentSource("mydata-nhi-premium", "保費繳納紀錄（健保）", "衛生福利部中央健康保險署", MYDATA + "personal/detail/API.1qIr0nM0BT", myData = true),
        DocumentSource("mydata-land", "地籍及實價資料", "內政部地政司", MYDATA + "personal/detail/API.KvvyRZSc5K", myData = true),
    )

    val others = listOf(
        DocumentSource("mydoc", "臺北市 MyDoc 電子文件服務平台", "高中職電子畢業證書等臺北市政府電子文件", "https://mydoc.gov.taipei/"),
        DocumentSource("moe", "教育部 大專校院數位證書驗證系統", "大專校院數位學位證書的驗證與新版本檢查", "https://dcert.moe.gov.tw/"),
        DocumentSource("dcert", "數位證明管理中心", "上傳學校核發的數位 PDF 學位證書，產生 QR 碼加入數位憑證皮夾卡片", "https://dcmc.csie.ncku.edu.tw/"),
        DocumentSource("ris", "內政部戶政司 全國戶政服務", "電子戶籍謄本（.asdt 只能保存原檔，內容需送戶政司查驗）", "https://www.ris.gov.tw/app/portal/"),
        DocumentSource("land", "地政電子謄本", "土地與建物登記謄本、地籍圖謄本", "https://ep.land.nat.gov.tw/"),
        DocumentSource("nia", "內政部移民署 入出國日期證明書", "以自然人憑證登入申請入出國日期證明書，下載的 PDF 直接保存", "https://ncp.immigration.gov.tw/niaweb/entryExitQuery"),
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
}

/** Who signs a document. */
sealed class SignerChoice {
    /** The citizen digital certificate (or another GPKI) card on [reader]; the PIN is used for this signing only. */
    class Card(val reader: NfcReaderOption, val pin: String) : SignerChoice()
    /** A PKCS#12 file opened with its password. */
    class Pkcs12(val file: ByteArray, val password: String) : SignerChoice()
    /** The wallet's own key with a self-issued certificate in [name]. */
    class Wallet(val name: String) : SignerChoice()
}

/** The signature a file gets. */
enum class SignForm(val title: String, val detail: String) {
    PADES("PDF 簽章（PAdES）", "簽章寫在 PDF 內，Adobe Reader 與 DSS 可驗證；已有的簽章保持有效"),
    XADES("XML 簽章（XAdES）", "包覆在 XML 內的簽章，適用電子公文（.di）等 XML 文件"),
    CADES_DETACHED("分離式簽章檔（.p7s）", "原檔不變，另存一個簽章檔"),
    CADES_ENVELOPING("包覆式簽章檔（.p7m）", "原檔包在簽章檔內"),
    ASIC("ASiC-E 容器（.asice）", "原檔與 CAdES 簽章放在同一個容器"),
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

        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = try {
            if (!url.startsWith("http://") && !url.startsWith("https://")) emptyList()
            else {
                val r = model.http.get(url)
                val bytes = if (r.status.isSuccess()) r.bodyAsBytes() else ByteArray(0)
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
        files.value = t.enumerate().mapNotNull { key ->
            t.get(key)?.let { runCatching { DiwJson.decodeFromString(StoredFile.serializer(), it.decodeToString()) }.getOrNull() }
        }.sortedByDescending { it.addedAt }
    }

    fun file(id: String): StoredFile? = files.value.firstOrNull { it.id == id }

    suspend fun data(id: String): ByteArray =
        model.storage.getTable(dataTable).get(id)?.toByteArray() ?: throw IllegalStateException("找不到檔案內容")

    private suspend fun save(f: StoredFile) {
        val t = model.storage.getTable(metaTable)
        val bytes = DiwJson.encodeToString(StoredFile.serializer(), f).encodeToByteString()
        if (t.get(f.id) == null) t.insert(f.id, bytes) else t.update(f.id, bytes)
        files.value = (files.value.filter { it.id != f.id } + f).sortedByDescending { it.addedAt }
    }

    /** Inspects [bytes] and stores them; the same content stored before is returned instead. */
    suspend fun store(
        name: String,
        bytes: ByteArray,
        origin: FileOrigin,
        source: String? = null,
        parentId: String? = null,
        contentId: String? = null,
    ): StoredFile {
        if (bytes.isEmpty()) throw SigningException("檔案是空的")
        if (bytes.size > MAX_FILE_BYTES) throw SigningException("檔案超過 ${MAX_FILE_BYTES / 1024 / 1024} MB，無法保存")
        val detached = contentId?.let { data(it) }
        val report = DocumentInspector.inspect(bytes, name, trustSource, detached)
        files.value.firstOrNull { it.sha256 == report.sha256 }?.let { return it }
        val f = StoredFile(
            id = WalletModel.randomId(),
            name = name.ifBlank { "未命名檔案" },
            mediaType = mediaTypeOf(report, name),
            size = bytes.size.toLong(),
            sha256 = report.sha256,
            addedAt = Clock.System.now().epochSeconds,
            origin = origin,
            source = source,
            report = report,
            contentId = contentId,
            parentId = parentId,
        )
        model.storage.getTable(dataTable).insert(f.id, ByteString(bytes))
        save(f)
        if (model.settings.timestampOnSave) runCatching { addTimestampNow(f) }
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
    fun pickAndImport() = run("讀取並檢查檔案") {
        val picked = model.platform.pickFile() ?: return@run
        importNow(picked, FileOrigin.IMPORTED, null)
    }

    /** A file handed over by another app or downloaded from a source site. */
    fun import(picked: PickedFile, origin: FileOrigin, source: String?) = run("讀取並檢查檔案") { importNow(picked, origin, source) }

    private suspend fun importNow(picked: PickedFile, origin: FileOrigin, source: String?) = receive(picked, origin, source, null)

    /**
     * Stores a file that came in (picked, shared by another app, or downloaded from [site]) and carries on with it:
     * a MyData ZIP, whether downloaded here or recognised by its file name, is unpacked at once; the national ID PDF
     * opens the national ID card screen; anything else opens its detail screen. The recorded source says how the
     * file was identified: downloaded from MyData in the app, or only named like a MyData file.
     */
    private suspend fun receive(picked: PickedFile, origin: FileOrigin, source: String?, site: DocumentSource?) {
        val known = files.value.size
        val item = MyDataFiles.recognize(picked.name)
        val myData = site?.myData == true || item != null
        val label = when {
            site?.myData == true -> "MyData（App 內下載" + (item?.let { "：${it.title}" } ?: site.takeIf { !it.nationalId && it.id != "mydata" }?.let { "：${it.name}" } ?: "") + "）"
            site != null -> site.name
            item != null -> "MyData（依檔名判斷為「${item.title}」，由${source ?: origin.title}取得，未經 App 內下載確認）"
            else -> source
        }
        val f = store(picked.name, picked.bytes, origin, label)
        val children = if (myData && f.report?.format == DocumentFormat.ZIP) {
            busy.value = "解出 MyData 壓縮檔"
            extractNow(f, label).first
        } else emptyList()
        val pdfs = children.ifEmpty { listOf(f) }.filter { it.report?.format == DocumentFormat.PDF }
        val nationalId = site?.nationalId == true || item?.nationalId == true || pdfs.any { MyDataFiles.recognize(it.name)?.nationalId == true }
        if (nationalId && pdfs.isNotEmpty()) {
            val pdf = pdfs.firstOrNull { MyDataFiles.recognize(it.name)?.nationalId == true } ?: pdfs.first()
            model.message.value = "已解出 MyData 檔案，輸入身分證統一編號開啟身分證資料"
            model.screen.value = Screen.NationalIdCreate(pdf.id)
            return
        }
        val target = when {
            children.size == 1 -> children.first()
            pdfs.size == 1 && children.isNotEmpty() -> pdfs.first()
            else -> f
        }
        model.message.value = when {
            children.isNotEmpty() -> "已解出 ${children.size} 個 MyData 檔案"
            files.value.size == known -> "這份文件已經保存過"
            else -> "已保存：${f.name}"
        }
        model.screen.value = Screen.FileDetail(target.id)
    }

    /** Checks the file again with the current time and trust anchors and stores the new report. */
    suspend fun refreshed(f: StoredFile): StoredFile {
        val data = data(f.id)
        val report = DocumentInspector.inspect(data, f.name, trustSource, f.contentId?.let { data(it) })
        // Apply the report to the latest copy so changes made meanwhile (a new time stamp) are kept; the time stamps
        // are checked again too, since the trusted authorities may have changed.
        val latest = file(f.id) ?: f
        val stamps = latest.timestamps.map { t ->
            runCatching { t.copy(trusted = DocumentInspector.verifyTimestamp(t.token.fromBase64(), data, trustSource).trusted) }.getOrDefault(t)
        }
        return latest.copy(report = report, timestamps = stamps).also { save(it) }
    }

    /** Re-checks a file when it is opened; the stored report stays if the check cannot run. */
    fun refresh(id: String) = model.scope.launch {
        val f = file(id) ?: return@launch
        try {
            refreshed(f)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
        }
    }

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
            FilePreview.Unavailable("無法預覽：" + model.describe(e))
        }
        previews.value = previews.value + (f.id to result)
    }

    /**
     * [bytes] of the PDF [f] opened with [password] (also trimmed and in upper case), the password entered earlier in
     * this session, or none; null while it stays locked. A password that opens it is kept for this session.
     */
    private fun unlock(f: StoredFile, bytes: ByteArray, password: String?): PdfFile? {
        val tries = listOfNotNull(password, password?.let { BondsNationalId.normalizePassword(it) }, passwords[f.id], "").distinct()
        for (pw in tries) {
            val p = PdfFile(bytes, pw)
            if (!p.passwordRequired) {
                if (pw.isNotEmpty()) passwords[f.id] = pw
                return p
            }
        }
        return null
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
    class DeriveFields(val claims: List<DerivedClaim>, val locked: Boolean)

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
            DocumentFormat.XML -> xml = bytes.decodeToString().takeIf { it.contains("<函") }
            else -> {}
        }
        DeriveFields(DerivedCredentials.suggestedClaims(report, f.name, f.source, text, xml), locked)
    }

    private suspend fun makePreview(f: StoredFile, password: String?): FilePreview {
        val bytes = data(f.id)
        return when (f.report?.format) {
            DocumentFormat.PDF -> {
                val pdf = unlock(f, bytes, password) ?: return FilePreview.NeedsPassword(wrong = password != null)
                pdf.encryptionProblem?.let { return FilePreview.Unavailable("無法解密這份 PDF：$it") }
                val plain = if (pdf.encrypted) PdfPlain.of(pdf) else bytes
                val pages = model.platform.renderPdf(plain, FilePreview.PREVIEW_PAGES, PREVIEW_WIDTH)
                val text = runCatching { PdfTextExtractor.extract(pdf, FilePreview.PREVIEW_PAGES) }.getOrNull()?.trim()?.ifEmpty { null }
                val total = runCatching { PdfTextExtractor.pages(pdf).size }.getOrDefault(pages.size)
                if (pages.isEmpty() && text == null) FilePreview.Unavailable("這個平台無法繪製這份 PDF，也沒有可擷取的文字")
                else FilePreview.Pages(pages, total, text)
            }
            DocumentFormat.IMAGE -> model.platform.decodeImage(bytes)?.let { FilePreview.Picture(it) }
                ?: FilePreview.Unavailable("無法解碼這張圖片")
            DocumentFormat.XML, DocumentFormat.JSON, DocumentFormat.TEXT, DocumentFormat.OPENCERTS -> {
                val text = bytes.decodeToString()
                FilePreview.Text(text.take(FilePreview.TEXT_LIMIT), text.length > FilePreview.TEXT_LIMIT)
            }
            DocumentFormat.ZIP, DocumentFormat.ASIC_E, DocumentFormat.OFD -> FilePreview.Unavailable("壓縮檔與容器請看下方的內容清單；ZIP 解出後可逐一預覽")
            DocumentFormat.CMS_ENVELOPED -> FilePreview.Unavailable("加密給特定對象的檔案，錢包無法開啟內容")
            else -> {
                // A signature with its content inside (.p7m) previews the content when it is a known kind.
                val inner = runCatching { DocumentInspector.encapsulatedContent(bytes) }.getOrNull()
                when {
                    inner != null && PdfFile.isPdf(inner) -> model.platform.renderPdf(inner, FilePreview.PREVIEW_PAGES, PREVIEW_WIDTH)
                        .takeIf { it.isNotEmpty() }?.let { FilePreview.Pages(it, it.size, null) } ?: FilePreview.Unavailable("無法繪製包覆的 PDF")
                    inner != null && runCatching { inner.decodeToString(throwOnInvalidSequence = true) }.isSuccess ->
                        inner.decodeToString().let { FilePreview.Text(it.take(FilePreview.TEXT_LIMIT), it.length > FilePreview.TEXT_LIMIT) }
                    else -> FilePreview.Unavailable("這種格式沒有內容預覽")
                }
            }
        }
    }

    /** Checks the file again with the current trust anchors. */
    fun reinspect(f: StoredFile) = run("重新檢查簽章") { refreshed(f) }

    /** Pairs a detached signature (.p7s) with the file it signs and checks it again. */
    fun attachContent(signature: StoredFile, content: StoredFile) = run("檢查分離式簽章") {
        val report = DocumentInspector.inspect(data(signature.id), signature.name, trustSource, data(content.id))
        save(signature.copy(report = report, contentId = content.id))
    }

    /** Stores every file of a ZIP archive (a MyData download) as its own entry. */
    fun extract(f: StoredFile) = run("解出壓縮檔") {
        val added = extractNow(f, f.source).second
        model.message.value = "已解出 $added 個檔案"
    }

    /** The files of the archive [f] as stored (new or already there), and how many were new. */
    private suspend fun extractNow(f: StoredFile, source: String?): Pair<List<StoredFile>, Int> {
        val entries = DocumentSigning.unzip(data(f.id))
        val stored = ArrayList<StoredFile>()
        var added = 0
        for ((path, bytes) in entries) {
            if (bytes.isEmpty()) continue
            val before = files.value.size
            val name = path.substringAfterLast('/')
            // The source names the archive and, for MyData, the item the file is.
            val item = MyDataFiles.recognize(name) ?: MyDataFiles.recognize(f.name)
            val label = (source?.let { "$it；" } ?: "") + "解自 ${f.name}" + (item?.let { "（${it.title}）" } ?: "")
            stored.add(store(name, bytes, FileOrigin.EXTRACTED, label, parentId = f.id))
            if (files.value.size > before) added++
        }
        return stored to added
    }

    /** A download from a source site in the app. */
    fun importDownload(picked: PickedFile, src: DocumentSource) = run("保存並檢查下載的文件") {
        receive(picked, FileOrigin.DOWNLOADED, src.name, src)
    }

    fun timestamper(): Timestamper = TsaClient(model.http, TsaServices.byId(model.settings.tsaId).url)

    /** Gets an RFC 3161 time stamp over the file from the chosen authority (only the hash is sent). */
    fun addTimestamp(f: StoredFile) = run("向時戳機構取得時戳") { addTimestampNow(f) }

    private suspend fun addTimestampNow(f: StoredFile) {
        val data = data(f.id)
        val token = timestamper().timestamp(data)
        val info = DocumentInspector.verifyTimestamp(token, data, trustSource)
        val stamp = StoredTimestamp(token.toBase64(), info.time, info.tsa, info.trusted)
        save((file(f.id) ?: f).let { it.copy(timestamps = it.timestamps + stamp) })
        model.message.value = if (info.trusted) "已加上時戳（${info.tsa ?: "時戳機構"}）" else "已加上時戳，但時戳機構不在信任錨點"
    }

    fun export(f: StoredFile) = run("匯出檔案") {
        if (!model.platform.saveFile(f.name, f.mediaType, data(f.id))) model.message.value = "未匯出"
    }

    /** Exports the vc+moica form of the derived credential (Bonds self-issued card). */
    fun exportMoica(f: StoredFile) = run("匯出 vc+moica") {
        val moica = f.moica ?: throw SigningException("這份文件沒有以自然人憑證簽署的衍生憑證")
        val name = f.name.substringBeforeLast('.') + ".vc-moica.json"
        if (!model.platform.saveFile(name, "application/vc+moica", moica.encodeToByteArray())) model.message.value = "未匯出"
    }

    fun delete(f: StoredFile) = run("刪除檔案") {
        model.storage.getTable(dataTable).delete(f.id)
        model.storage.getTable(metaTable).delete(f.id)
        files.value = files.value.filter { it.id != f.id }
        model.showTab(HomeTab.FILES)
    }

    // ---------------------------------------------------------------- signing

    /** Forms that apply to [f]: PAdES for PDF, XAdES for XML, and CAdES and ASiC-E for any file. */
    fun formsFor(f: StoredFile): List<SignForm> = buildList {
        when (f.report?.format) {
            DocumentFormat.PDF -> if (f.report.encrypted != true) add(SignForm.PADES)
            DocumentFormat.XML -> add(SignForm.XADES)
            else -> {}
        }
        add(SignForm.CADES_DETACHED)
        add(SignForm.CADES_ENVELOPING)
        add(SignForm.ASIC)
    }

    /** Signs [f] as [form]; the signed result is stored as a new file. */
    fun sign(f: StoredFile, choice: SignerChoice, form: SignForm, reason: String, location: String, timestamp: Boolean) = run("準備簽署") {
        val data = data(f.id)
        val signer = withContext(model.unlockProvider) { signer(choice) }
        val ts = if (timestamp) timestamper() else null
        busy.value = if (choice is SignerChoice.Card) "簽署中：依提示再次感應卡片" else "簽署中"
        val signerName = DocumentSigning.certificateSummary(signer.certificateChain.first())?.first
        val base = f.name.substringBeforeLast('.')
        val (bytes, name) = withContext(model.unlockProvider) {
            when (form) {
                SignForm.PADES -> DocumentSigning.signPdf(
                    data, signer,
                    PdfSignOptions(reason = reason.ifBlank { null }, location = location.ifBlank { null }, signerName = signerName), ts,
                ) to "$base-signed.pdf"
                SignForm.XADES -> DocumentSigning.signXml(data, signer, ts) to (base + "-signed." + f.name.substringAfterLast('.', "xml"))
                SignForm.CADES_DETACHED -> DocumentSigning.signCades(data, signer, true, ts) to "${f.name}.p7s"
                SignForm.CADES_ENVELOPING -> DocumentSigning.signCades(data, signer, false, ts) to "${f.name}.p7m"
                SignForm.ASIC -> DocumentSigning.buildAsic(listOf(f.name to data), signer, ts) to "$base.asice"
            }
        }
        busy.value = "檢查並保存簽署結果"
        val stored = store(name, bytes, FileOrigin.SIGNED, f.name, parentId = f.id, contentId = if (form == SignForm.CADES_DETACHED) f.id else null)
        model.record(HistoryKind.SIGNED, signerName ?: signer.source.title, null, listOf(f.name), note = "${form.title}，以${signer.source.title}簽署")
        model.message.value = "已簽署並保存：${stored.name}"
        model.screen.value = Screen.FileDetail(stored.id)
    }

    private suspend fun signer(choice: SignerChoice): DocumentSigner = when (choice) {
        is SignerChoice.Card -> cardSigner(choice)
        is SignerChoice.Pkcs12 -> DocumentSigning.pkcs12Signer(choice.file, choice.password)
        is SignerChoice.Wallet -> walletSigner(choice.name)
    }

    /** A card signer with its certificate read (first tap); MOICA G3 is added to the chain when it issued the card. */
    private suspend fun cardSigner(choice: SignerChoice.Card): GpkiTapSigner {
        busy.value = if (choice.reader.external) "請把卡片放到讀卡機「${choice.reader.name}」" else "請將自然人憑證卡靠近手機背面"
        val moica = TwPkiAnchors.moicaG3.encoded.toByteArray()
        val probe = GpkiTapSigner(choice.reader.reader, choice.pin)
        val cert = probe.load()
        val intermediates = if (PlatformCrypto.certificateSignedBy(cert, moica)) listOf(moica) else emptyList()
        return if (intermediates.isEmpty()) probe else GpkiTapSigner(choice.reader.reader, choice.pin, intermediates).also { it.load() }
    }

    /** The wallet's own P-256 key (document-signer identity) with a self-issued certificate in [name]. */
    private suspend fun walletSigner(name: String): DocumentSigner {
        val key = identity(HolderIdentities.DOCUMENT_SIGNER)
        val subject = name.trim().ifEmpty { "DIW MY WALLET 使用者" }
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

    // ---------------------------------------------------------------- composing

    /** Writes a PDF with [title] and [body] (paragraphs separated by blank lines) and stores it. */
    fun composePdf(title: String, body: String, author: String) = run("製作 PDF") {
        val blocks = buildList {
            add(PdfComposer.Block.Heading(title))
            add(PdfComposer.Block.Spacer())
            body.split(Regex("\\n\\s*\\n")).filter { it.isNotBlank() }.forEach { add(PdfComposer.Block.Paragraph(it.trim())); add(PdfComposer.Block.Spacer(6.0)) }
        }
        val pdf = PdfComposer.compose(title, blocks, author = author.ifBlank { null })
        val f = store(safeName(title) + ".pdf", pdf, FileOrigin.COMPOSED)
        model.message.value = "已製作：${f.name}"
        model.screen.value = Screen.FileDetail(f.id)
    }

    /** Writes an official letter (.di) and stores it; it can then be signed with XAdES. */
    fun composeLetter(letter: OfficialLetter) = run("製作公文") {
        val f = store(safeName(letter.subject.take(30)) + ".di", letter.toXml(), FileOrigin.LETTER)
        model.message.value = "已製作公文：${f.name}"
        model.screen.value = Screen.FileDetail(f.id)
    }

    // ---------------------------------------------------------------- derived credentials

    /**
     * Derives a credential from [f]: an SD-JWT VC with [claims] in the documents list, with the document check and
     * a time stamp as evidence; with [card], the citizen certificate signs the same claims (vc+moica, cardholder
     * name added from the certificate).
     */
    fun derive(f: StoredFile, claims: List<DerivedClaim>, card: SignerChoice.Card?, timestamp: Boolean, validDays: Int?) = run("產生衍生憑證") {
        val data = data(f.id)
        // The evidence states the result as of now, never a report cached from an earlier check.
        val report = refreshed(f).report ?: DocumentInspector.inspect(data, f.name, trustSource)
        val now = Clock.System.now()
        val validUntil = validDays?.let { now + it.days }
        val document = DerivedDocument(f.sha256, f.mediaType, f.size)
        val evidence = buildList {
            add(DerivedCredentials.signatureEvidence(report))
            val stamp = f.timestamps.lastOrNull { it.trusted }?.let { it.token.fromBase64() }
                ?: if (timestamp) { busy.value = "向時戳機構取得時戳"; timestamper().timestamp(data) } else null
            stamp?.let { add(DerivedCredentials.timestampEvidence(it, DocumentInspector.verifyTimestamp(it, data, trustSource))) }
        }
        val cardSigner = card?.let { cardSigner(it) }
        val all = if (cardSigner != null) {
            val cn = DocumentSigning.certificateSummary(cardSigner.certificateChain.first())?.first
                ?: throw SigningException("讀不到卡片憑證上的姓名")
            claims.filter { it.name != DerivedCredentials.CLAIM_NAME } + DerivedClaim(DerivedCredentials.CLAIM_NAME, cn)
        } else claims
        if (all.isEmpty()) throw SigningException("請至少選擇一個欄位")
        val disclosures = DerivedCredentials.disclosures(all)
        val doc = withContext(model.unlockProvider) {
            val moica = cardSigner?.let { signer ->
                val self = identity(HolderIdentities.BONDS_SELF_ISSUED)
                val payload = DerivedCredentials.moicaPayload(self.did!!, document, evidence, disclosures, now, validUntil)
                busy.value = "簽署中：依提示再次感應卡片"
                DerivedCredentials.signMoica(payload, disclosures, self, signer)
            }
            busy.value = "產生衍生憑證"
            val issuer = identity(HolderIdentities.DOCUMENT_ISSUER)
            val keys = model.keyRequest()
            val title = all.firstOrNull { it.name == DerivedCredentials.CLAIM_TITLE }?.value ?: f.name
            val record = IssuanceRecord(
                credentialIssuer = issuer.did!!,
                configurationId = CONFIGURATION,
                format = "dc+sd-jwt",
                vct = DerivedCredentials.VCT,
                tier = TrustTier.T3.name,
                environment = TrustEnvironment.USER.id,
                official = false,
                anchorName = "本錢包（文件衍生）",
                issuedAt = now.epochSeconds,
                keyStorage = keys.keyStorage,
                specs = listOfNotNull("IETF SD-JWT VC", if (moica != null) "Bonds vc+moica" else null),
                claimNames = DerivedCredentials.claimLabels + all.filter { it.label != null }.associate { it.name to it.label!! },
                profile = PROFILE,
            )
            val created = model.documentStore.createDocument(displayName = title, typeDisplayName = "文件衍生憑證", appData = record.encode())
            try {
                val credential = KeyBoundSdJwtVcCredential.create(
                    created, null, CredentialDomains.SD_JWT, keys.secureArea, DerivedCredentials.VCT,
                    keys.createKeySettings(ByteString(PlatformCrypto.randomBytes(16))),
                )
                val holderKey = credential.secureArea.getKeyInfo(credential.alias).publicKey
                val compact = DerivedCredentials.sdJwtVc(issuer, holderKey, document, evidence, disclosures, moica, now, validUntil)
                credential.certify(compact.encodeToByteString())
                created.edit { provisioned = true }
            } catch (e: Exception) {
                model.documentStore.deleteDocument(created.identifier)
                throw e
            }
            save(f.copy(derivedDocumentId = created.identifier, moica = moica?.serialized() ?: f.moica))
            created
        }
        model.documents.value = model.documentStore.listDocuments()
        model.platform.registerDigitalCredentials(model)
        model.record(HistoryKind.ISSUED, "本錢包（文件衍生）", null, listOf(doc.displayName ?: f.name), all.map { DerivedCredentials.labelOf(it) })
        model.message.value = "已產生衍生憑證，可在「證件」出示"
        model.screen.value = Screen.FileDetail(f.id)
    }

    /** Vault files whose derived credential can answer a Bonds request for a self-issued card. */
    fun moicaCards(): List<Pair<StoredFile, MoicaSignedCredential>> =
        files.value.mapNotNull { f -> f.moica?.let { m -> runCatching { MoicaSignedCredential.parse(m) }.getOrNull()?.let { f to it } } }

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
    fun readNationalId(f: StoredFile, idNumber: String) = run("開啟並讀取身分證資料") {
        nationalIdDraft.value = null
        val bytes = data(f.id)
        val text = withContext(Dispatchers.Default) { BondsNationalId.readPdf(bytes, idNumber) }
        passwords[f.id] = listOf(idNumber, BondsNationalId.normalizePassword(idNumber)).first { !PdfFile(bytes, it).passwordRequired }
        val fields = BondsNationalId.parse(text) ?: throw SigningException("這份 PDF 不是 MyData 的國民身分證資料（找不到統號、姓名或出生日期）")
        if (fields.unifiedNo == null || fields.name == null) throw SigningException("讀不到身分證統一編號或姓名，無法製作身分證卡")
        nationalIdDraft.value = NationalIdDraft(f.id, fields, BondsNationalId.over18(fields.birthdate, Clock.System.now()))
    }

    /** Signs the confirmed fields with the citizen certificate card and stores the card with the file. */
    fun issueNationalId(draft: NationalIdDraft, card: SignerChoice.Card) =
        issueNationalId(draft, if (card.reader.external) "簽署中" else "簽署中：依提示再次感應卡片") { cardSigner(card) }

    /** Signs with the RSA certificate [signer] gives (the card, read with its first tap); tests pass their own. */
    internal fun issueNationalId(draft: NationalIdDraft, signing: String, signer: suspend () -> DocumentSigner) = run("製作身分證卡") {
        val f = file(draft.fileId) ?: throw SigningException("找不到身分證資料檔案")
        val cardSigner = signer()
        val issued = withContext(model.unlockProvider) {
            val self = identity(HolderIdentities.BONDS_SELF_ISSUED)
            busy.value = signing
            BondsNationalId.issue(draft.fields, self, cardSigner)
        }
        save((file(f.id) ?: f).copy(nationalId = issued.serialized()))
        nationalIdDraft.value = null
        model.record(
            HistoryKind.ISSUED, "本人（自然人憑證簽署）", null, listOf("國民身分證（Bonds 自發卡）"),
            BondsNationalId.claims(draft.fields, Clock.System.now()).map { BondsNationalId.claimLabels[it.first] ?: it.first },
        )
        model.message.value = "已製作身分證卡，可回應 Bonds 的自然人憑證自發卡查驗"
        model.screen.value = Screen.NationalId(f.id)
    }

    /** Exports the national ID card as Bonds vc+moica JSON. */
    fun exportNationalId(f: StoredFile) = run("匯出身分證卡") {
        val card = f.nationalId ?: throw SigningException("這份文件沒有身分證卡")
        if (!model.platform.saveFile("national-id.vc-moica.json", "application/vc+moica", card.encodeToByteArray())) model.message.value = "未匯出"
    }

    /** Removes the national ID card; the PDF it was made from stays in the vault. */
    fun deleteNationalId(f: StoredFile) = run("刪除身分證卡") {
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
        private val metaTable = StorageTableSpec(name = "DiwFiles", supportPartitions = false, supportExpiration = false)
        private val dataTable = StorageTableSpec(name = "DiwFileData", supportPartitions = false, supportExpiration = false)

        fun mediaTypeOf(report: DocumentReport, name: String): String = when (report.format) {
            DocumentFormat.IMAGE -> when (name.substringAfterLast('.', "").lowercase()) {
                "png" -> "image/png"
                "jpg", "jpeg" -> "image/jpeg"
                "webp" -> "image/webp"
                "gif" -> "image/gif"
                else -> "image/*"
            }
            else -> report.format.mediaType
        }

        fun safeName(s: String): String = s.map { if (it in "\\/:*?\"<>|" || it.code < 0x20) '_' else it }.joinToString("").trim().ifEmpty { "document" }

        /** SubjectPublicKeyInfo DER of a P-256 public key. */
        fun spki(key: EcPublicKey): ByteArray {
            val k = key as? EcPublicKeyDoubleCoordinate ?: throw SigningException("錢包金鑰不是 P-256")
            val prefix = "3059301306072a8648ce3d020106082a8648ce3d030107034200"
            val head = ByteArray(prefix.length / 2) { prefix.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            return head + byteArrayOf(0x04) + k.x + k.y
        }
    }
}
