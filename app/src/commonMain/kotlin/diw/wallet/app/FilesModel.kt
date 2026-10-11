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
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.profile.bonds.TwPkiAnchors
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
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
)

/** A site where a holder gets an official document (opened in the app on Android, downloads go to the vault). */
class DocumentSource(val id: String, val name: String, val detail: String, val url: String)

object DocumentSources {
    val all = listOf(
        DocumentSource("mydata", "MyData 個人化資料自主運用", "以自然人憑證或行動自然人憑證登入，下載戶籍、地籍、所得等資料（ZIP 會解出逐一保存）", "https://mydata.nat.gov.tw/"),
        DocumentSource("mydoc", "臺北市 MyDoc 電子文件服務平台", "高中職電子畢業證書等臺北市政府電子文件", "https://mydoc.gov.taipei/"),
        DocumentSource("moe", "教育部 大專校院數位證書驗證系統", "大專校院數位學位證書的驗證與新版本檢查", "https://dcert.moe.gov.tw/"),
        DocumentSource("dcert", "數位證明管理中心", "加入的學校可直接產生數位憑證（數位憑證皮夾卡片）", "https://dcert.wallet.gov.tw/"),
        DocumentSource("ris", "內政部戶政司 全國戶政服務", "電子戶籍謄本（.asdt 只能保存原檔，內容需送戶政司查驗）", "https://www.ris.gov.tw/app/portal/"),
        DocumentSource("land", "地政電子謄本", "土地與建物登記謄本、地籍圖謄本", "https://ep.land.nat.gov.tw/"),
        DocumentSource("nia", "內政部移民署 入出國日期證明書", "線上申請入出國日期證明書；查驗頁可確認證明書真偽", "https://ncp.immigration.gov.tw/NIA_OnlineApply_inter/entryexitQuery/entryexitQueryForm.action"),
    )

    fun byId(id: String) = all.firstOrNull { it.id == id }
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

    private suspend fun importNow(picked: PickedFile, origin: FileOrigin, source: String?) {
        val known = files.value.size
        val f = store(picked.name, picked.bytes, origin, source)
        model.message.value = if (files.value.size == known) "這份文件已經保存過" else "已保存：${f.name}"
        model.screen.value = Screen.FileDetail(f.id)
    }

    /** Checks the file again with the current time and trust anchors and stores the new report. */
    suspend fun refreshed(f: StoredFile): StoredFile {
        val report = DocumentInspector.inspect(data(f.id), f.name, trustSource, f.contentId?.let { data(it) })
        // Apply the report to the latest copy so changes made meanwhile (a new time stamp) are kept.
        return (file(f.id) ?: f).copy(report = report).also { save(it) }
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

    /** Checks the file again with the current trust anchors. */
    fun reinspect(f: StoredFile) = run("重新檢查簽章") { refreshed(f) }

    /** Pairs a detached signature (.p7s) with the file it signs and checks it again. */
    fun attachContent(signature: StoredFile, content: StoredFile) = run("檢查分離式簽章") {
        val report = DocumentInspector.inspect(data(signature.id), signature.name, trustSource, data(content.id))
        save(signature.copy(report = report, contentId = content.id))
    }

    /** Stores every file of a ZIP archive (a MyData download) as its own entry. */
    fun extract(f: StoredFile) = run("解出壓縮檔") {
        val entries = DocumentSigning.unzip(data(f.id))
        var added = 0
        for ((path, bytes) in entries) {
            if (bytes.isEmpty()) continue
            val before = files.value.size
            store(path.substringAfterLast('/'), bytes, FileOrigin.EXTRACTED, f.name, parentId = f.id)
            if (files.value.size > before) added++
        }
        model.message.value = "已解出 $added 個檔案"
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
                claimNames = DerivedCredentials.claimLabels,
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
        model.record(HistoryKind.ISSUED, "本錢包（文件衍生）", null, listOf(doc.displayName ?: f.name), all.map { DerivedCredentials.claimLabels[it.name] ?: it.name })
        model.message.value = "已產生衍生憑證，可在「證件」出示"
        model.screen.value = Screen.FileDetail(f.id)
    }

    /** Vault files whose derived credential can answer a Bonds request for a self-issued card. */
    fun moicaCards(): List<Pair<StoredFile, MoicaSignedCredential>> =
        files.value.mapNotNull { f -> f.moica?.let { m -> runCatching { MoicaSignedCredential.parse(m) }.getOrNull()?.let { f to it } } }

    companion object {
        const val PROFILE = "document"
        const val CONFIGURATION = "document-derived"
        const val MAX_FILE_BYTES = 64 * 1024 * 1024
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
