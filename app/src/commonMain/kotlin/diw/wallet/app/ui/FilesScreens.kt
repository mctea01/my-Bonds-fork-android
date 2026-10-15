package diw.wallet.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.produceState
import diw.wallet.app.FilesModel
import androidx.compose.runtime.Composable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import diw.wallet.app.FilePreview
import diw.wallet.core.document.official.OfficialDocument
import diw.wallet.core.document.official.OfficialEntry
import diw.wallet.core.document.official.OfficialItem
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import diw.wallet.app.DocumentSources
import diw.wallet.app.FileOrigin
import diw.wallet.app.HomeTab
import diw.wallet.app.NfcReaderList
import diw.wallet.app.NfcReaderOption
import diw.wallet.app.PickedFile
import diw.wallet.app.Screen
import diw.wallet.app.SignForm
import diw.wallet.app.SignerChoice
import diw.wallet.app.ExternalKeyOption
import diw.wallet.app.MobileMoicaSp
import diw.wallet.core.document.sign.MobileMoicaEnvironment
import diw.wallet.core.document.sign.MobileMoicaMode
import diw.wallet.app.StoredFile
import diw.wallet.app.WalletModel
import diw.wallet.app.CredentialDetails
import diw.wallet.core.profile.bonds.MoicaVerification
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.profile.bonds.MyDataProfile
import diw.wallet.core.document.Check
import diw.wallet.core.document.CertInfo
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.LaterChanges
import diw.wallet.core.document.SignatureInfo
import diw.wallet.core.document.TimestampInfo
import diw.wallet.core.document.card.GpkiCard
import diw.wallet.core.document.derived.DerivedClaim
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.EvidenceResult
import diw.wallet.core.document.sign.TsaServices
import kotlinx.coroutines.launch
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import diw.wallet.core.document.OpenCertInfo
import diw.wallet.core.document.opencerts.OaMethod
import diw.wallet.core.document.opencerts.OpenCertView
import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64
import kotlin.time.Instant

/** A script the source site runs on its pages at [host] only (MyData sign-in values), and what to do when it fills inputs. */
class PortalAutofill(val host: String, val script: String, val onFilled: (Int) -> Unit)

/** A site page shown inside the app; downloads come back as [onFile], links for other apps go to [onExternal]. */
@Composable
expect fun PortalWebView(url: String, modifier: Modifier, onFile: (PickedFile) -> Unit, onExternal: (String) -> Unit, onError: (String) -> Unit, autofill: PortalAutofill? = null)

/**
 * The host page of an OpenCerts renderer ([html], see OpenCertRenderer): inside the app where a web view exists,
 * otherwise opened in the system browser on request. Links the renderer opens go to [onExternal].
 */
@Composable
expect fun OpenCertRendererView(html: String, modifier: Modifier, onExternal: (String) -> Unit)

internal fun localTime(epochSeconds: Long): String {
    val t = Instant.fromEpochSeconds(epochSeconds).toLocalDateTime(TimeZone.currentSystemDefault())
    fun two(n: Int) = n.toString().padStart(2, '0')
    return "${t.year}-${two(t.month.ordinal + 1)}-${two(t.day)} ${two(t.hour)}:${two(t.minute)}"
}

internal fun sizeText(size: Long): String = when {
    size < 1024 -> "$size B"
    size < 1024 * 1024 -> "${size / 1024} KB"
    else -> "${size / 1024 / 1024}.${(size % (1024 * 1024)) * 10 / (1024 * 1024)} MB"
}

private fun verdictOf(v: DocumentVerdict): Pair<Verdict, String> = when (v) {
    DocumentVerdict.VALID -> Verdict.PASS to "簽章有效"
    DocumentVerdict.PARTIAL -> Verdict.CAUTION to "簽章部分通過"
    DocumentVerdict.INVALID -> Verdict.FAIL to "簽章無效"
    DocumentVerdict.UNSIGNED -> Verdict.CAUTION to "沒有簽章"
}

private fun checkVerdict(c: Check): Verdict = when (c) {
    Check.PASS -> Verdict.PASS
    Check.FAIL -> Verdict.FAIL
    else -> Verdict.CAUTION
}

private fun checkText(c: Check): String = when (c) {
    Check.PASS -> "通過"
    Check.WARN -> "需留意"
    Check.FAIL -> "失敗"
    Check.NOT_CHECKED -> "無法檢查"
}

private fun formatTitle(f: DocumentFormat): String = when (f) {
    DocumentFormat.PDF -> "PDF"
    DocumentFormat.CMS_SIGNED -> "CMS 簽章（PKCS#7）"
    DocumentFormat.CMS_ENVELOPED -> "CMS 加密信封（PKCS#7）"
    DocumentFormat.TIMESTAMP -> "RFC 3161 時戳"
    DocumentFormat.XML -> "XML"
    DocumentFormat.OFD -> "OFD"
    DocumentFormat.ASIC_E -> "ASiC-E 容器"
    DocumentFormat.ZIP -> "ZIP 壓縮檔"
    DocumentFormat.OPENCERTS -> "OpenCerts（OpenAttestation）"
    DocumentFormat.JSON -> "JSON"
    DocumentFormat.IMAGE -> "圖片"
    DocumentFormat.TEXT -> "文字檔"
    DocumentFormat.OTHER -> "其他檔案"
}

// ---------------------------------------------------------------- files tab

/**
 * Files and official documents, as Bonds keeps its MyData vault and official document inbox beside the cards: the
 * stored files with their signature checks, the sites that issue documents, and making and signing documents.
 */
@Composable
fun FilesTab(model: WalletModel) {
    val files by model.files.files.collectAsState()
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(Tokens.ContainerRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(WalletIcons.Document, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                Text("文件與公文", style = MaterialTheme.typography.titleLarge)
                Text("簽章文件、檔案與電子公文保存在這支裝置，連同簽章、時戳與憑證鏈的檢查結果；也可以用自然人憑證簽署，或把文件變成可出示的衍生憑證。",
                    style = MaterialTheme.typography.bodyMedium)
                Button(onClick = { model.files.pickAndImport() }, enabled = busy == null) {
                    Icon(WalletIcons.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("匯入文件")
                }
            }
        }
        BusyLine(busy, error)
        SectionTitle("我的文件")
        if (files.isEmpty()) {
            Text("還沒有文件。匯入 PDF、XML（公文）、OFD、.p7s／.p7m、ASiC-E、ZIP（MyData）、OpenCerts 等檔案，或從下方的來源網站取得。",
                style = MaterialTheme.typography.bodySmall)
        }
        files.forEach { f ->
            FileRow(f) { model.screen.value = Screen.FileDetail(f.id) }
        }
        SectionTitle("取得文件")
        Text(
            if (model.platform.embeddedBrowser) "在 App 內開啟來源網站，下載的文件直接保存到這裡；需要行動自然人憑證登入時會轉到官方 App。"
            else "在系統瀏覽器開啟來源網站，下載後用「匯入文件」保存。",
            style = MaterialTheme.typography.bodySmall,
        )
        Text("MyData", style = MaterialTheme.typography.titleSmall)
        DocumentSources.myData.forEach { src ->
            ActionRow(if (src.nationalId) WalletIcons.Person else WalletIcons.Government, src.name, src.detail) {
                if (model.platform.embeddedBrowser) model.screen.value = Screen.Portal(src.id) else model.platform.openBrowser(src.url)
            }
        }
        Text("其他來源", style = MaterialTheme.typography.titleSmall)
        DocumentSources.others.forEach { src ->
            ActionRow(WalletIcons.Government, src.name, src.detail) {
                if (model.platform.embeddedBrowser) model.screen.value = Screen.Portal(src.id) else model.platform.openBrowser(src.url)
            }
        }
        SectionTitle("電子公文收發")
        ActionRow(WalletIcons.Send, "公文交換（收發）", "需要機關的公文電子交換帳號與憑證，個人錢包目前無法收發；收到的公文檔案可匯入保存與檢查", enabled = false) {}
        SectionTitle("遠端與行動簽章")
        Text("行動自然人憑證簽章已加入文件的「簽署」，需要內政部核發的服務提供者（SP）帳號，供持有 SP 授權者測試。",
            style = MaterialTheme.typography.bodySmall)
        ActionRow(WalletIcons.Link, "CSC 遠端簽章", "需要遠端簽章服務商的帳號與 CSC API 授權，尚無可用的服務商", enabled = false) {}
    }
}

@Composable
internal fun BusyLine(busy: String?, error: String?) {
    busy?.let {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            CircularProgressIndicator(Modifier.size(18.dp))
            Text(it, style = MaterialTheme.typography.bodyMedium)
        }
    }
    error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
}

@Composable
private fun FileRow(f: StoredFile, onClick: () -> Unit) {
    val (verdict, text) = f.report?.let { verdictOf(it.verdict) } ?: (Verdict.CAUTION to "尚未檢查")
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(WalletIcons.Document, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(f.report?.title ?: f.name, style = MaterialTheme.typography.titleSmall)
                Text(listOfNotNull(f.report?.format?.let { formatTitle(it) }, sizeText(f.size), f.origin.title, localTime(f.addedAt)).joinToString("　"),
                    style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    VerdictPill(verdict, text)
                    if (f.timestamps.isNotEmpty()) VerdictPill(if (f.timestamps.any { it.trusted }) Verdict.PASS else Verdict.CAUTION, "時戳")
                    if (f.derivedDocumentId != null) VerdictPill(Verdict.PASS, "已衍生憑證")
                    if (f.nationalId != null) VerdictPill(Verdict.PASS, "身分證卡")
                }
            }
        }
    }
}

// ---------------------------------------------------------------- file detail

@Composable
fun FileDetailScreen(model: WalletModel, screen: Screen.FileDetail) {
    val files by model.files.files.collectAsState()
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val docs by model.documents.collectAsState()
    val f = files.firstOrNull { it.id == screen.fileId }
    // Every open checks the signatures again with the current time and trust anchors.
    LaunchedEffect(screen.fileId) { model.files.refresh(screen.fileId) }
    if (f == null) {
        EmptyState(WalletIcons.Document, "找不到這份文件", "文件可能已刪除。", "回到文件") { model.showTab(HomeTab.FILES) }
        return
    }
    val report = f.report
    var confirmDelete by remember { mutableStateOf(false) }
    var pickContent by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        BusyLine(busy, error)
        if (report != null) ReportVerdict(report)
        SectionTitle("文件")
        LabelValue("檔名", f.name)
        report?.title?.let { LabelValue("標題", it) }
        LabelValue("格式", report?.format?.let { formatTitle(it) } ?: f.mediaType)
        LabelValue("大小", sizeText(f.size))
        report?.pages?.let { LabelValue("頁數", "$it") }
        LabelValue("保存時間", localTime(f.addedAt))
        LabelValue("來源", f.source ?: f.origin.title)
        if (f.source != null || f.archive != null) LabelValue("取得方式", f.origin.title + (f.archive?.let { "（$it）" } ?: ""))
        LabelValue("SHA-256", f.sha256, small = true)
        f.contentId?.let { id -> files.firstOrNull { it.id == id } }?.let { c ->
            LabelValue("簽署的檔案", c.name, onClick = { model.screen.value = Screen.FileDetail(c.id) })
        }
        // An OpenCerts certificate is shown field by field below rather than as JSON text.
        if (report?.format != DocumentFormat.OPENCERTS) FilePreviewSection(model, f)
        if (report != null) {
            report.signatures.forEachIndexed { i, s -> SignatureCard(model, s, i, report.signatures.size) }
            report.envelope?.let { e ->
                SectionTitle("加密信封")
                Text("這是加密給特定對象的檔案（CMS EnvelopedData），錢包無法開啟內容，只能保存原檔。", style = MaterialTheme.typography.bodySmall)
                e.recipients.forEach { LabelValue("收件者", it, small = true) }
                e.contentEncryption?.let { LabelValue("內容加密", it, small = true) }
            }
            report.openCert?.let { oc -> OpenCertSection(model, f, oc, busy) }
            if (report.entries.isNotEmpty()) {
                SectionTitle("容器內的檔案")
                report.entries.take(50).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                if (report.entries.size > 50) Text("另有 ${report.entries.size - 50} 個檔案", style = MaterialTheme.typography.bodySmall)
            }
            report.notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            report.problems.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            Text("檢查時間：${localTime(report.checkedAt)}", style = MaterialTheme.typography.bodySmall)
        }
        SectionTitle("時戳")
        if (f.timestamps.isEmpty()) Text("還沒有時戳。時戳由時戳機構證明這份檔案在某個時間已存在，只會送出檔案的 SHA-256。", style = MaterialTheme.typography.bodySmall)
        f.timestamps.forEach { t ->
            VerdictPill(if (t.trusted) Verdict.PASS else Verdict.CAUTION, "${t.tsa ?: "時戳機構"}　${localTime(t.time)}" + if (t.trusted) "" else "（機構不在信任錨點）")
        }
        OutlinedButton(onClick = { model.files.addTimestamp(f) }, enabled = busy == null) {
            Text("加上時戳（${TsaServices.byId(model.settings.tsaId).name}）")
        }
        SectionTitle("衍生憑證")
        val derived = f.derivedDocumentId?.let { id -> docs.firstOrNull { it.identifier == id } }
        if (derived != null) {
            ActionRow(WalletIcons.Card, derived.displayName ?: "文件衍生憑證", "在「證件」出示：IETF SD-JWT VC，由本錢包的文件發行金鑰簽發") {
                model.screen.value = Screen.DocumentDetail(derived.identifier, Screen.FileDetail(f.id))
            }
        } else {
            Text("把文件變成可出示的證件（IETF SD-JWT VC），附上簽章檢查與時戳。要以自然人憑證或其他憑證簽署文件，請用上方的「簽署」，簽章會成為文件檢查的一部分。", style = MaterialTheme.typography.bodySmall)
        }
        ActionRow(WalletIcons.Card, if (derived != null) "重新產生衍生憑證" else "產生衍生憑證", "選擇要放進證件的欄位與證據") {
            model.screen.value = Screen.FileDerive(f.id)
        }
        if (report?.format == DocumentFormat.PDF) {
            ActionRow(WalletIcons.Shield, "產生 zkPDF 證明", "P4 尚未完成：以零知識證明 PDF 內的機關簽章與指定欄位，不必交出整份文件", enabled = false) {}
        }
        ActionRow(WalletIcons.Link, "產生 zkTLS 證明", "P4 尚未完成：以 TLSNotary 證明官方查驗頁回覆的內容（如移民署、學信網查驗）", enabled = false) {}
        if (f.nationalId != null) {
            SectionTitle("身分證卡")
            ActionRow(WalletIcons.Person, "國民身分證（Bonds 自發卡）", "由這份 MyData 身分證資料製作，以自然人憑證簽署") {
                model.screen.value = Screen.NationalId(f.id, Screen.FileDetail(f.id))
            }
        } else if (report?.format == DocumentFormat.PDF) {
            SectionTitle("身分證卡")
            ActionRow(WalletIcons.Person, "製作 Bonds 身分證卡", "這是 MyData 下載的國民身分證資料 PDF 時，可做成以自然人憑證簽署的身分證卡") {
                model.screen.value = Screen.NationalIdCreate(f.id)
            }
        }
        SectionTitle("動作")
        ActionRow(WalletIcons.Shield, "簽署", "自然人憑證卡、憑證檔（PKCS#12）或錢包自有金鑰") { model.screen.value = Screen.FileSign(f.id) }
        if (report?.format == DocumentFormat.ZIP) ActionRow(WalletIcons.Document, "解出檔案", "逐一保存並檢查壓縮檔內的檔案（MyData 下載檔）") { model.files.extract(f) }
        if (report?.format == DocumentFormat.CMS_SIGNED && f.contentId == null && report.signatures.any { it.integrity == Check.NOT_CHECKED }) {
            ActionRow(WalletIcons.Link, "選擇被簽署的檔案", "分離式簽章（.p7s）需要原檔才能檢查") { pickContent = true }
        }
        ActionRow(WalletIcons.History, "重新檢查", "以目前的信任錨點再檢查一次") { model.files.reinspect(f) }
        ActionRow(WalletIcons.Send, "匯出", "另存原檔") { model.files.export(f) }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { confirmDelete = true }) {
            Icon(WalletIcons.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text("刪除文件", color = MaterialTheme.colorScheme.error)
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("刪除這份文件？") },
            text = { Text("檔案與它的時戳會從這支裝置刪除，無法復原。已產生的衍生憑證保留在「證件」。") },
            confirmButton = { TextButton(onClick = { confirmDelete = false; model.files.delete(f) }) { Text("刪除", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("取消") } },
        )
    }
    if (pickContent) {
        AlertDialog(
            onDismissRequest = { pickContent = false },
            title = { Text("選擇被簽署的檔案") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    val others = files.filter { it.id != f.id }
                    if (others.isEmpty()) Text("請先匯入原檔。")
                    others.forEach { c ->
                        Text(c.name, Modifier.fillMaxWidth().clickable { pickContent = false; model.files.attachContent(f, c) }.padding(vertical = 6.dp),
                            color = MaterialTheme.colorScheme.primary)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { pickContent = false }) { Text("取消") } },
        )
    }
}

@Composable
private fun ReportVerdict(report: DocumentReport) {
    val (verdict, title) = verdictOf(report.verdict)
    val caveats = buildList {
        when (report.verdict) {
            DocumentVerdict.VALID -> report.bestTier?.let { add("簽署者信任等級：" + WalletModel.tierTitle(it)) }
            DocumentVerdict.PARTIAL -> add("簽章本身完整，但有項目無法確認，請看下方各簽章的說明。")
            DocumentVerdict.INVALID -> add("文件在簽署後被修改，或簽章、憑證不成立，不要依賴它的內容。")
            DocumentVerdict.UNSIGNED -> add(if (report.envelope != null) "這是加密信封，不是簽章文件。" else "這份檔案沒有可檢查的數位簽章，只保存原檔與指紋。")
        }
        if (report.encrypted) add("PDF 已加密，簽章仍可檢查。")
    }
    VerdictCard(verdict, title, caveats)
}

private fun certOf(c: CertInfo): X509Cert? = runCatching { X509Cert(ByteString(c.der.fromBase64())) }.getOrNull()

@Composable
private fun SignatureCard(model: WalletModel, s: SignatureInfo, index: Int, count: Int) {
    val (verdict, text) = verdictOf(s.verdict)
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (count > 1) "簽章 ${index + 1}" else "簽章", style = MaterialTheme.typography.titleSmall)
                VerdictPill(verdict, text)
            }
            Text(s.format.title, style = MaterialTheme.typography.bodySmall)
            s.signer?.let { signer ->
                LabelValue("簽署者", signer.commonName ?: signer.subject, onClick = {
                    val chain = s.chain.mapNotNull { certOf(it) }
                    if (chain.isNotEmpty()) model.screen.value = Screen.Certificate(chain, 0, model.screen.value)
                })
            }
            s.trust?.let { t ->
                val d = t.decision()
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TierBadge(d)
                    d.anchorName?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
                Text(signerTrustLine(d), style = MaterialTheme.typography.bodySmall)
            }
            LabelValue("內容完整", checkText(s.integrity), small = true)
            LabelValue("憑證效期", checkText(s.certificateValidity), small = true)
            s.coversWholeDocument?.let { LabelValue("涵蓋整份文件", if (it) "是" else "否", small = true) }
            s.laterChanges?.let {
                LabelValue("簽署後的修改", when (it) {
                    LaterChanges.NONE -> "沒有"
                    LaterChanges.SIGNATURES_ONLY -> "只有後續簽章或時戳"
                    LaterChanges.OTHER -> "有其他修改"
                }, small = true)
            }
            s.timestamp?.let { TimestampLine(it) } ?: s.claimedTime?.let { LabelValue("聲稱的簽署時間", localTime(it) + "（未經時戳證明）", small = true) }
            LabelValue("撤銷資訊", if (s.revocationData) "簽章或文件內附 OCSP／CRL" else "沒有內附", small = true)
            s.reason?.let { LabelValue("原因", it, small = true) }
            s.location?.let { LabelValue("地點", it, small = true) }
            s.problems.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            s.notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

@Composable
private fun TimestampLine(t: TimestampInfo) {
    LabelValue("時戳", localTime(t.time) + "　" + (t.tsa ?: "") + if (t.trusted) "" else "（${checkText(if (t.signature == Check.PASS) Check.WARN else t.signature)}）", small = true)
}

/** Checked evidence of a derived credential, for the verifier result. */
@Composable
fun EvidenceRows(evidence: List<EvidenceResult>) {
    if (evidence.isEmpty()) return
    Text("文件證據", style = MaterialTheme.typography.titleSmall)
    evidence.forEach { e ->
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            VerdictPill(checkVerdict(e.check), e.title + "：" + checkText(e.check))
            Text(e.detail, style = MaterialTheme.typography.bodySmall)
        }
    }
}

// ---------------------------------------------------------------- signer choice

private enum class SignerKind(val title: String) {
    CARD("自然人憑證卡"), MOBILE("行動自然人憑證"), SYSTEM("系統金鑰"), TOKEN("硬體憑證（PKCS#11）"), PKCS12("憑證檔（PKCS#12）"), WALLET("錢包自有金鑰"),
}

/** Picks a reader for the citizen certificate card and takes its PIN; [onChange] gets the choice or null. */
@Composable
internal fun CardPicker(model: WalletModel, onChange: (SignerChoice.Card?) -> Unit) {
    var readers by remember { mutableStateOf<NfcReaderList?>(null) }
    var reader by remember { mutableStateOf<NfcReaderOption?>(null) }
    var pin by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    LaunchedEffect(Unit) {
        readers = runCatching { model.platform.nfcReaders() }.getOrElse { NfcReaderList(emptyList(), model.describe(it)) }
        reader = readers?.readers?.firstOrNull()
    }
    fun update() = onChange(reader?.takeIf { pin.length in GpkiCard.PIN_MIN..GpkiCard.PIN_MAX }?.let { SignerChoice.Card(it, pin) })
    val list = readers
    when {
        list == null -> CircularProgressIndicator(Modifier.size(20.dp))
        list.readers.isEmpty() -> {
            Text(list.problem ?: "找不到 NFC 或讀卡機", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            OutlinedButton(onClick = { scope.launch { readers = runCatching { model.platform.nfcReaders() }.getOrNull(); reader = readers?.readers?.firstOrNull(); update() } }) { Text("重新尋找") }
        }
        else -> Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            list.readers.forEach { r -> FilterChip(selected = r === reader, onClick = { reader = r; update() }, label = { Text(r.name) }) }
        }
    }
    OutlinedTextField(
        value = pin,
        onValueChange = { v -> pin = v.filter { it.isDigit() }.take(GpkiCard.PIN_MAX); update() },
        label = { Text("卡片 PIN 碼（${GpkiCard.PIN_MIN} 至 ${GpkiCard.PIN_MAX} 位數字）") },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth(),
    )
    Text("PIN 碼只用於這次簽署，不會保存或記錄。輸入錯誤時會立即停止並顯示剩餘次數，以免鎖卡。手機需感應兩次：先讀取憑證，再簽署。",
        style = MaterialTheme.typography.bodySmall)
}

@Composable
private fun SignerPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    var kind by remember { mutableStateOf(SignerKind.CARD) }
    var p12 by remember { mutableStateOf<PickedFile?>(null) }
    var password by remember { mutableStateOf("") }
    var walletName by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    var other by remember { mutableStateOf<SignerChoice?>(null) }
    fun update(card: SignerChoice.Card? = null) = onChange(
        when (kind) {
            SignerKind.CARD -> card
            SignerKind.PKCS12 -> p12?.takeIf { password.isNotEmpty() }?.let { SignerChoice.Pkcs12(it.bytes, password) }
            SignerKind.WALLET -> SignerChoice.Wallet(walletName)
            SignerKind.SYSTEM, SignerKind.TOKEN, SignerKind.MOBILE -> other
        }
    )
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SignerKind.entries.forEach { k -> FilterChip(selected = k == kind, onClick = { kind = k; other = null; update() }, label = { Text(k.title) }) }
    }
    when (kind) {
        SignerKind.SYSTEM -> SystemKeyPicker(model) { other = it; update() }
        SignerKind.TOKEN -> TokenKeyPicker(model) { other = it; update() }
        SignerKind.MOBILE -> MobileMoicaPicker(model) { other = it; update() }
        SignerKind.CARD -> CardPicker(model) { update(it) }
        SignerKind.PKCS12 -> {
            OutlinedButton(onClick = { scope.launch { model.platform.pickFile()?.let { p12 = it; update() } } }) { Text(p12?.name ?: "選擇 .p12／.pfx 檔") }
            OutlinedTextField(
                value = password, onValueChange = { password = it; update() }, label = { Text("憑證檔密碼") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
            )
            Text("憑證檔與密碼只用於這次簽署，不會保存。", style = MaterialTheme.typography.bodySmall)
        }
        SignerKind.WALLET -> {
            OutlinedTextField(value = walletName, onValueChange = { walletName = it.take(64); update() }, label = { Text("憑證上的名稱") }, singleLine = true,
                modifier = Modifier.fillMaxWidth())
            Text("以錢包的金鑰與自簽憑證簽署：可證明文件沒有被修改，但無法證明你是誰（查驗方會看到 T3 或無法確認）。", style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** A key in the operating system's store: Android shows its own picker, desktops list the store here. */
@Composable
private fun SystemKeyPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    val keys = model.platform.externalKeys
    val reason = keys.systemUnavailableReason
    if (reason != null) {
        Text(reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        return
    }
    if (keys.systemPicker) {
        LaunchedEffect(Unit) { onChange(SignerChoice.System(null)) }
        Text("按下「簽署」後由系統列出已安裝的憑證（設定中的「加密與憑證」），由你選擇要讓錢包使用哪一把。金鑰留在系統內，錢包只取得簽章結果。",
            style = MaterialTheme.typography.bodySmall)
        return
    }
    var list by remember { mutableStateOf<List<ExternalKeyOption>?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    var chosen by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    fun load() = scope.launch {
        problem = null
        list = runCatching { keys.systemKeys() }.getOrElse { problem = model.describe(it); emptyList() }
    }
    LaunchedEffect(Unit) { load() }
    KeyList(list, chosen, problem, "系統金鑰庫中沒有可簽章的憑證") { chosen = it; onChange(SignerChoice.System(it)) }
    OutlinedButton(onClick = { load() }) { Text("重新讀取") }
    Text("Windows 列出「個人」憑證存放區（含 HiCOS 等驅動程式登錄的自然人憑證卡），macOS 列出鑰匙圈；使用卡片時系統可能另外要求 PIN 碼。",
        style = MaterialTheme.typography.bodySmall)
}

/** A PKCS#11 module and PIN, then a key on the token. */
@Composable
private fun TokenKeyPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    val keys = model.platform.externalKeys
    keys.tokenUnavailableReason?.let {
        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        return
    }
    val found = remember { keys.tokenLibraries() }
    var library by remember { mutableStateOf(found.firstOrNull().orEmpty()) }
    var pin by remember { mutableStateOf("") }
    var list by remember { mutableStateOf<List<ExternalKeyOption>?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    var chosen by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    if (found.isNotEmpty()) {
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            found.forEach { path -> FilterChip(selected = path == library, onClick = { library = path; list = null; onChange(null) },
                label = { Text(path.substringAfterLast('/').substringAfterLast('\\')) }) }
        }
    }
    OutlinedTextField(value = library, onValueChange = { library = it.trim(); list = null; onChange(null) }, label = { Text("PKCS#11 模組路徑") },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(
        value = pin, onValueChange = { pin = it.take(32); list = null; onChange(null) }, label = { Text("PIN 碼") }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
    )
    OutlinedButton(onClick = {
        busy = true
        scope.launch {
            problem = null
            list = runCatching { keys.tokenKeys(library, pin) }.getOrElse { problem = model.describe(it); emptyList() }
            busy = false
        }
    }, enabled = library.isNotBlank() && pin.isNotEmpty() && !busy) { Text(if (busy) "讀取中" else "讀取金鑰") }
    if (list != null || problem != null) {
        KeyList(list, chosen, problem, "這個硬體憑證沒有可簽章的金鑰") { chosen = it; onChange(SignerChoice.Token(library, pin, it)) }
    }
    Text("例如 HiCOS 的 PKCS#11 模組可直接使用自然人憑證卡，其他 USB 憑證請填入廠商提供的模組。PIN 碼只用於這次簽署，不會保存；輸入錯誤次數過多會鎖卡。",
        style = MaterialTheme.typography.bodySmall)
}

@Composable
private fun KeyList(list: List<ExternalKeyOption>?, chosen: String?, problem: String?, empty: String, onPick: (String) -> Unit) {
    when {
        problem != null -> Text(problem, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        list == null -> CircularProgressIndicator(Modifier.size(20.dp))
        list.isEmpty() -> Text(empty, style = MaterialTheme.typography.bodySmall)
        else -> list.forEach { k ->
            Row(Modifier.fillMaxWidth().clickable { onPick(k.id) }, verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(selected = k.id == chosen, onClick = { onPick(k.id) })
                Column {
                    Text(k.label, style = MaterialTheme.typography.bodyMedium)
                    Text(k.detail, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

/**
 * The mobile citizen certificate through an SP account. The account belongs to whoever holds the licence from the
 * Ministry of the Interior; it is typed in here for this run only and never stored or built into the app.
 */
@Composable
private fun MobileMoicaPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    val last = model.files.mobileMoicaSp
    var env by remember { mutableStateOf(last?.environment ?: MobileMoicaEnvironment.UAT) }
    var serviceId by remember { mutableStateOf(last?.serviceId.orEmpty()) }
    var aesKey by remember { mutableStateOf(last?.aesKeyBase64.orEmpty()) }
    var idNumber by remember { mutableStateOf("") }
    val canOpenApp = model.platform.mobileMoicaReturnUrl != null
    var mode by remember { mutableStateOf(if (canOpenApp) MobileMoicaMode.APP_TO_APP else MobileMoicaMode.PUSH) }
    fun update() {
        val id = idNumber.trim().uppercase()
        val ok = serviceId.isNotBlank() && aesKey.isNotBlank() && MyDataProfile.isValidId(id)
        onChange(if (ok) SignerChoice.MobileMoica(MobileMoicaSp(env, serviceId.trim(), aesKey.trim()), id, mode) else null)
    }
    Text("需要內政部核發的服務提供者（SP）帳號。這裡供持有 SP 授權的共同開發者測試：帳號與金鑰只保存在這次執行的記憶體，不會寫入裝置或 App。",
        style = MaterialTheme.typography.bodySmall)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        MobileMoicaEnvironment.entries.forEach { e -> FilterChip(selected = e == env, onClick = { env = e; update() }, label = { Text(e.title) }) }
    }
    OutlinedTextField(value = serviceId, onValueChange = { serviceId = it.take(64); update() }, label = { Text("SP 服務代碼（sp_service_id）") },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(
        value = aesKey, onValueChange = { aesKey = it.take(64); update() }, label = { Text("SP AES 金鑰（base64）") }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(value = idNumber, onValueChange = { idNumber = it.take(10); update() }, label = { Text("身分證統一編號") },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        MobileMoicaMode.entries.forEach { m ->
            FilterChip(selected = m == mode, enabled = m != MobileMoicaMode.APP_TO_APP || canOpenApp, onClick = { mode = m; update() }, label = { Text(m.title) })
        }
    }
    Text(
        "第一次簽署需在 App 確認兩次：先取得你的憑證，再簽署文件；之後這次執行內只需確認一次。" +
            if (canOpenApp) "" else "電腦無法開啟行動自然人憑證 App，請用推播。",
        style = MaterialTheme.typography.bodySmall,
    )
}

// ---------------------------------------------------------------- sign

@Composable
fun FileSignScreen(model: WalletModel, screen: Screen.FileSign) {
    val f = model.files.file(screen.fileId) ?: return
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val forms = remember(f) { model.files.formsFor(f) }
    var form by remember { mutableStateOf(forms.first()) }
    var choice by remember { mutableStateOf<SignerChoice?>(null) }
    var reason by remember { mutableStateOf("") }
    var location by remember { mutableStateOf("") }
    var timestamp by remember { mutableStateOf(true) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(f.name, style = MaterialTheme.typography.titleMedium)
        SectionTitle("簽章格式")
        forms.forEach { sf ->
            Row(Modifier.fillMaxWidth().clickable { form = sf }, verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(selected = sf == form, onClick = { form = sf })
                Column {
                    Text(sf.title, style = MaterialTheme.typography.bodyMedium)
                    Text(sf.detail, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        SectionTitle("簽署者")
        SignerPicker(model) { choice = it }
        if (form == SignForm.PADES) {
            OutlinedTextField(value = reason, onValueChange = { reason = it.take(100) }, label = { Text("簽署原因（選填）") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = location, onValueChange = { location = it.take(100) }, label = { Text("簽署地點（選填）") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = timestamp, onCheckedChange = { timestamp = it })
            Text("加上簽章時戳（${TsaServices.byId(model.settings.tsaId).name}，需要網路）")
        }
        BusyLine(busy, error)
        Button(onClick = { choice?.let { model.files.sign(f, it, form, reason, location, timestamp) } }, enabled = choice != null && busy == null) {
            Text("簽署")
        }
    }
}

// ---------------------------------------------------------------- preview

/** The content of [f]: PDF pages (with the password field of an encrypted PDF), a picture, or the text. */
@Composable
private fun FilePreviewSection(model: WalletModel, f: StoredFile) {
    val previews by model.files.previews.collectAsState()
    LaunchedEffect(f.id, f.sha256) { if (previews[f.id] == null) model.files.preview(f) }
    val p = previews[f.id]
    var password by remember(f.id) { mutableStateOf("") }
    var page by remember(f.id) { mutableStateOf(0) }
    var showText by remember(f.id) { mutableStateOf(false) }
    SectionTitle("預覽")
    when (p) {
        null, FilePreview.Loading -> Text("正在產生預覽", style = MaterialTheme.typography.bodySmall)
        is FilePreview.Pages -> {
            if (p.pages.isNotEmpty()) {
                val i = page.coerceIn(0, p.pages.lastIndex)
                PreviewImage(p.pages[i], "第 ${i + 1} 頁")
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { page = i - 1 }, enabled = i > 0) { Text("上一頁") }
                    Text("第 ${i + 1} / ${p.total} 頁", style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = { page = i + 1 }, enabled = i < p.pages.lastIndex) { Text("下一頁") }
                }
                if (p.total > p.pages.size) Text("預覽前 ${p.pages.size} 頁；完整內容請匯出後以閱讀器開啟。", style = MaterialTheme.typography.bodySmall)
            } else {
                Text("這個平台無法繪製頁面，以下是文件的文字。", style = MaterialTheme.typography.bodySmall)
            }
            p.text?.let { t ->
                TextButton(onClick = { showText = !showText }) { Text(if (showText) "隱藏文字層" else "顯示文字層") }
                if (showText || p.pages.isEmpty()) SelectableText(t)
            }
        }
        is FilePreview.Picture -> PreviewImage(p.image, f.name)
        is FilePreview.Text -> {
            SelectableText(p.text)
            if (p.truncated) Text("只顯示前 ${FilePreview.TEXT_LIMIT} 字。", style = MaterialTheme.typography.bodySmall)
        }
        is FilePreview.Official -> {
            OfficialDocumentView(p.document)
            TextButton(onClick = { showText = !showText }) { Text(if (showText) "隱藏原始 XML" else "顯示原始 XML") }
            if (showText) {
                SelectableText(p.source)
                if (p.truncated) Text("只顯示前 ${FilePreview.TEXT_LIMIT} 字。", style = MaterialTheme.typography.bodySmall)
            }
        }
        is FilePreview.NeedsPassword -> {
            Text(if (p.wrong) "密碼不正確，請再試一次。" else "這份 PDF 有開啟密碼。MyData 的文件通常是身分證統一編號；密碼只用於這次開啟，不會保存。",
                style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(value = password, onValueChange = { password = it.take(64) }, label = { Text("開啟密碼") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.weight(1f))
                Button(onClick = { model.files.preview(f, password) }, enabled = password.isNotBlank()) { Text("開啟") }
            }
        }
        is FilePreview.Unavailable -> Text(p.reason, style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * An official document as it reads on paper: the agency and type on top, then its fields, subject and numbered
 * paragraphs, nested parts (such as each co-signing agency) and, for an online approval file, the planned flow and
 * every signing point.
 */
@Composable
private fun OfficialDocumentView(doc: OfficialDocument) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(doc.title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        doc.sections.forEach { section ->
            section.title?.let { Text(it, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp)) }
            section.entries.forEach { e ->
                when (e) {
                    is OfficialEntry.Field -> LabelValue(e.label, e.value)
                    is OfficialEntry.Paragraph -> OfficialParagraphView(e)
                }
            }
        }
        if (doc.flow.isNotEmpty()) {
            Text("簽核流程", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp))
            doc.flow.forEachIndexed { i, node ->
                Text("${i + 1}. ${node.name}" + (node.action?.takeIf { it != node.name }?.let { "（$it）" } ?: ""),
                    style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = (node.depth * 16).dp))
            }
        }
        doc.steps.forEachIndexed { i, step ->
            Column(
                Modifier.fillMaxWidth().padding(top = 6.dp).background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp)).padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text("簽核點 ${i + 1}：" + listOfNotNull(step.action, step.point?.takeIf { it != step.action }).joinToString("・"),
                    style = MaterialTheme.typography.titleSmall)
                step.signer?.let { LabelValue("簽核人員", it + (step.role?.let { r -> "（$r）" } ?: "")) }
                step.time?.let { LabelValue("簽章時間", it, small = true) }
                step.opinions.forEach { LabelValue("簽核意見", it) }
                if (step.next.isNotEmpty()) LabelValue("次位簽核人員", step.next.joinToString("、"), small = true)
                step.certificate?.let { LabelValue("簽章憑證", it, small = true) }
                if (step.drafts.isNotEmpty()) LabelValue("文稿", step.drafts.joinToString("、"), small = true)
                if (step.files.isNotEmpty()) LabelValue("檔案", step.files.joinToString("\n"), small = true)
            }
        }
    }
}

@Composable
private fun OfficialParagraphView(p: OfficialEntry.Paragraph) {
    Column(Modifier.fillMaxWidth().padding(top = 4.dp)) {
        val line = (p.heading?.trim().orEmpty() + p.text.orEmpty()).ifEmpty { null }
        line?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        p.items.forEach { OfficialItemView(it, 1) }
    }
}

@Composable
private fun OfficialItemView(item: OfficialItem, depth: Int) {
    Row(Modifier.fillMaxWidth().padding(start = (depth * 14).dp)) {
        item.number?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        Text(item.text ?: "", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
    }
    item.items.forEach { OfficialItemView(it, depth + 1) }
}

@Composable
private fun PreviewImage(image: ImageBitmap, description: String) {
    Image(
        image, contentDescription = description, contentScale = ContentScale.FillWidth,
        modifier = Modifier.fillMaxWidth().aspectRatio(image.width.toFloat() / image.height.coerceAtLeast(1))
            .clip(RoundedCornerShape(8.dp)).border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)),
    )
}

@Composable
private fun SelectableText(text: String) {
    SelectionContainer {
        Text(text, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            modifier = Modifier.fillMaxWidth().heightIn(max = 480.dp).verticalScroll(rememberScrollState())
                .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp)).padding(10.dp))
    }
}

// ---------------------------------------------------------------- OpenCerts

private fun methodText(m: OaMethod): String = when (m) {
    OaMethod.DOCUMENT_STORE -> "以太坊文件庫"
    OaMethod.TOKEN_REGISTRY -> "以太坊權杖登錄（可轉讓文件）"
    OaMethod.DID -> "DID 簽章"
    OaMethod.NONE -> "未提供"
}

/**
 * An OpenCerts certificate: integrity, the online check of issuance and issuer identity (checked again when opened
 * after a while, or on request), and what the certificate shows: recipient, main fields, issuers, signatories,
 * transcript, images, attachments and the remaining fields with readable labels.
 */
@Composable
private fun OpenCertSection(model: WalletModel, f: StoredFile, oc: OpenCertInfo, busy: String?) {
    val view by produceState<OpenCertView?>(null, f.id, f.sha256) { value = model.files.openCertView(f) }
    val v = view
    SectionTitle("OpenCerts 證書")
    (v?.title ?: oc.name)?.let { LabelValue("名稱", it) }
    LabelValue("版本", oc.version, small = true)
    VerdictPill(checkVerdict(oc.integrity), "內容完整性：" + checkText(oc.integrity))
    if (oc.integrity == Check.FAIL) Text("內容與 Merkle 證明不一致，檔案在發行後被改過。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    val online = oc.online
    if (online == null) {
        Text("尚未在網路上查驗：發行者是否在以太坊發行且未撤銷，以及網域的 DNS 紀錄是否證明發行者身分。", style = MaterialTheme.typography.bodySmall)
    } else {
        VerdictPill(checkVerdict(online.issuance), "發行狀態：" + checkText(online.issuance))
        online.issuanceDetail.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        VerdictPill(checkVerdict(online.identity), "發行者身分：" + checkText(online.identity))
        online.identityDetail.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        online.registryName?.let { LabelValue("OpenCerts 登錄名稱", it, small = true) }
        Text("查驗時間：${localTime(online.checkedAt)}", style = MaterialTheme.typography.bodySmall)
    }
    OutlinedButton(onClick = { model.files.recheckOpenCert(f) }, enabled = busy == null) { Text(if (online == null) "查驗發行狀態" else "重新查驗") }
    if (v == null) return
    v.templateUrl?.let { url ->
        val origin = Regex("^https://[^/]+").find(url.trim())?.value
        if (origin != null) {
            ActionRow(WalletIcons.Document, "以發證機構樣式顯示", "證書內容會傳給發證機構指定的顯示程式（$origin）") {
                model.screen.value = Screen.OpenCertRender(f.id)
            }
        } else {
            ActionRow(WalletIcons.Document, "以發證機構樣式顯示", "顯示程式不是 https 網址，無法安全載入", enabled = false) {}
        }
    }
    if (v.recipient.isNotEmpty()) {
        SectionTitle("受領人")
        v.recipient.forEach { (k, value) -> LabelValue(k, value) }
    }
    if (v.main.isNotEmpty()) {
        SectionTitle("證書內容")
        v.main.forEach { (k, value) -> LabelValue(k, value) }
    }
    v.issuers.forEachIndexed { i, issuer ->
        SectionTitle(if (v.issuers.size > 1) "發行者 ${i + 1}" else "發行者")
        issuer.name?.let { LabelValue("名稱", it) }
        issuer.url?.let { LabelValue("網址", it, small = true) }
        LabelValue("發行方式", methodText(issuer.method), small = true)
        issuer.value?.let { LabelValue(if (issuer.method == OaMethod.DID) "DID" else "合約地址", it, small = true) }
        issuer.identityType?.let { t -> LabelValue("身分證明", t + (issuer.identityLocation?.let { "：$it" } ?: ""), small = true) }
        issuer.revocationType?.let { t -> LabelValue("撤銷機制", t + (issuer.revocationLocation?.let { "：$it" } ?: ""), small = true) }
    }
    if (v.signatories.isNotEmpty()) {
        SectionTitle("簽署人")
        v.signatories.forEach { s ->
            listOfNotNull(s.name, s.position, s.organisation).takeIf { it.isNotEmpty() }?.let { Text(it.joinToString("，"), style = MaterialTheme.typography.bodyMedium) }
            s.image?.let { model.platform.decodeImage(it) }?.let { img ->
                Image(img, contentDescription = "簽名", contentScale = ContentScale.Fit, modifier = Modifier.height(64.dp))
            }
        }
    }
    if (v.transcript.isNotEmpty()) {
        SectionTitle("成績單")
        Column(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
            Row {
                v.transcriptColumns.forEach { c -> Text(c, style = MaterialTheme.typography.labelMedium, modifier = Modifier.width(120.dp).padding(4.dp)) }
            }
            v.transcript.forEach { row ->
                Row { row.forEach { cell -> Text(cell, style = MaterialTheme.typography.bodySmall, modifier = Modifier.width(120.dp).padding(4.dp)) } }
            }
        }
    }
    if (v.images.isNotEmpty()) {
        SectionTitle("圖片")
        v.images.forEach { (name, bytes) ->
            model.platform.decodeImage(bytes)?.let { img ->
                Text(name, style = MaterialTheme.typography.bodySmall)
                Image(img, contentDescription = name, contentScale = ContentScale.Fit, modifier = Modifier.heightIn(max = 160.dp))
            }
        }
    }
    if (v.attachments.isNotEmpty()) {
        SectionTitle("附件")
        v.attachments.forEach { a ->
            Text("${a.name}（${sizeText(a.bytes.size.toLong())}）", style = MaterialTheme.typography.bodyMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { model.files.storeOpenCertAttachment(f, a) }, enabled = busy == null) { Text("存入文件") }
                OutlinedButton(onClick = { model.files.exportOpenCertAttachment(a) }, enabled = busy == null) { Text("匯出") }
            }
        }
    }
    if (v.other.isNotEmpty()) {
        SectionTitle("其他欄位")
        v.other.forEach { (k, value) -> LabelValue(k, value, small = true) }
    }
}

/** The certificate shown by the renderer its issuer chose; the content goes to that site only when this opens. */
@Composable
fun OpenCertRenderScreen(model: WalletModel, screen: Screen.OpenCertRender) {
    val f = model.files.file(screen.fileId) ?: return
    val page by produceState<String?>(null, f.id) { value = model.files.openCertRendererPage(f) ?: "" }
    Column(Modifier.fillMaxSize()) {
        Text("由發證機構指定的顯示程式繪製；內容與上一頁的檢查結果相同，查驗結果以上一頁為準。", style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
        when (val html = page) {
            null -> Text("正在準備", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
            "" -> Text("這份證書沒有可用的 https 顯示程式。", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
            else -> OpenCertRendererView(html, Modifier.fillMaxWidth().weight(1f)) { url ->
                model.platform.openBrowser(url)
            }
        }
    }
}

// ---------------------------------------------------------------- derive

@Composable
fun FileDeriveScreen(model: WalletModel, screen: Screen.FileDerive) {
    val f = model.files.file(screen.fileId) ?: return
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    var password by remember(f) { mutableStateOf("") }
    var tried by remember(f) { mutableStateOf<String?>(null) }
    val fields by produceState<FilesModel.DeriveFields?>(null, f, tried) { value = model.files.deriveFields(f, tried) }
    val suggested = fields?.claims.orEmpty()
    var chosen by remember(f, suggested) { mutableStateOf(suggested.map { it.name }.toSet()) }
    var showNote by remember { mutableStateOf(false) }
    var noteName by remember { mutableStateOf("") }
    var noteValue by remember { mutableStateOf("") }
    var timestamp by remember { mutableStateOf(true) }
    var validDays by remember { mutableStateOf<Int?>(null) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("把「${f.report?.title ?: f.name}」變成可出示的證件。查驗方只會看到你勾選的欄位，以及文件指紋、格式與大小；原檔不會送出。",
            style = MaterialTheme.typography.bodyMedium)
        f.report?.let { ReportVerdict(it) }
        f.source?.let { LabelValue("文件來源", it) }
        SectionTitle("欄位（由文件內容解析）")
        if (fields == null) Text("正在讀取文件內容", style = MaterialTheme.typography.bodySmall)
        if (fields?.locked == true) {
            Text(if (tried != null) "密碼不正確，請再試一次。" else "這份 PDF 有開啟密碼，輸入後才能讀出文件內的欄位（MyData 文件通常是身分證統一編號）。密碼只用於這次讀取，不會保存；在設定保存 MyData 自動填入，或已製作身分證卡時，MyData 文件會自動開啟。",
                style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(value = password, onValueChange = { password = it.take(64) }, label = { Text("開啟密碼") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.weight(1f))
                Button(onClick = { tried = password }, enabled = password.isNotBlank()) { Text("讀取") }
            }
        }
        fields?.notice?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        suggested.forEach { c ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = c.name in chosen, onCheckedChange = { chosen = if (it) chosen + c.name else chosen - c.name })
                Column {
                    Text(DerivedCredentials.labelOf(c), style = MaterialTheme.typography.bodyMedium)
                    Text(c.value, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        if (fields != null && suggested.isEmpty()) Text("文件內沒有可解析的欄位。", style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = { showNote = !showNote }) { Text(if (showNote) "不加入自填欄位" else "加入自填欄位（查驗方會看到這是持有人自填）") }
        if (showNote) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = noteName, onValueChange = { noteName = it.take(32) }, label = { Text("欄位名稱") }, singleLine = true, modifier = Modifier.weight(1f))
                OutlinedTextField(value = noteValue, onValueChange = { noteValue = it.take(200) }, label = { Text("內容") }, singleLine = true, modifier = Modifier.weight(1f))
            }
        }
        SectionTitle("證據")
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = timestamp, onCheckedChange = { timestamp = it })
            Text(if (f.timestamps.any { it.trusted }) "附上已保存的時戳" else "取得並附上文件時戳（只送出 SHA-256）")
        }
        SectionTitle("有效期間")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf<Pair<Int?, String>>(null to "不限", 365 to "一年", 1825 to "五年").forEach { (d, t) ->
                FilterChip(selected = validDays == d, onClick = { validDays = d }, label = { Text(t) })
            }
        }
        BusyLine(busy, error)
        val claims = suggested.filter { it.name in chosen } + listOfNotNull(
            if (showNote && noteName.isNotBlank() && noteValue.isNotBlank()) {
                DerivedClaim(DerivedCredentials.SELF_ASSERTED_PREFIX + noteName.trim(), noteValue.trim(), "持有人自填：" + noteName.trim())
            } else null,
        )
        Button(
            onClick = { model.files.derive(f, claims, timestamp, validDays) },
            enabled = busy == null && claims.isNotEmpty(),
        ) { Text("產生衍生憑證") }
        Text("衍生憑證由這支錢包的文件發行金鑰（did:key）簽發，結構是 IETF SD-JWT VC，信任等級為 T3：它證明你在何時、以哪些證據保存了這份文件，不代表原發文機關另行背書。Bonds 的 vc+moica 結構只用於身分證卡；Bonds 查驗方要的 MyData 衍生答案（所得、勞保、戶籍）在出示當下才由原檔產生，不需先在這裡製作。",
            style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
fun PortalScreen(model: WalletModel, screen: Screen.Portal) {
    val src = DocumentSources.byId(screen.sourceId) ?: return
    val busy by model.files.busy.collectAsState()
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(src.name, style = MaterialTheme.typography.titleSmall)
            Text(
                when {
                    src.nationalId -> "1. 在 MyData 頁面選擇驗證方式並同意；2. 行動自然人憑證會轉到官方 App，完成後回到這裡；3. 按下載，ZIP 會自動解出，接著輸入身分證統一編號開啟 PDF。"
                    src.myData -> "在 MyData 頁面完成驗證後按下載；ZIP 會自動解出，每個檔案各自保存並檢查。需要較久產生的文件，完成後從「MyData 個人文件」下載。"
                    else -> "下載的文件會直接保存並檢查；網站要求行動自然人憑證時，會轉到官方 App 完成登入後回到這裡。"
                },
                style = MaterialTheme.typography.bodySmall,
            )
            busy?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
        }
        PortalWebView(
            url = src.url,
            modifier = Modifier.fillMaxWidth().weight(1f),
            onFile = { model.files.importDownload(it, src) },
            onExternal = { url ->
                if (!model.platform.openExternal(url)) model.message.value = "這支手機沒有可開啟這個連結的 App（例如行動自然人憑證）"
            },
            onError = { model.message.value = it },
            autofill = myDataAutofill(model).takeIf { src.myData },
        )
    }
}

/** The saved MyData ID number and birth date, filled into MyData's own pages (Bonds autofill). */
private fun myDataAutofill(model: WalletModel): PortalAutofill? {
    val id = model.settings.myDataIdNumber ?: return null
    val birth = model.settings.myDataBirthDate ?: return null
    return PortalAutofill(MyDataProfile.HOST, MyDataProfile.autofillScript(id, birth)) { n -> model.message.value = "已在 MyData 頁面填入 $n 個已保存的欄位" }
}

