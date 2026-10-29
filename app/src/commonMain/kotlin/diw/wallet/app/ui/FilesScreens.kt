package diw.wallet.app.ui

import diw.wallet.app.CscPrompt
import diw.wallet.core.document.sign.CscEnvironment
import diw.wallet.core.document.sign.CscServices
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
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
import diw.wallet.core.document.official.ApprovalPoint
import diw.wallet.core.document.sign.SignatureLevel
import diw.wallet.app.SignerChoice
import diw.wallet.app.ExternalKeyOption
import diw.wallet.app.MobileMoicaSp
import diw.wallet.core.document.sign.MobileMoicaEnvironment
import diw.wallet.core.document.sign.MobileMoicaMode
import diw.wallet.app.StoredFile
import diw.wallet.app.WalletModel
import diw.wallet.app.CredentialDetails
import diw.wallet.core.document.official.OfficialBundles
import diw.wallet.core.profile.bonds.HouseholdTranscript
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
import diw.wallet.core.document.SignaturePlacementInfo
import diw.wallet.core.document.TimestampInfo
import diw.wallet.core.document.card.GpkiCard
import diw.wallet.core.document.derived.DerivedClaim
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.EvidenceResult
import androidx.compose.material3.HorizontalDivider
import kotlinx.datetime.LocalDate
import diw.wallet.core.document.derived.DocumentFields
import diw.wallet.core.document.derived.EntryExitCertificate
import diw.wallet.core.document.derived.MainlandEntryExitRecord
import diw.wallet.core.document.derived.MainlandPermitLink
import diw.wallet.core.document.derived.StudentStatusProof
import diw.wallet.core.document.sign.TsaServices
import kotlinx.coroutines.launch
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import diw.wallet.core.document.OpenCertInfo
import diw.wallet.core.document.opencerts.OaMethod
import diw.wallet.core.document.opencerts.OpenCertOffline
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
 * The host page of an OpenCerts renderer ([html], see OpenCertRenderer), or an [offline] page (OpenCertOffline:
 * no scripts, nothing loaded from the network): inside the app where a web view exists, otherwise opened in the
 * system browser on request. Links the renderer opens go to [onExternal].
 */
@Composable
expect fun OpenCertRendererView(html: String, modifier: Modifier, offline: Boolean = false, onExternal: (String) -> Unit)

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
    DocumentFormat.OFFICE -> "Office 文件"
    DocumentFormat.IMAGE -> "圖片"
    DocumentFormat.TEXT -> "文字檔"
    DocumentFormat.OTHER -> "其他檔案"
}

// ---------------------------------------------------------------- files tab

/**
 * Files and official documents, as Bonds keeps its MyData vault and official document inbox beside the cards: the
 * stored files with their signature checks first; the sites that issue documents are one row away.
 */
@Composable
fun FilesTab(model: WalletModel) {
    val files by model.files.files.collectAsState()
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = { model.files.pickAndImport() }, enabled = busy == null) {
                Icon(WalletIcons.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text("匯入文件")
            }
            OutlinedButton(onClick = { model.screen.value = Screen.DocumentSources }) {
                Icon(WalletIcons.Government, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text("從網站取得")
            }
        }
        BusyLine(busy, error)
        if (files.isEmpty()) {
            EmptyState(
                WalletIcons.Document, "還沒有文件",
                "匯入 PDF、電子公文、OFD、.p7s／.p7m、ASiC-E、MyData 壓縮檔或 OpenCerts 等檔案，錢包會保存原檔並檢查簽章、時戳與憑證鏈；之後可以簽署，或做成可出示的衍生憑證。",
                "從 MyData 等網站取得",
            ) { model.screen.value = Screen.DocumentSources }
        } else FileList(model, files)
    }
}

/** The sites that issue documents: in the app where a web view exists (downloads are saved directly), else the browser. */
@Composable
fun DocumentSourcesScreen(model: WalletModel) {
    fun open(src: diw.wallet.app.DocumentSource) {
        if (model.platform.embeddedBrowser) model.screen.value = Screen.Portal(src.id) else model.platform.openBrowser(src.url)
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            if (model.platform.embeddedBrowser) "在 App 內開啟來源網站，下載的文件直接保存到「文件」；需要行動自然人憑證登入時會轉到官方 App。"
            else "在系統瀏覽器開啟來源網站，下載後回到「文件」用「匯入文件」保存。",
            style = MaterialTheme.typography.bodySmall,
        )
        SectionTitle("MyData")
        DocumentSources.myData.forEach { src ->
            ActionRow(if (src.nationalId) WalletIcons.Person else WalletIcons.Government, src.name, src.detail) { open(src) }
        }
        SectionTitle("其他來源")
        DocumentSources.others.forEach { src -> ActionRow(WalletIcons.Government, src.name, src.detail) { open(src) } }
        SectionTitle("電子公文收發")
        ActionRow(WalletIcons.Send, "公文交換（收發）", "需要機關的公文電子交換帳號與憑證，個人錢包目前無法收發；收到的公文檔案可匯入保存與檢查", enabled = false) {}
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

/** How the files list is laid out: newest first, or grouped by what the files are (MyData item, official documents). */
private enum class FileOrder(val title: String) { RECENT("依保存時間"), ITEM("依項目") }

/** The files outside containers; a container's own files show on its document's screen. */
@Composable
private fun FileList(model: WalletModel, files: List<StoredFile>) {
    var order by remember { mutableStateOf(FileOrder.RECENT) }
    var query by remember { mutableStateOf("") }
    val outside = files.filter { it.bundleOf == null }
    val counts = files.mapNotNull { it.bundleOf }.groupingBy { it }.eachCount()
    val q = query.trim()
    // A search also finds a container by the names of the files inside it.
    val shown = if (q.isEmpty()) outside else outside.filter { f ->
        listOfNotNull(f.name, f.report?.title, f.source, f.period).any { it.contains(q, ignoreCase = true) } ||
            files.any { it.bundleOf == f.id && it.name.contains(q, ignoreCase = true) }
    }
    if (outside.size > 5) {
        OutlinedTextField(value = query, onValueChange = { query = it.take(60) }, label = { Text("搜尋檔名、標題或來源") }, singleLine = true,
            modifier = Modifier.fillMaxWidth())
    }
    if (outside.size > 1) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("${outside.size} 份文件", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            FileOrder.entries.forEach { o -> FilterChip(selected = o == order, onClick = { order = o }, label = { Text(o.title) }) }
        }
    }
    if (q.isNotEmpty() && shown.isEmpty()) Text("沒有符合「$q」的文件。", style = MaterialTheme.typography.bodySmall)
    when (order) {
        FileOrder.RECENT -> shown.forEach { f -> FileRow(f, counts[f.id] ?: 0) { model.screen.value = Screen.FileDetail(f.id) } }
        FileOrder.ITEM -> shown.groupBy { groupOf(it, counts[it.id] ?: 0) }.toSortedMap().forEach { (group, list) ->
            Text("$group（${list.size}）", style = MaterialTheme.typography.titleSmall)
            list.sortedWith(compareByDescending<StoredFile> { periodKey(it.period) }.thenByDescending { it.addedAt }).forEach { f ->
                FileRow(f, counts[f.id] ?: 0) { model.screen.value = Screen.FileDetail(f.id) }
            }
        }
    }
}

/** The group a file is listed under: its MyData item, official documents, else its format. */
private fun groupOf(f: StoredFile, members: Int): String {
    val source = f.source.orEmpty()
    if (source.startsWith("MyData")) return source.substringAfter("・", "MyData").substringBefore("（").ifBlank { "MyData" }
    val ext = f.name.substringAfterLast('.', "").lowercase()
    if (members > 0 || ext in setOf("di", "sw", "si", "dm", "co")) return "電子公文"
    return f.report?.format?.let { formatTitle(it) } ?: "其他檔案"
}

/** "113 年度" as a number for sorting, newest first; files without a period sort last. */
private fun periodKey(period: String?): Int = period?.let { Regex("\\d+").find(it)?.value?.toIntOrNull() } ?: -1

@Composable
private fun FileRow(f: StoredFile, members: Int = 0, onClick: () -> Unit) {
    val (verdict, text) = f.report?.let { verdictOf(it.verdict) } ?: (Verdict.CAUTION to "尚未檢查")
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(WalletIcons.Document, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(f.report?.title ?: f.name, style = MaterialTheme.typography.titleSmall)
                Text(listOfNotNull(f.period, f.report?.format?.let { formatTitle(it) }, sizeText(f.size), localTime(f.addedAt)).joinToString("・"),
                    style = MaterialTheme.typography.bodySmall)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    VerdictPill(verdict, text)
                    if (f.timestamps.isNotEmpty()) VerdictPill(if (f.timestamps.any { it.trusted }) Verdict.PASS else Verdict.CAUTION, "時戳")
                    if (f.derivedDocumentId != null) InfoPill("已衍生憑證")
                    if (f.nationalId != null) InfoPill("身分證卡")
                    if (members > 0) InfoPill("公文容器・$members 個關連檔")
                }
            }
        }
    }
}

// ---------------------------------------------------------------- official document containers

/** The container of an official document (its exchange form, approval file, attachments), or the one a file is in. */
@Composable
private fun OfficialContainerSection(model: WalletModel, f: StoredFile, files: List<StoredFile>) {
    val owner = f.bundleOf?.let { id -> files.firstOrNull { it.id == id } }
    if (owner != null) {
        SectionTitle("公文容器")
        LabelValue("屬於", owner.name, onClick = { model.screen.value = Screen.FileDetail(owner.id) })
        OutlinedButton(onClick = { model.files.leaveBundle(f) }) { Text("移出容器") }
        return
    }
    var main by remember(f.id) { mutableStateOf(false) }
    LaunchedEffect(f.id) { main = model.files.isOfficialMain(f) }
    if (!main) return
    val own = files.filter { it.bundleOf == f.id }.sortedBy { it.name }
    val inherited = remember(f.id, files) { model.files.inherited(f) }.sortedBy { it.name }
    val members = own + inherited
    // With an online approval in the container, its files are shown under the signing point that signed them.
    val layout by produceState<FilesModel.ContainerLayout?>(null, f.id, files) { value = model.files.containerLayout(f) }
    SectionTitle("公文容器")
    if (members.isEmpty()) {
        Text("這份公文還沒有關連檔。交換表單（.sw）、簽核檔（.si）與附件可放進同一個容器，一起保存與查看。", style = MaterialTheme.typography.bodySmall)
    }
    val open = { m: StoredFile -> model.screen.value = Screen.FileDetail(m.id) }
    val l = layout
    if (l != null) {
        ContainerHealth(l, listOf(f) + members)
        Text("依線上簽核檔的簽核點排列：每個檔案列在第一個簽署它的簽核點下。", style = MaterialTheme.typography.bodySmall)
        FileRow(l.approval) { open(l.approval) }
        l.points.forEach { p -> ContainerPointView(p, f, open) }
        if (l.others.isNotEmpty()) {
            Text("簽核檔未列出的檔案", style = MaterialTheme.typography.titleSmall)
            l.others.forEach { m -> FileRow(m) { open(m) } }
        }
    } else {
        own.forEach { m -> FileRow(m) { open(m) } }
        if (inherited.isNotEmpty()) {
            Text("沿用簽署前公文的關連檔（未另外簽署）：", style = MaterialTheme.typography.bodySmall)
            inherited.forEach { m -> FileRow(m) { open(m) } }
        }
    }
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = { model.files.importIntoBundle(f) }) { Text("匯入關連文件") }
        OutlinedButton(onClick = { model.screen.value = Screen.OfficialBundle(f.id, null) }) { Text("從已保存的文件加入") }
    }
    if (members.isNotEmpty()) {
        ActionRow(WalletIcons.Shield, "取得容器內簽章的撤銷資訊", "為容器內每個含簽章的檔案與尚未保存撤銷資訊的時戳取得 OCSP（取不到才用 CRL）") {
            model.files.collectContainerValidation(f)
        }
        ActionRow(WalletIcons.Send, "匯出公文容器", "壓縮檔內含全部檔案（原檔名）、時戳與撤銷資訊，以及依簽核點整理的說明") { model.files.exportContainer(f) }
        if (model.platform.canShareFiles) {
            ActionRow(WalletIcons.Share, "分享公文容器", "同一個壓縮檔直接交給其他 App，不另存檔") { model.files.exportContainer(f, share = true) }
        }
    }
}

/**
 * The health of a container in the categories the archives' check uses: files missing or changed since they were
 * signed, the signatures of the signing points, and the revocation data kept for signed files.
 */
@Composable
private fun ContainerHealth(l: FilesModel.ContainerLayout, all: List<StoredFile>) {
    val signatures = l.points.mapNotNull { it.signature }
    val failed = signatures.count { it.verdict == DocumentVerdict.INVALID }
    val unsigned = l.points.size - signatures.size
    val signed = all.filter { it.report?.signatures?.isNotEmpty() == true }
    val withRevocation = signed.count { it.signatureValidation != null }
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        VerdictPill(if (l.missing == 0) Verdict.PASS else Verdict.CAUTION, if (l.missing == 0) "檔案齊全" else "缺 ${l.missing} 個檔案")
        if (l.changed > 0) VerdictPill(Verdict.CAUTION, "${l.changed} 個檔案與簽核時不同")
        VerdictPill(
            when { failed > 0 -> Verdict.FAIL; unsigned == 0 && signatures.all { it.verdict == DocumentVerdict.VALID } -> Verdict.PASS; else -> Verdict.CAUTION },
            "簽核點 ${l.points.size} 個" + (if (failed > 0) "，$failed 個簽章不成立" else "") + (if (unsigned > 0) "，$unsigned 個沒有憑證簽章" else ""),
        )
        if (signed.isNotEmpty()) VerdictPill(if (withRevocation == signed.size) Verdict.PASS else Verdict.CAUTION, "撤銷資訊 $withRevocation／${signed.size}")
    }
}

/** One signing point: who signed and when, its signature check, and the files it signed first. */
@Composable
private fun ContainerPointView(p: FilesModel.ContainerPoint, main: StoredFile, open: (StoredFile) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(top = 4.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(p.title, style = MaterialTheme.typography.titleSmall)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            p.signature?.let { s -> val (v, t) = verdictOf(s.verdict); VerdictPill(v, t) } ?: VerdictPill(Verdict.CAUTION, "沒有憑證簽章")
            p.time?.let { Text(localTime(it), style = MaterialTheme.typography.bodySmall) }
        }
        Column(Modifier.padding(start = 12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            p.files.forEach { m ->
                if (m.id == main.id) Text("本公文：${m.name}", style = MaterialTheme.typography.bodySmall)
                else FileRow(m) { open(m) }
            }
            if (p.repeated.isNotEmpty()) Text("另簽核前面簽核點已列出的 ${p.repeated.size} 個檔案（內容未變）", style = MaterialTheme.typography.bodySmall)
            p.changed.forEach { VerdictPill(Verdict.CAUTION, "$it：內容與這個簽核點簽署時不同") }
            p.missing.forEach { VerdictPill(Verdict.CAUTION, "$it：不在容器內") }
        }
    }
}

/** Confirms which files go into an official document's container, showing why each one may belong to it. */
@Composable
fun OfficialBundleScreen(model: WalletModel, screen: Screen.OfficialBundle) {
    val files by model.files.files.collectAsState()
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val main = files.firstOrNull { it.id == screen.mainId }
    if (main == null) {
        EmptyState(WalletIcons.Document, "找不到這份公文", "公文可能已刪除。", "回到文件") { model.showTab(HomeTab.FILES) }
        return
    }
    var candidates by remember(screen) { mutableStateOf<List<FilesModel.BundleCandidate>?>(null) }
    val chosen = remember(screen) { androidx.compose.runtime.mutableStateMapOf<String, Boolean>() }
    LaunchedEffect(screen) {
        val list = model.files.bundleCandidates(main, screen.only)
        list.forEach { chosen[it.file.id] = it.match.suggested }
        candidates = list
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(main.report?.title ?: main.name, style = MaterialTheme.typography.titleMedium)
        Text("檔案本身沒有寫明屬於哪一份公文，錢包依檔名、交換表單的發送對象與公文附件欄比對，請確認要放進這份公文容器的檔案。",
            style = MaterialTheme.typography.bodySmall)
        BusyLine(busy, error)
        val list = candidates
        when {
            list == null -> CircularProgressIndicator(Modifier.size(20.dp))
            list.isEmpty() -> Text("沒有可以放入的檔案。", style = MaterialTheme.typography.bodySmall)
            else -> list.forEach { c ->
                Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                        Checkbox(checked = chosen[c.file.id] == true, onCheckedChange = { chosen[c.file.id] = it })
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(c.file.name, style = MaterialTheme.typography.titleSmall)
                            Text(listOfNotNull(c.file.report?.title, c.file.report?.format?.let { formatTitle(it) }, localTime(c.file.addedAt)).joinToString("　"),
                                style = MaterialTheme.typography.bodySmall)
                            if (c.match.evidence.isEmpty()) Text("沒有找到與這份公文相關的線索", style = MaterialTheme.typography.bodySmall)
                            c.match.evidence.forEach { e -> VerdictPill(if (e.supports) Verdict.PASS else Verdict.CAUTION, e.text) }
                        }
                    }
                }
            }
        }
        val ids = chosen.filterValues { it }.keys.toList()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.files.confirmBundle(main, ids, screen.only, screen.next) }, enabled = ids.isNotEmpty() && busy == null) {
                Text("放入容器（${ids.size}）")
            }
            OutlinedButton(onClick = { model.files.confirmBundle(main, emptyList(), screen.only, screen.next) }, enabled = busy == null) {
                Text(if (screen.next.isEmpty()) "都不放入" else "略過這份公文")
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
    val previews by model.files.previews.collectAsState()
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
    var withMembers by remember { mutableStateOf(false) }
    var removeStamp by remember { mutableStateOf<Int?>(null) }
    var pickContent by remember { mutableStateOf(false) }
    val derived = f.derivedDocumentId?.let { id -> docs.firstOrNull { it.identifier == id } }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        // What it is and whether it holds, then what can be done with it.
        Text(report?.title ?: f.name, style = MaterialTheme.typography.titleLarge)
        Text(listOfNotNull(if (report?.title != null && report.title != f.name) f.name else null, f.period,
            report?.format?.let { formatTitle(it) } ?: f.mediaType, sizeText(f.size), f.source ?: f.origin.title).joinToString("・"),
            style = MaterialTheme.typography.bodySmall)
        BusyLine(busy, error)
        if (report != null) ReportVerdict(report)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.screen.value = Screen.FileSign(f.id) }) { Text("簽署") }
            OutlinedButton(onClick = { model.files.addTimestamp(f) }, enabled = busy == null) { Text("加上時戳") }
            OutlinedButton(onClick = { model.screen.value = Screen.FileDerive(f.id) }) { Text(if (derived != null) "重新產生衍生憑證" else "衍生憑證") }
            OutlinedButton(onClick = { model.files.export(f) }) { Text("匯出") }
            if (model.platform.canShareFiles) OutlinedButton(onClick = { model.files.export(f, share = true) }) { Text("分享") }
        }
        f.contentId?.let { id -> files.firstOrNull { it.id == id } }?.let { c ->
            LabelValue("簽署的檔案", c.name, onClick = { model.screen.value = Screen.FileDetail(c.id) })
        }
        OfficialContainerSection(model, f, files)
        // An OpenCerts certificate is shown field by field below rather than as JSON text.
        if (report?.format != DocumentFormat.OPENCERTS) FilePreviewSection(model, f)

        if (report != null) {
            SectionTitle(if (report.signatures.isEmpty()) "檢查結果" else "簽章（${report.signatures.size}）")
            report.signatures.forEachIndexed { i, s -> SignatureCard(model, s, i, report.signatures.size) { model.files.reinspect(f) } }
            if (report.signatures.isNotEmpty()) {
                val v = f.signatureValidation
                if (v != null) LabelValue("簽章撤銷資訊", v.summary() + "，取得於 ${localTime(v.collectedAt)}", small = true)
                TextButton(onClick = { model.files.collectSignatureValidation(f) }, enabled = busy == null) {
                    Text(if (v == null) "取得並保存簽署者的撤銷資訊（OCSP 優先）" else "重新取得簽署者的撤銷資訊")
                }
                if (model.files.canExtend(f)) {
                    TextButton(onClick = { model.files.extendPdf(f) }, enabled = busy == null) { Text("延長保存：把所有簽章的撤銷資訊與文件時戳寫進 PDF（另存新檔）") }
                }
            }
            report.envelope?.let { e ->
                Text("加密信封", style = MaterialTheme.typography.titleSmall)
                Text("這是加密給特定對象的檔案（CMS EnvelopedData），錢包無法開啟內容，只能保存原檔。", style = MaterialTheme.typography.bodySmall)
                e.recipients.forEach { LabelValue("收件者", it, small = true) }
                e.contentEncryption?.let { LabelValue("內容加密", it, small = true) }
            }
            report.openCert?.let { oc -> OpenCertSection(model, f, oc, busy) }
            if (report.entries.isNotEmpty()) {
                val zip = report.format == DocumentFormat.ASIC_E || report.format == DocumentFormat.ZIP
                CollapsibleSection("容器內的檔案", report.entries.size, initiallyExpanded = report.entries.size <= 10, key = "entries-${f.id}") {
                    if (zip) Text("點選檔案可開啟與檢查；容器與它的簽章保持不變。", style = MaterialTheme.typography.bodySmall)
                    report.entries.take(50).forEach { entry ->
                        if (zip) LabelValue("檔案", OfficialBundles.decodeZipName(entry), small = true, onClick = { model.files.openEntry(f, entry) })
                        else Text(entry, style = MaterialTheme.typography.bodySmall)
                    }
                    if (report.entries.size > 50) Text("另有 ${report.entries.size - 50} 個檔案", style = MaterialTheme.typography.bodySmall)
                }
            }
            report.notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            // The stored check runs without the open password; once this session's password has opened the PDF, the
            // locked-PDF problem no longer holds for the holder.
            val opened = previews[f.id] is FilePreview.Pages
            report.problems.forEach { p ->
                if (opened && p.startsWith(ENCRYPTED_PDF_PROBLEM)) {
                    Text("PDF 已加密，已用這次輸入的密碼開啟（密碼不保存）；簽章檢查不需要密碼。", style = MaterialTheme.typography.bodySmall)
                } else Text(p, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("檢查時間：${localTime(report.checkedAt)}", style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                TextButton(onClick = { model.files.reinspect(f) }, enabled = busy == null) { Text("重新檢查") }
            }
        }

        SectionTitle("時戳（${f.timestamps.size}）")
        if (f.timestamps.isEmpty()) Text("還沒有時戳。時戳由時戳機構（${TsaServices.byId(model.settings.tsaId).name}）證明這份檔案在某個時間已存在，只會送出檔案的 SHA-256。",
            style = MaterialTheme.typography.bodySmall)
        f.timestamps.forEachIndexed { i, t ->
            VerdictPill(if (t.trusted) Verdict.PASS else Verdict.CAUTION, "${t.tsa ?: "時戳機構"}　${localTime(t.time)}" + if (t.trusted) "" else "（機構不在信任錨點）")
            val v = t.validation
            if (v != null) Text(v.summary() + "，取得於 ${localTime(v.collectedAt)}", style = MaterialTheme.typography.bodySmall)
            Row(Modifier.horizontalScroll(rememberScrollState())) {
                if (v == null) TextButton(onClick = { model.files.refreshTimestampValidation(f, i) }, enabled = busy == null) { Text("取得並保存時戳機構的撤銷資訊（OCSP 優先）") }
                TextButton(onClick = { removeStamp = i }, enabled = busy == null) { Text("移除這個時戳", color = MaterialTheme.colorScheme.error) }
            }
        }

        SectionTitle("證件與證明")
        if (derived != null) {
            ActionRow(WalletIcons.Card, derived.displayName ?: "文件衍生憑證", "已在「證件」：IETF SD-JWT VC，由本錢包的文件發行金鑰簽發") {
                model.screen.value = Screen.DocumentDetail(derived.identifier, Screen.FileDetail(f.id))
            }
        } else {
            Text("衍生憑證把文件變成可出示的證件（IETF SD-JWT VC），只交出你選的欄位，附上簽章檢查與時戳；原檔不會送出。", style = MaterialTheme.typography.bodySmall)
        }
        if (f.nationalId != null) {
            ActionRow(WalletIcons.Person, "國民身分證（Bonds 自發卡）", "由這份 MyData 身分證資料製作，以自然人憑證簽署") {
                model.screen.value = Screen.NationalId(f.id, Screen.FileDetail(f.id))
            }
        } else if (report?.format == DocumentFormat.PDF) {
            ActionRow(WalletIcons.Person, "製作 Bonds 身分證卡", "這是 MyData 下載的國民身分證資料 PDF 時，可做成以自然人憑證簽署的身分證卡") {
                model.screen.value = Screen.NationalIdCreate(f.id)
            }
        }
        if (report?.format == DocumentFormat.PDF) {
            ActionRow(WalletIcons.Shield, "產生 zkPDF 證明", "P4 尚未完成：以零知識證明 PDF 內的機關簽章與指定欄位，不必交出整份文件", enabled = false) {}
        }
        f.webProofIds.mapNotNull { id -> docs.firstOrNull { it.identifier == id } }.forEach { proof ->
            ActionRow(WalletIcons.Link, proof.displayName ?: "網站查驗結果", "這份文件的網站查驗證據，已在「證件」") {
                model.screen.value = Screen.DocumentDetail(proof.identifier, Screen.FileDetail(f.id))
            }
        }
        ActionRow(WalletIcons.Link, "產生網站查驗證明（zkTLS）",
            "到官方查驗頁查詢，把結果存成這份文件的證據：透過查驗主機產生 zkTLS 證明，或只用這支手機存為本機紀錄") {
            model.taiwan.zkTls.openSelf(f.id)
        }

        CollapsibleSection("檔案資訊", key = "file-info-${f.id}") {
            LabelValue("檔名", f.name)
            report?.title?.let { LabelValue("標題", it) }
            LabelValue("格式", report?.format?.let { formatTitle(it) } ?: f.mediaType)
            LabelValue("大小", sizeText(f.size))
            report?.pages?.let { LabelValue("頁數", "$it") }
            f.period?.let { LabelValue("期間", it) }
            LabelValue("保存時間", localTime(f.addedAt))
            LabelValue("來源", f.source ?: f.origin.title)
            if (f.source != null || f.archive != null) LabelValue("取得方式", f.origin.title + (f.archive?.let { "（$it）" } ?: ""))
            LabelValue("SHA-256", f.sha256, small = true)
        }
        SectionTitle("其他動作")
        if (report?.format == DocumentFormat.ZIP) ActionRow(WalletIcons.Document, "解出檔案", "逐一保存並檢查壓縮檔內的檔案（MyData 下載檔）") { model.files.extract(f) }
        if (report?.format == DocumentFormat.CMS_SIGNED && f.contentId == null && report.signatures.any { it.integrity == Check.NOT_CHECKED }) {
            ActionRow(WalletIcons.Link, "選擇被簽署的檔案", "分離式簽章（.p7s）需要原檔才能檢查") { pickContent = true }
        }
        if (model.files.hasEvidence(f)) {
            ActionRow(WalletIcons.Send, "匯出文件與證據", "壓縮檔內含原檔、時戳（.tsr）、憑證、OCSP 與 CRL，可在其他工具查驗") { model.files.exportWithEvidence(f) }
            if (model.platform.canShareFiles) {
                ActionRow(WalletIcons.Share, "分享文件與證據", "同一個壓縮檔直接交給其他 App，不另存檔") { model.files.exportWithEvidence(f, share = true) }
            }
        }
        OutlinedButton(onClick = { confirmDelete = true }) {
            Icon(WalletIcons.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text("刪除文件", color = MaterialTheme.colorScheme.error)
        }
    }
    if (confirmDelete) {
        val own = files.count { it.bundleOf == f.id }
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("刪除這份文件？") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("檔案與它的時戳會從這支裝置刪除，無法復原。已產生的衍生憑證保留在「證件」。")
                    if (own > 0) {
                        Row(Modifier.clickable { withMembers = !withMembers }, verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = withMembers, onCheckedChange = { withMembers = it })
                            Text("一併刪除容器內的 $own 個檔案（不勾選時改回獨立檔案）")
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { confirmDelete = false; model.files.delete(f, withMembers && own > 0) }) { Text("刪除", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("取消") } },
        )
    }
    removeStamp?.let { index ->
        AlertDialog(
            onDismissRequest = { removeStamp = null },
            title = { Text("移除這個時戳？") },
            text = { Text("時戳與一起保存的撤銷資訊會刪除，無法復原；之後可以再向時戳機構取得新的時戳。") },
            confirmButton = { TextButton(onClick = { removeStamp = null; model.files.removeTimestamp(f, index) }) { Text("移除", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { removeStamp = null }) { Text("取消") } },
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
private fun SignatureCard(model: WalletModel, s: SignatureInfo, index: Int, count: Int, onTrusted: () -> Unit) {
    val (verdict, text) = verdictOf(s.verdict)
    var trusting by remember(s) { mutableStateOf(false) }
    // The chain ends in a self-issued root that no enabled anchor holds: the user may trust it after confirming.
    val untrustedRoot = s.chain.lastOrNull()?.takeIf { root ->
        s.integrity == Check.PASS && s.chain.size > 1 && root.subject == root.issuer &&
            s.trust.let { t -> t == null || t.anchorName == null || "UNKNOWN_ANCHOR" in t.labels }
    }
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
            untrustedRoot?.let { root ->
                TextButton(onClick = { trusting = true }) { Text("信任根憑證「${root.commonName ?: root.subject}」") }
                if (trusting) RiskConfirmDialog(
                    title = "信任「${root.commonName ?: root.subject}」",
                    lines = listOf(
                        "這個根憑證不在錢包的信任錨點內，錢包無法確認它的管理方式與簽發對象。",
                        "請先由官方網站等可靠來源確認它的指紋，再決定是否信任。",
                        "信任後，連到它的文件簽章與時間戳記判定為 T2（使用者匯入，非官方），可隨時在信任錨點移除。",
                    ),
                    confirm = "信任",
                    onConfirm = { trusting = false; model.trustRootCertificate(root.der.fromBase64(), onTrusted) },
                    onDismiss = { trusting = false },
                )
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

/** Start of the inspector's problem for a PDF whose open password is not known. */
private const val ENCRYPTED_PDF_PROBLEM = "PDF 已加密且需要開啟密碼"

private enum class SignerKind(val title: String) {
    CARD("自然人憑證卡"), MOBILE("行動自然人憑證"), CSC("遠端簽章（CSC）"), SYSTEM("系統金鑰"), TOKEN("硬體憑證（PKCS#11）"),
    PKCS12("憑證檔（PKCS#12）"), WALLET("錢包自有金鑰"),
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
            SignerKind.SYSTEM, SignerKind.TOKEN, SignerKind.MOBILE, SignerKind.CSC -> other
        }
    )
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SignerKind.entries.forEach { k -> FilterChip(selected = k == kind, onClick = { kind = k; other = null; update() }, label = { Text(k.title) }) }
    }
    when (kind) {
        SignerKind.SYSTEM -> SystemKeyPicker(model) { other = it; update() }
        SignerKind.TOKEN -> TokenKeyPicker(model) { other = it; update() }
        SignerKind.MOBILE -> MobileMoicaPicker(model) { other = it; update() }
        SignerKind.CSC -> CscPicker(model) { other = it; update() }
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

/** Whose SP account of the Ministry of the Interior a mobile citizen certificate signature goes through. */
private enum class MobileMoicaSource(val title: String) {
    SERVER("正式服務端的 SP"),
    BUILT_IN("本版內建的 SP"),
    MANUAL("手動輸入 SP"),
}

/**
 * The mobile citizen certificate through an SP account of the Ministry of the Interior: the production server's (no
 * key in the app), the account built into this build, or, with the developer setting on, one typed in here for this
 * run only (kept in memory, never stored).
 */
@Composable
private fun MobileMoicaPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    val settings by model.settingsFlow.collectAsState()
    val manual = settings.manualMobileMoicaSp
    val builtIn = model.files.builtInMobileMoicaSp
    val configured = remember(settings.zkVerifierUrl) { model.server.base() }
    // The server is offered only after its /info says it holds an SP account; null while asking.
    val serverSp by produceState<Result<MobileMoicaEnvironment?>?>(null, configured) {
        value = configured?.let { url -> runCatching { model.server.mobileMoica(url) } } ?: Result.success(null)
    }
    val serverEnvironment = serverSp?.getOrNull()
    val server = configured?.takeIf { serverEnvironment != null }
    val serverNote = when {
        configured == null -> null
        serverSp == null -> "正在確認正式服務端是否提供行動自然人憑證簽署…"
        serverSp?.exceptionOrNull() != null -> "無法確認正式服務端是否提供行動自然人憑證簽署：" + serverSp?.exceptionOrNull()?.let(model::describe)
        serverEnvironment == null -> "正式服務端（${configured.substringAfter("://")}）沒有提供行動自然人憑證簽署（未啟用 twfido）。"
        else -> null
    }
    val sources = listOfNotNull(
        MobileMoicaSource.SERVER.takeIf { server != null },
        MobileMoicaSource.BUILT_IN.takeIf { builtIn != null },
        MobileMoicaSource.MANUAL.takeIf { manual },
    )
    var source by remember(sources) { mutableStateOf(if (manual) MobileMoicaSource.MANUAL else sources.firstOrNull()) }
    val last = model.files.mobileMoicaSp
    var env by remember { mutableStateOf(last?.environment ?: MobileMoicaEnvironment.UAT) }
    var serviceId by remember { mutableStateOf(last?.serviceId.orEmpty()) }
    var aesKey by remember { mutableStateOf(last?.aesKeyBase64.orEmpty()) }
    var idNumber by remember { mutableStateOf(settings.myDataIdNumber.orEmpty()) }
    val canOpenApp = model.platform.mobileMoicaReturnUrl != null
    var mode by remember { mutableStateOf(if (canOpenApp) MobileMoicaMode.APP_TO_APP else MobileMoicaMode.PUSH) }
    fun update() {
        val id = idNumber.trim().uppercase()
        val choice = when (source) {
            MobileMoicaSource.SERVER -> server?.let { SignerChoice.MobileMoica(null, id, mode, server = it) }
            MobileMoicaSource.BUILT_IN -> builtIn?.let { SignerChoice.MobileMoica(it, id, mode) }
            MobileMoicaSource.MANUAL -> MobileMoicaSp(env, serviceId.trim(), aesKey.trim())
                .takeIf { serviceId.isNotBlank() && aesKey.isNotBlank() }?.let { SignerChoice.MobileMoica(it, id, mode) }
            null -> null
        }
        onChange(choice?.takeIf { MyDataProfile.isValidId(id) })
    }
    LaunchedEffect(source) { update() }
    serverNote?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    if (source == null) {
        if (configured != null && serverSp == null) return
        Text("沒有可用的行動自然人憑證服務提供者（SP）帳號：在設定的「零知識證明」頁填入啟用行動自然人憑證簽署的正式服務端；持有 SP 授權的開發者也可在設定開啟「手動輸入 SP 帳號」。",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        return
    }
    if (sources.size > 1) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            sources.forEach { o -> FilterChip(selected = o == source, onClick = { source = o }, label = { Text(o.title) }) }
        }
    }
    when (source) {
        MobileMoicaSource.SERVER -> Text(
            "經由正式服務端（${server?.substringAfter("://")}）的 SP 帳號簽署（${serverEnvironment?.title}），App 內不放 SP 金鑰。服務端會看到你的身分證統一編號與要簽署的摘要資料（不含文件內容）。" +
                "送出前會再向服務端確認一次；" + (if (serverEnvironment == MobileMoicaEnvironment.PRODUCTION) "第一次取得的憑證必須由內政部憑證管理中心簽發，" else "測試環境的憑證只標示為測試，") +
                "簽章也由這支手機驗證。使用設定中的存取權杖。",
            style = MaterialTheme.typography.bodySmall,
        )
        MobileMoicaSource.BUILT_IN -> builtIn?.let { Text("使用本版內建的 SP 帳號（${it.environment.title}）。", style = MaterialTheme.typography.bodySmall) }
        MobileMoicaSource.MANUAL -> {
            Text("開發者選項：以你持有的 SP 帳號簽署。帳號與金鑰只保存在這次執行的記憶體，不會寫入裝置。",
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
        }
        null -> Unit
    }
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

/** The remote signing services, test ones apart from production ones, and a form to add one. */
@Composable
private fun CscPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    val settings by model.settingsFlow.collectAsState()
    val services = remember(settings.cscServices) { model.csc.services }
    var chosen by remember { mutableStateOf<String?>(null) }
    var adding by remember { mutableStateOf(false) }
    LaunchedEffect(services) {
        if (services.none { it.id == chosen }) {
            chosen = null
            onChange(null)
        }
    }
    CscEnvironment.entries.reversed().forEach { env ->
        Text(env.title, style = MaterialTheme.typography.titleSmall)
        val list = services.filter { it.environment == env }
        if (list.isEmpty()) {
            Text(if (env == CscEnvironment.PRODUCTION) "沒有內建的正式服務。正式服務需要向服務商申請帳號，取得 client_id 後在下方加入。" else "沒有測試服務",
                style = MaterialTheme.typography.bodySmall)
        }
        list.forEach { svc ->
            Row(Modifier.fillMaxWidth().clickable { chosen = svc.id; onChange(SignerChoice.Csc(svc)) }, verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(selected = svc.id == chosen, onClick = { chosen = svc.id; onChange(SignerChoice.Csc(svc)) })
                Column(Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(svc.name, style = MaterialTheme.typography.bodyMedium)
                        if (svc.environment == CscEnvironment.TEST) VerdictPill(Verdict.CAUTION, "測試")
                    }
                    Text(svc.baseUrl.substringAfter("://").substringBefore('/') + if (svc.builtIn) "（內建）" else "（自行加入）",
                        style = MaterialTheme.typography.bodySmall)
                    svc.note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
                if (!svc.builtIn) TextButton(onClick = { model.csc.remove(svc.id) }) { Text("移除") }
            }
        }
    }
    if (chosen?.let { model.csc.service(it)?.environment } == CscEnvironment.TEST) {
        Text("測試服務簽出的簽章由測試 CA 簽發，沒有法律效力，查驗時會顯示為無法確認的憑證。", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error)
    }
    Text("按下「簽署」後先登入服務（需要時由錢包出示身分證件），再授權這一次簽章；登入在這次執行內有效，不會保存。若帳號有多張憑證，使用第一張可用的。",
        style = MaterialTheme.typography.bodySmall)
    if (!adding) {
        OutlinedButton(onClick = { adding = true }) { Text("加入遠端簽章服務") }
    } else {
        CscServiceForm(model) { adding = false }
    }
}

@Composable
private fun CscServiceForm(model: WalletModel, onDone: () -> Unit) {
    var name by remember { mutableStateOf("") }
    var baseUrl by remember { mutableStateOf("https://") }
    var clientId by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var redirect by remember { mutableStateOf(CscServices.WALLET_REDIRECT) }
    var env by remember { mutableStateOf(CscEnvironment.PRODUCTION) }
    val problem = model.csc.problem(name, baseUrl, clientId, redirect)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        CscEnvironment.entries.forEach { e -> FilterChip(selected = e == env, onClick = { env = e }, label = { Text(e.title) }) }
    }
    OutlinedTextField(value = name, onValueChange = { name = it.take(60) }, label = { Text("服務名稱") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = baseUrl, onValueChange = { baseUrl = it.trim().take(300) }, label = { Text("CSC API 位址（例如 https://host/csc/v2）") },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = clientId, onValueChange = { clientId = it.trim().take(200) }, label = { Text("client_id") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = secret, onValueChange = { secret = it.trim().take(200) }, label = { Text("client_secret（選填）") }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = redirect, onValueChange = { redirect = it.trim().take(300) }, label = { Text("redirect_uri（向服務商登記的位址）") },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    Text("服務商需登記 redirect_uri；Android 會接收 ${CscServices.WALLET_REDIRECT}，電腦版在瀏覽器完成後貼上最後的網址。client_secret 保存在錢包的加密儲存區。",
        style = MaterialTheme.typography.bodySmall)
    problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { model.csc.add(name, baseUrl, clientId, secret, redirect, env); onDone() }, enabled = problem == null) { Text("加入") }
        OutlinedButton(onClick = onDone) { Text("取消") }
    }
}

/** A PIN or OTP the service asks for, or the address to paste when the browser does not come back by itself. */
@Composable
internal fun CscPromptPanel(model: WalletModel) {
    val p by model.csc.prompt.collectAsState()
    when (val prompt = p) {
        null -> {}
        is CscPrompt.Secret -> {
            var value by remember(prompt) { mutableStateOf("") }
            OutlinedTextField(
                value = value, onValueChange = { value = it.take(64) }, label = { Text(prompt.label) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = if (prompt.numeric) KeyboardType.NumberPassword else KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { prompt.answer.complete(value) }, enabled = value.isNotEmpty()) { Text("送出") }
                OutlinedButton(onClick = { prompt.answer.complete(null) }) { Text("取消") }
            }
        }
        is CscPrompt.Browser -> {
            var pasted by remember(prompt) { mutableStateOf("") }
            Text("已在瀏覽器開啟：${prompt.purpose}。完成後通常會自動回到錢包；沒有回來時，把瀏覽器最後的網址（以 ${prompt.redirectUri} 開頭）貼在這裡。",
                style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(value = pasted, onValueChange = { pasted = it.trim() }, label = { Text("瀏覽器最後的網址") }, singleLine = true,
                modifier = Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { prompt.answer.complete(pasted) }, enabled = pasted.startsWith(prompt.redirectUri)) { Text("繼續") }
                OutlinedButton(onClick = { prompt.answer.complete(null) }) { Text("取消") }
            }
        }
    }
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
        Text(f.report?.title ?: f.name, style = MaterialTheme.typography.titleLarge)
        if (f.report?.title != null && f.report.title != f.name) Text(f.name, style = MaterialTheme.typography.bodySmall)
        SectionTitle("1. 簽章格式")
        forms.forEach { sf ->
            Row(Modifier.fillMaxWidth().clickable { form = sf }, verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(selected = sf == form, onClick = { form = sf })
                Column {
                    Text(sf.title, style = MaterialTheme.typography.bodyMedium)
                    Text(sf.detail, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        SectionTitle("2. 簽署者")
        SignerPicker(model) { choice = it }
        val tsaName = TsaServices.byId(model.settings.tsaId).name
        var level by remember { mutableStateOf(SignatureLevel.of(model.settings.padesLevel)) }
        var certification by remember { mutableStateOf<Int?>(null) }
        val firstSignature = f.report?.signatures.isNullOrEmpty()
        var action by remember { mutableStateOf(ApprovalPoint().action) }
        var organization by remember { mutableStateOf("") }
        var unit by remember { mutableStateOf("") }
        var jobTitle by remember { mutableStateOf("") }
        var account by remember { mutableStateOf("") }
        var role by remember { mutableStateOf("") }
        var returned by remember { mutableStateOf(false) }
        when (form) {
            SignForm.PADES -> {
                SectionTitle("3. 保證層級")
                LevelPicker("PAdES", level) { level = it }
                if (level.timestamp) Text("時戳機構：$tsaName（需要網路）", style = MaterialTheme.typography.bodySmall)
                if (level.revocation) Text("取不到撤銷資訊時不會簽署，請改選較低的等級或稍後再試。", style = MaterialTheme.typography.bodySmall)
                SectionTitle("4. 認證簽章（選填）")
                if (firstSignature) {
                    CERTIFICATIONS.forEach { (p, title, detail) ->
                        Row(Modifier.fillMaxWidth().clickable { certification = p }, verticalAlignment = Alignment.CenterVertically) {
                            androidx.compose.material3.RadioButton(selected = p == certification, onClick = { certification = p })
                            Column {
                                Text(title, style = MaterialTheme.typography.bodyMedium)
                                Text(detail, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                } else Text("文件已有簽章；認證簽章只能是第一個簽章，這次是一般的核准簽章。", style = MaterialTheme.typography.bodySmall)
                Text("簽章不加頁面外觀（不可見簽章），在 PDF 閱讀器的簽章面板查看。頁面上的簽章圖樣需要內嵌中文字型，尚未支援。", style = MaterialTheme.typography.bodySmall)
                CollapsibleSection("簽署原因與地點（選填）", key = "sign-reason-${f.id}") {
                    OutlinedTextField(value = reason, onValueChange = { reason = it.take(100) }, label = { Text("簽署原因") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = location, onValueChange = { location = it.take(100) }, label = { Text("簽署地點") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }
            }
            SignForm.APPROVAL -> {
                val case by produceState<FilesModel.ApprovalCase?>(null, f.id) { value = runCatching { model.files.approvalCase(f) }.getOrNull() }
                case?.let { c ->
                    InfoCard("簽核範圍", buildList {
                        add(if (c.approval != null) "加在簽核檔「${c.approval.name}」之後，涵蓋前一個簽核點" else "建立新的簽核檔")
                        add("涵蓋 ${c.files.size} 個檔案：" + c.files.joinToString("、") { it.name })
                        if (c.missing.isNotEmpty()) add("不在錢包內，無法簽核：" + c.missing.joinToString("、"))
                        add("公文與附件本身不改動，簽核點以檔名與 SHA-256 摘要列出每個檔案。")
                    })
                }
                if (choice is SignerChoice.Wallet) {
                    VerdictCard(Verdict.CAUTION, "錢包金鑰不符合線上簽核規範", listOf(
                        "規範要求簽核點以經核定憑證機構簽發的憑證（自然人憑證、公務人員電子識別證等）簽章，演算法為 RSA-SHA256。",
                        "錢包金鑰是自簽的 ECDSA 憑證，只能證明檔案沒有被改過，機關的公文系統不會接受。",
                    ))
                }
                SectionTitle("3. 簽核內容")
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ApprovalPoint.ACTIONS.forEach { a -> FilterChip(selected = a == action, onClick = { action = a }, label = { Text(a) }) }
                }
                OutlinedTextField(value = action, onValueChange = { action = it.trim().take(ApprovalPoint.ACTION_MAX) }, label = { Text("異動別（最多 10 字，可自行輸入）") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = returned, onCheckedChange = { returned = it })
                    Text("退文（退回前一個簽核點或承辦人）")
                }
                OutlinedTextField(value = reason, onValueChange = { reason = it.take(500) }, label = { Text("簽核意見（選填）") }, modifier = Modifier.fillMaxWidth())
                SectionTitle("4. 簽核人員")
                OutlinedTextField(value = organization, onValueChange = { organization = it.take(60) }, label = { Text("機關（選填）") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = unit, onValueChange = { unit = it.take(60) }, label = { Text("單位") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = jobTitle, onValueChange = { jobTitle = it.take(60) }, label = { Text("職稱") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = account, onValueChange = { account = it.take(60) }, label = { Text("公文系統帳號") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = role, onValueChange = { role = it.take(60) }, label = { Text("角色（選填，例如承辦人員、會辦人員）") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Text("姓名取自簽署憑證。單位、職稱與帳號是規範的必要欄位，沒有填寫時寫入空白。", style = MaterialTheme.typography.bodySmall)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = timestamp, onCheckedChange = { timestamp = it })
                    Text("為新的簽核檔加上文件時戳（$tsaName，需要網路）")
                }
            }
            else -> {
                SectionTitle("3. 保證層級")
                LevelPicker(if (form == SignForm.XADES) "XAdES" else if (form == SignForm.ASIC) "ASiC-E" else "CAdES", level) { level = it }
                if (level.timestamp) Text("時戳機構：$tsaName（需要網路）", style = MaterialTheme.typography.bodySmall)
                if (level.archive) Text("B-LTA 取不到撤銷資訊時不會簽署；B-LT 取不到時只做到 B-T，簽完會顯示實際等級。", style = MaterialTheme.typography.bodySmall)
                else if (level.revocation) Text("取不到撤銷資訊時只做到 B-T，簽完會顯示實際等級。", style = MaterialTheme.typography.bodySmall)
            }
        }
        var details by remember { mutableStateOf(false) }
        TextButton(onClick = { details = !details }) { Text(if (details) "隱藏技術細節" else "技術細節") }
        if (details) InfoCard("技術細節", signDetails(form, level, timestamp, certification.takeIf { form == SignForm.PADES && firstSignature }))
        val locked = form == SignForm.PADES && f.report?.signatures?.any { it.docMdp == 1 } == true
        val breakOk = if (locked) {
            VerdictCard(Verdict.FAIL, "此文件有不允許任何修改的認證簽章", listOf("再加簽會產生新的版本，原認證簽章將被判定為「之後仍有更新」而失效。建議改用 CAdES 或 ASiC-E 另外簽署。"))
            riskOverride(
                f.id, "仍要以 PAdES 加簽", "破壞原有的認證簽章",
                listOf("原認證者宣告這份文件不允許任何修改。", "加簽後，查驗方會看到原認證簽章之後仍有更新，可能拒絕這份文件。", "原始檔案仍保留在文件分頁。"),
            )
        } else true
        BusyLine(busy, error)
        CscPromptPanel(model)
        Button(onClick = { choice?.let { model.files.sign(
                    f, it, form, reason, location, timestamp, allowBreakingCertification = locked,
                    point = ApprovalPoint(
                        action.ifBlank { ApprovalPoint().action }, reason.ifBlank { null }, unit.ifBlank { null }, jobTitle.ifBlank { null }, role.ifBlank { null },
                        account.ifBlank { null }, organization.ifBlank { null }, returned,
                    ),
                    level = level, certification = certification.takeIf { form == SignForm.PADES && firstSignature },
                ) } }, enabled = choice != null && busy == null && breakOk) {
            Text("簽署")
        }
    }
}

/** A plain card with a title and lines (no verdict colours). */
@Composable
private fun InfoCard(title: String, lines: List<String>) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            lines.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/** DocMDP permissions a certification signature can carry: value, title and what it allows. */
private val CERTIFICATIONS = listOf(
    Triple(null, "不認證", "一般簽章，之後任何人都可以再加簽"),
    Triple(2, "認證：允許填表與簽署（P=2）", "宣告自己是文件作者；之後只能填寫表單欄位與加簽，其他修改會讓認證失效"),
    Triple(3, "認證：也允許註解（P=3）", "同 P=2，另外允許加入、修改與刪除註解"),
    Triple(1, "認證：不允許任何修改（P=1）", "之後不能再加簽；只允許加入長期驗證資料與文件時戳（ISO 32000-2）"),
)

/** The four baseline levels for [format], each with what it adds. */
@Composable
private fun LevelPicker(format: String, level: SignatureLevel, onPick: (SignatureLevel) -> Unit) {
    SignatureLevel.entries.forEach { l ->
        Row(Modifier.fillMaxWidth().clickable { onPick(l) }, verticalAlignment = Alignment.CenterVertically) {
            androidx.compose.material3.RadioButton(selected = l == level, onClick = { onPick(l) })
            Column {
                Text(l.title(format), style = MaterialTheme.typography.bodyMedium)
                Text(l.detail, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** What the chosen form and options put in the signature, for the expandable technical details. */
private fun signDetails(form: SignForm, level: SignatureLevel, timestamp: Boolean, certification: Int?): List<String> = when (form) {
    SignForm.PADES -> buildList {
        add("SubFilter ETSI.CAdES.detached，摘要 SHA-256，簽署屬性含 signing-certificate-v2，不寫 signingTime（以 PDF 的 /M 宣稱時間）")
        add("增量更新：原有內容與既有簽章不變，簽章涵蓋整份 PDF 到簽章值之前")
        certification?.let { add("認證簽章：簽章字典的 /Reference 帶 DocMDP 轉換（/P $it），文件目錄的 /Perms /DocMDP 指向這個簽章") }
        if (level.timestamp) add("signature-time-stamp：時戳機構對簽章值的 RFC 3161 時戳，放在未簽署屬性")
        if (level.revocation) add("DSS：簽署者與時戳機構的憑證鏈（以 AIA 補齊）、OCSP 回應或 CRL，並以簽章的 SHA-1 建 VRI 項目")
        if (level.archive) add("文件時戳：另一個 /Type /DocTimeStamp 欄位（SubFilter ETSI.RFC3161），涵蓋 DSS；文件頁的「延長保存」可再加一層")
        add("簽完以憑證公鑰重新檢查簽章值，不符就不寫入")
    }
    SignForm.APPROVAL -> listOf(
        "文書處理手冊的線上簽核格式（104_sign DTD）：在 <線上簽核資訊> 加一個 <簽核點定義>，內含不帶命名空間的 XMLDSig <Signature>",
        "Reference：每個公文與附件以檔名指向檔案本身（SHA-256 摘要）、自己的 <Object>（異動資訊與簽核檔案清單）、前一個簽核點",
        "SignedInfo 以 C14N 20010315 正規化，簽章演算法依憑證（rsa-sha256 或 ecdsa-sha256），KeyInfo 放簽署憑證",
        "簽章時間以民國年月日時分（臺北時間）寫在異動資訊",
    ) + (if (timestamp) listOf("文件時戳：對新的簽核檔 SHA-256 取 RFC 3161 時戳，與檔案分開保存") else emptyList())
    SignForm.XADES -> buildList {
        add("XAdES enveloped：SignedProperties 含 SigningTime、SigningCertificateV2 與 DataObjectFormat，摘要 SHA-256，exclusive C14N")
        if (level.timestamp) add("SignatureTimeStamp：對 SignatureValue 的 RFC 3161 時戳（B-T）")
        if (level.revocation) add("CertificateValues 與 RevocationValues（OCSP 優先，取不到才用 CRL）（B-LT）")
        if (level.archive) add("xadesv141:ArchiveTimeStamp：涵蓋文件、SignedInfo、SignatureValue、KeyInfo 與之前的未簽署屬性（EN 319 132-1 5.5.2）（B-LTA）")
    }
    else -> buildList {
        add("CMS SignedData，摘要 SHA-256，簽署屬性含 signing-certificate-v2 與 signingTime")
        if (level.timestamp) add("signature-time-stamp：對簽章值的 RFC 3161 時戳（B-T）")
        if (level.revocation) add("SignedData 的 certificates 加上完整憑證鏈，crls 加上 CRL 與 OCSP 回應（RFC 5940 otherRevInfo）（B-LT）")
        if (level.archive) add("archive-time-stamp-v3：涵蓋內容、簽章與 ats-hash-index-v3 列出的憑證、撤銷資訊與未簽署屬性（EN 319 122-1 5.5.2）（B-LTA）")
        if (form == SignForm.ASIC) add("ASiC-E：mimetype、原檔與 META-INF/signature001.p7s，ASiCManifest 列出原檔摘要")
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
            when (val r = p.entryExit) {
                is EntryExitCertificate -> EntryExitView(r)
                is MainlandEntryExitRecord -> MainlandEntryExitView(r)
                null -> {}
            }
            p.household?.let { HouseholdView(it) }
            when (val c = p.certificate) {
                is StudentStatusProof -> StudentStatusView(c)
                is MainlandPermitLink -> PermitLinkView(c)
                null -> {}
            }
            if (p.pages.isNotEmpty()) {
                val i = page.coerceIn(0, p.pages.lastIndex)
                val placements = f.report?.signaturePlacements.orEmpty()
                val signatures = f.report?.signatures.orEmpty()
                PreviewImage(p.pages[i], "第 ${i + 1} 頁", placements.filter { it.page == i }, signatures)
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { page = i - 1 }, enabled = i > 0) { Text("上一頁") }
                    Text("第 ${i + 1} / ${p.total} 頁", style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = { page = i + 1 }, enabled = i < p.pages.lastIndex) { Text("下一頁") }
                }
                SignaturePlacementLegend(placements, signatures, i, p.pages.size)
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
 * A household transcript: the household's fields, then one person at a time with a switch between people; the
 * holder (matched by the national ID card or the saved ID number) comes first and is marked.
 */
@Composable
private fun HouseholdView(h: HouseholdTranscript) {
    var selected by remember(h) { mutableStateOf(0) }
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(h.title ?: "戶籍資料", style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        if (h.household.isNotEmpty()) {
            Text("戶籍", style = MaterialTheme.typography.titleSmall)
            h.household.forEach { (k, v) -> if (k.isEmpty()) Text(v, style = MaterialTheme.typography.bodySmall) else LabelValue(k, v, small = true) }
        }
        Text("住戶（${h.people.size} 位）", style = MaterialTheme.typography.titleSmall)
        if (!h.holderFound) {
            Text("沒有比對到持有人本人（以身分證卡或設定的身分證統一編號比對），依文件順序列出。", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline)
        }
        if (h.people.size > 1) {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                h.people.forEachIndexed { i, person ->
                    FilterChip(
                        selected = i == selected,
                        onClick = { selected = i },
                        label = { Text((person.member.name ?: "住戶 ${i + 1}") + if (person.holder) "（本人）" else "") },
                    )
                }
            }
        }
        val person = h.people[selected.coerceIn(0, h.people.lastIndex)]
        if (person.holder) Text("持有人本人", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        person.fields.forEach { (k, v) -> if (k.isEmpty()) Text(v, style = MaterialTheme.typography.bodySmall) else LabelValue(k, v, small = true) }
    }
}

/** An entry and exit certificate laid out as its parts: the person, the certificate and the table of trips. */
@Composable
private fun EntryExitView(c: EntryExitCertificate) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text("入出國日期證明書", style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        Text("個人資訊", style = MaterialTheme.typography.titleSmall)
        c.name?.let { LabelValue("姓名", it, small = true) }
        c.englishName?.let { LabelValue("英文姓名", it, small = true) }
        c.nationality?.let { LabelValue("國籍", it, small = true) }
        c.gender?.let { LabelValue("性別", it, small = true) }
        c.idNumber?.let { LabelValue("護照號碼或統一證號", it, small = true) }
        c.birthDate?.let { LabelValue("出生日期", it.toString(), small = true) }
        Text("文件資訊", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        c.issuer?.let { LabelValue("發證機關", it, small = true) }
        c.serialNumber?.let { LabelValue("證明書序號", it, small = true) }
        c.issuedAt?.let { LabelValue("發證時間", it, small = true) }
        if (c.periodFrom != null && c.periodTo != null) LabelValue("查詢期間", "${c.periodFrom} 至 ${c.periodTo}", small = true)
        c.pages?.let { LabelValue("頁數", "$it 頁", small = true) }
        Text("入出境摘要", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        LabelValue("紀錄筆數", "${c.trips.size} 筆", small = true)
        c.latestExit?.let { LabelValue("最後出境日期", it.toString(), small = true) }
        c.latestEntry?.let { LabelValue("最後入境日期", it.toString(), small = true) }
        c.returnedFromLatestTrip?.let { LabelValue("最近一次出境", if (it) "已入境" else "尚未入境", small = true) }
        c.inTaiwanAtEnd?.let { LabelValue("${c.coveredUntil} 時", if (it) "在境內" else "在境外", small = true) }
        if (c.trips.isNotEmpty()) {
            Text("入出境紀錄", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
            Row(Modifier.fillMaxWidth()) {
                Text("項次", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(0.6f))
                Text("出境日期", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.2f))
                Text("入境日期", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.2f))
            }
            HorizontalDivider()
            c.trips.forEach { t ->
                Row(Modifier.fillMaxWidth()) {
                    Text(t.item.toString(), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(0.6f))
                    Text(t.exit?.toString() ?: "無", style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1.2f))
                    Text(t.entry?.toString() ?: "尚未入境", style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1.2f))
                }
            }
        }
    }
}

/** A proof of student status laid out as its parts: the student, the study, the issuing office and verification. */
@Composable
private fun StudentStatusView(c: StudentStatusProof) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(c.title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        c.number?.let { Text("NO. $it", style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center) }
        Text("學生", style = MaterialTheme.typography.titleSmall)
        c.name?.let { LabelValue("姓名", it, small = true) }
        c.englishName?.let { LabelValue("英文姓名", it, small = true) }
        c.gender?.let { LabelValue("性別", it, small = true) }
        c.birthDate?.let { LabelValue("出生日期", it.toString(), small = true) }
        c.studentId?.let { LabelValue("學號", it, small = true) }
        c.idNumber?.let { LabelValue("證件號碼", it, small = true) }
        Text("學籍", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        c.school?.let { LabelValue("學校", it, small = true) }
        LabelValue("狀態", "在學（證明列印時）", small = true)
        c.enrolled?.let { LabelValue("入學年月", it, small = true) }
        c.college?.let { LabelValue("學院", it + (c.collegeEnglish?.let { e -> "\n$e" } ?: ""), small = true) }
        c.major?.let { LabelValue("專業", it + (c.majorEnglish?.let { e -> "\n$e" } ?: ""), small = true) }
        c.programme?.let { LabelValue("學制", it + (c.programmeEnglish?.let { e -> "\n$e" } ?: ""), small = true) }
        Text("出具單位", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        c.office?.let { LabelValue("單位", it + (c.officeEnglish?.let { e -> "\n$e" } ?: ""), small = true) }
        c.printDate?.let { LabelValue("列印日期", it.toString(), small = true) }
        c.address?.let { LabelValue("地址", it + (c.zipCode?.let { z -> "（郵遞區號 $z）" } ?: ""), small = true) }
        c.phone?.let { LabelValue("電話", it, small = true) }
        c.contactPhone?.let { LabelValue("諮詢電話", it, small = true) }
        c.email?.let { LabelValue("電子郵件", it, small = true) }
        c.website?.let { LabelValue("網站", it, small = true) }
        if (c.verificationCode != null || c.verificationUrl != null) {
            Text("驗證", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
            c.verificationCode?.let { LabelValue("驗證密鑰", it, small = true) }
            c.verificationUrl?.let { LabelValue("驗證網址", it, small = true) }
            Text("學校的驗證網頁以驗證密鑰查詢這份證明；網址若是 http，連線沒有加密，查詢結果只能當作輔助比對。",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        }
    }
}

/**
 * A mainland China permit association laid out as its parts: the person, the documents linked to them (travel
 * permit with its expiry, residence permit) and the record with the last day it is valid.
 */
@Composable
private fun PermitLinkView(c: MainlandPermitLink) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text("通行證與居住證關聯查詢結果", style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        Text("個人資訊", style = MaterialTheme.typography.titleSmall)
        c.name?.let { LabelValue("姓名", it, small = true) }
        c.gender?.let { LabelValue("性別", it, small = true) }
        c.birthDate?.let { LabelValue("出生日期", it.toString(), small = true) }
        c.residentOf?.let { LabelValue("身分", "${it}居民", small = true) }
        Text("同時持用或曾持用的證件", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        if (c.permits.isEmpty()) Text("讀不出證件清單，請看下方頁面。", style = MaterialTheme.typography.bodySmall)
        c.permits.forEach { p -> LabelValue(p.name, p.number + (p.validUntil?.let { "\n有效期至 $it" } ?: ""), small = true) }
        if (c.travelPermit != null && c.residencePermit != null) {
            Text("文件記載通行證與居住證屬於同一人。", style = MaterialTheme.typography.bodySmall)
        }
        Text("文件資訊", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        LabelValue("發證機關", c.issuer, small = true)
        c.number?.let { LabelValue("編號", it, small = true) }
        c.queryDate?.let { LabelValue("查詢日期", it.toString(), small = true) }
        c.validUntil?.let { LabelValue("有效期至", "$it（自查詢日期起 ${c.validDays} 天）", small = true) }
        c.pages?.let { LabelValue("頁數", "$it 頁", small = true) }
    }
}

/**
 * A mainland China entry and exit record laid out as its parts: the person, the record and every movement of the
 * queried period, latest first (出境 leaves mainland China, 入境 arrives).
 */
@Composable
private fun MainlandEntryExitView(c: MainlandEntryExitRecord) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text("出入境記錄查詢結果（中國大陸）", style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        Text("個人資訊", style = MaterialTheme.typography.titleSmall)
        c.name?.let { LabelValue("姓名", it, small = true) }
        c.gender?.let { LabelValue("性別", it, small = true) }
        c.birthDate?.let { LabelValue("出生日期", it.toString(), small = true) }
        c.documentNumber?.let { LabelValue((c.documentLabel ?: "證件") + "號碼", it, small = true) }
        Text("文件資訊", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        LabelValue("發證機關", c.issuer, small = true)
        c.number?.let { LabelValue("編號", it, small = true) }
        c.queryDate?.let { LabelValue("查詢日期", it.toString(), small = true) }
        if (c.periodFrom != null && c.periodTo != null) LabelValue("查詢期間", "${c.periodFrom} 至 ${c.periodTo}", small = true)
        c.madeAt?.let { LabelValue("製作日期", it, small = true) }
        c.pages?.let { LabelValue("頁數", "$it 頁", small = true) }
        Text("出入境摘要", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        LabelValue("紀錄筆數", "${c.movements.size} 筆", small = true)
        c.latestArrival?.let { LabelValue("最後入境中國大陸", it.toString(), small = true) }
        c.latestDeparture?.let { LabelValue("最後離開中國大陸", it.toString(), small = true) }
        c.insideAtEnd?.let { LabelValue("${c.coveredUntil} 時", if (it) "在中國大陸境內" else "不在中國大陸境內", small = true) }
        if (c.movements.isNotEmpty()) {
            Text("出入境記錄", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
            Row(Modifier.fillMaxWidth()) {
                Text("序號", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(0.5f))
                Text("出入境", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(0.6f))
                Text("日期", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.1f))
                Text("口岸與航班", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.6f))
            }
            HorizontalDivider()
            c.movements.forEach { m ->
                Row(Modifier.fillMaxWidth()) {
                    Text(m.item.toString(), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(0.5f))
                    Text(if (m.arrival) "入境" else "出境", style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(0.6f))
                    Text(m.date.toString(), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1.1f))
                    Text(listOfNotNull(m.port, m.flight).joinToString(" ").ifEmpty { "未記載" }, style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1.6f))
                }
            }
        }
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
private fun PreviewImage(
    image: ImageBitmap,
    description: String,
    placements: List<SignaturePlacementInfo> = emptyList(),
    signatures: List<SignatureInfo> = emptyList(),
) {
    val visible = placements.filter { it.visible }
    if (visible.isEmpty()) {
        Image(
            image, contentDescription = description, contentScale = ContentScale.FillWidth,
            modifier = Modifier.fillMaxWidth().aspectRatio(image.width.toFloat() / image.height.coerceAtLeast(1))
                .clip(RoundedCornerShape(8.dp)).border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)),
        )
        return
    }
    // Frame each visible signature over the rendered page; the frame colour follows the signature's verdict.
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val w = maxWidth
        val h = w * (image.height.toFloat() / image.width.coerceAtLeast(1))
        Image(
            image, contentDescription = description, contentScale = ContentScale.FillWidth,
            modifier = Modifier.fillMaxWidth().height(h)
                .clip(RoundedCornerShape(8.dp)).border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)),
        )
        visible.forEach { pl ->
            val verdict = signatures.firstOrNull { it.label == pl.label }?.verdict
            val color = when (verdict) {
                DocumentVerdict.VALID -> MaterialTheme.colorScheme.primary
                DocumentVerdict.INVALID -> MaterialTheme.colorScheme.error
                else -> MaterialTheme.colorScheme.tertiary
            }
            Box(
                Modifier.offset(x = w * pl.x0, y = h * pl.y0)
                    .size(width = (w * (pl.x1 - pl.x0)).coerceAtLeast(6.dp), height = (h * (pl.y1 - pl.y0)).coerceAtLeast(6.dp))
                    .border(2.dp, color, RoundedCornerShape(3.dp)),
            )
        }
    }
}

/** Which signatures sit on the page now shown, and which are invisible, so the frames above are readable. */
@Composable
private fun SignaturePlacementLegend(placements: List<SignaturePlacementInfo>, signatures: List<SignatureInfo>, page: Int, previewPages: Int) {
    if (placements.isEmpty()) return
    val onPage = placements.filter { it.page == page && it.visible }
    val invisible = placements.filter { !it.visible }
    if (onPage.isNotEmpty()) {
        Text("本頁的可見簽章：" + onPage.joinToString("、") { it.label }, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    val otherPages = placements.filter { it.visible && it.page != page }.map { it.page }.distinct().sorted()
    if (otherPages.isNotEmpty()) {
        Text("其他頁的簽章位置：第 " + otherPages.joinToString("、") { (it + 1).toString() } + " 頁" +
            (if (otherPages.any { it >= previewPages }) "（部分頁未在預覽內）" else ""),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
    }
    if (invisible.isNotEmpty()) {
        Text("不可見簽章（沒有外觀，不顯示位置）：" + invisible.joinToString("、") { it.label },
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
    }
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
    val builtIn = v.templateUrl?.let { url -> Regex("^https://([^/:]+)").find(url.trim())?.groupValues?.get(1)?.lowercase() in OpenCertOffline.BUILT_IN_HOSTS } == true
    ActionRow(WalletIcons.Document, "離線顯示證書",
        if (builtIn) "依發證機構使用的 OpenCerts 範例樣式排版，不需要網路，內容不離開手機" else "由錢包依證書內容排版，不需要網路，內容不離開手機") {
        model.screen.value = Screen.OpenCertRender(f.id, offline = true)
    }
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
                if (model.platform.canShareFiles) {
                    OutlinedButton(onClick = { model.files.exportOpenCertAttachment(a, share = true) }, enabled = busy == null) { Text("分享") }
                }
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
    val page by produceState<String?>(null, f.id, screen.offline) {
        value = (if (screen.offline) model.files.openCertOfflinePage(f)?.html else model.files.openCertRendererPage(f)) ?: ""
    }
    Column(Modifier.fillMaxSize()) {
        if (!screen.offline) {
            Text("由發證機構指定的顯示程式繪製；內容與上一頁的檢查結果相同，查驗結果以上一頁為準。", style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
        }
        when (val html = page) {
            null -> Text("正在準備", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
            "" -> Text(if (screen.offline) "無法讀取這份證書。" else "這份證書沒有可用的 https 顯示程式。", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
            else -> OpenCertRendererView(html, Modifier.fillMaxWidth().weight(1f), offline = screen.offline) { url ->
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
    var dayText by remember(f) { mutableStateOf("") }
    var dayClaims by remember(f) { mutableStateOf<List<DerivedClaim>>(emptyList()) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("把「${f.report?.title ?: f.name}」變成可出示的證件。查驗方只會看到你勾選的欄位，以及文件指紋、格式與大小；原檔不會送出。",
            style = MaterialTheme.typography.bodyMedium)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            f.report?.let { r -> val (v, t) = verdictOf(r.verdict); VerdictPill(v, t) }
            if (f.timestamps.any { it.trusted }) VerdictPill(Verdict.PASS, "已有時戳")
            f.source?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        SectionTitle("1. 欄位（由文件內容解析）")
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
        val entryExit = fields?.entryExit
        if (entryExit != null) {
            Text("指定日期是否在${entryExit.inside}（依出入境紀錄計算，可加入多個日期）", style = MaterialTheme.typography.bodyMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(value = dayText, onValueChange = { dayText = it.take(10) }, label = { Text("日期（2026-01-31）") }, singleLine = true,
                    modifier = Modifier.weight(1f))
                val day = runCatching { LocalDate.parse(dayText.trim()) }.getOrNull()
                val answer = day?.let { DocumentFields.insideOn(entryExit, it) }
                Button(onClick = { answer?.let { a -> dayClaims = dayClaims.filter { it.name != a.name } + a } }, enabled = answer != null) { Text("加入") }
            }
            val day = runCatching { LocalDate.parse(dayText.trim()) }.getOrNull()
            if (dayText.isNotBlank() && (day == null || DocumentFields.insideOn(entryExit, day) == null)) {
                Text(if (day == null) "日期格式為 年-月-日。" else "這個日期不在文件的查詢期間（${entryExit.periodFrom} 至 ${entryExit.coveredUntil}），無法判斷。",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            dayClaims.forEach { c ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = true, onCheckedChange = { dayClaims = dayClaims - c })
                    Column {
                        Text(DerivedCredentials.labelOf(c), style = MaterialTheme.typography.bodyMedium)
                        Text(if (c.value == "true") "在${entryExit.inside}" else "不在${entryExit.inside}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
        TextButton(onClick = { showNote = !showNote }) { Text(if (showNote) "不加入自填欄位" else "加入自填欄位（查驗方會看到這是持有人自填）") }
        if (showNote) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = noteName, onValueChange = { noteName = it.take(32) }, label = { Text("欄位名稱") }, singleLine = true, modifier = Modifier.weight(1f))
                OutlinedTextField(value = noteValue, onValueChange = { noteValue = it.take(200) }, label = { Text("內容") }, singleLine = true, modifier = Modifier.weight(1f))
            }
        }
        SectionTitle("2. 證據")
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = timestamp, onCheckedChange = { timestamp = it })
            Text(if (f.timestamps.any { it.trusted }) "附上已保存的時戳" else "取得並附上文件時戳（只送出 SHA-256）")
        }
        SectionTitle("3. 有效期間")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf<Pair<Int?, String>>(null to "不限", 365 to "一年", 1825 to "五年").forEach { (d, t) ->
                FilterChip(selected = validDays == d, onClick = { validDays = d }, label = { Text(t) })
            }
        }
        BusyLine(busy, error)
        val claims = suggested.filter { it.name in chosen } + dayClaims + listOfNotNull(
            if (showNote && noteName.isNotBlank() && noteValue.isNotBlank()) {
                DerivedClaim(DerivedCredentials.SELF_ASSERTED_PREFIX + noteName.trim(), noteValue.trim(), "持有人自填：" + noteName.trim())
            } else null,
        )
        Button(
            onClick = { model.files.derive(f, claims, timestamp, validDays) },
            enabled = busy == null && claims.isNotEmpty(),
        ) { Text("產生衍生憑證") }
        CollapsibleSection("衍生憑證證明什麼", key = "derive-about") {
            Text("衍生憑證由這支錢包的文件發行金鑰（did:key）簽發，結構是 IETF SD-JWT VC，信任等級為 T3：它證明你在何時、以哪些證據保存了這份文件，不代表原發文機關另行背書。Bonds 的 vc+moica 結構只用於身分證卡；Bonds 查驗方要的 MyData 衍生答案（所得、勞保、戶籍）在出示當下才由原檔產生，不需先在這裡製作。",
                style = MaterialTheme.typography.bodySmall)
        }
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

