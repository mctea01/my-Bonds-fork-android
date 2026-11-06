package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import diw.wallet.app.ServerStrings
import diw.wallet.app.WalletModel
import diw.wallet.app.ZkJobPhase
import diw.wallet.app.ZkMeasurement
import diw.wallet.core.zk.ZkAsset
import diw.wallet.core.zk.ZkAssetStatus
import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.RemoteZkPdfEngine
import diw.wallet.core.zk.ZkCapability
import diw.wallet.core.zk.ZkPdfStatement
import diw.wallet.core.zk.ZkProverHost
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.ZkTier
import kotlinx.coroutines.launch

internal val ZkBackend.title: String
    get() = when (this) {
        ZkBackend.NOIR_ULTRAHONK -> "PDF 簽章證明（zkPDF）"
        ZkBackend.TLSN -> "網站查驗證明（zkTLS）"
        ZkBackend.OPENAC_SPARTAN2 -> "年齡證明（OpenAC）"
        ZkBackend.LONGFELLOW -> "mdoc 年齡證明（Longfellow）"
    }

internal val ZkTier.title: String
    get() = when (this) {
        ZkTier.A -> "等級 A：建議在這台裝置產生"
        ZkTier.B -> "等級 B：多數證明可在這台裝置產生"
        ZkTier.C -> "等級 C：建議在電腦版產生"
    }

/** The settings-list summary: the device tier once it is known. */
internal fun zkSummary(capability: ZkCapability?): String =
    capability?.let { "零知識：等級 ${it.tier.name}" } ?: "零知識：尚未評估"

private val ZkAssetStatus.title: String
    get() = when (this) {
        ZkAssetStatus.MISSING -> "未下載"
        ZkAssetStatus.PARTIAL -> "下載未完成，可續傳"
        ZkAssetStatus.READY -> "已安裝"
        ZkAssetStatus.CORRUPT -> "檢查不符，需重新下載"
    }

/**
 * Zero-knowledge proofs in the security settings: the device tier and why, each engine and whether it is in this
 * build, the circuit assets with their sizes (downloaded only after the user agrees to the size, deletable), and the
 * self-hosted prover, which opens with zkPDF.
 */
@Composable
fun ZkSettingsScreen(model: WalletModel) {
    val zk = model.zk
    val capability by zk.capability.collectAsState()
    val native by zk.native.collectAsState()
    val problem by zk.nativeProblem.collectAsState()
    val info by zk.platformInfo.collectAsState()
    val statuses by zk.assetStatus.collectAsState()
    val downloads by zk.downloads.collectAsState()
    val refreshing by zk.refreshing.collectAsState()
    val scope = rememberCoroutineScope()
    var confirmDownload by remember { mutableStateOf<List<ZkAsset>?>(null) }
    var confirmDelete by remember { mutableStateOf<List<ZkAsset>?>(null) }
    LaunchedEffect(Unit) { zk.refresh() }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text(
            "零知識證明讓查驗方只看到要證明的結論（例如已滿 18 歲、文件由某機關簽署），看不到其他內容。證明在這台裝置產生，" +
                "私密內容不離開裝置；需要的電路檔較大，使用前才下載。",
            style = MaterialTheme.typography.bodySmall,
        )
        SectionTitle("這台裝置")
        val cap = capability
        if (cap == null) Text(if (refreshing) "正在評估…" else "尚未評估", style = MaterialTheme.typography.bodyMedium)
        else {
            Text(cap.tier.title, style = MaterialTheme.typography.titleSmall)
            info?.let { i ->
                Text(
                    "架構 ${i.abi}・記憶體 ${i.totalRamMb} MB（可用 ${i.availableRamMb} MB）・可用儲存空間 ${i.freeDiskMb} MB",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Text("等級只是建議，不會阻止產生；算力不足時開始前會讓你選擇在這台裝置產生、改用電腦版或不加零知識證據。",
                style = MaterialTheme.typography.bodySmall)
        }
        problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }

        HorizontalDivider()
        SectionTitle("證明引擎")
        native?.version?.takeIf { it.isNotEmpty() }?.let { Text("原生程式庫版本 $it", style = MaterialTheme.typography.bodySmall) }
        ZkBackend.entries.forEach { backend ->
            val available = cap != null && backend in cap.backends
            val reason = cap?.reasons?.get(backend)
            Column {
                Text(backend.title, style = MaterialTheme.typography.titleSmall)
                Text(
                    when {
                        cap == null -> "尚未評估"
                        available && reason == null -> "可在這台裝置產生"
                        available -> "可產生；$reason"
                        else -> reason ?: "此版本尚未包含此證明後端"
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        HorizontalDivider()
        SectionTitle("電路檔")
        if (zk.catalog.isEmpty()) Text("此版本沒有附電路檔清單。", style = MaterialTheme.typography.bodySmall)
        zk.catalog.groupBy { it.backend }.forEach { (backend, assets) ->
            val installed = assets.filter { statuses[it.id] == ZkAssetStatus.READY }
            val missing = assets - installed.toSet()
            Text(backend.title, style = MaterialTheme.typography.titleSmall)
            Text(
                "已安裝 ${installed.size} / ${assets.size}・佔用 ${sizeText(installed.sumOf { it.installedBytes })}" +
                    if (missing.isNotEmpty()) "・尚需下載 ${sizeText(missing.sumOf { it.gzipBytes })}" else "",
                style = MaterialTheme.typography.bodySmall,
            )
            assets.forEach { asset ->
                val download = downloads[asset.id]
                Column(Modifier.fillMaxWidth().padding(start = 8.dp)) {
                    Text(
                        "${asset.id}・${if ("verifier" in asset.role) "產生與查驗" else "產生"}・安裝後 ${sizeText(asset.installedBytes)}・" +
                            (statuses[asset.id]?.title ?: if (refreshing) "檢查中" else "未檢查"),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (download != null && download.error == null) {
                        LinearProgressIndicator(
                            progress = { if (download.total <= 0) 0f else download.received.toFloat() / download.total },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    download?.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                val busy = assets.any { downloads[it.id]?.error == null && it.id in downloads }
                if (busy) OutlinedButton(onClick = { zk.cancelDownload() }) { Text("停止下載") }
                else if (missing.isNotEmpty()) OutlinedButton(onClick = { confirmDownload = missing }) { Text("下載") }
                if (installed.isNotEmpty() && !busy) OutlinedButton(onClick = { confirmDelete = installed }) { Text("刪除") }
            }
        }
        OutlinedButton(onClick = { zk.refresh() }, enabled = !refreshing) { Text(if (refreshing) "檢查中…" else "重新檢查") }

        HorizontalDivider()
        SectionTitle("查驗頁與文件版型")
        ZkTemplatesSection(model)

        HorizontalDivider()
        SectionTitle("正式服務端")
        ServerSection(model)
        HorizontalDivider()
        SectionTitle("自架主機")
        ProverSection(model)
        if (info?.isDesktop == true) {
            HorizontalDivider()
            SectionTitle("代手機產生 zkPDF 證明")
            PhoneRequestSection(model)
        }
        HorizontalDivider()
        SectionTitle("證明效能紀錄")
        MeasurementSection(model)
    }

    confirmDownload?.let { assets ->
        AlertDialog(
            onDismissRequest = { confirmDownload = null },
            title = { Text("下載電路檔？") },
            text = {
                Text(
                    "將下載 ${sizeText(assets.sumOf { it.gzipBytes })}，安裝後佔用 ${sizeText(assets.sumOf { it.installedBytes })}。" +
                        "建議使用 Wi-Fi；可隨時停止，下次會從中斷處續傳。每個檔案都會比對清單上的 SHA-256，不符就刪除。",
                )
            },
            confirmButton = { TextButton(onClick = { confirmDownload = null; zk.download(assets.map { it.id }) }) { Text("下載") } },
            dismissButton = { TextButton(onClick = { confirmDownload = null }) { Text("取消") } },
        )
    }
    confirmDelete?.let { assets ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text("刪除電路檔？") },
            text = { Text("將釋放 ${sizeText(assets.sumOf { it.installedBytes })}。之後要產生這類證明時需重新下載。已產生的證明不受影響。") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = null
                    scope.launch { assets.forEach { zk.delete(it.id) } }
                }) { Text("刪除", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("取消") } },
        )
    }
}

/** The signed page templates from the release: what is installed, when it was checked, and a manual update. */
@Composable
private fun ZkTemplatesSection(model: WalletModel) {
    val st by model.zkTemplates.state.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    Text("zkTLS 查驗頁與 zkPDF 文件版型隨每次發布更新，不需要更新 App。版型只描述要揭露的欄位，電路仍以 App 內的版本為準；" +
        "版型包須有本專案發布金鑰的簽章，也不會被較舊的版本取代。", style = MaterialTheme.typography.bodySmall)
    val lines = buildList {
        if (!st.keyConfigured) add("此版本尚未設定版型簽章金鑰，暫時只能使用查驗方在測試環境附上的查驗頁。")
        if (st.version != null) add("已安裝：${st.pages} 個查驗頁、${st.documents} 個文件版型・發布於 ${localTime(st.issuedAt!!)}" + (st.source?.let { "・來源：$it" } ?: ""))
        else if (st.keyConfigured) add(if (st.running) "下載中" else "尚未下載")
        st.checkedAt?.let { add("上次檢查：${localTime(it)}") }
        st.error?.let { add("最近一次更新失敗：$it" + if (st.version != null) "（仍使用已安裝的版型）" else "") }
    }
    lines.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(enabled = st.keyConfigured && !st.running, onClick = { model.zkTemplates.refresh() }) { Text("立即更新") }
        OutlinedButton(enabled = !st.running, onClick = { model.zkTemplates.importFiles() }) { Text("從檔案匯入") }
    }
    Text(
        "可匯入發布的 zk-templates.jwt，或 CI 產物的 ZIP 檔，簽章與版本檢查和線上更新相同。" +
            if (settings.testEnvironment) "測試環境另可匯入未簽章的查驗頁描述檔與 zkPDF 文件版型（.json），只在測試環境使用；查驗頁會附在請求中，文件版型則雙方都要匯入，對方也須開啟測試環境。" else "",
        style = MaterialTheme.typography.bodySmall,
    )
    st.notice?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
    if (st.testPages.isNotEmpty() || st.testDocuments.isNotEmpty()) {
        Text("測試版型" + if (settings.testEnvironment) "" else "（測試環境關閉中，不會使用）", style = MaterialTheme.typography.titleSmall)
        st.testPages.forEach { p ->
            Text("查驗頁：${p.title}（${p.id}）・${p.host}" + if (p.port != 443) ":${p.port}" else "", style = MaterialTheme.typography.bodySmall)
        }
        st.testDocuments.forEach { d ->
            Text("文件版型：${d.title}（${d.id}）・${d.fields.size} 個欄位", style = MaterialTheme.typography.bodySmall)
        }
        OutlinedButton(onClick = { model.zkTemplates.clearTestPages() }) { Text("清除測試版型") }
    }
}

/** The proofs' row on the security page. */
@Composable
internal fun ZkSettingsRow(model: WalletModel, onOpen: () -> Unit) {
    val capability by model.zk.capability.collectAsState()
    ActionRow(WalletIcons.Shield, "零知識證明", zkSummary(capability).removePrefix("零知識：") + "・電路檔下載與刪除", onClick = onOpen)
}

/**
 * The production server (diw-wallet-server, or the test server's API) used as relay, zkTLS verifier host and age
 * host: its address, the access token its zkTLS host asks for, and trusting the root that signs its requests and
 * receipts after the user compares the fingerprint.
 */
@Composable
private fun ServerSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    val server by model.server.state.collectAsState()
    var url by remember(settings.zkVerifierUrl) { mutableStateOf(settings.zkVerifierUrl) }
    var token by remember(settings.serverToken) { mutableStateOf(settings.serverToken) }
    val valid = url.isEmpty() || url.startsWith("https://") || settings.testEnvironment && url.startsWith("http://")
    val saved = settings.zkVerifierUrl.isNotEmpty()
    val trustedAny = settings.serverRootSha256.isNotEmpty() || settings.serverVerifierDid.isNotEmpty()
    LaunchedEffect(settings.zkVerifierUrl) { if (saved && trustedAny) model.server.check(confirm = false) }
    Text(
        "轉送、網站查驗（zkTLS）與年齡查驗都使用這台服務端；它只轉送與查驗，看不到你的出生日期或文件其他內容。" +
            "可部署 diw-wallet-server 或專案的測試伺服器（test-servers）。留空時在測試環境使用測試伺服器。",
        style = MaterialTheme.typography.bodySmall,
    )
    OutlinedTextField(
        value = url, onValueChange = { url = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text("服務端網址（https）") }, isError = !valid,
    )
    OutlinedTextField(
        value = token, onValueChange = { token = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text("存取權杖（服務端要求時才填）") }, visualTransformation = PasswordVisualTransformation(),
    )
    Text("權杖只送給上面這台服務端，以加密方式存在這台裝置。", style = MaterialTheme.typography.bodySmall)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(
            onClick = {
                val changedUrl = url.trimEnd('/') != settings.zkVerifierUrl
                model.updateSettings {
                    it.copy(
                        zkVerifierUrl = url.trimEnd('/'), serverToken = token,
                        serverRootSha256 = if (changedUrl) "" else it.serverRootSha256,
                        serverVerifierDid = if (changedUrl) "" else it.serverVerifierDid,
                    )
                }
            },
            enabled = valid && (url != settings.zkVerifierUrl || token != settings.serverToken),
        ) { Text("儲存") }
        OutlinedButton(onClick = { model.server.check(confirm = true) }, enabled = saved && !server.checking && url == settings.zkVerifierUrl) {
            Text(if (server.checking) "讀取中…" else if (!trustedAny) "加入信任" else "重新確認信任")
        }
    }
    if (settings.serverRootSha256.isNotEmpty()) {
        Text("已信任簽章根憑證 SHA-256：${fingerprint(settings.serverRootSha256)}", style = MaterialTheme.typography.bodySmall)
    }
    if (settings.serverVerifierDid.isNotEmpty()) {
        Text("已信任網頁查驗端：${settings.serverVerifierDid}", style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
    if (server.changed) {
        Text(
            "這台服務端的簽章根憑證或網頁查驗端 DID 和你先前信任的不同。可能是業者換了金鑰，也可能不是原本的服務端；請向業者確認後再按「重新確認信任」。",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
        )
    }
    server.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    server.addressWarning?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    ServerShareSection(model)
    HorizontalDivider()
    ServerPolicySection(model)

    server.pending?.let { info ->
        AlertDialog(
            onDismissRequest = { model.server.dismiss() },
            title = { Text("信任這台服務端？") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("服務端：${info.url}", style = MaterialTheme.typography.bodySmall)
                    if (info.sha256 != null) {
                        Text("簽章根憑證：${info.subject}", style = MaterialTheme.typography.bodySmall)
                        Text("SHA-256：${fingerprint(info.sha256)}", style = MaterialTheme.typography.bodySmall)
                    }
                    info.verifierDid?.let { Text("網頁查驗端 DID：$it", style = MaterialTheme.typography.bodySmall) }
                    if (info.features.isNotEmpty()) Text("提供功能：${info.features.joinToString("、")}", style = MaterialTheme.typography.bodySmall)
                    info.federation?.let {
                        Text(ServerStrings.FEDERATION_CONFIRMED + ServerStrings.federationVerified(it), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary)
                    }
                    if (info.sharedFingerprint) Text(ServerStrings.shareFingerprintMatches(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                    info.settingsSha256?.let { Text(ServerStrings.SETTINGS_DIGEST + it.take(16), style = MaterialTheme.typography.bodySmall) }
                    info.addressWarning?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                    Text(
                        "請和業者公布的指紋逐字比對，相符再信任。信任後，這台服務端簽的網站查驗請求與收據會以使用者匯入（T2）顯示，" +
                            "它的網頁查驗端向你要求出示卡片時也顯示為使用者信任（T2）；網頁查驗端 DID 只由這個網址確認，沒有另外的指紋。" +
                            "可在「自訂信任」頁移除。",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            },
            confirmButton = { TextButton(onClick = { model.server.confirm(info) }) { Text(if (info.sha256 != null) "指紋相符，信任" else "信任") } },
            dismissButton = { TextButton(onClick = { model.server.dismiss() }) { Text("取消") } },
        )
    }
}

/**
 * The self-hosted zkPDF prover (tools/zk-prover-server): its address and access token, and a check that it answers
 * and which circuit compositions it can prove. Proofs it returns are verified on this device before they are used.
 */
@Composable
private fun ProverSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    var url by remember(settings.zkProverUrl) { mutableStateOf(settings.zkProverUrl) }
    var token by remember(settings.zkProverToken) { mutableStateOf(settings.zkProverToken) }
    var result by remember(settings.zkProverUrl, settings.zkProverToken) { mutableStateOf<String?>(null) }
    var checking by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val urlProblem = url.takeIf { it.isNotEmpty() }?.let { ZkProverHost.problem(it, model.platform::cleartextPermitted) }
    val tokenProblem = if (url.isNotEmpty() && token.length < ZkProverHost.MIN_TOKEN) "存取權杖至少 ${ZkProverHost.MIN_TOKEN} 個字元" else null
    Text(
        "這台裝置算力不足時，可把 PDF 第 1 頁的內容與證明需要的私密資料送到你自己架設的 zk-prover-server 產生 zkPDF 證明，" +
            "不會送出整份文件；回傳的證明會先在這台裝置驗證，不通過就不使用。請只使用你自己管理、信任的主機。",
        style = MaterialTheme.typography.bodySmall,
    )
    OutlinedTextField(
        value = url, onValueChange = { url = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(if (model.platform.cleartextPermitted("192.168.0.1")) "主機網址（https；區域網路可用 http）" else "主機網址（https）") }, isError = urlProblem != null,
        supportingText = urlProblem?.let { { Text(it) } },
    )
    OutlinedTextField(
        value = token, onValueChange = { token = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text("存取權杖") }, visualTransformation = PasswordVisualTransformation(), isError = tokenProblem != null,
        supportingText = tokenProblem?.let { { Text(it) } },
    )
    Text("權杖只送給這台主機，以加密方式存在這台裝置。", style = MaterialTheme.typography.bodySmall)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(
            onClick = { model.updateSettings { it.copy(zkProverUrl = url.trimEnd('/'), zkProverToken = if (url.isEmpty()) "" else token) } },
            enabled = urlProblem == null && tokenProblem == null && (url.trimEnd('/') != settings.zkProverUrl || token != settings.zkProverToken),
        ) { Text("儲存") }
        OutlinedButton(
            onClick = {
                checking = true
                scope.launch {
                    result = try {
                        val local = model.zk.pdf()
                        if (local == null) "這個版本或裝置沒有 zkPDF 引擎，無法驗證主機回傳的證明"
                        else when (val r = RemoteZkPdfEngine(ZkProverHost("自架主機", settings.zkProverUrl, settings.zkProverToken), local, model.http).compositions()) {
                            is ZkResult.Ok -> if (r.value.isEmpty()) "主機可連線，但沒有完整的 zkPDF 電路檔"
                                else "主機可連線，可產生：" + r.value.joinToString("、") { compositionTitle(it) }
                            is ZkResult.Failed -> r.reason
                            ZkResult.Cancelled -> null
                        }
                    } finally {
                        checking = false
                    }
                }
            },
            enabled = settings.zkProverUrl.isNotEmpty() && !checking && url.trimEnd('/') == settings.zkProverUrl,
        ) { Text(if (checking) "連線中…" else "測試連線") }
        if (settings.zkProverUrl.isNotEmpty()) {
            TextButton(onClick = { model.updateSettings { it.copy(zkProverUrl = "", zkProverToken = "") } }) { Text("移除") }
        }
    }
    result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
}

/**
 * Desktop wallet: proves a request file (.zkpdfreq) a phone exported and saves the proof file (.zkpdf) for the phone
 * to import. The request is used once and not kept; the phone verifies the proof before it uses it.
 */
@Composable
private fun PhoneRequestSection(model: WalletModel) {
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val jobs by model.zk.jobs.collectAsState()
    val running = jobs[diw.wallet.app.FilesModel.PHONE_JOB]?.active == true
    Text(
        "手機算力不足時，可在手機匯出證明請求檔（${diw.wallet.core.zk.ZkPdfRemote.REQUEST_EXTENSION}），在這裡用電腦版電路產生證明，" +
            "再把證明檔（${diw.wallet.core.zk.ZkPdfRemote.RESPONSE_EXTENSION}）匯入手機。請求檔含 PDF 第 1 頁的內容，用完請刪除；這裡不保存它。",
        style = MaterialTheme.typography.bodySmall,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(onClick = { model.files.proveForPhone() }, enabled = busy == null) { Text("開啟證明請求檔") }
        if (running) TextButton(onClick = { model.zk.cancel(diw.wallet.app.FilesModel.PHONE_JOB) }) { Text("停止") }
    }
    busy?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
    error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
}

/**
 * The latest proofs of this session with their time and memory peak, so a holder can report how a device performs.
 * The text holds no proof input, only the device class, the composition and the numbers.
 */
@Composable
private fun MeasurementSection(model: WalletModel) {
    val entries by model.zk.measurements.collectAsState()
    @Suppress("DEPRECATION")
    val clipboard = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }
    Text(
        "這次開啟 App 後完成或停止的證明，記錄耗時與記憶體峰值（不含證明內容），可複製後回報，用來調整裝置建議。關閉 App 後清除。",
        style = MaterialTheme.typography.bodySmall,
    )
    if (entries.isEmpty()) {
        Text("尚無紀錄", style = MaterialTheme.typography.bodySmall)
        return
    }
    entries.forEach { Text(measurementLine(it), style = MaterialTheme.typography.bodySmall) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(onClick = {
            clipboard.setText(AnnotatedString(measurementReport(entries)))
            copied = true
        }) { Text("複製紀錄") }
        if (copied) Text("已複製", style = MaterialTheme.typography.bodySmall)
    }
}

internal fun measurementLine(m: ZkMeasurement): String {
    val outcome = when (m.phase) {
        ZkJobPhase.DONE -> "完成"
        ZkJobPhase.FAILED -> "失敗"
        ZkJobPhase.TIMED_OUT -> "逾時"
        ZkJobPhase.CANCELLED -> "已停止"
        else -> m.phase.name
    }
    val peak = m.peakMemoryMb?.let { "，記憶體峰值 $it MB" } ?: ""
    val note = m.note?.let { "（$it）" } ?: ""
    val step = m.lastStep?.takeIf { m.phase != ZkJobPhase.DONE }?.let { "，停在「$it」" } ?: ""
    return "${m.kind.label}$note：$outcome，${m.seconds} 秒$peak$step"
}

/** Plain lines for a report: device class first, then one line per proof. */
internal fun measurementReport(entries: List<ZkMeasurement>): String {
    val device = entries.firstNotNullOfOrNull { it.platform }?.let {
        "裝置：${it.abi}，記憶體 ${it.totalRamMb} MB（偵測時可用 ${it.availableRamMb} MB），${if (it.isDesktop) "電腦版" else "手機版"}"
    } ?: "裝置：未知"
    return (listOf(device) + entries.map { "${it.at} ${it.kind.name} ${measurementLine(it)}" }).joinToString("\n")
}

internal fun compositionTitle(id: String): String = when (id) {
    ZkPdfStatement.PHONE -> "手機版電路"
    ZkPdfStatement.DESKTOP -> "電腦版電路"
    else -> id
}

/** A SHA-256 hex in groups of four for comparing by eye. */
private fun fingerprint(hex: String): String = hex.uppercase().chunked(4).joinToString(" ")
