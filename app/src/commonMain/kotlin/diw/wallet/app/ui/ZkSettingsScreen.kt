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
import androidx.compose.ui.unit.dp
import diw.wallet.app.WalletModel
import diw.wallet.core.zk.ZkAsset
import diw.wallet.core.zk.ZkAssetStatus
import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.ZkCapability
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
        SectionTitle("年齡查驗主機")
        AgeVerifierHost(model)
        HorizontalDivider()
        SectionTitle("自架主機")
        ActionRow(WalletIcons.Link, "加入自架主機", "zkPDF 完成後開放：手機算力不足時可把文件送到自己的主機產生證明，手機先驗證再使用", enabled = false) {}
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
        if (st.version != null) add("已安裝：${st.pages} 個查驗頁、${st.documents} 個文件版型・發布於 ${localTime(st.issuedAt!!)}")
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
            if (settings.testEnvironment) "測試環境另可匯入未簽章的查驗頁描述檔（.json），只在測試環境使用，查驗時會附在請求中，對方也須開啟測試環境。" else "",
        style = MaterialTheme.typography.bodySmall,
    )
    st.notice?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
    if (st.testPages.isNotEmpty()) {
        Text("測試查驗頁" + if (settings.testEnvironment) "" else "（測試環境關閉中，不會使用）", style = MaterialTheme.typography.titleSmall)
        st.testPages.forEach { p ->
            Text("${p.title}（${p.id}）・${p.host}" + if (p.port != 443) ":${p.port}" else "", style = MaterialTheme.typography.bodySmall)
        }
        OutlinedButton(onClick = { model.zkTemplates.clearTestPages() }) { Text("清除測試查驗頁") }
    }
}

/** The proofs' row on the security page. */
@Composable
internal fun ZkSettingsRow(model: WalletModel, onOpen: () -> Unit) {
    val capability by model.zk.capability.collectAsState()
    ActionRow(WalletIcons.Shield, "零知識證明", zkSummary(capability).removePrefix("零知識：") + "・電路檔下載與刪除", onClick = onOpen)
}

/** The Bonds-compatible host the Verify tab's age check uses (the test server, or the user's deployment of it). */
@Composable
private fun AgeVerifierHost(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    var url by remember(settings.zkVerifierUrl) { mutableStateOf(settings.zkVerifierUrl) }
    val valid = url.isEmpty() || url.startsWith("https://") || settings.testEnvironment && url.startsWith("http://")
    Text(
        "查驗他人年齡時，對方的證明送到這台主機，再轉給這支手機驗證；主機只轉送，看不到出生日期。可部署專案的測試伺服器（test-servers）作為主機。" +
            "留空時在測試環境使用測試伺服器。",
        style = MaterialTheme.typography.bodySmall,
    )
    OutlinedTextField(
        value = url, onValueChange = { url = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text("主機網址（https）") }, isError = !valid,
    )
    OutlinedButton(onClick = { model.updateSettings { it.copy(zkVerifierUrl = url.trimEnd('/')) } }, enabled = valid && url != settings.zkVerifierUrl) {
        Text("儲存")
    }
}
