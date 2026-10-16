package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import diw.wallet.app.DocumentSources
import diw.wallet.app.HomeTab
import diw.wallet.app.MyDataFiles
import diw.wallet.app.Screen
import diw.wallet.app.TwdiwTrustRow
import diw.wallet.app.WalletModel
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.profile.twdiw.AnchorState
import diw.wallet.core.profile.twdiw.TwdiwPlatform

/**
 * Adding a document: cards the government wallet issuers offer, cards the holder makes from their own documents with
 * the citizen certificate (as Bonds does), and any other OpenID4VCI issuer by its address.
 */
@Composable
fun AddDocumentScreen(model: WalletModel) {
    val cards by model.taiwan.cardServices.collectAsState()
    val error by model.taiwan.servicesError.collectAsState()
    val files by model.files.files.collectAsState()
    var issuer by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { if (cards == null && error == null) model.taiwan.loadServices() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("向發行端申請證件，或用自己的文件與自然人憑證製作。發行端的 QR Code 請在「使用」掃描。", style = MaterialTheme.typography.bodyMedium)
        if (model.twdiwPlatform != TwdiwPlatform.PRODUCTION) {
            Text("測試平台：${model.twdiwPlatform.frontendUrl}（結果不具效力）", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        SectionTitle("政府皮夾卡片")
        Text("在發行端網站完成申請後，卡片自動加入這支手機。", style = MaterialTheme.typography.bodySmall)
        when {
            error != null -> InlineError(error!!) { model.taiwan.loadServices() }
            cards == null -> CircularProgressIndicator(Modifier.size(24.dp))
            cards!!.isEmpty() -> Text("目前沒有可申請的卡片。", style = MaterialTheme.typography.bodySmall)
            else -> cards!!.forEach { c ->
                ActionRow(
                    WalletIcons.Government, c.name,
                    when {
                        c.issuerServiceUrl == null -> "發行端沒有提供申請頁面"
                        c.opensExternally -> "前往發行端網站申請"
                        else -> "在發行端頁面完成申請後自動加入"
                    },
                    enabled = c.issuerServiceUrl != null,
                    leading = c.logoUrl?.let { logo -> { CardLogo(model, logo, WalletIcons.Government, MaterialTheme.colorScheme.primary, size = 28) } },
                ) { model.taiwan.applyFor(c) }
            }
        }
        SectionTitle("自己製作")
        Text("內容來自你下載的官方文件，由你的自然人憑證簽署，表示你本人聲明；不是發證機關核發。", style = MaterialTheme.typography.bodySmall)
        val idSource = DocumentSources.byId("mydata-id")!!
        val idPdf = files.firstOrNull { f ->
            f.nationalId == null && f.report?.format == DocumentFormat.PDF && (MyDataFiles.recognize(f.name)?.nationalId == true || f.source?.contains("國民身分證資料") == true)
        }
        val hasCard = files.any { it.nationalId != null }
        ActionRow(
            WalletIcons.Person, "國民身分證卡（Bonds 自發卡）",
            if (hasCard) "已有身分證卡；從 MyData 重新下載可再製作" else "從 MyData 下載國民身分證資料，以自然人憑證簽成卡片，可回應 Bonds 的自然人憑證自發卡查驗",
        ) {
            if (model.platform.embeddedBrowser) model.screen.value = Screen.Portal(idSource.id) else model.platform.openBrowser(idSource.url)
        }
        idPdf?.let { f ->
            ActionRow(WalletIcons.Document, "用已保存的身分證資料製作", f.name) { model.screen.value = Screen.NationalIdCreate(f.id) }
        }
        ActionRow(
            WalletIcons.Card, "文件衍生憑證",
            "在「文件」選一份文件（MyData、在學證明、公文、OpenCerts 等），由內容產生可出示的 SD-JWT VC（本錢包簽發，與 Bonds 身分證卡的 vc+moica 結構不同）",
        ) { model.showTab(HomeTab.FILES) }
        ActionRow(
            WalletIcons.Shield, "年齡證明（零知識）",
            "P4 尚未完成：Bonds 以 OpenAC 電路證明年滿 18 歲而不揭露生日；目前可只揭露身分證卡的「年滿 18 歲」欄位",
            enabled = false,
        ) {}
        SectionTitle("其他發行端")
        Text("輸入支援 OpenID4VCI 的發行端網址，列出它提供的證件後再選擇。", style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = issuer,
                onValueChange = { issuer = it.trim() },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text("發行端網址") },
            )
            Button(onClick = { model.handleUri(issuer) }, enabled = issuer.isNotEmpty()) { Text("查詢") }
        }
    }
}

private fun anchorText(anchor: String?): String = when (anchor?.let { runCatching { AnchorState.valueOf(it) }.getOrNull() }) {
    AnchorState.VERIFIED -> "已在 Arbitrum 區塊鏈註冊且內容相符"
    AnchorState.NOT_ANCHORED -> "未在區塊鏈註冊"
    AnchorState.MISMATCH -> "與區塊鏈註冊內容不符"
    AnchorState.UNAVAILABLE -> "暫時無法查詢區塊鏈"
    AnchorState.DEVELOPMENT_SANDBOX -> "測試平台（不查區塊鏈）"
    null -> "尚未驗證"
}

/** The TWDIW trust list: listed issuers and verifiers, their DID documents and Arbitrum registrations. */
@Composable
fun TrustListScreen(model: WalletModel) {
    val rows by model.taiwan.trustRows.collectAsState()
    val error by model.taiwan.trustError.collectAsState()
    val progress by model.taiwan.trustProgress.collectAsState()
    var filter by remember { mutableStateOf("") }
    // Opening the list checks every organisation not checked in the last day, without a tap per entry.
    LaunchedEffect(Unit) { if (rows == null) model.taiwan.loadTrust() else model.taiwan.verifyAll(force = false) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("數位憑證皮夾公布的發行端與查驗方。組織的 DID 文件需自簽有效，並與 Arbitrum One 上的註冊內容相符，才列為官方已驗證（T1）。開啟清單時會自動查驗一天內未查驗的組織。",
            style = MaterialTheme.typography.bodyMedium)
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = filter,
                onValueChange = { filter = it },
                leadingIcon = { Icon(WalletIcons.Search, contentDescription = null) },
                label = { Text("搜尋名稱或統一編號") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { model.taiwan.loadTrust(refresh = true) }) { Text("重新整理") }
        }
        error?.let { InlineError(it) { model.taiwan.loadTrust(refresh = true) } }
        progress?.let { (done, total) ->
            LinearProgressIndicator(progress = { if (total == 0) 0f else done.toFloat() / total }, modifier = Modifier.fillMaxWidth())
            Text("正在查驗 DID 文件與區塊鏈註冊：$done / $total", style = MaterialTheme.typography.bodySmall)
        }
        val list = rows
        if (list == null && error == null) CircularProgressIndicator(Modifier.size(24.dp))
        list?.filter { r ->
            filter.isBlank() || listOfNotNull(r.entry.name, r.entry.nameEn, r.entry.taxId).any { it.contains(filter.trim(), ignoreCase = true) }
        }?.forEach { row -> TrustRowCard(model, row) }
    }
}

@Composable
private fun TrustRowCard(model: WalletModel, row: TwdiwTrustRow) {
    val e = row.entry
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(if (2 in e.orgTypes && 1 !in e.orgTypes) WalletIcons.Scan else WalletIcons.Government, contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                Column(Modifier.weight(1f)) {
                    Text(e.displayName, style = MaterialTheme.typography.titleSmall)
                    e.nameEn?.takeIf { it != e.name }?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            }
            val roles = buildList { if (1 in e.orgTypes) add("發行端"); if (2 in e.orgTypes) add("查驗方") }
            Text(roles.joinToString("、") + (e.taxId?.let { "　統一編號 $it" } ?: ""), style = MaterialTheme.typography.bodySmall)
            Text(e.did, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            if (e.hosts.isNotEmpty()) Text("服務網域：" + e.hosts.joinToString(), style = MaterialTheme.typography.bodySmall)
            Text("區塊鏈：" + anchorText(row.anchor) + (row.checkedAt?.let { "（${localTime(kotlin.time.Instant.fromEpochMilliseconds(it))} 查驗）" } ?: ""),
                style = MaterialTheme.typography.bodySmall)
            row.decision?.let { TierBadge(it) }
            TextButton(onClick = { model.taiwan.verifyEntry(row) }) { Text(if (row.decision == null) "驗證" else "重新驗證") }
        }
    }
}
