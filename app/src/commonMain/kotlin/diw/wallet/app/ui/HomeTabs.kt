package diw.wallet.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
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
import diw.wallet.app.HistoryEntry
import diw.wallet.app.HistoryKind
import diw.wallet.app.HomeTab
import diw.wallet.app.Screen
import diw.wallet.app.StatusMonitor
import diw.wallet.app.WalletModel
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.trust.TrustTier
import org.multipaz.revocation.RevocationCheckState
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Clock
import kotlin.time.Instant

@Composable
fun HomeNavigationBar(selected: HomeTab, onSelect: (HomeTab) -> Unit) {
    NavigationBar {
        listOf(
            Triple(HomeTab.DOCUMENTS, "證件", WalletIcons.Wallet),
            Triple(HomeTab.FILES, "文件", WalletIcons.Document),
            Triple(HomeTab.USE, "使用", WalletIcons.Scan),
            Triple(HomeTab.VERIFY, "查驗", WalletIcons.Shield),
            Triple(HomeTab.HISTORY, "紀錄", WalletIcons.History),
        ).forEach { (tab, label, icon) ->
            NavigationBarItem(
                selected = tab == selected,
                onClick = { onSelect(tab) },
                icon = { Icon(icon, contentDescription = null) },
                label = { Text(label) },
            )
        }
    }
}

/** Add a document: from the list of documents that can be requested, or by scanning the issuer's code. */
@Composable
fun AddDocumentSheet(model: WalletModel, onDismiss: () -> Unit, onList: () -> Unit, onScan: (() -> Unit)?) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 32.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("加入證件", style = MaterialTheme.typography.titleLarge)
            Text("從清單選擇要申請的證件，或掃描發行端提供的 QR Code。", style = MaterialTheme.typography.bodyMedium)
            ActionRow(WalletIcons.Document, "從清單選擇", "政府皮夾卡片、自製的身分證卡與文件衍生憑證，或輸入發行端網址") { onList() }
            ActionRow(
                WalletIcons.Scan, "掃描 QR Code",
                if (onScan != null) "發行端網頁或櫃台提供的領卡 QR Code" else "這個裝置沒有相機，請到「使用」貼上領卡連結",
                enabled = onScan != null,
            ) { onScan?.invoke() }
        }
    }
}

// ---------------------------------------------------------------- documents

/** Every document in one list, grouped by category, with search and category filters. */
@Composable
fun DocumentsTab(model: WalletModel, onAdd: () -> Unit) {
    val docs by model.documents.collectAsState()
    val files by model.files.files.collectAsState()
    val hasNationalId = files.any { it.nationalId != null }
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf<DocumentCategory?>(null) }
    if (docs.isEmpty() && !hasNationalId) {
        EmptyState(WalletIcons.Wallet, "還沒有任何證件", "掃描發行端的 QR Code，或從清單選擇要申請的證件。", "加入證件", onAdd)
        return
    }
    val categories = docs.map { categoryOf(it.issuanceRecord) }.distinct().sortedBy { it.ordinal }
    val q = query.trim()
    val shown = docs.filter { d ->
        (filter == null || categoryOf(d.issuanceRecord) == filter) &&
            (q.isEmpty() || listOfNotNull(d.displayName, d.typeDisplayName, d.issuanceRecord?.credentialIssuer).any { it.contains(q, ignoreCase = true) })
    }
    val groups = shown.groupBy { categoryOf(it.issuanceRecord) }.entries.sortedBy { it.key.ordinal }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (docs.size > 3) item(key = "search") {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                leadingIcon = { Icon(WalletIcons.Search, contentDescription = null) },
                placeholder = { Text("搜尋證件名稱或發行端") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        if (categories.size > 1) item(key = "filters") {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = filter == null, onClick = { filter = null }, label = { Text("全部") })
                categories.forEach { c -> FilterChip(selected = filter == c, onClick = { filter = if (filter == c) null else c }, label = { Text(c.title) }) }
            }
        }
        // The Bonds national ID card lives with the MyData PDF it was made from; it is listed here with the cards.
        if (hasNationalId && filter == null && q.isEmpty()) item(key = "national-id") {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (groups.isNotEmpty()) SectionTitle("自然人憑證自發卡")
                NationalIdCards(model)
            }
        }
        groups.forEach { (category, list) ->
            if (groups.size > 1 || hasNationalId) item(key = "h-" + category.name) { SectionTitle(category.title) }
            items(list, key = { it.identifier }) { doc ->
                CredentialCard(model, doc) { model.screen.value = Screen.DocumentDetail(doc.identifier) }
            }
        }
        if (shown.isEmpty() && !(hasNationalId && filter == null && q.isEmpty())) item(key = "none") {
            Text("沒有符合搜尋或篩選條件的證件。", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 16.dp))
        }
    }
}

// ---------------------------------------------------------------- use

/**
 * What the holder does: present (one entry, the scanned code decides the flow), counter services, and adding
 * documents.
 */
@Composable
fun UseTab(model: WalletModel, scan: (() -> Unit)?) {
    val docs by model.documents.collectAsState()
    val services by model.taiwan.offlineServices.collectAsState()
    val error by model.taiwan.servicesError.collectAsState()
    var input by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { if (services == null && error == null) model.taiwan.loadServices() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(Tokens.ContainerRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(WalletIcons.Qr, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                Text("出示我的證件", style = MaterialTheme.typography.titleLarge)
                Text("掃描查驗方的 QR Code，面對面或線上都可以，出示哪些欄位由你決定。", style = MaterialTheme.typography.bodyMedium)
                when {
                    docs.isEmpty() -> Text("先加入證件，就能出示給查驗方。", style = MaterialTheme.typography.bodySmall)
                    scan == null -> Text("這個裝置沒有相機，請在下方貼上查驗方給的連結。", style = MaterialTheme.typography.bodySmall)
                }
                Button(onClick = { scan?.invoke() }, enabled = scan != null && docs.isNotEmpty()) {
                    Icon(WalletIcons.Scan, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("掃描 QR Code")
                }
            }
        }
        ActionRow(
            WalletIcons.Nfc, "感應出示（NFC）",
            "手機靠近查驗設備，或讓對方掃描 QR Code；適用行動駕照等 mdoc 證件（ISO/IEC 18013-5）",
            enabled = docs.isNotEmpty(),
        ) { model.proximity.open() }
        SectionTitle("臨櫃出示")
        Text("出示證件後，由服務方系統產生條碼，給店員或機台掃描。", style = MaterialTheme.typography.bodySmall)
        when {
            error != null -> InlineError(error!!) { model.taiwan.loadServices() }
            services == null -> CircularProgressIndicator(Modifier.size(24.dp))
            services!!.isEmpty() -> Text("目前沒有臨櫃服務。", style = MaterialTheme.typography.bodySmall)
            else -> services!!.forEach { s ->
                ActionRow(WalletIcons.Store, s.name, if (docs.isEmpty()) "先加入證件才能出示" else "出示證件後顯示條碼", enabled = docs.isNotEmpty()) {
                    model.taiwan.startPickup(s)
                }
            }
        }
        SectionTitle("加入證件")
        ActionRow(
            WalletIcons.Scan, "掃描領取卡片",
            if (scan != null) "發行端網頁或櫃台提供的領卡 QR Code" else "這個裝置沒有相機，請在下方貼上領卡連結",
            enabled = scan != null,
        ) { scan?.invoke() }
        ActionRow(WalletIcons.Document, "從清單選擇", "政府皮夾卡片、自製的身分證卡與文件衍生憑證，或輸入發行端網址") { model.screen.value = Screen.AddDocument }
        SectionTitle("貼上連結")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text("領卡連結、出示請求或發行端網址") },
            )
            Button(onClick = { model.handleUri(input); input = "" }, enabled = input.isNotBlank()) { Text("開啟") }
        }
    }
}

// ---------------------------------------------------------------- verify

/**
 * The wallet as a verifier: the offline check of a Bonds or TWDIW presentation, and in-person reading of an mdoc
 * by NFC. The rest of the verifier is laid out and stays disabled until its design is implemented.
 */
@Composable
fun VerifyTab(model: WalletModel) {
    var purpose by remember { mutableStateOf("身分確認") }
    var risk by remember { mutableStateOf(RiskLevel.MEDIUM) }
    var source by remember { mutableStateOf(BondsCredentialSource.TWDIW) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(Tokens.ContainerRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(WalletIcons.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                Text("查驗他人證件", style = MaterialTheme.typography.titleLarge)
                Text("這支手機顯示一次性的查驗挑戰，對方用錢包或 Bonds 掃描後出示，簽章、挑戰與發行端都在這支手機上檢查。有網路時也會查詢證件狀態。",
                    style = MaterialTheme.typography.bodyMedium)
                Text("接受的證件", style = MaterialTheme.typography.titleSmall)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(BondsCredentialSource.TWDIW, BondsCredentialSource.SELF_ISSUED, BondsCredentialSource.ANY).forEach { s ->
                        FilterChip(selected = source == s, onClick = { source = s }, label = { Text(bondsSourceLabel(s)) })
                    }
                }
                if (source == BondsCredentialSource.SELF_ISSUED) {
                    Text("以自然人憑證簽署的 Bonds 身分證卡（vc+moica）；姓名一定揭露並與自然人憑證比對。文件衍生憑證是 SD-JWT VC，回應「本錢包擴充」請求。",
                        style = MaterialTheme.typography.bodySmall)
                }
                if (source == BondsCredentialSource.ANY) {
                    Text("任何綁定金鑰的 SD-JWT VC 或 W3C 證件，由出示者以本錢包出示；發行端由信任錨點或 DID 判定。Bonds App 只能出示政府皮夾卡片。",
                        style = MaterialTheme.typography.bodySmall)
                }
                OutlinedTextField(
                    value = purpose,
                    onValueChange = { purpose = it.take(100) },
                    label = { Text("查驗用途（會顯示給出示者）") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text("用途的風險", style = MaterialTheme.typography.titleSmall)
                RiskSelector(risk) { risk = it }
                Button(onClick = { model.taiwan.startVerifier(purpose.trim(), risk, source) }, enabled = purpose.isNotBlank()) {
                    Icon(WalletIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("產生查驗挑戰")
                }
            }
        }
        SectionTitle("查驗方身分")
        ActionRow(WalletIcons.Person, "以誰的身分查驗", "個人、法人或組織中的個人，以查驗方的認證憑證為證據，將於後續版本支援", enabled = false) {}
        SectionTitle("其他查驗方式")
        ActionRow(WalletIcons.Link, "線上查驗（OpenID4VP）", "產生出示請求並驗證回應，將於後續版本支援", enabled = false) {}
        ActionRow(WalletIcons.Nfc, "感應查驗（NFC）", "以手機的 NFC 或電腦的 PC/SC 讀卡機，讀取對方的行動駕照等 ISO 18013-5 證件") { model.reader.open() }
        ActionRow(WalletIcons.Shield, "查驗零知識證明", "只確認年齡等條件、不看原始資料，將於後續版本支援", enabled = false) {}
    }
}

// ---------------------------------------------------------------- history

private enum class HistoryFilter(val title: String, val kinds: Set<HistoryKind>) {
    PRESENTED("出示", setOf(HistoryKind.PRESENTED, HistoryKind.DECLINED)),
    ISSUED("領取", setOf(HistoryKind.ISSUED)),
    VERIFIED("查驗", setOf(HistoryKind.VERIFIED)),
    STATUS("狀態", setOf(HistoryKind.STATUS)),
    SIGNED("簽署", setOf(HistoryKind.SIGNED)),
}

/** Who received what and when, newest first; tapping an entry shows the documents and claim names. */
@Composable
fun HistoryTab(model: WalletModel) {
    val entries by model.history.collectAsState()
    var filter by remember { mutableStateOf<HistoryFilter?>(null) }
    var open by remember { mutableStateOf<String?>(null) }
    var confirmClear by remember { mutableStateOf(false) }
    if (entries.isEmpty()) {
        EmptyState(WalletIcons.History, "還沒有紀錄", "領取、出示與查驗證件後，這裡會列出對象、時間與交出的欄位名稱；證件狀態或發行端信任改變時也會記錄。欄位內容不會留存。")
        return
    }
    val zone = TimeZone.currentSystemDefault()
    val today = Clock.System.now().toLocalDateTime(zone).date
    val shown = entries.filter { filter == null || it.kind in filter!!.kinds }
    val days = shown.groupBy { Instant.fromEpochSeconds(it.epochSeconds).toLocalDateTime(zone).date }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item(key = "filters") {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = filter == null, onClick = { filter = null }, label = { Text("全部") })
                HistoryFilter.entries.forEach { f -> FilterChip(selected = filter == f, onClick = { filter = if (filter == f) null else f }, label = { Text(f.title) }) }
            }
        }
        days.forEach { (day, list) ->
            item(key = "d-$day") {
                val diff = today.toEpochDays().toLong() - day.toEpochDays().toLong()
                SectionTitle(when (diff) { 0L -> "今天"; 1L -> "昨天"; else -> day.toString() })
            }
            items(list, key = { it.id }) { e -> HistoryRow(e, expanded = open == e.id, zone) { open = if (open == e.id) null else e.id } }
        }
        if (shown.isEmpty()) item(key = "none") { Text("沒有符合篩選條件的紀錄。", style = MaterialTheme.typography.bodyMedium) }
        item(key = "clear") {
            TextButton(onClick = { confirmClear = true }, modifier = Modifier.padding(top = 8.dp)) { Text("清除所有紀錄") }
        }
    }
    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("清除所有紀錄？") },
            text = { Text("紀錄刪除後無法復原。證件本身不受影響。") },
            confirmButton = {
                TextButton(onClick = { confirmClear = false; model.clearHistory() }) { Text("清除紀錄", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("取消") } },
        )
    }
}

private fun historyTitle(e: HistoryEntry): String = when (e.kind) {
    HistoryKind.ISSUED -> "從 ${e.party} 領取"
    HistoryKind.PRESENTED -> "出示給 ${e.party}"
    HistoryKind.DECLINED -> "拒絕 ${e.party} 的要求"
    HistoryKind.VERIFIED -> "查驗 ${e.party}"
    HistoryKind.STATUS -> (e.documents.firstOrNull() ?: "證件") + if (e.status == StatusMonitor.TRUST_CHANGE) " 發行端信任變更" else " 狀態變更"
    HistoryKind.SIGNED -> "以 ${e.party} 簽署"
}

private fun hhmm(t: LocalDateTime) = t.hour.toString().padStart(2, '0') + ":" + t.minute.toString().padStart(2, '0')

@Composable
private fun HistoryRow(e: HistoryEntry, expanded: Boolean, zone: TimeZone, onClick: () -> Unit) {
    val (verdict, status) = when {
        e.failure != null -> Verdict.FAIL to "未完成"
        e.kind == HistoryKind.DECLINED -> Verdict.CAUTION to "已拒絕"
        e.kind == HistoryKind.STATUS -> when (e.status) {
            RevocationCheckState.VALID.name -> Verdict.PASS to "有效"
            RevocationCheckState.INVALID.name -> Verdict.FAIL to "已撤銷"
            RevocationCheckState.SUSPENDED.name -> Verdict.CAUTION to "暫停"
            else -> when (e.tier?.let { runCatching { TrustTier.valueOf(it) }.getOrNull() }) {
                TrustTier.T1 -> Verdict.PASS to "T1"
                TrustTier.T2 -> Verdict.CAUTION to "T2"
                TrustTier.T3 -> Verdict.CAUTION to "T3"
                else -> Verdict.FAIL to "T4"
            }
        }
        else -> Verdict.PASS to "完成"
    }
    val icon = when (e.kind) {
        HistoryKind.ISSUED -> WalletIcons.Receive
        HistoryKind.PRESENTED -> WalletIcons.Send
        HistoryKind.DECLINED -> WalletIcons.Fail
        HistoryKind.VERIFIED -> WalletIcons.Shield
        HistoryKind.STATUS -> WalletIcons.Caution
        HistoryKind.SIGNED -> WalletIcons.Document
    }
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                Column(Modifier.weight(1f)) {
                    Text(historyTitle(e), style = MaterialTheme.typography.titleSmall)
                    Text(
                        hhmm(Instant.fromEpochSeconds(e.epochSeconds).toLocalDateTime(zone)) +
                            (if (e.documents.isNotEmpty()) "　" + e.documents.joinToString("、") else ""),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Icon(verdict.icon, contentDescription = null, tint = verdict.color, modifier = Modifier.size(16.dp))
                    Text(status, style = MaterialTheme.typography.labelMedium)
                }
            }
            if (expanded) {
                e.tier?.let { t ->
                    val tier = runCatching { TrustTier.valueOf(t) }.getOrNull()
                    if (tier != null) Text((if (e.kind == HistoryKind.STATUS) "發行端" else "對方") + "的信任等級：" + WalletModel.tierTitle(tier) + (if (e.test) "（測試環境）" else ""), style = MaterialTheme.typography.bodySmall)
                }
                e.note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                if (e.claims.isNotEmpty()) {
                    Text(if (e.kind == HistoryKind.VERIFIED) "對方揭露的欄位" else "涉及的欄位", style = MaterialTheme.typography.labelLarge)
                    Text(e.claims.joinToString("、"), style = MaterialTheme.typography.bodySmall)
                }
                e.failure?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            }
        }
    }
}
