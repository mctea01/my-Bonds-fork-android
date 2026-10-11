package diw.wallet.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import diw.wallet.app.Screen
import diw.wallet.app.TwdiwTrustRow
import diw.wallet.app.WalletModel
import diw.wallet.core.profile.twdiw.AnchorState
import diw.wallet.core.profile.twdiw.TwdiwPlatform

@Composable
private fun SectionHeader(icon: ImageVector, title: String, subtitle: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.padding(top = 8.dp)) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
        Column {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(subtitle, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun ActionTile(icon: ImageVector, title: String, detail: String, modifier: Modifier = Modifier, enabled: Boolean = true, onClick: () -> Unit) {
    Card(
        modifier.then(if (enabled) Modifier.clickable(onClick = onClick) else Modifier),
        colors = if (enabled) CardDefaults.cardColors() else CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Icon(icon, contentDescription = null, tint = if (enabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                modifier = Modifier.size(28.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(detail, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** Taiwan digital credentials: TWDIW cards and services, Bonds offline presentation, Verified ID cards. */
@Composable
fun TaiwanScreen(model: WalletModel, scanQr: (suspend () -> String?)?) {
    val docs by model.documents.collectAsState()
    val offline by model.taiwan.offlineServices.collectAsState()
    val cards by model.taiwan.cardServices.collectAsState()
    val error by model.taiwan.servicesError.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    var scanning by remember { mutableStateOf(false) }
    var purpose by remember { mutableStateOf("身分確認") }
    LaunchedEffect(Unit) { if (offline == null && error == null) model.taiwan.loadServices() }
    LaunchedEffect(scanning) {
        if (scanning && scanQr != null) {
            scanQr()?.let { model.handleUri(it) }
            scanning = false
        }
    }
    val twdiwDocs = model.taiwan.twdiwDocuments(docs)
    val msDocs = model.taiwan.verifiedIdDocuments(docs)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        SectionHeader(WalletIcons.Government, "數位憑證皮夾（TWDIW）", "數位發展部數位憑證皮夾的憑證、取貨與服務，流程與官方 App 相同")
        if (model.twdiwPlatform != TwdiwPlatform.PRODUCTION) {
            Text("測試平台：${model.twdiwPlatform.frontendUrl}（結果不具效力）", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        if (twdiwDocs.isEmpty()) {
            Text("尚未領取數位憑證皮夾的憑證。掃描發行端的 QR Code，或從下方的申請服務取得。", style = MaterialTheme.typography.bodyMedium)
        }
        twdiwDocs.forEach { doc -> CredentialCard(model, doc) { model.screen.value = Screen.DocumentDetail(doc.identifier, from = Screen.Taiwan) } }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ActionTile(WalletIcons.Store, "7-ELEVEN 取貨", "出示憑證後顯示取貨條碼", Modifier.weight(1f)) { model.taiwan.startPickup711() }
            ActionTile(WalletIcons.Shield, "信任清單", "發行端與驗證端及區塊鏈註冊", Modifier.weight(1f)) { model.screen.value = Screen.TwdiwTrust }
        }
        if (scanQr != null) {
            ActionTile(WalletIcons.Scan, "掃描 QR Code", "領卡、出示、靜態服務碼與 Bonds 查驗方的挑戰") { scanning = true }
        }
        Text("臨櫃與線上出示服務", style = MaterialTheme.typography.titleSmall)
        when {
            error != null -> {
                Text(error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                OutlinedButton(onClick = { model.taiwan.loadServices() }) { Text("重新整理") }
            }
            offline == null -> CircularProgressIndicator(Modifier.size(24.dp))
            offline!!.isEmpty() -> Text("目前沒有服務", style = MaterialTheme.typography.bodySmall)
            else -> offline!!.forEach { s ->
                ActionTile(WalletIcons.Store, s.name, "出示憑證後由對方系統產生條碼") { model.taiwan.startPickup(s) }
            }
        }
        Text("可申請的憑證", style = MaterialTheme.typography.titleSmall)
        when {
            cards == null && error == null -> CircularProgressIndicator(Modifier.size(24.dp))
            cards.isNullOrEmpty() -> Text("目前沒有可申請的憑證", style = MaterialTheme.typography.bodySmall)
            else -> cards!!.forEach { c ->
                ActionTile(WalletIcons.Phone, c.name, if (c.opensExternally) "前往發行端網站申請" else "在發行端頁面完成申請後自動加入") { model.taiwan.applyFor(c) }
            }
        }
        HorizontalDivider(Modifier.padding(vertical = 6.dp))
        SectionHeader(WalletIcons.Link, "Bonds 離線出示", "以 QR Code 或藍牙向 Bonds 查驗方出示數位憑證皮夾的憑證，不需連網")
        Text("請對方顯示查驗挑戰的 QR Code，掃描後選擇要出示的憑證與欄位。", style = MaterialTheme.typography.bodySmall)
        Text("自行查驗他人出示", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(
            value = purpose,
            onValueChange = { purpose = it.take(100) },
            label = { Text("查驗用途（顯示給出示者）") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(onClick = { model.taiwan.startVerifier(purpose) }, enabled = purpose.isNotBlank()) {
            Icon(WalletIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text("產生查驗挑戰")
        }
        ActionTile(WalletIcons.Document, "自然人憑證自發卡與簽章文件", "Bonds 的 vc+moica 自發卡與文件將於 P5 支援；目前可查驗他人出示的自發卡", enabled = false) {}
        HorizontalDivider(Modifier.padding(vertical = 6.dp))
        SectionHeader(WalletIcons.Organization, "Microsoft Entra Verified ID", "掃描 openid-vc 開頭的 QR Code 即可加入或出示")
        if (msDocs.isEmpty()) Text("尚未加入 Verified ID 憑證。", style = MaterialTheme.typography.bodySmall)
        msDocs.forEach { doc -> CredentialCard(model, doc) { model.screen.value = Screen.DocumentDetail(doc.identifier, from = Screen.Taiwan) } }
        if (settings.testEnvironment) {
            Text("TWDIW client_id：${settings.twdiwClientId}", style = MaterialTheme.typography.bodySmall)
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
fun TwdiwTrustScreen(model: WalletModel) {
    val rows by model.taiwan.trustRows.collectAsState()
    val error by model.taiwan.trustError.collectAsState()
    var filter by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { if (rows == null) model.taiwan.loadTrust() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("數位憑證皮夾公布的發行端與驗證端。每個組織的 DID 文件需自簽有效，並與 Arbitrum One 上的註冊內容相符，才列為官方已驗證（T1）。",
            style = MaterialTheme.typography.bodySmall)
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(value = filter, onValueChange = { filter = it }, label = { Text("搜尋名稱或統一編號") }, singleLine = true, modifier = Modifier.weight(1f))
            TextButton(onClick = { model.taiwan.loadTrust(refresh = true) }) { Text("重新整理") }
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
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
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(if (2 in e.orgTypes && 1 !in e.orgTypes) WalletIcons.Scan else WalletIcons.Government, contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                Column(Modifier.weight(1f)) {
                    Text(e.displayName, style = MaterialTheme.typography.titleSmall)
                    e.nameEn?.takeIf { it != e.name }?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            }
            val roles = buildList { if (1 in e.orgTypes) add("發行端"); if (2 in e.orgTypes) add("驗證端") }
            Text(roles.joinToString("、") + (e.taxId?.let { "　統一編號 $it" } ?: ""), style = MaterialTheme.typography.bodySmall)
            Text(e.did, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            if (e.hosts.isNotEmpty()) Text("服務網域：" + e.hosts.joinToString(), style = MaterialTheme.typography.bodySmall)
            Text("區塊鏈：" + anchorText(row.anchor), style = MaterialTheme.typography.bodySmall)
            row.decision?.let { TierBadge(it) }
            TextButton(onClick = { model.taiwan.verifyEntry(row) }) { Text(if (row.decision == null) "驗證" else "重新驗證") }
        }
    }
}
