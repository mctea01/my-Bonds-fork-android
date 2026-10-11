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
import diw.wallet.app.TwdiwTrustRow
import diw.wallet.app.WalletModel
import diw.wallet.core.profile.twdiw.AnchorState
import diw.wallet.core.profile.twdiw.TwdiwPlatform

/** Documents that can be requested: the government wallet catalogue, any OpenID4VCI issuer, and what comes later. */
@Composable
fun AddDocumentScreen(model: WalletModel) {
    val cards by model.taiwan.cardServices.collectAsState()
    val error by model.taiwan.servicesError.collectAsState()
    var issuer by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { if (cards == null && error == null) model.taiwan.loadServices() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("選擇要申請的證件。在發行端完成申請後，證件會自動加入這支手機。", style = MaterialTheme.typography.bodyMedium)
        if (model.twdiwPlatform != TwdiwPlatform.PRODUCTION) {
            Text("測試平台：${model.twdiwPlatform.frontendUrl}（結果不具效力）", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        SectionTitle("政府皮夾卡片")
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
                ) { model.taiwan.applyFor(c) }
            }
        }
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
        SectionTitle("後續版本")
        NfcCardRow()
        ActionRow(WalletIcons.Document, "以自然人憑證建立身分證卡", "Bonds 的自發身分證卡（vc+moica）與簽章文件將於後續版本支援", enabled = false) {}
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
    var filter by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { if (rows == null) model.taiwan.loadTrust() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("數位憑證皮夾公布的發行端與查驗方。組織的 DID 文件需自簽有效，並與 Arbitrum One 上的註冊內容相符，才列為官方已驗證（T1）。",
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
            Text("區塊鏈：" + anchorText(row.anchor), style = MaterialTheme.typography.bodySmall)
            row.decision?.let { TierBadge(it) }
            TextButton(onClick = { model.taiwan.verifyEntry(row) }) { Text(if (row.decision == null) "驗證" else "重新驗證") }
        }
    }
}
