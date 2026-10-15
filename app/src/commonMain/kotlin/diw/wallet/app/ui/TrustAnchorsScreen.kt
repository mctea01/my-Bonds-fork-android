package diw.wallet.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
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
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.StoredAnchor
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.UserTrustedDid
import diw.wallet.core.x509.displaySubject
import kotlin.time.Instant

private fun roleName(r: TrustRole): String = when (r) {
    TrustRole.ISSUER -> "發行端"
    TrustRole.VERIFIER -> "查驗方"
    TrustRole.STATUS_LIST -> "狀態清單"
    TrustRole.WALLET_PROVIDER -> "錢包提供者"
    TrustRole.TSA -> "時間戳記"
    TrustRole.DOCUMENT -> "文件簽章"
}

private fun environmentTitle(e: TrustEnvironment): String = when (e) {
    TrustEnvironment.PRODUCTION -> "正式錨點（官方 T1、政府憑證 T2）"
    TrustEnvironment.USER -> "使用者匯入（T3，非官方）"
    TrustEnvironment.TEST -> "測試錨點（T3，結果標示為測試）"
    TrustEnvironment.SYSTEM -> "系統憑證庫（T3，非官方）"
}

/** One certificate in one environment with every role it is an anchor for. */
private data class AnchorGroup(val environment: TrustEnvironment, val anchors: List<StoredAnchor>) {
    val first: StoredAnchor get() = anchors.first()
}

/**
 * Trust anchors of every kind, not only TWDIW: X.509 roots by environment and role, the DID trust sources (the
 * TWDIW list anchored on Arbitrum, Linked Domains) and DIDs the user trusts. Imported anchors and trusted DIDs are
 * the user's own (T3): accepted, never shown as official.
 */
@Composable
fun TrustAnchorsScreen(model: WalletModel) {
    val anchors by model.anchors.collectAsState()
    val dids by model.trustedDids.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    var removing by remember { mutableStateOf<AnchorGroup?>(null) }
    LaunchedEffect(Unit) { model.loadAnchors() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("信任錨點決定哪些發行端、查驗方與狀態清單可以信任，以及信任到什麼程度。只有 T1 會顯示為官方。",
            style = MaterialTheme.typography.bodyMedium)
        CollapsibleSection("信任等級說明（T1 至 T4）", initiallyExpanded = true, key = "tier-legend") { TierLegend() }

        SectionTitle("DID 信任來源")
        ActionRow(WalletIcons.Government, "數位憑證皮夾信任清單", "數位發展部公布的組織，DID 文件自簽並在 Arbitrum One 註冊") {
            model.screen.value = Screen.TrustList
        }
        Row(Modifier.padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(WalletIcons.Link, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
            Column(Modifier.weight(1f)) {
                Text("網域連結（Linked Domains）", style = MaterialTheme.typography.titleMedium)
                Text("DID 文件列出的網域以 DIF Well Known DID Configuration 證明擁有者，用於 Microsoft Verified ID 等。發證與出示時自動檢查，不需設定。",
                    style = MaterialTheme.typography.bodySmall)
            }
        }
        TrustedDidSection(model, dids)

        HorizontalDivider()
        SectionTitle("X.509 根憑證")
        val list = anchors
        if (list == null) CircularProgressIndicator(Modifier.size(24.dp))
        else {
            val groups = list.groupBy { it.environment to it.certificate }.map { (k, v) -> AnchorGroup(k.first, v) }
            TrustEnvironment.entries.filter { it != TrustEnvironment.SYSTEM }.forEach { env ->
                val inEnv = groups.filter { it.environment == env }
                // Long lists start folded; the user's own imports stay open so a new import is seen at once.
                CollapsibleSection(environmentTitle(env), inEnv.size, initiallyExpanded = env == TrustEnvironment.USER || inEnv.size <= 3, key = "anchors-$env") {
                    if (inEnv.isEmpty()) Text(
                        when (env) {
                            TrustEnvironment.PRODUCTION -> "尚未載入內建錨點。"
                            TrustEnvironment.USER -> "尚未匯入。可在下方貼上其他國家、組織或企業的根憑證。"
                            TrustEnvironment.TEST -> "尚未載入。Multipaz 內建的測試發行端與查驗端在啟動時載入，其他測試錨點在「設定 > 自訂測試伺服器」匯入。"
                            TrustEnvironment.SYSTEM -> ""
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                    inEnv.forEach { g -> AnchorCard(g) { removing = g } }
                }
            }
        }
        SystemStoreSection(model)
        ImportAnchorSection(model)
    }
    removing?.let { g ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text("移除這個信任錨點？") },
            text = { Text("「${g.first.metadata.displayName}」移除後，由它簽發的證件與請求不再被這個錨點信任。已加入的證件不會刪除。") },
            confirmButton = {
                TextButton(onClick = { g.anchors.forEach { model.removeAnchor(it) }; removing = null }) {
                    Text("移除", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("取消") } },
        )
    }
}

@Composable
private fun AnchorCard(g: AnchorGroup, onRemove: () -> Unit) {
    val a = g.first
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(WalletIcons.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                Column(Modifier.weight(1f)) {
                    Text(a.metadata.displayName ?: a.certificate.displaySubject(), style = MaterialTheme.typography.titleSmall)
                    Text("用途：" + g.anchors.map { roleName(it.role) }.distinct().joinToString("、"), style = MaterialTheme.typography.bodySmall)
                }
                if (g.environment != TrustEnvironment.PRODUCTION) TextButton(onClick = onRemove) { Text("移除") }
            }
            Text(a.certificate.displaySubject(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            Text("有效至 " + localTime(a.certificate.validityNotAfter), style = MaterialTheme.typography.bodySmall)
            a.source?.takeIf { it != "pasted" }?.let { Text("來源：$it", style = MaterialTheme.typography.bodySmall) }
            if (a.official) Text("官方來源", style = MaterialTheme.typography.bodySmall)
            if (a.metadata.extensions[diw.wallet.core.trust.TrustMetadataKeys.IDENTITY] == "true") {
                Text("內建：證明對方身分（T2），不代表列於發行端清單", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** The platform's certificate store: on or off, and how many authorities it holds. */
@Composable
private fun SystemStoreSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    var count by remember { mutableStateOf<Int?>(null) }
    LaunchedEffect(Unit) { count = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) { diw.wallet.core.trust.SystemTrustStore.anchors().size } }
    HorizontalDivider()
    SectionTitle(environmentTitle(TrustEnvironment.SYSTEM))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("信任系統憑證庫", style = MaterialTheme.typography.titleSmall)
            Text("憑證鏈連到這台裝置的系統根憑證（公開憑證機構），或下列常用服務的根憑證時，接受為發行端、查驗方或狀態清單簽署者，信任等級 T3，不顯示為官方。" +
                (count?.let { "目前系統憑證庫有 $it 個根憑證。" } ?: ""), style = MaterialTheme.typography.bodySmall)
        }
        androidx.compose.material3.Switch(checked = settings.systemTrustStore, onCheckedChange = { v -> model.updateSettings { it.copy(systemTrustStore = v) } })
    }
    val services = diw.wallet.core.trust.BuiltInPublicRoots.services
    CollapsibleSection("常用服務的根憑證", services.size, key = "roots-services") { BuiltInRootList(model, services) }

    HorizontalDivider()
    SectionTitle("中國大陸憑證機構（T3，非官方）")
    val mainland = diw.wallet.core.trust.BuiltInPublicRoots.mainlandChina
    val national = mainland.count { it.national }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("信任中國大陸的憑證機構", style = MaterialTheme.typography.titleSmall)
            Text("內建 ${mainland.size} 個根憑證" + (if (national > 0) "，其中 $national 個為國密 SM2 根憑證" else "") +
                "：列於 Mozilla 或 Microsoft 根憑證計畫的中國大陸 CA，以及持牌 CA 與國家根 CA 公布的 SM2 根憑證。國家稅務總局的發票查驗與數電票平台、國家移民管理局的網站，以及電子發票的電子文件驗簽，都連到其中的根憑證。信任等級 T3，不顯示為官方。",
                style = MaterialTheme.typography.bodySmall)
        }
        androidx.compose.material3.Switch(checked = settings.mainlandChinaRoots, onCheckedChange = { v -> model.updateSettings { it.copy(mainlandChinaRoots = v) } })
    }
    val programs = mainland.filter { !it.national }
    val sm2 = mainland.filter { it.national }
    CollapsibleSection("根憑證計畫收錄", programs.size, key = "roots-mainland") { BuiltInRootList(model, programs) }
    if (sm2.isNotEmpty()) CollapsibleSection("國密 SM2 根憑證", sm2.size, key = "roots-sm2") { BuiltInRootList(model, sm2) }
    Text("內建清單更新於 ${diw.wallet.core.trust.BuiltInPublicRoots.UPDATED}。清單隨 App 更新，到期的根憑證自動停用。",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
}

/** Built-in public roots: name, owner, algorithm and purpose; a tap opens the certificate. */
@Composable
private fun BuiltInRootList(model: WalletModel, roots: List<diw.wallet.core.trust.BuiltInPublicRoots.Root>) {
    roots.forEach { r ->
        Column(Modifier.fillMaxWidth().clickable {
            model.screen.value = Screen.Certificate(listOf(r.certificate), 0, Screen.TrustAnchors)
        }.padding(vertical = 4.dp)) {
            Text(r.name + if (r.national) "（國密 SM2）" else "", style = MaterialTheme.typography.bodyMedium)
            Text("${r.owner}・${r.algorithm}・${r.purposes}", style = MaterialTheme.typography.bodySmall)
            Text("有效至 " + localTime(r.certificate.validityNotAfter) + "・來源：" + r.source, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline)
        }
    }
}

@Composable
private fun RoleChips(options: List<TrustRole>, selected: Set<TrustRole>, onChange: (Set<TrustRole>) -> Unit) {
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        options.forEach { r ->
            FilterChip(selected = r in selected, onClick = { onChange(if (r in selected) selected - r else selected + r) }, label = { Text(roleName(r)) })
        }
    }
}

@Composable
private fun ImportAnchorSection(model: WalletModel) {
    var pem by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var roles by remember { mutableStateOf(setOf(TrustRole.ISSUER, TrustRole.STATUS_LIST)) }
    HorizontalDivider()
    SectionTitle("匯入根憑證")
    Text("貼上 PEM 格式的憑證（可一次多張），或提供 PEM 的 https 網址。匯入的錨點屬於使用者自訂。", style = MaterialTheme.typography.bodySmall)
    OutlinedTextField(
        value = pem,
        onValueChange = { pem = it },
        label = { Text("-----BEGIN CERTIFICATE----- 或 https://") },
        minLines = 3,
        maxLines = 8,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = name,
        onValueChange = { name = it.take(80) },
        label = { Text("顯示名稱（留空則用憑證的 CN）") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Text("用途", style = MaterialTheme.typography.labelLarge)
    RoleChips(listOf(TrustRole.ISSUER, TrustRole.STATUS_LIST, TrustRole.VERIFIER, TrustRole.DOCUMENT, TrustRole.TSA, TrustRole.WALLET_PROVIDER), roles) { roles = it }
    Button(onClick = { model.importAnchor(pem, name, roles); pem = ""; name = "" }, enabled = pem.isNotBlank() && roles.isNotEmpty()) {
        Text("匯入為信任錨點")
    }
}

@Composable
private fun TrustedDidSection(model: WalletModel, dids: List<UserTrustedDid>) {
    var did by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var roles by remember { mutableStateOf(setOf(TrustRole.ISSUER)) }
    Text("自行信任的 DID（${dids.size}）", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 4.dp))
    if (dids.isEmpty()) Text("尚未加入。信任清單以外的組織（例如企業自建發行端）可在這裡加入。", style = MaterialTheme.typography.bodySmall)
    dids.forEach { d ->
        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(d.name, style = MaterialTheme.typography.titleSmall)
                    Text(d.did, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                    Text("用途：" + d.roles.mapNotNull { id -> TrustRole.entries.firstOrNull { it.id == id }?.let(::roleName) }.joinToString("、") +
                        "　加入於 " + localTime(Instant.fromEpochSeconds(d.addedAt)), style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onClick = { model.untrustDid(d.did) }) { Text("移除") }
            }
        }
    }
    OutlinedTextField(value = did, onValueChange = { did = it.trim() }, label = { Text("DID（did:web、did:key、did:ion…）") }, singleLine = true,
        modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = name, onValueChange = { name = it.take(80) }, label = { Text("組織名稱") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    RoleChips(listOf(TrustRole.ISSUER, TrustRole.VERIFIER), roles) { roles = it }
    Button(onClick = { model.trustDid(did, name, roles); did = ""; name = "" }, enabled = did.startsWith("did:") && roles.isNotEmpty()) {
        Text("信任這個 DID")
    }
}
