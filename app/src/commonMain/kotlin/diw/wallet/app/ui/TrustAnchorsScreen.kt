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
    TrustRole.TRUST_LIST_PROVIDER -> "VICAL／RICAL 清單發行者"
    TrustRole.TSA -> "時間戳記"
    TrustRole.DOCUMENT -> "文件簽章"
}

private fun environmentTitle(e: TrustEnvironment): String = when (e) {
    TrustEnvironment.PRODUCTION -> "正式錨點（官方 T1、政府憑證 T2）"
    TrustEnvironment.USER -> "使用者匯入（T2，非官方）"
    TrustEnvironment.TEST -> "測試錨點（T3，結果標示為測試）"
    TrustEnvironment.SYSTEM -> "系統憑證庫（T2，非官方）"
}

/** One certificate in one environment with every role it is an anchor for. */
private data class AnchorGroup(val environment: TrustEnvironment, val anchors: List<StoredAnchor>) {
    val first: StoredAnchor get() = anchors.first()
}

/**
 * Trust anchors of every kind, not only TWDIW: X.509 roots by environment and role, the DID trust sources (the
 * TWDIW list anchored on Arbitrum, Linked Domains) and DIDs the user trusts. Imported anchors and trusted DIDs are
 * the user's own (T2): accepted, never shown as official. Intermediates only complete chains.
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
        CustomTrustRow(model)

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
        Text("自行信任的 DID（${dids.size}）在「自訂信任」加入或移除。", style = MaterialTheme.typography.bodySmall)

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
                            TrustEnvironment.USER -> "尚未匯入。可在「自訂信任」貼上其他國家、組織或企業的根憑證。"
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
        TrustListsSection(model)
        IntermediateSection(model)
    }
    removing?.let { g -> RemoveAnchorDialog(model, g) { removing = null } }
}

/** Entry to the user's own trust, with what it holds now. */
@Composable
internal fun CustomTrustRow(model: WalletModel) {
    val anchors by model.anchors.collectAsState()
    val dids by model.trustedDids.collectAsState()
    val intermediates by model.intermediates.collectAsState()
    val lists by model.mdocLists.collectAsState()
    val federation by model.federationAnchorList.collectAsState()
    val roots = anchors?.filter { it.environment == TrustEnvironment.USER }?.map { it.certificate }?.distinct()?.size ?: 0
    ActionRow(WalletIcons.Shield, "自訂信任",
        "匯入的根憑證 $roots 張、中繼憑證 ${intermediates.size} 張、自行信任的 DID ${dids.size} 個、mdoc 簽署清單 ${lists.size} 份；" +
            "可匯入其他國家、組織或企業的根憑證，或信任清單以外的 DID") {
        model.screen.value = Screen.CustomTrust
    }
}

/**
 * Everything the user added to trust in one place: imported roots (T2, never official), imported intermediates
 * (chain completion only) and trusted DIDs, with the forms that add them.
 */
@Composable
fun CustomTrustScreen(model: WalletModel) {
    val anchors by model.anchors.collectAsState()
    val dids by model.trustedDids.collectAsState()
    val intermediates by model.intermediates.collectAsState()
    var removing by remember { mutableStateOf<AnchorGroup?>(null) }
    LaunchedEffect(Unit) { model.loadAnchors() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("這裡是你自己加入的信任：匯入的根憑證與自行信任的 DID 判定為 T2（使用者自訂，高可信但不顯示為官方）；中繼憑證只用來補足憑證鏈。" +
            "信任來源改變時，已持有證件的發行端會重新判定並記入紀錄。",
            style = MaterialTheme.typography.bodyMedium)

        SectionTitle("匯入的根憑證")
        val list = anchors
        if (list == null) CircularProgressIndicator(Modifier.size(24.dp))
        else {
            val groups = list.filter { it.environment == TrustEnvironment.USER }
                .groupBy { it.certificate }.map { (_, v) -> AnchorGroup(TrustEnvironment.USER, v) }
            if (groups.isEmpty()) Text("尚未匯入。可在下方貼上根憑證；文件簽章卡與信任錨點頁也可以信任線上簽核平台的根憑證。",
                style = MaterialTheme.typography.bodySmall)
            groups.forEach { g -> AnchorCard(g) { removing = g } }
        }

        HorizontalDivider()
        SectionTitle("匯入的中繼憑證")
        if (intermediates.isEmpty()) Text("尚未匯入。簽署者沒有附上中繼憑證、內建也沒有時，可在下方貼上。", style = MaterialTheme.typography.bodySmall)
        intermediates.forEach { i ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    IntermediateRow(model, i.name, i.certificate.displaySubject(), i.certificate, i.source ?: "使用者匯入", Screen.CustomTrust)
                }
                TextButton(onClick = { model.removeIntermediate(i) }) { Text("移除") }
            }
        }

        HorizontalDivider()
        SectionTitle("自行信任的 DID")
        TrustedDidSection(model, dids)

        HorizontalDivider()
        FederationSection(model)

        HorizontalDivider()
        SignedListSection(model)

        ImportAnchorSection(model)
    }
    removing?.let { g -> RemoveAnchorDialog(model, g) { removing = null } }
}

/**
 * mdoc VICAL (issuer CAs) and RICAL (reader CAs) downloaded from an HTTPS address. A list counts only when it is
 * signed under a root imported for the list-publisher role; its CAs are then the user's own trust (T2).
 */
@Composable
private fun SignedListSection(model: WalletModel) {
    val lists by model.mdocLists.collectAsState()
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var kind by remember { mutableStateOf("vical") }
    SectionTitle("mdoc 簽署清單（VICAL、RICAL）")
    Text("VICAL 列出 mdoc 發行端的根憑證，RICAL 列出查驗方的根憑證。清單須由下方以「VICAL／RICAL 清單發行者」用途匯入的根憑證簽署，" +
        "清單內的根憑證判定為 T2（使用者自訂，不顯示為官方）；清單過期後不再採用，可重新取得新版。",
        style = MaterialTheme.typography.bodySmall)
    if (lists.isEmpty()) Text("尚未匯入。", style = MaterialTheme.typography.bodySmall)
    lists.forEach { l ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(l.name, style = MaterialTheme.typography.titleSmall)
                Text((if (l.kind == "vical") "VICAL・發行端" else "RICAL・查驗方") + "・${l.certificates} 張根憑證・版本 ${l.issue ?: "未標示"}",
                    style = MaterialTheme.typography.bodySmall)
                Text(
                    if (l.expired) "已過期，不再採用" + (l.notAfter?.let { "（" + localTime(it) + "）" } ?: "")
                    else "有效至 " + (l.notAfter?.let { localTime(it) } ?: "未標示") + (l.nextUpdate?.let { "・下次更新 " + localTime(it) } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (l.expired) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                l.source?.let { Text("來源：$it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
            }
            TextButton(onClick = { model.removeMdocTrustList(l) }) { Text("移除") }
        }
    }
    if (lists.isNotEmpty()) TextButton(onClick = { model.refreshMdocTrustLists() }) { Text("更新到期的清單") }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(selected = kind == "vical", onClick = { kind = "vical" }, label = { Text("VICAL・發行端") })
        FilterChip(selected = kind == "rical", onClick = { kind = "rical" }, label = { Text("RICAL・查驗方") })
    }
    OutlinedTextField(
        value = url,
        onValueChange = { url = it.trim().take(1024) },
        modifier = Modifier.fillMaxWidth(),
        label = { Text("清單的 HTTPS 網址") },
        singleLine = true,
    )
    OutlinedTextField(
        value = name,
        onValueChange = { name = it.take(80) },
        modifier = Modifier.fillMaxWidth(),
        label = { Text("顯示名稱（選填）") },
        singleLine = true,
    )
    Button(onClick = { model.importMdocTrustList(kind, url, name); url = ""; name = "" }, enabled = url.startsWith("https://")) {
        Text("驗證簽章後匯入")
    }
}

@Composable
private fun RemoveAnchorDialog(model: WalletModel, g: AnchorGroup, onDone: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text("移除這個信任錨點？") },
        text = { Text("「${g.first.metadata.displayName ?: g.first.certificate.displaySubject()}」移除後，由它簽發的證件與請求不再被這個錨點信任。已加入的證件不會刪除。") },
        confirmButton = {
            TextButton(onClick = { g.anchors.forEach { model.removeAnchor(it) }; onDone() }) {
                Text("移除", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDone) { Text("取消") } },
    )
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
            Text("憑證鏈連到這台裝置的系統根憑證（公開憑證機構），或下列常用服務的根憑證時，接受為發行端、查驗方或狀態清單簽署者，信任等級 T2，不顯示為官方。" +
                (count?.let { "目前系統憑證庫有 $it 個根憑證。" } ?: ""), style = MaterialTheme.typography.bodySmall)
        }
        androidx.compose.material3.Switch(checked = settings.systemTrustStore, onCheckedChange = { v -> model.updateSettings { it.copy(systemTrustStore = v) } })
    }
    val services = diw.wallet.core.trust.BuiltInPublicRoots.services
    CollapsibleSection("常用服務的根憑證", services.size, key = "roots-services") { BuiltInRootList(model, services) }

    HorizontalDivider()
    SectionTitle("中國大陸憑證機構（T2，非官方）")
    val mainland = diw.wallet.core.trust.BuiltInPublicRoots.mainlandChina
    val national = mainland.count { it.national }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("信任中國大陸的憑證機構", style = MaterialTheme.typography.titleSmall)
            Text("內建 ${mainland.size} 個根憑證" + (if (national > 0) "，其中 $national 個為國密 SM2 根憑證" else "") +
                "：列於 Mozilla 或 Microsoft 根憑證計畫的中國大陸 CA，以及持牌 CA 與國家根 CA 公布的 SM2 根憑證。國家稅務總局的發票查驗與數電票平台、國家移民管理局的網站，以及電子發票的電子文件驗簽，都連到其中的根憑證。信任等級 T2，不顯示為官方。",
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

/** The public trust lists for document signers and time-stamp authorities: on or off, what is stored, and updates. */
@Composable
private fun TrustListsSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    val states by model.trustLists.states.collectAsState()
    HorizontalDivider()
    SectionTitle("文件簽章信任清單（T2，非官方）")
    Text("憑證鏈連到清單列出的憑證機構時，接受為文件簽署者或時戳機構，信任等級 T2，不顯示為官方。清單在 App 內驗證簽章後保存，可離線使用，每週以條件下載更新。",
        style = MaterialTheme.typography.bodySmall)
    for (kind in diw.wallet.core.trust.TrustListKind.entries) {
        val st = states[kind] ?: continue
        val on = when (kind) {
            diw.wallet.core.trust.TrustListKind.AATL -> settings.aatlTrustList
            diw.wallet.core.trust.TrustListKind.EUTL -> settings.eutlTrustList
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(kind.title, style = MaterialTheme.typography.titleSmall)
                Text(when (kind) {
                    diw.wallet.core.trust.TrustListKind.AATL -> "Adobe Acrobat 信任的文件簽章與時戳根憑證。清單是 Adobe 簽署的 PDF，簽章須連到 Adobe Root CA G2。"
                    diw.wallet.core.trust.TrustListKind.EUTL -> "歐盟各會員國依 eIDAS 監管的合格憑證機構與合格時戳服務，只在核准期間內有效。歐盟清單的簽署憑證已釘選，各國清單由歐盟清單公告的憑證簽署。首次下載約 27 MB。"
                }, style = MaterialTheme.typography.bodySmall)
            }
            androidx.compose.material3.Switch(checked = on, onCheckedChange = { v ->
                model.updateSettings {
                    when (kind) {
                        diw.wallet.core.trust.TrustListKind.AATL -> it.copy(aatlTrustList = v)
                        diw.wallet.core.trust.TrustListKind.EUTL -> it.copy(eutlTrustList = v)
                    }
                }
            })
        }
        val lines = buildList {
            if (st.fetchedAt != null) add("${st.services} 個服務・更新於 ${localTime(st.fetchedAt)}")
            else add(if (st.running) "下載中" else "尚未下載")
            st.issued?.let { add("清單發布於 ${localTime(it)}") }
            st.nextUpdate?.let { add("下次發布預定 ${localTime(it)}") }
            st.signer?.let { add("簽署者：$it") }
            st.error?.let { add("最近一次更新失敗：$it（仍使用上一次保存的清單）") }
        }
        lines.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
        if (st.partErrors.isNotEmpty()) {
            CollapsibleSection("無法更新的國家清單", st.partErrors.size, key = "list-errors-${kind.id}") {
                st.partErrors.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(enabled = on && !st.running, onClick = { model.trustLists.refresh(kind) }) { Text("立即更新") }
            if (st.fetchedAt != null) TextButton(enabled = !st.running, onClick = { model.trustLists.clear(kind) }) { Text("刪除保存的清單") }
            if (st.running) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
        }
    }
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
internal fun RoleChips(options: List<TrustRole>, selected: Set<TrustRole>, onChange: (Set<TrustRole>) -> Unit) {
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
    SectionTitle("匯入根憑證或中繼憑證")
    Text("貼上 PEM 格式的憑證（可一次多張），或提供 PEM 的 https 網址。根憑證成為使用者自訂的信任錨點（T2）；中繼憑證只用來補足憑證鏈，不需選擇用途。",
        style = MaterialTheme.typography.bodySmall)
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
    Text("用途（根憑證）", style = MaterialTheme.typography.labelLarge)
    RoleChips(listOf(TrustRole.ISSUER, TrustRole.STATUS_LIST, TrustRole.VERIFIER, TrustRole.DOCUMENT, TrustRole.TSA, TrustRole.WALLET_PROVIDER, TrustRole.TRUST_LIST_PROVIDER), roles) { roles = it }
    Button(onClick = { model.importAnchor(pem, name, roles); pem = ""; name = "" }, enabled = pem.isNotBlank() && roles.isNotEmpty()) {
        Text("匯入")
    }
}

/**
 * Intermediates never set a tier: built-in ones (document signing services such as BJCA DocSign and e簽寶) and the
 * user's own fill the gap between a signer and its root. Importable roots are built in but not trusted until the
 * user chooses to trust one.
 */
@Composable
private fun IntermediateSection(model: WalletModel) {
    val user by model.intermediates.collectAsState()
    val anchors by model.anchors.collectAsState()
    var trusting by remember { mutableStateOf<diw.wallet.core.trust.BuiltInPublicRoots.Intermediate?>(null) }
    HorizontalDivider()
    SectionTitle("中繼憑證（只用來補足憑證鏈）")
    Text("簽署者沒有附上中繼憑證時，錢包以這些憑證接到根憑證。中繼憑證本身不決定信任等級，等級由最後連到的根憑證決定。",
        style = MaterialTheme.typography.bodySmall)
    val builtIn = diw.wallet.core.trust.BuiltInPublicRoots.intermediates
    CollapsibleSection("內建中繼憑證", builtIn.size, key = "intermediates-builtin") {
        builtIn.forEach { i -> IntermediateRow(model, i.name, "${i.owner}・由 ${i.issuer} 簽發・${i.purposes}", i.certificate, i.source, Screen.TrustAnchors) }
    }
    val importable = diw.wallet.core.trust.BuiltInPublicRoots.importableRoots
    if (importable.isNotEmpty()) CollapsibleSection("可信任的線上簽核平台根憑證", importable.size, key = "intermediates-importable") {
        Text("這些根憑證不在任何根憑證計畫內，預設不信任；文件簽章連到它們時顯示為 T3。確認來源後可在這裡或文件的簽章卡信任，成為使用者匯入的錨點（T2）。",
            style = MaterialTheme.typography.bodySmall)
        importable.forEach { r ->
            val trusted = anchors?.any { it.certificate == r.certificate } == true
            IntermediateRow(model, r.name, "${r.owner}・${r.purposes}", r.certificate, r.source, Screen.TrustAnchors)
            if (trusted) Text("已信任（使用者匯入，T2）", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
            else TextButton(onClick = { trusting = r }) { Text("信任這個根憑證") }
        }
    }
    Text("使用者匯入的中繼憑證 ${user.size} 張，在「自訂信任」匯入或移除。", style = MaterialTheme.typography.bodySmall)
    trusting?.let { r ->
        RiskConfirmDialog(
            title = "信任「${r.name}」",
            lines = listOf(
                "${r.owner} 的根憑證不在 Mozilla、Microsoft 等根憑證計畫內，錢包無法確認它的管理方式。",
                "信任後，連到它的文件簽章與時間戳記會判定為 T2（使用者匯入，非官方）。",
                "可隨時在「設定 > 信任 > 自訂信任」移除。",
            ),
            confirm = "信任",
            onConfirm = { model.trustRootCertificate(r.certificate.encoded.toByteArray()); trusting = null },
            onDismiss = { trusting = null },
        )
    }
}

@Composable
private fun IntermediateRow(model: WalletModel, name: String, detail: String, cert: org.multipaz.crypto.X509Cert, source: String?, from: Screen) {
    Column(Modifier.fillMaxWidth().clickable { model.screen.value = Screen.Certificate(listOf(cert), 0, from) }.padding(vertical = 4.dp)) {
        Text(name, style = MaterialTheme.typography.bodyMedium)
        Text(detail, style = MaterialTheme.typography.bodySmall)
        Text("有效至 " + localTime(cert.validityNotAfter) + (source?.let { "・來源：$it" } ?: ""), style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline)
    }
}

@Composable
private fun TrustedDidSection(model: WalletModel, dids: List<UserTrustedDid>) {
    var did by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var roles by remember { mutableStateOf(setOf(TrustRole.ISSUER)) }
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

/**
 * OpenID Federation Trust Anchors: a Verifier whose client_id is openid_federation:<entity> is accepted when its
 * trust chain ends at one of these. The anchor's keys come from its own Entity Configuration and are trusted only
 * after the user compares the thumbprints with what the federation publishes.
 */
@Composable
private fun FederationSection(model: WalletModel) {
    val anchors by model.federationAnchorList.collectAsState()
    val pending by model.pendingFederationAnchor.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    var entityId by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var test by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf<diw.wallet.core.federation.FederationAnchor?>(null) }
    SectionTitle("OpenID Federation 信任錨點")
    Text("查驗方以 openid_federation: 開頭的識別碼出示請求時，錢包沿著聯邦的信任鏈驗證到這裡的 Trust Anchor，並採用信任鏈套用政策後的查驗方資訊與金鑰。" +
        "使用者加入的錨點判定為 T2（不顯示為官方），測試錨點為 T3，且只在測試環境開啟時採用。",
        style = MaterialTheme.typography.bodySmall)
    if (anchors.isEmpty()) Text("尚未加入。", style = MaterialTheme.typography.bodySmall)
    anchors.forEach { a ->
        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(a.name, style = MaterialTheme.typography.titleSmall)
                    Text(a.entityId, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                    Text((if (a.trustEnvironment == TrustEnvironment.TEST) "測試錨點（T3）" else "使用者加入（T2）") +
                        "・金鑰 ${a.keys.size} 把・加入於 " + localTime(Instant.fromEpochSeconds(a.addedAt)),
                        style = MaterialTheme.typography.bodySmall)
                    if (a.trustEnvironment == TrustEnvironment.TEST && !settings.testEnvironment) {
                        Text("測試環境未開啟，目前不採用", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
                TextButton(onClick = { removing = a }) { Text("移除") }
            }
        }
    }
    OutlinedTextField(value = entityId, onValueChange = { entityId = it.trim().take(512) }, label = { Text("Trust Anchor 的 Entity Identifier（https://…）") },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = name, onValueChange = { name = it.take(80) }, label = { Text("顯示名稱（選填）") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(selected = !test, onClick = { test = false }, label = { Text("正式使用（T2）") })
        FilterChip(selected = test, onClick = { test = true }, enabled = settings.testEnvironment, label = { Text("測試錨點（T3）") })
    }
    Button(onClick = {
        model.fetchFederationAnchor(entityId, name, if (test && settings.testEnvironment) TrustEnvironment.TEST else TrustEnvironment.USER)
    }, enabled = entityId.startsWith("https://") || (settings.testEnvironment && entityId.startsWith("http://"))) {
        Text("取得錨點資訊")
    }
    pending?.let { p ->
        AlertDialog(
            onDismissRequest = { model.pendingFederationAnchor.value = null },
            title = { Text("信任這個 Trust Anchor？") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(p.anchor.name, style = MaterialTheme.typography.titleSmall)
                    Text(p.anchor.entityId, style = MaterialTheme.typography.bodySmall)
                    p.organization?.let { Text("組織名稱：$it", style = MaterialTheme.typography.bodySmall) }
                    Text("請將以下金鑰指紋（RFC 7638 SHA-256）與聯邦公布的值比對，一致才加入。網路取得的資訊本身無法證明這是正確的錨點。",
                        style = MaterialTheme.typography.bodySmall)
                    p.thumbprints.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
                    if (p.authorityHints.isNotEmpty()) {
                        Text("注意：這個實體還有上級（" + p.authorityHints.joinToString("、") + "），它可能是中介機構而不是 Trust Anchor。",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { model.confirmFederationAnchor(); entityId = ""; name = "" }) { Text("指紋一致，加入") } },
            dismissButton = { TextButton(onClick = { model.pendingFederationAnchor.value = null }) { Text("取消") } },
        )
    }
    removing?.let { a ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text("移除這個 Trust Anchor？") },
            text = { Text("「${a.name}」移除後，經由它的聯邦驗證的查驗方不再被信任。") },
            confirmButton = { TextButton(onClick = { model.removeFederationAnchor(a); removing = null }) { Text("移除", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("取消") } },
        )
    }
}
