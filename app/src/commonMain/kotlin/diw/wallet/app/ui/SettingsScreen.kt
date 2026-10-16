package diw.wallet.app.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import diw.wallet.app.AppBuild
import diw.wallet.app.Screen
import diw.wallet.app.SettingsSection
import diw.wallet.app.WalletModel
import diw.wallet.app.WalletSettings
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.document.sign.PadesLevel
import diw.wallet.core.document.sign.TsaServices
import diw.wallet.core.profile.bonds.MyDataProfile
import diw.wallet.core.profile.twdiw.TwdiwPlatform

@Composable
private fun Toggle(title: String, detail: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(detail, style = MaterialTheme.typography.bodySmall)
        }
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
    }
}

@Composable
private fun SettingsColumn(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp), content = content)
}

private fun onOff(v: Boolean) = if (v) "開" else "關"

private val SettingsSection.icon: ImageVector
    get() = when (this) {
        SettingsSection.SECURITY -> WalletIcons.Shield
        SettingsSection.CREDENTIALS -> WalletIcons.Card
        SettingsSection.DOCUMENTS -> WalletIcons.Document
        SettingsSection.TRUST -> WalletIcons.Organization
        SettingsSection.INTEROP -> WalletIcons.Link
        SettingsSection.DEVELOPER -> WalletIcons.Phone
        SettingsSection.GENERAL -> WalletIcons.Settings
        SettingsSection.ABOUT -> WalletIcons.Info
    }

/** The settings list: one row per group, each saying what it holds and how it is set now. */
@Composable
fun SettingsScreen(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    val history by model.history.collectAsState()
    val reg by model.dcApiRegistration.collectAsState()
    SettingsColumn {
        SettingsSection.entries.forEach { section ->
            val summary = when (section) {
                SettingsSection.SECURITY -> listOfNotNull(
                    model.backends.firstOrNull()?.let { "金鑰保護：" + it.protection.displayName },
                    "每次使用需驗證：" + onOff(s.requireUserAuth),
                    "紀錄 ${history.size} 筆",
                ).joinToString("・")
                SettingsSection.CREDENTIALS -> listOfNotNull(
                    "自動更新狀態：" + onOff(s.autoStatus),
                    reg?.let { r -> if (r.error != null) "系統選擇器註冊失敗" else "系統選擇器 ${r.registered} 張" },
                ).joinToString("・")
                SettingsSection.DOCUMENTS -> listOfNotNull(
                    "時戳機構：" + TsaServices.byId(s.tsaId).name,
                    "PDF 預設 " + padesLevel(s).title,
                    if (s.myDataIdNumber != null) "MyData 自動填入已設定" else null,
                ).joinToString("・")
                SettingsSection.TRUST -> listOf(
                    "系統憑證庫：" + onOff(s.systemTrustStore),
                    "中國大陸 CA：" + onOff(s.mainlandChinaRoots),
                    "AATL：" + onOff(s.aatlTrustList),
                    "EUTL：" + onOff(s.eutlTrustList),
                ).joinToString("・")
                SettingsSection.INTEROP -> "相容處理常駐啟用・錢包後端：" + if (s.walletProviderUrl.isNullOrBlank()) "未設定" else "已設定"
                SettingsSection.DEVELOPER -> "自訂測試伺服器：" + onOff(s.testEnvironment) + if (s.manualMobileMoicaSp) "・手動 SP 帳號" else ""
                SettingsSection.GENERAL -> "預設展開技術細節：" + onOff(s.showDetails)
                SettingsSection.ABOUT -> "版本 " + appVersion() + "・授權、第三方元件與原始碼"
            }
            ActionRow(section.icon, section.title, summary) { model.screen.value = Screen.SettingsPage(section) }
        }
    }
}

/** One group of settings on its own page. */
@Composable
fun SettingsPageScreen(model: WalletModel, section: SettingsSection) {
    SettingsColumn {
        when (section) {
            SettingsSection.SECURITY -> SecurityPage(model)
            SettingsSection.CREDENTIALS -> CredentialsPage(model)
            SettingsSection.DOCUMENTS -> DocumentsPage(model)
            SettingsSection.TRUST -> TrustPage(model)
            SettingsSection.INTEROP -> InteropPage(model)
            SettingsSection.DEVELOPER -> DeveloperPage(model)
            SettingsSection.GENERAL -> GeneralPage(model)
            SettingsSection.ABOUT -> AboutPage(model)
        }
    }
}

private fun padesLevel(s: WalletSettings) = PadesLevel.entries.firstOrNull { it.name == s.padesLevel } ?: PadesLevel.B_T

@Composable
private fun SecurityPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    val history by model.history.collectAsState()
    var confirmClear by remember { mutableStateOf(false) }
    SectionTitle("金鑰")
    model.backends.forEachIndexed { i, b ->
        Text((if (i == 0) "金鑰保護：" else "備用：") + b.protection.displayName, style = MaterialTheme.typography.bodyMedium)
    }
    Toggle("每次使用需驗證", "使用證件金鑰前要求生物辨識或裝置 PIN（軟體金鑰一律需 App PIN）", s.requireUserAuth) { v ->
        model.updateSettings { it.copy(requireUserAuth = v) }
    }
    HorizontalDivider()
    SectionTitle("紀錄")
    Text("紀錄只保存對象、時間、證件與欄位名稱，不保存欄位內容。目前共 ${history.size} 筆。", style = MaterialTheme.typography.bodySmall)
    OutlinedButton(onClick = { confirmClear = true }, enabled = history.isNotEmpty()) { Text("清除所有紀錄") }
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

@Composable
private fun CredentialsPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    SectionTitle("證件狀態")
    Toggle(
        "自動更新證件狀態",
        "開啟或回到 App 時，在背景查詢逾時的狀態：身分證件每 30 分鐘、政府皮夾卡片每 12 小時、其他每 3 天；狀態改變時通知並記入紀錄。也會每 12 小時重新查驗所持卡片發行端的信任清單與區塊鏈註冊。",
        s.autoStatus,
    ) { v -> model.updateSettings { it.copy(autoStatus = v) } }
    val issuerCheck by model.status.issuerCheck.collectAsState()
    issuerCheck?.let { (done, total) -> Text("正在重新查驗發行端：$done / $total", style = MaterialTheme.typography.bodySmall) }
    OutlinedButton(onClick = { model.status.refreshDue(force = true) }) { Text("立即更新所有證件狀態") }
    DigitalCredentialsSection(model)
}

@Composable
private fun DocumentsPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    SectionTitle("時戳")
    Text("簽署文件、保存檔案與產生衍生憑證時使用的時戳機構（RFC 3161）。只會送出檔案的 SHA-256。", style = MaterialTheme.typography.bodySmall)
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TsaServices.all.forEach { t ->
            FilterChip(selected = s.tsaId == t.id, onClick = { model.updateSettings { it.copy(tsaId = t.id) } }, label = { Text(t.name) })
        }
    }
    val tsa = TsaServices.byId(s.tsaId)
    Text(tsa.url + if (tsa.publicRoot) "（根憑證在常見憑證庫，信任等級 T2）" else "（根憑證不在內建清單，需在信任錨點匯入，用途選時間戳記）",
        style = MaterialTheme.typography.bodySmall)
    Toggle("保存文件時自動加時戳", "匯入或製作的文件保存後立即向時戳機構取得時戳，證明檔案當時已存在", s.timestampOnSave) { v ->
        model.updateSettings { it.copy(timestampOnSave = v) }
    }
    Toggle("時戳與簽章一併保存撤銷資訊", "取得時戳時，同時取得時戳機構憑證鏈的 OCSP 回應（取不到才用 CRL）與時戳一起保存；保存含簽章的文件時，也取得簽署者與其時戳機構的撤銷資訊。憑證過期後仍可驗證", s.timestampRevocation) { v ->
        model.updateSettings { it.copy(timestampRevocation = v) }
    }
    HorizontalDivider()
    SectionTitle("PDF 簽署的預設保證層級")
    val level = padesLevel(s)
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        PadesLevel.entries.forEach { l ->
            FilterChip(selected = l == level, onClick = { model.updateSettings { it.copy(padesLevel = l.name) } }, label = { Text(l.title) })
        }
    }
    Text(level.detail + "。簽署畫面仍可逐次調整，最後選的層級會記住。", style = MaterialTheme.typography.bodySmall)
    Text("遠端簽章（CSC）服務在簽署畫面的「簽署者」選擇或新增。", style = MaterialTheme.typography.bodySmall)
    HorizontalDivider()
    MyDataProfileSection(model)
}

@Composable
private fun TrustPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    var signedListUrl by remember { mutableStateOf("") }
    var signedListName by remember { mutableStateOf("") }
    var signedListKind by remember { mutableStateOf("rical") }
    Text("信任等級：T1 官方清單並經額外驗證，T2 連到信任根，兩者都視為高可信；T3 可驗證但沒有連到信任根；T4 驗證失敗。測試環境的結果永遠不是官方。",
        style = MaterialTheme.typography.bodySmall)
    CustomTrustRow(model)
    HorizontalDivider()
    SectionTitle("信任來源")
    Toggle("系統憑證庫與常用服務根憑證", "憑證鏈連到這台裝置的系統根憑證或內建的常用服務根憑證時為 T2，不顯示為官方", s.systemTrustStore) { v ->
        model.updateSettings { it.copy(systemTrustStore = v) }
    }
    Toggle("中國大陸憑證機構", "Mozilla 或 Microsoft 根憑證計畫收錄的中國大陸 CA 與公布的國密 SM2 根憑證，T2，加上中國大陸憑證機構標籤", s.mainlandChinaRoots) { v ->
        model.updateSettings { it.copy(mainlandChinaRoots = v) }
    }
    Toggle("Adobe AATL", "只用於文件簽章與時戳，T2", s.aatlTrustList) { v -> model.updateSettings { it.copy(aatlTrustList = v) } }
    Toggle("歐盟 EUTL", "只用於文件簽章與時戳，依各國監管期間判定，T2", s.eutlTrustList) { v -> model.updateSettings { it.copy(eutlTrustList = v) } }
    HorizontalDivider()
    SectionTitle("mdoc VICAL／RICAL 簽署信任清單")
    Text("請先到「信任 > 自訂信任」匯入清單發行者的根憑證，並只選用途「VICAL／RICAL 清單發行者」。清單須由該根憑證授權簽署，才可加入發行端／查驗方信任。",
        style = MaterialTheme.typography.bodySmall)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(selected = signedListKind == "rical", onClick = { signedListKind = "rical" }, label = { Text("RICAL・查驗方") })
        FilterChip(selected = signedListKind == "vical", onClick = { signedListKind = "vical" }, label = { Text("VICAL・發行端") })
    }
    OutlinedTextField(
        value = signedListUrl,
        onValueChange = { signedListUrl = it.trim().take(1024) },
        modifier = Modifier.fillMaxWidth(),
        label = { Text("簽署清單 HTTPS 下載網址") }, singleLine = true,
    )
    OutlinedTextField(
        value = signedListName,
        onValueChange = { signedListName = it.take(80) },
        modifier = Modifier.fillMaxWidth(),
        label = { Text("顯示名稱（選填）") }, singleLine = true,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(
            onClick = { model.importMdocTrustList(signedListKind, signedListUrl, signedListName) },
            enabled = signedListUrl.startsWith("https://"),
        ) { Text("驗簽後匯入") }
        OutlinedButton(onClick = { model.refreshMdocTrustLists() }) { Text("更新已匯入清單") }
    }
    Text("清單需有有效簽章與受信任的清單發行者憑證；到期不再授權。不符合條件的清單不會被當成信任根。",
        style = MaterialTheme.typography.bodySmall)
    HorizontalDivider()
    SectionTitle("清單與錨點")
    ActionRow(WalletIcons.Shield, "數位憑證皮夾信任清單", "數位憑證皮夾公布的發行端與查驗方，以及各組織在區塊鏈上的註冊") {
        model.screen.value = Screen.TrustList
    }
    ActionRow(WalletIcons.Shield, "信任錨點", "全部內建與匯入的 X.509 根憑證、中繼憑證、DID 信任來源與文件簽章信任清單的下載狀態") {
        model.screen.value = Screen.TrustAnchors
    }
}

@Composable
private fun InteropPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    var twdiwClientId by remember(s.twdiwClientId) { mutableStateOf(s.twdiwClientId) }
    var walletClientId by remember(s.clientId) { mutableStateOf(s.clientId) }
    var providerUrl by remember(s.walletProviderUrl) { mutableStateOf(s.walletProviderUrl.orEmpty()) }
    var twdiwUserAgent by remember(s.twdiwUserAgent) { mutableStateOf(s.twdiwUserAgent) }
    var twdiwFrontend by remember(s.twdiwFrontendUrl) { mutableStateOf(s.twdiwFrontendUrl) }
    Text("數位憑證皮夾（TWDIW）、Bonds、OpenID4VCI 草案 11/13、EUDI 參考實作與 Microsoft Verified ID 的相容處理一律啟用，只用於屬於它們的請求，不影響標準流程。",
        style = MaterialTheme.typography.bodySmall)
    SectionTitle("OpenID4VCI 錢包身分")
    Text("正式發證端可要求 Wallet Attestation 或 Client Assertion。需向受信任的錢包後端申請並登錄 client_id；後端及其簽章來源必須獲得發證端信任，不能以測試憑證冒充。",
        style = MaterialTheme.typography.bodySmall)
    OutlinedTextField(
        value = walletClientId,
        onValueChange = { walletClientId = it.trim().take(256) },
        label = { Text("錢包 client_id") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = providerUrl,
        onValueChange = { providerUrl = it.trim().take(500) },
        label = { Text("受信任的錢包後端 HTTPS 網址") },
        supportingText = { Text("留空時使用公開用戶端；測試後端另於開發者設定。請勿填寫發證端網址。") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    val validProvider = providerUrl.isBlank() ||
        (providerUrl.startsWith("https://") && !providerUrl.contains('#') && !providerUrl.contains('?') &&
            providerUrl.substringAfter("https://").substringBefore('/').isNotBlank())
    val walletChanged = walletClientId != s.clientId || providerUrl.ifBlank { null } != s.walletProviderUrl
    OutlinedButton(
        enabled = validProvider && walletClientId.isNotBlank() && walletChanged,
        onClick = { model.updateSettings { it.copy(clientId = walletClientId, walletProviderUrl = providerUrl.ifBlank { null }) } },
    ) { Text("儲存錢包身分") }
    if (!validProvider) Text("錢包後端必須使用 HTTPS 網址，且不得包含查詢參數或片段。", color = MaterialTheme.colorScheme.error)
    HorizontalDivider()
    SectionTitle("數位憑證皮夾")
    OutlinedTextField(
        value = twdiwClientId,
        onValueChange = { twdiwClientId = it.trim() },
        label = { Text("發行端 client_id") },
        supportingText = { Text("預設 moda_dw 是官方數位憑證皮夾的識別碼，發行端只接受它；這個 App 以它表明相容官方流程") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = twdiwUserAgent,
        onValueChange = { twdiwUserAgent = it },
        label = { Text("送往 wallet.gov.tw 的 User-Agent") },
        supportingText = { Text("只用於 wallet.gov.tw；其防護會拒絕程式庫預設值（錯誤 1010）") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = twdiwFrontend,
        onValueChange = { twdiwFrontend = it.trim() },
        label = { Text("平台位址（需使用自訂測試伺服器）") },
        supportingText = { Text("正式環境固定使用 ${TwdiwPlatform.PRODUCTION_FRONTEND}；UAT 為 ${TwdiwPlatform.UAT_FRONTEND}") },
        singleLine = true,
        enabled = s.testEnvironment,
        modifier = Modifier.fillMaxWidth(),
    )
    val changed = twdiwClientId != s.twdiwClientId || twdiwUserAgent != s.twdiwUserAgent || twdiwFrontend != s.twdiwFrontendUrl
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = {
            model.updateSettings {
                it.copy(
                    twdiwClientId = twdiwClientId.ifEmpty { TwdiwDialect.DEFAULT_CLIENT_ID },
                    twdiwUserAgent = twdiwUserAgent.ifBlank { TwdiwPlatform.DEFAULT_USER_AGENT },
                    twdiwFrontendUrl = twdiwFrontend.ifEmpty { TwdiwPlatform.PRODUCTION_FRONTEND },
                )
            }
        }, enabled = changed) { Text("儲存") }
        OutlinedButton(onClick = {
            twdiwClientId = TwdiwDialect.DEFAULT_CLIENT_ID
            twdiwUserAgent = TwdiwPlatform.DEFAULT_USER_AGENT
            twdiwFrontend = TwdiwPlatform.PRODUCTION_FRONTEND
        }) { Text("還原預設") }
    }
}

@Composable
private fun DeveloperPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    var url by remember(s.testServerUrl) { mutableStateOf(s.testServerUrl) }
    Text("測試用的信任錨點（Multipaz 內建發行端與查驗端、EUDI 參考實作、匯入的測試錨點）一律可用，驗證結果標示為測試且不具效力；這個開關只管理下方自訂的測試伺服器位址。",
        style = MaterialTheme.typography.bodySmall)
    SectionTitle("自訂測試伺服器")
    Toggle("使用自訂測試伺服器", "啟用測試伺服器網址、測試錢包提供者與非正式的數位憑證皮夾平台位址", s.testEnvironment) { v ->
        model.updateSettings { it.copy(testEnvironment = v, allowLoopbackHttp = v && it.allowLoopbackHttp) }
    }
    Toggle("允許本機與區網 HTTP", "僅限 localhost、模擬器主機與私有網段（10.x、172.16 至 172.31、192.168.x），用於本地測試伺服器；正式版 APK 只允許前兩者", s.allowLoopbackHttp, enabled = s.testEnvironment) { v ->
        model.updateSettings { it.copy(allowLoopbackHttp = v) }
    }
    Toggle("使用測試錢包提供者", "向測試伺服器取得錢包證明與金鑰證明", s.useWalletProvider, enabled = s.testEnvironment) { v ->
        model.updateSettings { it.copy(useWalletProvider = v) }
    }
    OutlinedTextField(
        value = url,
        onValueChange = { url = it.trim() },
        label = { Text("測試伺服器網址") },
        singleLine = true,
        enabled = s.testEnvironment,
        modifier = Modifier.fillMaxWidth(),
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = { model.updateSettings { it.copy(testServerUrl = url) } }, enabled = s.testEnvironment && url != s.testServerUrl) {
            Text("儲存網址")
        }
        OutlinedButton(onClick = { model.importTestAnchors() }, enabled = s.testEnvironment) { Text("從測試伺服器匯入錨點") }
    }
    HorizontalDivider()
    SectionTitle("測試錨點")
    OutlinedButton(onClick = { model.importEudiTestAnchors() }) { Text("匯入 EUDI 參考實作測試錨點") }
    OutlinedButton(onClick = { model.importMultipazTestAnchors() }) { Text("從 issuer.multipaz.org 更新 Multipaz 發行端錨點") }
    HorizontalDivider()
    SectionTitle("行動自然人憑證")
    Toggle(
        "手動輸入 SP 帳號",
        "行動自然人憑證簽章改用簽署畫面輸入的服務提供者帳號，供持有 SP 授權的開發者測試；帳號只保存在這次執行的記憶體。" +
            if (model.files.builtInMobileMoicaSp == null) "這個版本沒有內建 SP 帳號。" else "關閉時使用本版內建的帳號。",
        s.manualMobileMoicaSp,
    ) { v -> model.updateSettings { it.copy(manualMobileMoicaSp = v) } }
}

@Composable
private fun GeneralPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    Toggle("預設展開技術細節", "證件與出示請求的規格、簽章、憑證鏈、有效期間、金鑰與信任判斷", s.showDetails) { v ->
        model.updateSettings { it.copy(showDetails = v) }
    }
}

private const val SOURCE_URL = "https://github.com/mctea01/my-Bonds-fork-android"

private fun appVersion(): String = AppBuild.version ?: "開發版"

/** Third-party software shipped in the app, as NOTICE lists it. */
private val THIRD_PARTY = listOf(
    "Multipaz" to "Apache License 2.0",
    "Kotlin、kotlinx.coroutines、kotlinx.serialization、kotlinx-io、kotlinx-datetime" to "Apache License 2.0",
    "Ktor" to "Apache License 2.0",
    "Compose Multiplatform、AndroidX" to "Apache License 2.0",
    "Google Play services identity credentials" to "Android Software Development Kit License",
    "Bouncy Castle" to "Bouncy Castle License（MIT 類）",
    "Apache Xerces2、xml-apis" to "Apache License 2.0",
    "Apache PDFBox（電腦版預覽）" to "Apache License 2.0",
    "SQLite JDBC（電腦版）" to "Apache License 2.0；SQLite 為公眾領域",
    "CMWallet 收卡比對程式（Android）" to "Apache License 2.0",
)

@Composable
private fun AboutPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    Text("DIW MY WALLET", style = MaterialTheme.typography.titleLarge)
    Text("跨平台的數位憑證錢包：保存與出示數位證件、查驗他人證件，並保存、檢查與簽署電子文件。依 OpenID4VCI 1.0、OpenID4VP 1.0、ISO/IEC 18013-5 與 18013-7、" +
        "SD-JWT VC、W3C VC 等標準實作，並相容數位憑證皮夾、Bonds、EUDI Wallet 與 Microsoft Verified ID。",
        style = MaterialTheme.typography.bodySmall)
    SectionTitle("版本")
    LabelValue("版本", appVersion())
    AppBuild.commit?.let { LabelValue("建置來源", it) }
    LabelValue("平台", model.platform.platformName)
    HorizontalDivider()
    SectionTitle("識別碼")
    LabelValue("Client ID", s.clientId, small = true)
    LabelValue("數位憑證皮夾 client_id", s.twdiwClientId, small = true)
    HorizontalDivider()
    SectionTitle("授權")
    Text("Copyright 2026 LIN, CHE-CHUAN。以 Apache License 2.0 授權。", style = MaterialTheme.typography.bodyMedium)
    Text("內建的信任錨點是各憑證機構與 Multipaz 專案公開的憑證，只用於驗證憑證鏈；Adobe AATL 與歐盟 EUTL 在 App 內下載並驗證，只內建簽署憑證的指紋。" +
        "沒有複製 Bonds 的程式碼，相容性依公開的格式與文件實作。",
        style = MaterialTheme.typography.bodySmall)
    SectionTitle("第三方元件")
    THIRD_PARTY.forEach { (name, license) -> LabelValue(name, license, small = true) }
    HorizontalDivider()
    SectionTitle("原始碼")
    LabelValue("GitHub", SOURCE_URL, small = true) { model.platform.openBrowser(SOURCE_URL) }
    OutlinedButton(onClick = { model.platform.openBrowser("$SOURCE_URL/blob/main/LICENSE") }) { Text("授權全文") }
    OutlinedButton(onClick = { model.platform.openBrowser("$SOURCE_URL/blob/main/NOTICE") }) { Text("第三方授權聲明（NOTICE）") }
}

/** Registration with the system credential picker (Android Digital Credentials API); hidden where there is none. */
@Composable
private fun DigitalCredentialsSection(model: WalletModel) {
    val reg by model.dcApiRegistration.collectAsState()
    val r = reg ?: return
    HorizontalDivider()
    SectionTitle("瀏覽器與 App 出示、收卡")
    val summary = when {
        r.error != null -> "最近一次向系統註冊失敗：${r.error}"
        r.registered == 0 -> "目前沒有可由系統選擇器出示的證件。系統選擇器只支援 mdoc 與 SD-JWT VC 證件。"
        else -> "已向系統註冊 ${r.registered} 張證件。網頁或其他 App 以 Digital Credentials API 要求證件時，系統選擇器會在證件類型相符時列出本 App。"
    }
    Text(summary, style = MaterialTheme.typography.bodySmall,
        color = if (r.error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
    if (r.notListable > 0) {
        Text("${r.notListable} 張只有 W3C 格式的證件（例如數位憑證皮夾卡片）不在系統選擇器的支援範圍，請改用 QR 碼或連結出示。",
            style = MaterialTheme.typography.bodySmall)
    }
    when {
        r.issuance -> Text("網頁或 App 以 Digital Credentials API 發卡（OpenID4VCI）時，系統會列出本 App 作為存放位置。", style = MaterialTheme.typography.bodySmall)
        r.issuanceError != null -> Text("Digital Credentials API 收卡註冊失敗：${r.issuanceError}", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error)
    }
    OutlinedButton(onClick = { model.reregisterDigitalCredentials() }) { Text("重新向系統註冊") }
}

/**
 * The MyData details the holder may save (Bonds MyDataAutofillProfile): filled into MyData's own sign-in pages in the
 * app and tried as the open password of MyData PDFs. Nothing is learned from pages; the holder types and removes them.
 */
@Composable
private fun MyDataProfileSection(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    var id by remember { mutableStateOf("") }
    var birth by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }
    SectionTitle("MyData 自動填入")
    Text("保存身分證統一編號與出生日期後，App 內開啟 MyData 時自動填入登入欄位，下載的 PDF 也會自動用統一編號開啟。只存在這支裝置，不會送到 MyData 以外的網站；不保存也可以，每次自行輸入。",
        style = MaterialTheme.typography.bodySmall)
    val saved = s.myDataIdNumber
    if (saved != null) {
        LabelValue("身分證統一編號", saved.take(1) + "*".repeat(6) + saved.takeLast(3))
        s.myDataBirthDate?.let { LabelValue("出生日期", it.take(4) + "-" + it.substring(4, 6) + "-" + it.substring(6)) }
        OutlinedButton(onClick = { model.updateSettings { it.copy(myDataIdNumber = null, myDataBirthDate = null) } }) { Text("移除已保存的資料") }
        return
    }
    OutlinedTextField(
        value = id, onValueChange = { v -> id = v.filter { it.isLetterOrDigit() }.take(10); problem = null },
        label = { Text("身分證統一編號") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = birth, onValueChange = { v -> birth = v.filter { it.isDigit() }.take(8); problem = null },
        label = { Text("出生日期（西元 19880101 或民國 0770101）") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
    )
    problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    OutlinedButton(
        onClick = {
            val today = kotlin.time.Clock.System.now().toString().take(10).replace("-", "")
            val date = MyDataProfile.normalizeBirthDate(birth, today)
            when {
                !MyDataProfile.isValidId(id) -> problem = "身分證統一編號不正確"
                date == null -> problem = "出生日期不正確"
                else -> {
                    model.updateSettings { it.copy(myDataIdNumber = MyDataProfile.normalizeId(id), myDataBirthDate = date) }
                    id = ""
                    birth = ""
                }
            }
        },
        enabled = id.isNotBlank() && birth.isNotBlank(),
    ) { Text("保存") }
}
