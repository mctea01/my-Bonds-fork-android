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
import androidx.compose.ui.unit.dp
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.core.compat.TwdiwDialect
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
fun SettingsScreen(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    val history by model.history.collectAsState()
    var url by remember(s.testServerUrl) { mutableStateOf(s.testServerUrl) }
    var twdiwClientId by remember(s.twdiwClientId) { mutableStateOf(s.twdiwClientId) }
    var twdiwUserAgent by remember(s.twdiwUserAgent) { mutableStateOf(s.twdiwUserAgent) }
    var twdiwFrontend by remember(s.twdiwFrontendUrl) { mutableStateOf(s.twdiwFrontendUrl) }
    var confirmClear by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        SectionTitle("安全")
        model.backends.forEachIndexed { i, b ->
            Text((if (i == 0) "金鑰保護：" else "備用：") + b.protection.displayName, style = MaterialTheme.typography.bodyMedium)
        }
        Toggle("每次使用需驗證", "使用證件金鑰前要求生物辨識或裝置 PIN（軟體金鑰一律需 App PIN）", s.requireUserAuth) { v ->
            model.updateSettings { it.copy(requireUserAuth = v) }
        }
        HorizontalDivider()
        SectionTitle("顯示")
        Toggle("預設展開技術細節", "證件與出示請求的規格、簽章、憑證鏈、有效期間、金鑰與信任判斷", s.showDetails) { v ->
            model.updateSettings { it.copy(showDetails = v) }
        }
        HorizontalDivider()
        SectionTitle("證件狀態")
        Toggle(
            "自動更新證件狀態",
            "開啟或回到 App 時，在背景查詢逾時的狀態：身分證件每 30 分鐘、政府皮夾卡片每 12 小時、其他每 3 天；狀態改變時通知並記入紀錄。也會每 12 小時重新查驗所持卡片發行端的信任清單與區塊鏈註冊。",
            s.autoStatus,
        ) { v -> model.updateSettings { it.copy(autoStatus = v) } }
        val issuerCheck by model.status.issuerCheck.collectAsState()
        issuerCheck?.let { (done, total) -> Text("正在重新查驗發行端：$done / $total", style = MaterialTheme.typography.bodySmall) }
        OutlinedButton(onClick = { model.status.refreshDue(force = true) }) { Text("立即更新所有證件狀態") }
        HorizontalDivider()
        SectionTitle("信任")
        ActionRow(WalletIcons.Shield, "信任清單", "數位憑證皮夾公布的發行端與查驗方，以及各組織在區塊鏈上的註冊") {
            model.screen.value = Screen.TrustList
        }
        ActionRow(WalletIcons.Shield, "信任錨點", "X.509 根憑證與自行信任的 DID，不限數位憑證皮夾；可匯入其他國家、組織或企業的錨點") {
            model.screen.value = Screen.TrustAnchors
        }
        HorizontalDivider()
        SectionTitle("資料與隱私")
        Text("紀錄只保存對象、時間、證件與欄位名稱，不保存欄位內容。目前共 ${history.size} 筆。", style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { confirmClear = true }, enabled = history.isNotEmpty()) { Text("清除所有紀錄") }
        HorizontalDivider()
        SectionTitle("互通設定")
        Text("數位憑證皮夾（TWDIW）、Bonds、OpenID4VCI 草案 11/13、EUDI 參考實作與 Microsoft Verified ID 的相容處理一律啟用，只用於屬於它們的請求，不影響標準流程。",
            style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(
            value = twdiwClientId,
            onValueChange = { twdiwClientId = it.trim() },
            label = { Text("數位憑證皮夾發行端 client_id") },
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
            label = { Text("數位憑證皮夾平台位址（僅測試環境）") },
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
        HorizontalDivider()
        SectionTitle("測試環境")
        Toggle("開啟測試環境", "接受測試信任錨點；測試結果一律標示且不具效力，正式錨點不受影響", s.testEnvironment) { v ->
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
            OutlinedButton(onClick = { model.importTestAnchors() }, enabled = s.testEnvironment) { Text("匯入測試信任錨點") }
        }
        OutlinedButton(onClick = { model.importEudiTestAnchors() }, enabled = s.testEnvironment) { Text("匯入 EUDI 參考實作測試錨點") }
        OutlinedButton(onClick = { model.importMultipazTestAnchors() }, enabled = s.testEnvironment) { Text("匯入 Multipaz 測試發行端錨點") }
        HorizontalDivider()
        SectionTitle("關於")
        Text("平台：${model.platform.platformName}", style = MaterialTheme.typography.bodySmall)
        Text("Client ID：${s.clientId}", style = MaterialTheme.typography.bodySmall)
        Text("數位憑證皮夾 client_id：${s.twdiwClientId}", style = MaterialTheme.typography.bodySmall)
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
