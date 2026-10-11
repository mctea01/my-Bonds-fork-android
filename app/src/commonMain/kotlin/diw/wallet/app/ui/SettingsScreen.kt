package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
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
    var url by remember(s.testServerUrl) { mutableStateOf(s.testServerUrl) }
    var twdiwClientId by remember(s.twdiwClientId) { mutableStateOf(s.twdiwClientId) }
    var twdiwUserAgent by remember(s.twdiwUserAgent) { mutableStateOf(s.twdiwUserAgent) }
    var twdiwFrontend by remember(s.twdiwFrontendUrl) { mutableStateOf(s.twdiwFrontendUrl) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("金鑰保護", style = MaterialTheme.typography.titleMedium)
        model.backends.forEachIndexed { i, b ->
            Text((if (i == 0) "使用中：" else "備用：") + b.protection.displayName, style = MaterialTheme.typography.bodyMedium)
        }
        Toggle("每次使用需驗證", "使用憑證金鑰前要求生物辨識或裝置 PIN（軟體金鑰一律需 App PIN）", s.requireUserAuth) { v ->
            model.updateSettings { it.copy(requireUserAuth = v) }
        }
        HorizontalDivider()
        Text("顯示", style = MaterialTheme.typography.titleMedium)
        Toggle("預設展開詳細資訊", "憑證與驗證請求的技術細節：規格、簽章、憑證鏈、有效期間、金鑰與信任判斷", s.showDetails) { v ->
            model.updateSettings { it.copy(showDetails = v) }
        }
        HorizontalDivider()
        Text("數位憑證皮夾（TWDIW）", style = MaterialTheme.typography.titleMedium)
        Text("TWDIW、Bonds、OpenID4VCI 草案 11/13、EUDI 參考實作與 Microsoft Verified ID 的相容處理一律啟用，只用於屬於它們的請求，不影響標準流程。",
            style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(
            value = twdiwClientId,
            onValueChange = { twdiwClientId = it.trim() },
            label = { Text("發行端 client_id") },
            supportingText = { Text("預設 moda_dw 是官方數位憑證皮夾的識別碼，TWDIW 發行端只接受它；本錢包以它向發行端表明相容官方流程") },
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
            label = { Text("平台位址（僅測試環境）") },
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
        Text("測試環境", style = MaterialTheme.typography.titleMedium)
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
        Text("平台：${model.platform.platformName}", style = MaterialTheme.typography.bodySmall)
        Text("Client ID：${s.clientId}", style = MaterialTheme.typography.bodySmall)
    }
}
