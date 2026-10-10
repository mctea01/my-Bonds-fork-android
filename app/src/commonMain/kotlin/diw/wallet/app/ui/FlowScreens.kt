package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import diw.wallet.app.IssuanceUi
import diw.wallet.app.PresentationUi
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.pick
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.trust.TrustTier

@Composable
private fun Busy(text: String) {
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator()
        Text(text, Modifier.padding(top = 12.dp))
    }
}

@Composable
private fun Failure(model: WalletModel, text: String) {
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("無法完成", style = MaterialTheme.typography.titleLarge)
        Text(text)
        Button(onClick = { model.screen.value = Screen.Home }) { Text("回首頁") }
    }
}

/** Untrusted parties (T3/T4) need an explicit acknowledgement; official or anchored parties do not. */
@Composable
private fun riskAcknowledgement(tier: TrustTier): Boolean {
    var ack by remember(tier) { mutableStateOf(false) }
    if (tier == TrustTier.T1 || tier == TrustTier.T2) return true
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = ack, onCheckedChange = { ack = it })
        Text(if (tier == TrustTier.T4) "我了解對方身分無法驗證，仍要繼續" else "我了解對方不在官方信任清單，仍要繼續")
    }
    return ack
}

@Composable
fun IssuanceScreen(model: WalletModel) {
    val state by model.issuance.collectAsState()
    when (val s = state) {
        IssuanceUi.Loading -> Busy("讀取發行端資訊")
        is IssuanceUi.Working -> Busy(s.message)
        is IssuanceUi.WaitingForBrowser -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Text("請在瀏覽器完成登入與授權，完成後會自動返回", Modifier.padding(vertical = 12.dp))
            OutlinedButton(onClick = { model.cancelBrowserWait() }) { Text("取消") }
        }
        is IssuanceUi.Failed -> Failure(model, s.message)
        is IssuanceUi.Review -> {
            var txCode by remember { mutableStateOf("") }
            // Offers start with everything selected; a wallet-initiated list starts empty.
            var selected by remember(s) { mutableStateOf(if (s.walletInitiated) emptySet() else s.configurations.map { it.id }.toSet()) }
            val tx = s.session.txCode
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                TrustCard("發行端", s.issuerName, s.trust, listOf(s.session.issuer.credentialIssuer))
                Text(if (s.walletInitiated) "此發行端提供下列憑證，請選擇要加入的項目：" else "將加入下列憑證：", style = MaterialTheme.typography.titleSmall)
                if (s.walletInitiated) {
                    Text("部分發行端（如 walt.id）只接受它自己產生的領卡連結；若登入頁顯示錯誤，請改用發行端網頁的 QR Code。", style = MaterialTheme.typography.bodySmall)
                }
                s.configurations.forEach { c ->
                    Card(Modifier.fillMaxWidth()) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = c.id in selected, onCheckedChange = { on -> selected = if (on) selected + c.id else selected - c.id })
                            Column(Modifier.weight(1f)) {
                                Text(c.display.pick(listOf("zh-TW", "en"))?.name ?: c.id, style = MaterialTheme.typography.titleMedium)
                                Text("${c.raw["format"]?.toString()?.trim('"') ?: c.format.wire}  ${c.docType ?: c.vct ?: ""}", style = MaterialTheme.typography.bodySmall)
                                if (c.proofTypes.values.any { it.keyAttestationsRequired != null }) {
                                    Text("發行端要求金鑰證明（由錢包提供者出具）", style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }
                if (s.unsupported.isNotEmpty()) {
                    Text("另有 ${s.unsupported.size} 種憑證格式本錢包尚不支援：", style = MaterialTheme.typography.bodySmall)
                    s.unsupported.take(20).forEach { (id, reason) ->
                        Text("$id：$reason", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                    }
                    if (s.unsupported.size > 20) Text("…", style = MaterialTheme.typography.bodySmall)
                }
                if (tx != null) {
                    OutlinedTextField(
                        value = txCode,
                        onValueChange = { v -> txCode = if (tx.inputMode == "numeric") v.filter { it.isDigit() } else v },
                        label = { Text(tx.description ?: "請輸入發行端提供的交易碼") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = if (tx.inputMode == "numeric") KeyboardType.Number else KeyboardType.Text),
                    )
                }
                val ok = riskAcknowledgement(s.trust.tier)
                val txOk = tx == null || (tx.length == null && txCode.isNotEmpty()) || txCode.length == tx.length
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { model.acceptOffer(s, txCode.ifEmpty { null }, selected.toList()) }, enabled = ok && txOk && selected.isNotEmpty()) {
                        Text(if (s.preAuthorized) "加入" else "前往登入")
                    }
                    OutlinedButton(onClick = { model.screen.value = Screen.Home }) { Text("取消") }
                }
            }
        }
        is IssuanceUi.Done -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            s.results.forEach { r ->
                when (r) {
                    is IssuanceResult.Issued -> TrustCard("已加入", r.document.displayName ?: "", r.trust, listOf("共 ${r.credentials.size} 份可用憑證"))
                    is IssuanceResult.Deferred -> Text("${r.document.displayName}：發行端尚未完成，稍後會再嘗試")
                }
            }
            s.failures.forEach { (name, reason) ->
                Text("$name：未加入（$reason）", color = MaterialTheme.colorScheme.error)
            }
            Button(onClick = { model.screen.value = Screen.Home }) { Text("完成") }
        }
    }
}

@Composable
fun PresentationScreen(model: WalletModel) {
    val state by model.presentation.collectAsState()
    when (val s = state) {
        PresentationUi.Loading -> Busy("驗證請求中")
        is PresentationUi.Working -> Busy(s.message)
        is PresentationUi.Failed -> Failure(model, s.message)
        is PresentationUi.Done -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("已送出", style = MaterialTheme.typography.titleLarge)
            when (val o = s.outcome) {
                is PresentationOutcome.Posted -> Text(if (o.redirectUri != null) "驗證端已接收，將開啟對方頁面" else "驗證端已接收")
                is PresentationOutcome.DcApi -> Text("已回傳給呼叫的網站或 App")
            }
            Button(onClick = { model.screen.value = Screen.Home }) { Text("完成") }
        }
        is PresentationUi.Consent -> {
            val req = s.request
            val v = req.verifier
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                val extra = buildList {
                    add("識別方式：${v.clientId.prefix.wire}")
                    if (v.dnsNames.isNotEmpty()) add("網域：${v.dnsNames.joinToString()}")
                    v.did?.let { add("DID：$it") }
                    req.origin?.let { add("呼叫來源：$it") }
                    req.responseUri?.let { add("回應送往：$it") }
                    if (req.verifierInfo.isNotEmpty()) add("對方附上 ${req.verifierInfo.size} 份身分或用途證明（將於後續版本逐項驗證）")
                    addAll(req.warnings)
                }
                TrustCard("驗證端", v.displayName, v.trust, extra)
                Text("對方要求的資料：", style = MaterialTheme.typography.titleSmall)
                s.items.forEach { item ->
                    Card(Modifier.fillMaxWidth()) {
                        Box(Modifier.padding(12.dp)) {
                            Column {
                                Text(item.documentName, style = MaterialTheme.typography.titleMedium)
                                item.claims.forEach { Text("・$it", style = MaterialTheme.typography.bodyMedium) }
                            }
                        }
                    }
                }
                if (req.transactionData.isNotEmpty()) Text("此請求包含 ${req.transactionData.size} 筆交易資料，同意即代表簽署。")
                val ok = riskAcknowledgement(v.trust.tier)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { model.approve(s) }, enabled = ok) { Text("同意分享") }
                    OutlinedButton(onClick = { model.decline(s) }) { Text("拒絕") }
                }
            }
        }
    }
}
