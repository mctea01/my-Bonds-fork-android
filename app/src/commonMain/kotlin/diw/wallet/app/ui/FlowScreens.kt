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
import androidx.compose.material3.TextButton
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
import diw.wallet.app.ConsentItem
import diw.wallet.app.CredentialDetails
import diw.wallet.app.HomeTab
import diw.wallet.app.IssuanceUi
import diw.wallet.app.PresentationUi
import diw.wallet.app.Screen
import diw.wallet.app.StatusTexts
import diw.wallet.app.WalletModel
import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.pick
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.status.StatusFinding
import diw.wallet.core.status.StatusPolicy
import diw.wallet.core.status.StatusVerdict
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier

@Composable
internal fun Busy(text: String) {
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator()
        Text(text, Modifier.padding(top = 12.dp))
    }
}

@Composable
internal fun Failure(text: String, onClose: () -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        VerdictCard(Verdict.FAIL, "無法完成", listOf(text))
        Button(onClick = onClose) { Text("回首頁") }
    }
}

/**
 * Untrusted parties (T3/T4) need an explicit acknowledgement; official or anchored parties do not, and neither does a
 * verified Microsoft Verified ID domain, which Microsoft Authenticator also accepts without a warning.
 */
@Composable
internal fun riskAcknowledgement(trust: TrustDecision): Boolean {
    val tier = trust.tier
    var ack by remember(trust) { mutableStateOf(false) }
    if (tier == TrustTier.T1 || tier == TrustTier.T2) return true
    if (tier == TrustTier.T3 && TrustLabel.LINKED_DOMAIN in trust.labels) return true
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
        is IssuanceUi.Failed -> Failure(s.message) { model.screen.value = Screen.Home }
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
                                Text(c.display.pick(model.locales)?.name ?: c.id, style = MaterialTheme.typography.titleMedium)
                                Text("${c.raw["format"]?.toString()?.trim('"') ?: c.format.wire}  ${c.docType ?: c.vct ?: ""}", style = MaterialTheme.typography.bodySmall)
                                if (c.proofTypes.values.any { it.keyAttestationsRequired != null }) {
                                    Text("發行端要求金鑰證明（由錢包提供者出具）；沒有時改送一般證明，由發行端決定是否接受", style = MaterialTheme.typography.bodySmall)
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
                val ok = riskAcknowledgement(s.trust)
                val txOk = tx == null || (tx.length == null && txCode.isNotEmpty()) || txCode.length == tx.length
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { model.acceptOffer(s, txCode.ifEmpty { null }, selected.toList()) }, enabled = ok && txOk && selected.isNotEmpty()) {
                        Text(if (s.preAuthorized) "加入" else "前往登入")
                    }
                    OutlinedButton(onClick = { model.screen.value = Screen.Home }) { Text("取消") }
                }
            }
        }
        is IssuanceUi.Done -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            val issued = s.results.count { it is IssuanceResult.Issued }
            when {
                s.failures.isEmpty() && issued == s.results.size -> VerdictCard(Verdict.PASS, "已加入 $issued 張證件")
                issued > 0 -> VerdictCard(Verdict.CAUTION, "部分證件已加入", listOf("已加入 $issued 張，其餘未完成，原因列在下方。"))
                else -> VerdictCard(Verdict.CAUTION, "發行端尚未完成", listOf("完成後會出現在「證件」。"))
            }
            if (issued > 0) Text("點選證件可查看內容", style = MaterialTheme.typography.bodySmall)
            s.results.forEach { r ->
                when (r) {
                    is IssuanceResult.Issued -> TrustCard(
                        "已加入",
                        r.document.displayName ?: "",
                        r.trust,
                        listOf("共 ${r.credentials.size} 份可用憑證"),
                        onClick = { model.screen.value = Screen.DocumentDetail(r.document.identifier, from = Screen.Issuance) },
                    )
                    is IssuanceResult.Deferred -> Text("${r.document.displayName}：發行端尚未完成，稍後會再嘗試")
                }
            }
            s.failures.forEach { (name, reason) ->
                Text("$name：未加入（$reason）", color = MaterialTheme.colorScheme.error)
            }
            Button(onClick = { model.showTab(HomeTab.DOCUMENTS) }) { Text("完成") }
        }
    }
}

@Composable
fun PresentationScreen(model: WalletModel) {
    val state by model.presentation.collectAsState()
    when (val s = state) {
        PresentationUi.Loading -> Busy("驗證請求中")
        is PresentationUi.Working -> Busy(s.message)
        // Leaving through back() also ends a pending DC API request, returning the caller to its page.
        is PresentationUi.Failed -> Failure(s.message) { model.back() }
        is PresentationUi.Done -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(
                Verdict.PASS, "已出示",
                listOf(
                    when (val o = s.outcome) {
                        is PresentationOutcome.Posted -> if (o.redirectUri != null) "查驗方已接收，將開啟對方頁面。" else "查驗方已接收。"
                        is PresentationOutcome.DcApi -> "已回傳給呼叫的網站或 App。"
                        is PresentationOutcome.Redirect -> "已交給對方頁面。"
                    },
                    "出示的對象與欄位名稱記在「紀錄」。",
                ),
            )
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
                    req.target?.let { add("回應送往：$it") }
                    if (req.specs.isNotEmpty()) add("採用規格：" + req.specs.joinToString("、"))
                    s.offline?.let { add("臨櫃服務：${it.service.name}，出示後會顯示取貨條碼") }
                    if (req.verifierInfo.isNotEmpty()) add("對方附上 ${req.verifierInfo.size} 份身分或用途證明（將於後續版本逐項驗證）")
                    addAll(req.warnings)
                }
                TrustCard("查驗方", v.displayName, v.trust, extra)
                val settings by model.settingsFlow.collectAsState()
                var showDetails by remember(settings.showDetails) { mutableStateOf(settings.showDetails) }
                TextButton(onClick = { showDetails = !showDetails }) { Text(if (showDetails) "隱藏詳細資訊" else "顯示詳細資訊") }
                if (showDetails) DetailSections(model, CredentialDetails.request(req))
                val statusOk = requestedDocuments(model, s.items, s.risk, v.trust.tier, s)
                if (s.items.isEmpty()) Text("對方只要求確認持有者身分（不含憑證資料）", style = MaterialTheme.typography.bodyMedium)
                if (req.transactionData.isNotEmpty()) Text("此請求包含 ${req.transactionData.size} 筆交易資料，同意即代表簽署。")
                val values = remember(s) { androidx.compose.runtime.mutableStateMapOf<String, String>() }
                if (s.fields.isNotEmpty()) Text("對方要求填寫：", style = MaterialTheme.typography.titleSmall)
                s.fields.forEach { f ->
                    val value = values[f.ename].orEmpty()
                    val bad = value.isNotEmpty() && f.regex != null && runCatching { !Regex(f.regex!!).matches(value) }.getOrDefault(false)
                    OutlinedTextField(
                        value = value,
                        onValueChange = { values[f.ename] = it },
                        label = { Text(f.cname) },
                        supportingText = { Text(if (bad) "格式不符" else f.description ?: f.ename) },
                        isError = bad,
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                val fieldsOk = s.fields.all { f ->
                    val v = values[f.ename].orEmpty()
                    v.isNotEmpty() && (f.regex == null || runCatching { Regex(f.regex!!).matches(v) }.getOrDefault(true))
                }
                val ok = riskAcknowledgement(v.trust)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { model.approve(s, values.toMap()) }, enabled = ok && fieldsOk && statusOk) { Text("同意分享") }
                    OutlinedButton(onClick = { model.decline(s) }) { Text("拒絕") }
                }
            }
        }
    }
}

/**
 * The request's risk and the documents asked for, each with its status judged at that risk. A document whose status
 * the request rejects (revoked; suspended or unconfirmed for the risk) cannot be shared: there is no override, only a
 * new status query. Returns whether the user may go on. [key] identifies the request.
 */
@Composable
internal fun requestedDocuments(model: WalletModel, items: List<ConsentItem>, risk: RiskLevel, verifierTier: TrustTier, key: Any): Boolean {
    val statuses by model.statuses.collectAsState()
    val decisions = items.map { item -> item.documentId?.let { StatusPolicy.decide(statuses[it]?.status, risk) } }
    Text("這次請求的風險：" + StatusTexts.risk(risk), style = MaterialTheme.typography.titleSmall)
    Text(requestRiskReason(risk, items.maxOfOrNull { it.sensitivity } ?: RiskLevel.LOW, verifierTier), style = MaterialTheme.typography.bodySmall)
    Text("對方要求的資料：", style = MaterialTheme.typography.titleSmall)
    items.forEachIndexed { i, item ->
        Card(Modifier.fillMaxWidth()) {
            Box(Modifier.padding(12.dp)) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(item.documentName, style = MaterialTheme.typography.titleMedium)
                    decisions[i]?.let { RequestStatusLine(it) }
                    item.claims.forEach { Text("・$it", style = MaterialTheme.typography.bodyMedium) }
                }
            }
        }
    }
    val rejected = decisions.filterNotNull().filter { it.verdict == StatusVerdict.REJECT }
    val checking by model.status.checking.collectAsState()
    if (rejected.isNotEmpty()) {
        VerdictCard(Verdict.FAIL, "證件狀態不符合這次請求，無法出示", rejected.map { d -> statusWarning(d.finding, risk) }.distinct())
        // Unconfirmed states may clear with a fresh query; a revocation never does.
        if (rejected.any { it.finding != StatusFinding.REVOKED }) {
            val ids = items.mapIndexedNotNull { i, item -> item.documentId.takeIf { decisions[i]?.verdict == StatusVerdict.REJECT } }
            val busy = ids.any { it in checking }
            OutlinedButton(onClick = {
                model.documents.value.filter { it.identifier in ids }.forEach { model.checkStatus(it) }
            }, enabled = !busy) { Text(if (busy) "查詢中" else "重新查詢狀態") }
        }
    } else if (decisions.any { it?.verdict == StatusVerdict.CAUTION }) {
        Text("部分證件的狀態無法完全確認，對方可能另行查證。", style = MaterialTheme.typography.bodySmall)
    }
    return rejected.isEmpty()
}

/** Why a request has its risk: the most sensitive field asked for, or a verifier that is not on an official list. */
private fun requestRiskReason(risk: RiskLevel, fields: RiskLevel, verifier: TrustTier): String = when {
    risk == RiskLevel.LOW -> "官方信任清單內的查驗方，只要求一般欄位。"
    fields == risk && fields == RiskLevel.HIGH -> "要求身分證號、照片、地址等高敏感欄位，證件狀態必須在線上確認有效。"
    fields == risk -> "要求姓名、出生日期等個人資料。"
    verifier == TrustTier.T4 -> "查驗方身分無法驗證。"
    else -> "查驗方不在官方信任清單。"
}

private fun statusWarning(f: StatusFinding, risk: RiskLevel): String = when (f) {
    StatusFinding.REVOKED -> "證件已被發行端撤銷，不能再出示。"
    StatusFinding.SUSPENDED -> "證件目前暫停使用，恢復前不能出示。"
    else -> "證件${StatusTexts.finding(f)}；${StatusTexts.risk(risk)}的請求需要線上確認有效的狀態，請連線後重新查詢。"
}
