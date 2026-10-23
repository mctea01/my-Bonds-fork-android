package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import diw.wallet.app.OfflineUi
import diw.wallet.app.WalletModel
import diw.wallet.app.ZkJobPhase
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.zktls.ZkTlsOutcome
import diw.wallet.core.zktls.ZkTlsProfile
import diw.wallet.core.zktls.ZkTlsSessionRequest
import diw.wallet.core.zktls.ZkTlsTransport
import kotlinx.coroutines.delay
import kotlin.time.Clock

/** Seconds until the request expires, refreshed every second. */
@Composable
private fun secondsLeft(request: ZkTlsSessionRequest): Long {
    var left by remember(request) { mutableStateOf((request.expiresAt - Clock.System.now()).inWholeSeconds) }
    LaunchedEffect(request) {
        while (left > 0) {
            delay(1000)
            left = (request.expiresAt - Clock.System.now()).inWholeSeconds
        }
    }
    return left.coerceAtLeast(0)
}

private fun clock(s: Long) = "${s / 60}:${(s % 60).toString().padStart(2, '0')}"

private fun site(profile: ZkTlsProfile): String = profile.host + if (profile.port == 443) "" else ":${profile.port}"

/** The page and what it reveals: the status and the requested fields, never the inputs or the rest of the page. */
@Composable
private fun PageCard(profile: ZkTlsProfile, fields: List<String>, test: Boolean) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(profile.title, style = MaterialTheme.typography.titleMedium)
            Text("網站：https://${site(profile)}${profile.request.path}" + if (profile.official) "（政府網站）" else "", style = MaterialTheme.typography.bodySmall)
            Text("揭露：查詢狀態、" + fields.mapNotNull { profile.field(it)?.label }.joinToString("、"), style = MaterialTheme.typography.bodyMedium)
            if (profile.request.inputs.isNotEmpty()) {
                Text("不揭露：" + profile.request.inputs.joinToString("、") { it.label } + "、網址的查詢參數、Cookie 與頁面其他內容",
                    style = MaterialTheme.typography.bodySmall)
            }
            if (test) Text("這個查驗頁隨請求附上，不在已安裝的版型中，只在測試環境接受。", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
internal fun ZkTlsConsentView(model: WalletModel, s: OfflineUi.ZkTlsConsent) {
    val request = s.session.request
    val inputs = remember(s.session.jws) { mutableStateMapOf<String, String>() }
    var confirm by remember(s) { mutableStateOf(false) }
    var keep by remember(s.session.jws) { mutableStateOf(false) }
    val left = secondsLeft(request)
    val complete = s.profile.request.inputs.all { !inputs[it.name].isNullOrEmpty() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        TrustCard("查驗方", s.verifier, s.trust, listOf("用途：" + request.purpose.ifEmpty { "未說明" }))
        PageCard(s.profile, request.fields, s.inline)
        Text("這支手機會直接連到網站查詢，對方在查詢過程中協同驗證連線，只看得到上面列出的部分；你填的資料留在這支手機。",
            style = MaterialTheme.typography.bodySmall)
        s.profile.request.inputs.forEach { input ->
            OutlinedTextField(
                value = inputs[input.name].orEmpty(),
                onValueChange = { inputs[input.name] = it.trim().take(200) },
                label = { Text(input.label + if (input.isPrivate) "（不揭露）" else "") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = keep, onCheckedChange = { keep = it })
            Column {
                Text("保存查詢結果到證件", style = MaterialTheme.typography.bodyMedium)
                Text("通過後把揭露的欄位存成憑證，之後可離線出示。查驗方簽發回執時存為網站查驗證明，否則存為本機紀錄（裝置證明，不是零知識證明）。",
                    style = MaterialTheme.typography.bodySmall)
            }
        }
        s.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        Text(if (left > 0) "請求剩餘 ${clock(left)}" else "請求已過期，請對方重新產生 QR Code", style = MaterialTheme.typography.bodySmall,
            color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { if (s.trust.tier == TrustTier.T4) confirm = true else model.taiwan.zkTls.prove(s, inputs.toMap(), keep) },
                enabled = left > 0 && complete,
            ) { Text("查詢並產生證明") }
            OutlinedButton(onClick = { model.back() }) { Text("取消") }
        }
    }
    if (confirm) {
        RiskConfirmDialog(
            title = "對無法驗證的查驗方出示？",
            lines = listOf("查驗方的簽章或身分驗證失敗，無法確認對方是誰。", "對方會看到網站上的查詢狀態與上面列出的欄位。"),
            confirm = "仍要出示",
            onConfirm = { confirm = false; model.taiwan.zkTls.prove(s, inputs.toMap(), keep) },
            onDismiss = { confirm = false },
        )
    }
}

@Composable
internal fun ZkTlsProvingView(model: WalletModel, s: OfflineUi.ZkTlsProving) {
    val jobs by model.zk.jobs.collectAsState()
    val job = jobs[s.jobId]
    val left = secondsLeft(s.consent.session.request)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        PageCard(s.consent.profile, s.consent.session.request.fields, s.consent.inline)
        Text(
            when {
                job?.step != null -> job.step!!
                job?.phase == ZkJobPhase.QUEUED -> "等待其他證明完成"
                else -> "連線到查驗方"
            },
            style = MaterialTheme.typography.titleMedium,
        )
        LinearProgressIndicator(Modifier.fillMaxWidth())
        Text("與 ${s.consent.verifier} 協同查詢 ${s.consent.profile.host}。", style = MaterialTheme.typography.bodySmall)
        Text("請求剩餘 ${clock(left)}", style = MaterialTheme.typography.bodySmall,
            color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        OutlinedButton(onClick = { model.taiwan.zkTls.cancel(s) }) { Text("取消") }
    }
}

/** The values the verifier reads back, under the page's labels. */
private fun outcomeLines(o: ZkTlsOutcome, fields: List<String>): List<String> = buildList {
    add("查詢狀態：" + (o.statusText ?: "未揭露") + if (o.found) "（找到資料）" else "")
    fields.forEach { name ->
        val label = o.profile.field(name)?.label ?: name
        add("$label：" + (o.fields[name] ?: "頁面沒有此欄位"))
    }
}

private fun serverLines(name: String, time: Long, trust: TrustDecision?): List<String> = buildList {
    add("網站：$name（憑證已在 TLS 連線時驗證）")
    if (time > 0) add("查詢時間：${localTime(time)}")
    trust?.let { add("網站憑證的信任等級：${WalletModel.tierTitle(it.tier)}" + (it.anchorName?.let { a -> "（$a）" } ?: "")) }
}

@Composable
internal fun ZkTlsHolderResultView(model: WalletModel, s: OfflineUi.ZkTlsHolderResult) {
    val proved = s.proved
    val fields = s.consent.session.request.fields
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            proved == null -> VerdictCard(Verdict.FAIL, "沒有完成網站查驗", listOfNotNull(s.error))
            proved.outcome.passed -> VerdictCard(Verdict.PASS, "已向 ${s.consent.verifier} 證明查詢結果", listOf("對方只看到下面列出的內容。"))
            else -> VerdictCard(Verdict.CAUTION, "證明已送出，但對方的判定未通過", proved.outcome.problems.ifEmpty { listOf("頁面沒有找到資料或缺少欄位。") })
        }
        if (proved != null) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("對方看到的內容", style = MaterialTheme.typography.titleSmall)
                    outcomeLines(proved.outcome, fields).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    serverLines(proved.serverName, proved.time, s.serverTrust).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            }
            s.kept?.let { k ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(if (k.receipt) "已保存網站查驗證明" else "已保存本機紀錄", style = MaterialTheme.typography.titleSmall)
                        Text(
                            if (k.receipt) "由 ${s.consent.verifier} 簽發，只含上面揭露的欄位，可在「證件」出示。"
                            else "由這個錢包簽署，說明這台裝置讀到的內容；這是裝置證明，不是零知識證明。可在「證件」出示。",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        k.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
                    }
                }
            }
            s.keepError?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            TechDetails(listOf(
                "傳輸：" + when (val t = proved.transport) {
                    is ZkTlsTransport.Lan -> "區網 ${t.host}:${t.port}"
                    is ZkTlsTransport.Relay -> "中繼 ${t.url}"
                    is ZkTlsTransport.Wss -> "查驗主機 ${t.url}"
                },
                "TLS 加密套件：${proved.cipherSuite}",
                "網站憑證鏈：${proved.certChainDer.size} 張",
                "揭露的回應位元組：" + proved.plan.received.joinToString(", ") { "${it.start}-${it.end}" },
            ), "zktls-holder-${s.consent.session.request.sessionId}")
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (s.retry) Button(onClick = { model.taiwan.offline.value = s.consent }) { Text("重試") }
            OutlinedButton(onClick = { model.back() }) { Text("完成") }
        }
    }
}

@Composable
internal fun ZkTlsVerifierSetupView(model: WalletModel, s: OfflineUi.ZkTlsVerifierSetup) {
    var index by remember(s) { mutableStateOf(0) }
    val page = s.pages.getOrNull(index)
    val chosen = remember(page) { mutableStateMapOf<String, Boolean>().apply { page?.fields?.forEach { put(it.name, true) } } }
    var purpose by remember { mutableStateOf("資格確認") }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("對方用自己的手機連到官方網站查詢，你只看到查詢狀態與選擇的欄位，看不到對方輸入的證號或驗證碼。",
            style = MaterialTheme.typography.bodyMedium)
        s.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        if (s.pages.isEmpty()) {
            OutlinedButton(onClick = { model.back() }) { Text("返回") }
            return@Column
        }
        Text("查驗頁", style = MaterialTheme.typography.titleSmall)
        s.pages.forEachIndexed { i, p ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = i == index, onClick = { index = i })
                Column {
                    Text(p.title + if (p.id in s.testPages) "（測試）" else "")
                    Text(site(p), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        if (page != null) {
            Text("要對方揭露的欄位", style = MaterialTheme.typography.titleSmall)
            page.fields.forEach { f ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = chosen[f.name] == true, onCheckedChange = { chosen[f.name] = it })
                    Text(f.label)
                }
            }
        }
        OutlinedTextField(value = purpose, onValueChange = { purpose = it.take(ZkTlsSessionRequest.MAX_PURPOSE) },
            label = { Text("查驗用途（會顯示給出示者）") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        val fields = page?.fields?.map { it.name }?.filter { chosen[it] == true }.orEmpty()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.taiwan.zkTls.startVerifier(page!!, fields, purpose.trim()) }, enabled = page != null && fields.isNotEmpty() && purpose.isNotBlank()) {
                Text("產生查驗 QR Code")
            }
            OutlinedButton(onClick = { model.back() }) { Text("取消") }
        }
    }
}

@Composable
internal fun ZkTlsVerifierWaitingView(model: WalletModel, s: OfflineUi.ZkTlsVerifierWaiting) {
    val left = secondsLeft(s.request)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        Text("請出示者用本錢包掃描", style = MaterialTheme.typography.titleMedium)
        QrImage(s.link, Modifier.fillMaxWidth().widthIn(max = 420.dp))
        PageCard(s.profile, s.request.fields, s.request.profileDefinition != null)
        Text(
            if (s.local) "出示者經${s.where}連到這支手機，證明在這支手機驗證。區網需在同一個 Wi-Fi 或熱點；中繼只轉送加密資料。"
            else "證明由 ${s.where} 驗證，這支手機只顯示主機的結果。",
            style = MaterialTheme.typography.bodySmall,
        )
        s.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        if (s.step != null) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(s.step, style = MaterialTheme.typography.titleSmall)
        } else {
            Text(if (left > 0) "等待出示，剩餘 ${clock(left)}" else "請求已過期", style = MaterialTheme.typography.bodySmall,
                color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        }
        TechDetails(s.details, "zktls-${s.request.sessionId}")
        OutlinedButton(onClick = { model.back() }) { Text("取消") }
    }
}

@Composable
internal fun ZkTlsVerifierResultView(model: WalletModel, s: OfflineUi.ZkTlsVerifierResult) {
    val o = s.outcome
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            o == null -> VerdictCard(Verdict.FAIL, "沒有完成網站查驗", listOfNotNull(s.error))
            o.passed && s.local -> VerdictCard(Verdict.PASS, "查驗通過：${s.profile.title}", listOf("連線與揭露的內容已在這支手機驗證。"))
            o.passed -> VerdictCard(Verdict.CAUTION, "${s.where} 回報：查驗通過", listOf("這支手機沒有驗證證明本身，結果取決於 ${s.where}。"))
            else -> VerdictCard(Verdict.FAIL, "查驗未通過", o.problems + o.missing.map { "沒有揭露 " + (s.profile.field(it)?.label ?: it) } +
                listOfNotNull("網站回應的查詢狀態是「${o.statusText}」".takeIf { o.statusText != null && !o.found }))
        }
        if (o != null) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("證據：網站查驗證明（zkTLS）", style = MaterialTheme.typography.titleSmall)
                    outcomeLines(o, s.request.fields).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    serverLines(o.serverName, o.time, s.serverTrust).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    Text("數值由出示者選擇揭露，查驗方以查驗頁的規則從網站回應中讀出。", style = MaterialTheme.typography.bodySmall)
                    if (s.receipt) Text("出示者要求保存結果，已簽發回執（網站查驗證明）給對方。", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Text("用途：${s.request.purpose.ifEmpty { "未說明" }}", style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { model.back() }) { Text("完成") }
    }
}
