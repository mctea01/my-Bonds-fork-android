package diw.wallet.app.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import diw.wallet.app.HomeTab
import diw.wallet.app.NfcReaderOption
import diw.wallet.app.ReadDocument
import diw.wallet.app.ReaderRequest
import diw.wallet.app.ReaderUi
import diw.wallet.app.Screen
import diw.wallet.app.StatusTexts
import diw.wallet.app.WalletModel
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.status.StatusVerdict
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.x509.displaySubject
import kotlin.time.Clock

/**
 * In-person verification (ISO/IEC 18013-5 mdoc reader): what to ask for, the purpose's risk and the NFC reader,
 * then the tap and the verdict for each returned document.
 */
@Composable
fun ReaderScreen(model: WalletModel) {
    val state by model.reader.state.collectAsState()
    when (val s = state) {
        ReaderUi.Setup -> SetupView(model)
        is ReaderUi.Scanning -> Column(
            Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(WalletIcons.Nfc, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(72.dp))
            CircularProgressIndicator()
            Text(s.message, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
            Text("要求：${s.request.title}（${s.request.detail}）", style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
            OutlinedButton(onClick = { model.reader.again() }) { Text("取消") }
        }
        is ReaderUi.Result -> ResultView(model, s)
        is ReaderUi.Failed -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.FAIL, "無法完成查驗", listOf(s.message))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { model.reader.again() }) { Text("再試一次") }
                OutlinedButton(onClick = { model.reader.close(); model.showTab(HomeTab.VERIFY) }) { Text("離開") }
            }
        }
    }
}

@Composable
private fun SetupView(model: WalletModel) {
    val list by model.reader.readers.collectAsState()
    var request by remember { mutableStateOf(ReaderRequest.MDL_IDENTITY) }
    var risk by remember { mutableStateOf(RiskLevel.MEDIUM) }
    var chosen by remember { mutableStateOf<String?>(null) }
    val readers = list?.readers.orEmpty()
    val selected: NfcReaderOption? = readers.firstOrNull { it.name == chosen } ?: readers.firstOrNull()
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(Tokens.ContainerRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(WalletIcons.Nfc, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                Text("感應查驗", style = MaterialTheme.typography.titleLarge)
                Text("以 NFC 讀取對方錢包裡的行動駕照等 mdoc 證件（ISO/IEC 18013-5）。簽章、資料完整性與出示者持有的金鑰都在這裡檢查，有網路時也會查詢證件狀態。這裡不保存對方的資料，紀錄只記欄位名稱。",
                    style = MaterialTheme.typography.bodyMedium)
            }
        }
        SectionTitle("要求的資料")
        ReaderRequest.entries.forEach { r ->
            Row(Modifier.fillMaxWidth().clickable { request = r }, verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = request == r, onClick = { request = r })
                Column {
                    Text(r.title, style = MaterialTheme.typography.bodyLarge)
                    Text(r.detail, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        SectionTitle("用途的風險")
        RiskSelector(risk) { risk = it }
        SectionTitle("讀卡機")
        if (list == null) {
            CircularProgressIndicator(Modifier.size(24.dp))
        } else {
            readers.forEach { r ->
                Row(Modifier.fillMaxWidth().clickable { chosen = r.name }, verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = selected?.name == r.name, onClick = { chosen = r.name })
                    Column {
                        Text(r.name, style = MaterialTheme.typography.bodyLarge)
                        Text(
                            when {
                                r.external -> "外接讀卡機，資料以 NFC 傳送"
                                r.bluetooth -> "這支手機的 NFC，感應後資料可能改經藍牙傳送"
                                else -> "這台裝置的 NFC"
                            },
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
            list?.problem?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            TextButton(onClick = { model.reader.refreshReaders() }) { Text("重新尋找讀卡機") }
        }
        Button(onClick = { selected?.let { model.reader.start(it, request, risk) } }, enabled = selected != null) {
            Icon(WalletIcons.Nfc, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("　開始感應")
        }
        Text("這個查驗方不送出身分憑證（reader authentication），對方的錢包會顯示為未提供身分的查驗設備。", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun ResultView(model: WalletModel, s: ReaderUi.Result) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (s.integrityError != null) {
            VerdictCard(Verdict.FAIL, "查驗未通過：證件無法驗證", listOf(s.integrityError, "沒有顯示對方的資料，因為內容無法確認來自發行端。"))
        }
        s.documents.forEach { d -> DocumentResult(model, d, s.risk) }
        Text("要求：${s.request.title}；用途風險：${StatusTexts.risk(s.risk)}；傳輸：${s.transport}", style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.reader.again() }) { Text("再次查驗") }
            OutlinedButton(onClick = { model.reader.close(); model.showTab(HomeTab.VERIFY) }) { Text("完成") }
        }
    }
}

/** The verdict for one document: integrity passed, so it depends on the issuer's trust and the status. */
internal fun readVerdict(d: ReadDocument, risk: RiskLevel): Triple<Verdict, String, List<String>> {
    val tier = d.issuerTrust.tier
    val test = d.issuerTrust.environment == TrustEnvironment.TEST
    val official = (tier == TrustTier.T1 || tier == TrustTier.T2) && !test
    val status = d.statusDecision
    val statusLine = StatusTexts.summary(status) + "。" + StatusTexts.explain(status.finding)
    val issuerLine = when {
        test -> "發行端只在測試環境受信任，結果不具效力。"
        tier == TrustTier.T1 -> "簽章、資料與出示者的金鑰都相符，發行端是正式信任錨點。"
        tier == TrustTier.T2 -> "簽章、資料與出示者的金鑰都相符，發行端已列名，但無法完全驗證。"
        d.issuerTrust.environment == TrustEnvironment.USER -> "簽章相符，發行端由你自行信任的錨點簽發（非官方）。"
        d.issuerTrust.environment == TrustEnvironment.SYSTEM -> "簽章相符，發行端憑證連到系統憑證庫（只確認網域，非官方身分）。"
        else -> "簽章相符，但發行端不在任何信任錨點，無法確認這張證件由誰簽發。"
    }
    return when {
        status.verdict == StatusVerdict.REJECT -> Triple(
            Verdict.FAIL, "查驗未通過：證件狀態不符",
            listOf(statusLine, "用途風險為${StatusTexts.risk(risk)}，" + StatusTexts.verdict(StatusVerdict.REJECT) + "這張證件。", issuerLine),
        )
        risk == RiskLevel.HIGH && !official -> Triple(Verdict.FAIL, "查驗未通過：發行端無法確認", listOf(issuerLine, "高風險用途只接受信任清單內的發行端。", statusLine))
        official && status.verdict == StatusVerdict.ACCEPT -> Triple(Verdict.PASS, "查驗通過", listOf(issuerLine, statusLine))
        official -> Triple(Verdict.CAUTION, "簽章相符，證件狀態需留意", listOf(issuerLine, statusLine))
        else -> Triple(Verdict.CAUTION, "簽章相符，發行端無法確認", listOf(issuerLine, statusLine))
    }
}

@Composable
private fun DocumentResult(model: WalletModel, d: ReadDocument, risk: RiskLevel) {
    val (verdict, title, caveats) = readVerdict(d, risk)
    VerdictCard(verdict, title, caveats)
    Text(d.title, style = MaterialTheme.typography.titleMedium)
    TrustCard("發行端", d.issuer, d.issuerTrust)
    if (d.chain.isNotEmpty()) {
        LabelValue("發行端憑證", d.chain.first().displaySubject(), small = true) {
            model.screen.value = Screen.Certificate(d.chain, 0, Screen.Reader)
        }
    }
    val now = Clock.System.now()
    LabelValue("有效期間", localTime(d.validFrom) + " 至 " + localTime(d.validUntil) + if (d.validUntil < now) "（已過期）" else "", small = true)
    LabelValue("簽發時間", localTime(d.signedAt), small = true)
    specStatus(d.status)?.let { LabelValue("規格狀態值", it, small = true) }
    SectionTitle("對方提供的資料")
    d.claims.filter { it.picture != null }.forEach { c ->
        val image = remember(c) { c.picture?.let { model.platform.decodeImage(it) } }
        if (image != null) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(c.label, style = MaterialTheme.typography.bodySmall)
                Image(image, contentDescription = c.label, contentScale = ContentScale.Fit,
                    modifier = Modifier.size(160.dp).clip(RoundedCornerShape(Tokens.CardRadius)))
            }
        }
    }
    d.claims.filter { it.picture == null }.forEach { c -> LabelValue(c.label, c.value) }
    if (d.claims.isEmpty()) Text("對方沒有揭露任何欄位", style = MaterialTheme.typography.bodySmall)
    if (d.withheld.isNotEmpty()) Text("對方未提供：" + d.withheld.joinToString("、"), style = MaterialTheme.typography.bodySmall)
}
