package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import diw.wallet.app.ProximityUi
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.util.QrEncoder
import diw.wallet.core.x509.displaySubject

/**
 * In-person presentation (ISO/IEC 18013-5): hold the phone to the reader, or let the reader scan a QR code. The
 * request is answered on the same consent screen as an online request, with the request's risk and each document's
 * status.
 */
@Composable
fun ProximityScreen(model: WalletModel) {
    val state by model.proximity.state.collectAsState()
    when (val s = state) {
        is ProximityUi.Ready -> ReadyView(model, s)
        is ProximityUi.Working -> Column(
            Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            CircularProgressIndicator()
            Text(s.message, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
            Text("請讓手機保持在查驗設備旁，直到完成。", style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
            OutlinedButton(onClick = { model.proximity.again() }) { Text("取消") }
        }
        is ProximityUi.Consent -> ConsentView(model, s)
        is ProximityUi.Done -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.PASS, "已出示", listOf("已將「${s.documents.joinToString("、")}」交給 ${s.verifier}。", "出示的對象與欄位名稱記在「紀錄」。"))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { model.back() }) { Text("完成") }
                OutlinedButton(onClick = { model.proximity.again() }) { Text("再出示一次") }
            }
        }
        is ProximityUi.Failed -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.FAIL, "無法完成", listOf(s.message))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { model.proximity.again() }) { Text("再試一次") }
                OutlinedButton(onClick = { model.back() }) { Text("離開") }
            }
        }
    }
}

@Composable
private fun ReadyView(model: WalletModel, s: ProximityUi.Ready) {
    val docs by model.documents.collectAsState()
    val mdocs = docs.count { it.issuanceRecord?.format == "mso_mdoc" }
    val nfcReason = remember { model.platform.nfcPresentationUnavailableReason() }
    var bleReason by remember { mutableStateOf<String?>(null) }
    // Asks for the Bluetooth permission up front: after the tap the data usually goes over Bluetooth.
    LaunchedEffect(Unit) { bleReason = model.platform.proximityTransportUnavailableReason() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(Tokens.ContainerRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(Modifier.padding(20.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(WalletIcons.Nfc, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(72.dp))
                Text("將手機靠近查驗設備", style = MaterialTheme.typography.titleLarge)
                Text("手機背面貼近讀卡機。感應後，對方要求的欄位會顯示在這支手機上，由你決定是否出示。資料依 ISO/IEC 18013-5 加密，經藍牙或 NFC 傳送。",
                    style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
                if (nfcReason == null) VerdictPill(Verdict.PASS, "NFC 感應已就緒")
                else VerdictPill(Verdict.CAUTION, nfcReason)
            }
        }
        bleReason?.let { Text("藍牙：$it。感應後的資料傳輸通常需要藍牙。", style = MaterialTheme.typography.bodySmall) }
        if (mdocs == 0) {
            Text("這支手機還沒有 mdoc 格式的證件（例如行動駕照）。近距離出示適用 mdoc 證件，其他證件請改用「掃描 QR Code」出示。",
                style = MaterialTheme.typography.bodySmall)
        }
        SectionTitle("對方沒有感應區時")
        val qr = s.qr
        if (qr == null) {
            OutlinedButton(onClick = { model.proximity.showQr() }) {
                Icon(WalletIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("　改用 QR Code")
            }
        } else {
            Text("請查驗設備掃描這個 QR Code，接著以藍牙連線。", style = MaterialTheme.typography.bodyMedium)
            QrImage(qr, Modifier.fillMaxWidth().widthIn(max = 360.dp).align(Alignment.CenterHorizontally), ecc = QrEncoder.Ecc.L)
        }
        OutlinedButton(onClick = { model.back() }) { Text("取消") }
    }
}

@Composable
private fun ConsentView(model: WalletModel, s: ProximityUi.Consent) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        val extra = buildList {
            add("出示方式：${s.channel.title}（${s.channel.spec}）")
            if (s.chain.isEmpty()) add("對方沒有提供身分憑證（reader authentication），無法確認是誰在讀取。")
            if (s.retained.isNotEmpty()) add("對方表示會保存：" + s.retained.joinToString("、"))
        }
        TrustCard(if (s.channel == diw.wallet.app.ProximityChannel.DC_API) "查驗方" else "查驗設備", s.verifier, s.trust, extra)
        if (s.chain.isNotEmpty()) {
            LabelValue("查驗設備憑證", s.chain.first().displaySubject(), small = true) {
                model.screen.value = Screen.Certificate(s.chain, 0, Screen.Proximity)
            }
        }
        val statusOk = requestedDocuments(model, s.items, s.risk, s.trust.tier, s)
        val ok = riskAcknowledgement(s.trust)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.proximity.approve(s) }, enabled = ok && statusOk) { Text("同意分享") }
            OutlinedButton(onClick = { model.proximity.decline(s) }) { Text("拒絕") }
        }
    }
}
