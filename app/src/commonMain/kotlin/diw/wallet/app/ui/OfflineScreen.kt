package diw.wallet.app.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import diw.wallet.app.BondsCardKind
import diw.wallet.app.HomeTab
import diw.wallet.app.Screen
import diw.wallet.app.OfflineUi
import diw.wallet.app.StatusTexts
import diw.wallet.app.WalletModel
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.x509.displaySubject
import diw.wallet.core.status.StatusVerdict
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.util.QrEncoder
import kotlinx.coroutines.delay
import kotlin.time.Clock
import kotlin.time.Instant

/** Seconds left until [until], refreshed every second. */
@Composable
private fun secondsLeft(until: Instant): Long {
    var left by remember(until) { mutableStateOf((until - Clock.System.now()).inWholeSeconds) }
    LaunchedEffect(until) {
        while (left > 0) {
            delay(1000)
            left = (until - Clock.System.now()).inWholeSeconds
        }
    }
    return left.coerceAtLeast(0)
}

private fun mmss(s: Long) = "${s / 60}:${(s % 60).toString().padStart(2, '0')}"

/**
 * Codes shown at a counter or to a verifier, and the Bonds verifier flow. [readQr] reads one code with the camera,
 * or from a picture where [hasCamera] is false.
 */
@Composable
fun OfflineScreen(model: WalletModel, readQr: suspend () -> String?, hasCamera: Boolean) {
    val state by model.taiwan.offline.collectAsState()
    when (val s = state) {
        is OfflineUi.Working -> Busy(s.message.ifEmpty { "處理中" })
        is OfflineUi.Failed -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.FAIL, "無法完成", listOf(s.message))
            Button(onClick = { model.back() }) { Text("返回") }
        }
        is OfflineUi.Unlisted -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.FAIL, "查驗模組不在信任清單", listOf(s.message, "如果這是你自己架設或熟悉的測試環境，可以確認風險後繼續；出示前仍會顯示同意畫面。"))
            if (riskOverride(s.service.vpUid, "仍要繼續（自行承擔風險）", "向未列名的查驗模組出示",
                    listOf("${s.service.name} 的查驗模組沒有列在數位憑證皮夾信任清單，或未在區塊鏈上註冊。", "對方可能不是它宣稱的機構，出示的資料可能被濫用。"))) {
                Button(onClick = { model.taiwan.startPickup(s.service, allowUnlisted = true) }) { Text("繼續建立交易") }
            }
            TextButton(onClick = { model.back() }) { Text("返回") }
        }
        is OfflineUi.Barcode -> BarcodeView(model, s)
        is OfflineUi.BondsChoose -> BondsChooseView(model, s)
        is OfflineUi.AgeChoose -> BondsAgeChooseView(model, s)
        is OfflineUi.AgeWorking -> BondsAgeWorkingView(model, s)
        is OfflineUi.AgeResult -> BondsAgeResultView(model, s)
        is OfflineUi.AgeVerifierWaiting -> BondsAgeVerifierWaitingView(model, s)
        is OfflineUi.AgeVerifierResult -> BondsAgeVerifierResultView(model, s)
        is OfflineUi.BondsFrames -> BondsFramesView(model, s)
        is OfflineUi.VerifierChallenge -> VerifierChallengeView(model, s, readQr, hasCamera)
        is OfflineUi.VerifierResult -> VerifierResultView(model, s)
    }
}

@Composable
private fun BarcodeView(model: WalletModel, s: OfflineUi.Barcode) {
    val left = secondsLeft(s.expiresAt)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        Text(s.serviceName, style = MaterialTheme.typography.titleLarge)
        Text("請出示給店員掃描", style = MaterialTheme.typography.bodyMedium)
        if (s.image != null && left > 0) {
            Image(s.image, contentDescription = "取貨條碼", contentScale = ContentScale.FillWidth, modifier = Modifier.fillMaxWidth().widthIn(max = 480.dp))
        } else if (s.image == null) {
            Text("條碼影像無法顯示", color = MaterialTheme.colorScheme.error)
        }
        Text(if (left > 0) "有效時間剩餘 ${mmss(left)}" else "條碼已過期，請重新出示", style = MaterialTheme.typography.titleMedium,
            color = if (left > 30) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        Text("條碼由服務方系統產生並加密，錢包只負責證明您持有這張憑證。", style = MaterialTheme.typography.bodySmall)
        Button(onClick = { model.back() }) { Text("完成") }
    }
}

@Composable
private fun BondsChooseView(model: WalletModel, s: OfflineUi.BondsChoose) {
    var cardIndex by remember(s) { mutableStateOf(0) }
    val card = s.cards[cardIndex]
    var chosen by remember(s, cardIndex) { mutableStateOf(card.claims.map { it.first }.toSet()) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("查驗方要求出示", style = MaterialTheme.typography.titleMedium)
                Text("用途：${s.request.purpose}")
                s.request.audience?.let { Text("查驗方：$it") }
                Text("挑戰建立時間：${s.request.createdAt}", style = MaterialTheme.typography.bodySmall)
                Text("Bonds 的查驗挑戰沒有查驗方簽章，無法確認對方身分；請確認用途與眼前的對象相符再出示。",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
        }
        Text("選擇憑證", style = MaterialTheme.typography.titleSmall)
        s.cards.forEachIndexed { i, c ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = i == cardIndex, onClick = { cardIndex = i })
                Column {
                    Text(c.name)
                    Text(bondsKindLabel(c.kind), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Text("要出示的欄位", style = MaterialTheme.typography.titleSmall)
        val record = card.document?.issuanceRecord
        if (!card.selective) {
            Text("這張證件不支援選擇性揭露，會出示下列全部欄位。", style = MaterialTheme.typography.bodySmall)
        }
        card.claims.forEach { (name, value) ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                val locked = card.kind == BondsCardKind.MOICA && name in BondsOfflinePresentation.CLAIMS_ALWAYS_DISCLOSED
                if (card.selective) Checkbox(checked = locked || name in chosen, enabled = !locked, onCheckedChange = { on -> chosen = if (on) chosen + name else chosen - name })
                Column(if (card.selective) Modifier else Modifier.padding(start = 12.dp)) {
                    Text(model.claimLabel(name.split('.'), null, record), style = MaterialTheme.typography.bodyMedium)
                    Text(value, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.taiwan.presentBonds(s.request, card, chosen) }) { Text("出示") }
            OutlinedButton(onClick = { model.back() }) { Text("取消") }
        }
    }
}

private fun bondsKindLabel(kind: BondsCardKind): String = when (kind) {
    BondsCardKind.W3C_SD_JWT -> "W3C VC（SD-JWT），可選擇欄位"
    BondsCardKind.SD_JWT_VC -> "SD-JWT VC，可選擇欄位"
    BondsCardKind.JWT_VC -> "W3C VC（JWT），出示全部欄位"
    BondsCardKind.MOICA -> "自然人憑證簽署（vc+moica），姓名一定揭露"
}

/** What a verifier's challenge accepts, in the holder's and the verifier's words. */
internal fun bondsSourceLabel(source: BondsCredentialSource): String = when (source) {
    BondsCredentialSource.TWDIW -> "政府皮夾卡片（與 Bonds 相容）"
    BondsCredentialSource.ANY -> "任何綁定金鑰的證件（SD-JWT VC、W3C VC）"
    BondsCredentialSource.SELF_ISSUED -> "自然人憑證自發卡片"
}

@Composable
private fun BondsFramesView(model: WalletModel, s: OfflineUi.BondsFrames) {
    var index by remember(s.frames) { mutableStateOf(0) }
    var paused by remember(s.frames) { mutableStateOf(false) }
    val left = secondsLeft(s.expiresAt)
    LaunchedEffect(s.frames, paused) {
        while (!paused && s.frames.size > 1) {
            delay(FRAME_INTERVAL_MS)
            index = (index + 1) % s.frames.size
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        Text("請讓查驗方掃描", style = MaterialTheme.typography.titleMedium)
        Text("用途：${s.request.purpose}", style = MaterialTheme.typography.bodyMedium)
        if (left > 0) {
            QrImage(s.frames[index], Modifier.fillMaxWidth().widthIn(max = 420.dp), QrEncoder.Ecc.Q)
            Text("第 ${index + 1} / ${s.frames.size} 張　剩餘 ${mmss(left)}", style = MaterialTheme.typography.bodySmall)
            if (s.frames.size > 1) OutlinedButton(onClick = { paused = !paused }) { Text(if (paused) "繼續輪播" else "暫停輪播") }
        } else {
            Text("出示已逾時（5 分鐘），請請對方重新產生挑戰。", color = MaterialTheme.colorScheme.error)
        }
        val link = model.platform.bondsLink
        if (s.request.linkServiceId != null && link != null && left > 0) {
            OutlinedButton(onClick = { model.taiwan.sendOverLink(s) }) {
                Icon(WalletIcons.Bluetooth, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(" 改用藍牙傳送")
            }
        }
        s.link?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        Text("出示內容以本機的持有者金鑰簽章，綁定查驗方的挑戰與用途，無法轉用於其他查驗。", style = MaterialTheme.typography.bodySmall)
        Button(onClick = { model.back() }) { Text("完成") }
    }
}

@Composable
private fun VerifierChallengeView(model: WalletModel, s: OfflineUi.VerifierChallenge, readQr: suspend () -> String?, hasCamera: Boolean) {
    var scanning by remember { mutableStateOf(false) }
    var pasted by remember { mutableStateOf("") }
    LaunchedEffect(scanning) {
        if (scanning) {
            // With the camera, one scan per frame until the presentation is complete or the user closes the scanner;
            // a picture holds one frame per pick.
            do {
                val text = readQr() ?: break
                model.handleUri(text)
            } while (hasCamera && model.taiwan.verifying)
            scanning = false
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        Text("請出示者用錢包或 Bonds 掃描", style = MaterialTheme.typography.titleMedium)
        QrImage(s.request.encode(), Modifier.fillMaxWidth().widthIn(max = 360.dp))
        Text("用途：${s.request.purpose}（${StatusTexts.risk(s.risk)}）", style = MaterialTheme.typography.bodyMedium)
        Text("接受：" + bondsSourceLabel(s.request.source), style = MaterialTheme.typography.bodySmall)
        if (s.request.source == BondsCredentialSource.ANY) {
            Text("這是本錢包的擴充格式，請對方使用本錢包出示；Bonds App 只能出示政府皮夾卡片。", style = MaterialTheme.typography.bodySmall)
        }
        s.request.audience?.let { Text("查驗方：$it", style = MaterialTheme.typography.bodyMedium) }
        if (s.total > 0) {
            LinearProgressIndicator(progress = { s.received.toFloat() / s.total }, modifier = Modifier.fillMaxWidth())
            Text("已收到 ${s.received} / ${s.total} 張畫面", style = MaterialTheme.typography.bodySmall)
        }
        Button(onClick = { scanning = true }, enabled = !scanning) {
            Icon(if (hasCamera) WalletIcons.Scan else WalletIcons.Image, contentDescription = null, modifier = Modifier.size(18.dp))
            Text(if (hasCamera) " 掃描對方畫面" else " 從圖片讀取對方畫面")
        }
        if (!hasCamera) {
            OutlinedTextField(value = pasted, onValueChange = { pasted = it.trim() }, label = { Text("貼上對方畫面的內容（BTWVP1:...）") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedButton(onClick = { model.handleUri(pasted); pasted = "" }, enabled = pasted.isNotEmpty()) { Text("加入") }
        }
        OutlinedButton(onClick = { model.back() }) { Text("取消") }
    }
}

@Composable
private fun VerifierResultView(model: WalletModel, s: OfflineUi.VerifierResult) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        val r = s.result
        if (r == null) {
            VerdictCard(Verdict.FAIL, "查驗未通過", listOf(s.error ?: "出示內容無法驗證"))
        } else {
            val official = s.issuerTrust?.tier == TrustTier.T1 || s.issuerTrust?.tier == TrustTier.T2
            val test = s.issuerTrust?.environment == TrustEnvironment.TEST
            val status = s.statusDecision
            val statusLine = status?.let { StatusTexts.summary(it) + "。" + StatusTexts.explain(it.finding) }
            val issuerLine = (if (official && !test) "簽章與這次的挑戰相符。" else "") + issuerTrustLine(s.issuerTrust)
            when {
                status?.verdict == StatusVerdict.REJECT -> VerdictCard(
                    Verdict.FAIL, "查驗未通過：證件狀態不符",
                    listOfNotNull(statusLine, "用途風險為${StatusTexts.risk(s.risk)}，" + StatusTexts.verdict(StatusVerdict.REJECT) + "這張證件。", issuerLine),
                )
                s.risk == RiskLevel.HIGH && (!official || test) -> VerdictCard(
                    Verdict.FAIL, "查驗未通過：發行端無法確認",
                    listOfNotNull(issuerLine, "高風險用途只接受官方信任清單（T1）或政府憑證確認身分（T2）的發行端。", statusLine),
                )
                official && !test && status?.verdict != StatusVerdict.CAUTION -> VerdictCard(
                    Verdict.PASS, "查驗通過", listOfNotNull(issuerLine, statusLine),
                )
                official && !test -> VerdictCard(Verdict.CAUTION, "簽章相符，證件狀態需留意", listOfNotNull(issuerLine, statusLine))
                else -> VerdictCard(
                    Verdict.CAUTION, "簽章相符，發行端無法確認",
                    listOfNotNull("出示者的簽章與這次的挑戰相符。", issuerLine, statusLine),
                )
            }
            Text("用途：${s.request.purpose}（${StatusTexts.risk(s.risk)}）")
            specStatus(s.status)?.let { Text("規格狀態值：$it", style = MaterialTheme.typography.bodySmall) }
            Text("出示時間：${r.created}", style = MaterialTheme.typography.bodySmall)
            Text("出示者：${r.holder}", style = MaterialTheme.typography.bodySmall)
            val issuer = r.moica?.let { "自然人憑證持有人 ${it.cardholderName}（憑證序號 ${it.certificateSerialHex}）" } ?: r.issuer ?: "未知"
            if (s.issuerTrust != null) TrustCard("發行端", issuer, s.issuerTrust)
            else Text("發行端：$issuer（不在任何信任來源，無法確認發行端身分）", color = tierColor(diw.wallet.core.trust.TrustTier.T3))
            Text("出示的資料", style = MaterialTheme.typography.titleSmall)
            r.credentialType?.let { LabelValue("證件類型", it, small = true) }
            r.issuerChain?.let { chain ->
                LabelValue("發行端憑證", chain.first().displaySubject(), small = true) {
                    model.screen.value = Screen.Certificate(chain, 0, Screen.Offline)
                }
            }
            r.claims.forEach { (k, v) -> LabelValue(model.claimLabel(k.split('.'), null, null), v) }
            if (r.claims.isEmpty()) Text("對方沒有揭露任何欄位", style = MaterialTheme.typography.bodySmall)
            r.moica?.let { if (it.withheldClaims > 0) Text("另有 ${it.withheldClaims} 個欄位未揭露", style = MaterialTheme.typography.bodySmall) }
            EvidenceRows(r.evidence)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.taiwan.startVerifier(s.request.purpose, s.risk, s.request.source) }) { Text("再次查驗") }
            OutlinedButton(onClick = { model.taiwan.closeOffline(); model.showTab(HomeTab.VERIFY) }) { Text("完成") }
        }
    }
}

private const val FRAME_INTERVAL_MS = 400L
