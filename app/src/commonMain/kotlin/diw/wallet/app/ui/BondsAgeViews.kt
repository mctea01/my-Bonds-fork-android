package diw.wallet.app.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import diw.wallet.app.BondsAgeFlow
import diw.wallet.app.BondsAgeVerifierFlow
import diw.wallet.app.OfflineUi
import diw.wallet.app.QrScanStep
import diw.wallet.app.WalletModel
import diw.wallet.app.ZkChoiceKind
import diw.wallet.app.ZkJobPhase
import diw.wallet.app.ZkProofKind
import diw.wallet.core.profile.bonds.AnimatedQrTransport
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.util.QrEncoder
import kotlinx.coroutines.delay
import kotlin.time.Clock

/** Seconds until the request expires, refreshed every second. */
@Composable
private fun requestSecondsLeft(request: BondsAgeRequest): Long {
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

@Composable
private fun AgeRequestCard(request: BondsAgeRequest, known: Boolean = request.knownHost) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("${if (request.lan) "區網查驗方 " + request.responseHost else request.responseHost ?: BondsAgeFlow.NEARBY} 要求證明你年滿 ${request.minimumAge} 歲",
                style = MaterialTheme.typography.titleMedium)
            if (request.purpose.isNotEmpty()) Text("用途：${request.purpose}")
            Text(
                when {
                    request.nearby && request.qr -> "送出方式：藍牙或動態 QR Code，直接傳到對方的手機，不經任何伺服器"
                    request.nearby -> "送出方式：藍牙，直接傳到對方的手機，不經任何伺服器"
                    request.lan -> "送出方式：區網（同一個 Wi-Fi 或熱點），直接傳到對方的手機。未加密，同一網路上的裝置可看到證明，但其中沒有出生日期。"
                    else -> "送出位置：${request.responseUrl}"
                },
                style = MaterialTheme.typography.bodySmall,
            )
            if (!known && !request.nearby && !request.lan) {
                Text("這個網站不在 Bonds 的查驗方清單，無法確認對方是誰。", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
internal fun BondsAgeChooseView(model: WalletModel, s: OfflineUi.AgeChoose) {
    var index by remember(s) { mutableStateOf(0) }
    var stage by remember(s) { mutableStateOf(0) }
    val card = s.cards[index.coerceAtMost(s.cards.lastIndex)]
    val left = requestSecondsLeft(s.request)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        AgeRequestCard(s.request, s.known)
        Text("只會送出零知識證明：證明出生日期不晚於 ${s.request.cutoff}。出生日期、姓名與卡片其他欄位都不會離開這台裝置。",
            style = MaterialTheme.typography.bodyMedium)
        Text(
            if (s.request.source == BondsCredentialSource.SELF_ISSUED) "這是自我聲明：證明由你自己的卡片金鑰簽署，查驗方會看到這把金鑰的 DID（每張卡固定）。"
            else "查驗方會看到發證機關的 DID，用來確認卡片由誰發行。",
            style = MaterialTheme.typography.bodySmall,
        )
        Text(if (left > 0) "請求剩餘 ${clock(left)}" else "請求已過期，請對方重新產生 QR Code", style = MaterialTheme.typography.bodySmall,
            color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        Text("選擇卡片", style = MaterialTheme.typography.titleSmall)
        s.cards.forEachIndexed { i, c ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = i == index, onClick = { index = i })
                Column {
                    Text(c.name)
                    Text("以出生日期欄位（${c.claim}）證明", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { stage = if (s.known) 2 else 1 }, enabled = left > 0) { Text("產生並送出證明") }
            OutlinedButton(onClick = { model.back() }) { Text("取消") }
        }
    }
    when (stage) {
        1 -> RiskConfirmDialog(
            title = "送到不在清單的網站？",
            lines = listOf(
                "${s.request.responseHost} 不在 Bonds 的查驗方清單，Bonds 本身會拒絕送出。",
                "對方會收到年齡證明與發證機關（或你的卡片金鑰）的 DID，可能用來追蹤你的出示紀錄。",
            ),
            confirm = "仍要送出",
            onConfirm = { stage = 2 },
            onDismiss = { stage = 0 },
        )
        2 -> ZkProofGate(
            zk = model.zk,
            kind = ZkProofKind.AGE,
            onDecision = { choice, extended ->
                stage = 0
                if (choice == ZkChoiceKind.ON_DEVICE) model.taiwan.age.prove(s.request, card, extended)
                else model.message.value = "請在電腦版錢包加入同一張卡片後，掃描查驗方的 QR Code 回應。"
            },
            onDismiss = { stage = 0 },
        )
    }
}

@Composable
internal fun BondsAgeWorkingView(model: WalletModel, s: OfflineUi.AgeWorking) {
    val jobs by model.zk.jobs.collectAsState()
    val job = jobs[s.jobId]
    val left = requestSecondsLeft(s.request)
    val qr = s.qr
    if (qr != null) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp),
            horizontalAlignment = Alignment.CenterHorizontally) {
            Text("請對方用本錢包掃描這個動態 QR Code", style = MaterialTheme.typography.titleMedium)
            AnimatedQr(qr, Modifier.fillMaxWidth().widthIn(max = 420.dp))
            Text("畫面會持續變換，對方漏掉幾張也沒關係，掃到足夠的畫面就會完成。對方的手機靠近時也會改用藍牙直接傳送。",
                style = MaterialTheme.typography.bodySmall)
            s.link?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            Text("只含年齡證明，沒有出生日期或其他欄位。請求剩餘 ${clock(left)}", style = MaterialTheme.typography.bodySmall,
                color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
            Button(onClick = { model.taiwan.age.qrDone() }) { Text("對方已掃描完成") }
        }
        return
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        AgeRequestCard(s.request)
        Text(
            when {
                s.sending && s.request.nearby -> s.link ?: "等待對方的手機以藍牙連線"
                s.sending -> "正在送出到 ${s.request.responseHost}"
                job?.step != null -> job.step!!
                job?.phase == ZkJobPhase.QUEUED -> "等待其他證明完成"
                else -> "準備中"
            },
            style = MaterialTheme.typography.titleMedium,
        )
        LinearProgressIndicator(Modifier.fillMaxWidth())
        Text("以 ${s.card.name} 產生。證明在這台裝置產生並先驗證，通過才會送出。", style = MaterialTheme.typography.bodySmall)
        Text("請求剩餘 ${clock(left)}", style = MaterialTheme.typography.bodySmall,
            color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        if (!s.sending) OutlinedButton(onClick = { model.taiwan.age.cancel(s) }) { Text("取消") }
    }
}

/** Cycles through the fountain frames; any [AnimatedQrTransport.Encoder.count] plus a few of them rebuild the payload. */
@Composable
private fun AnimatedQr(encoder: AnimatedQrTransport.Encoder, modifier: Modifier) {
    var seed by remember(encoder) { mutableStateOf(0) }
    LaunchedEffect(encoder) {
        while (true) {
            delay(QR_FRAME_MS)
            seed++
        }
    }
    val frame = remember(encoder, seed) { encoder.frame(seed) }
    // Low error correction keeps each frame small enough to scan quickly; a missed frame costs nothing.
    QrImage(frame, modifier, QrEncoder.Ecc.L)
}

private const val QR_FRAME_MS = 150L

@Composable
internal fun BondsAgeResultView(model: WalletModel, s: OfflineUi.AgeResult) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        VerdictCard(if (s.accepted) Verdict.PASS else Verdict.FAIL, s.title, s.lines)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (s.retry && s.request.isFresh(Clock.System.now())) {
                Button(onClick = { model.taiwan.age.prove(s.request, s.card, false) }) { Text("重試") }
            }
            OutlinedButton(onClick = { model.back() }) { Text("完成") }
        }
    }
}

@Composable
internal fun BondsAgeVerifierWaitingView(
    model: WalletModel,
    s: OfflineUi.AgeVerifierWaiting,
    streamQr: (suspend (onCode: (String) -> QrScanStep) -> Unit)?,
) {
    val left = requestSecondsLeft(s.request)
    var scanning by remember { mutableStateOf(false) }
    LaunchedEffect(scanning) {
        if (scanning && streamQr != null) {
            streamQr { model.taiwan.ageVerifier.acceptFrame(it) }
            scanning = false
        }
    }
    val qrOnly = s.host == BondsAgeVerifierFlow.ANIMATED_QR
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        Text(if (s.request.nearby && !qrOnly) "請出示者用本錢包或 Bonds App 掃描" else "請出示者用本錢包掃描", style = MaterialTheme.typography.titleMedium)
        QrImage(s.request.encode(), Modifier.fillMaxWidth().widthIn(max = 360.dp))
        Text("證明年滿 ${s.request.minimumAge} 歲（出生日期不晚於 ${s.request.cutoff}）", style = MaterialTheme.typography.bodyLarge)
        Text("接受：" + bondsSourceLabel(s.request.source) + "・用途：" + s.request.purpose.ifEmpty { "未說明" }, style = MaterialTheme.typography.bodySmall)
        Text(
            when {
                qrOnly -> "出示者的手機產生證明後會顯示動態 QR Code，按下方按鈕持續掃描到完成，在這支手機驗證，不需要網路或藍牙。"
                s.request.nearby -> "出示者的手機產生證明後，以藍牙直接傳到這支手機驗證，不經任何伺服器。請讓兩支手機保持靠近並開著藍牙；藍牙連不上時，可改掃描出示者的動態 QR Code。"
                s.request.lan -> "出示者的手機產生證明後，經 ${s.host} 直接傳到這支手機驗證，不經網際網路。出示者的手機需連在同一個 Wi-Fi 或這支手機的熱點。"
                s.relay -> "證明送到 ${s.host} 後轉給這支手機驗證，主機只轉送。"
                else -> "證明由 ${s.host} 驗證，這支手機只顯示主機的結果。"
            },
            style = MaterialTheme.typography.bodySmall,
        )
        s.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        if (!s.request.nearby) Text("Bonds App 只會把證明送到 Bonds 的查驗網站，出示者需使用本錢包。", style = MaterialTheme.typography.bodySmall)
        if (s.checking) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(if (s.relay) "已收到證明，正在這支手機驗證" else "已收到證明，等待 ${s.host} 的結果", style = MaterialTheme.typography.titleSmall)
        } else {
            Text(if (left > 0) "等待出示，剩餘 ${clock(left)}" else "請求已過期，等待最後的回應", style = MaterialTheme.typography.bodySmall,
                color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        }
        s.link?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        s.scanned?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        if (s.request.qr && !s.checking) {
            if (streamQr != null) Button(onClick = { scanning = true }, enabled = !scanning) { Text("掃描出示者的動態 QR Code") }
            else Text("這個裝置沒有相機，無法掃描動態 QR Code。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        OutlinedButton(onClick = { model.back() }) { Text("取消") }
    }
}

@Composable
internal fun BondsAgeVerifierResultView(model: WalletModel, s: OfflineUi.AgeVerifierResult) {
    val v = s.verification
    val age = s.request.minimumAge
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            v != null && !v.proofValid -> VerdictCard(Verdict.FAIL, "查驗未通過", listOfNotNull(v.reason))
            v != null && v.selfIssued -> VerdictCard(Verdict.CAUTION, "證明有效：年滿 $age 歲（自發卡）",
                listOf("出示者以自己的卡片金鑰簽署出生日期再證明，不是政府背書；Bonds 也如此標示。"))
            v != null && v.accepted -> VerdictCard(Verdict.PASS, "查驗通過：年滿 $age 歲", listOf(issuerTrustLine(v.issuerTrust)))
            v != null -> VerdictCard(Verdict.CAUTION, "證明有效，發卡者無法確認", listOfNotNull(v.reason, issuerTrustLine(v.issuerTrust)))
            s.remote != null -> VerdictCard(
                if (s.remote.accepted) Verdict.CAUTION else Verdict.FAIL,
                if (s.remote.accepted) "${s.host} 回報：年滿 $age 歲" else "${s.host} 回報：未通過",
                listOfNotNull(s.remote.reason, "這支手機沒有驗證證明本身，結果取決於 ${s.host}。"),
            )
            else -> VerdictCard(Verdict.FAIL, "沒有完成查驗", listOfNotNull(s.error))
        }
        if (v != null && v.proofValid) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("證據：零知識證明", style = MaterialTheme.typography.titleSmall)
                    BondsAgeVerifierFlow.summary(v).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    Text("發卡者：${v.issuerDid}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Text("用途：${s.request.purpose.ifEmpty { "未說明" }}", style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { model.back() }) { Text("完成") }
    }
}

/** How the holder's proof reaches the verifying phone. */
private enum class AgeRoute(val label: String) {
    BLUETOOTH("藍牙"),
    QR("動態 QR"),
    LAN("區網"),
    HOST("查驗主機"),
}

/**
 * The Verify tab's age check: how the proof arrives, minimum age, accepted cards and purpose, then the request QR.
 * The animated QR route needs a camera that keeps scanning ([canScanFrames]).
 */
@Composable
internal fun BondsAgeVerifierSetup(model: WalletModel, canScanFrames: Boolean) {
    var ageText by remember { mutableStateOf("18") }
    var source by remember { mutableStateOf(BondsCredentialSource.TWDIW) }
    var purpose by remember { mutableStateOf("年齡確認") }
    val host = model.taiwan.ageVerifier.host()
    val available = mapOf(
        AgeRoute.BLUETOOTH to (model.platform.bondsLinkCentral != null),
        AgeRoute.QR to canScanFrames,
        AgeRoute.LAN to (model.platform.bondsLan != null),
        AgeRoute.HOST to (host != null),
    )
    var route by remember { mutableStateOf(AgeRoute.entries.firstOrNull { available[it] == true } ?: AgeRoute.HOST) }
    val age = ageText.toIntOrNull()?.takeIf { it in 1..120 }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("年齡查驗（零知識）", style = MaterialTheme.typography.titleMedium)
            Text("只確認對方年滿指定年齡，看不到出生日期與其他欄位。證明在這支手機驗證。", style = MaterialTheme.typography.bodySmall)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AgeRoute.entries.forEach { r ->
                    FilterChip(selected = route == r, onClick = { route = r }, enabled = r == AgeRoute.HOST || available[r] == true,
                        label = { Text(r.label) })
                }
            }
            Text(
                when (route) {
                    AgeRoute.BLUETOOTH -> "出示者的手機以藍牙把證明直接傳到這支手機，雙方都不需要網路。出示者可使用本錢包或 Bonds App（格式與 Bonds 的雙機查驗相同）；本錢包同時會顯示動態 QR Code 備用。"
                    AgeRoute.QR -> "不用網路也不用藍牙：出示者的錢包把證明顯示成連續變換的動態 QR Code，用這支手機的相機掃描到完成（約數十秒）。出示者需使用本錢包。"
                    AgeRoute.LAN -> "兩支手機連在同一個 Wi-Fi（或一支開熱點讓另一支連上），證明直接傳到這支手機，不經網際網路。出示者需使用本錢包。"
                    AgeRoute.HOST -> host?.let { "年齡查驗主機：$it。請求與 Bonds 的網頁查驗相同，由主機轉送。" }
                        ?: "尚未設定年齡查驗主機：到設定的「零知識證明」頁填入（測試環境會使用測試伺服器）。"
                },
                style = MaterialTheme.typography.bodySmall,
                color = if (route == AgeRoute.HOST && host == null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(value = ageText, onValueChange = { t -> ageText = t.filter { it.isDigit() }.take(3) },
                label = { Text("年滿幾歲") }, singleLine = true, modifier = Modifier.width(140.dp), isError = age == null)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(BondsCredentialSource.TWDIW, BondsCredentialSource.SELF_ISSUED).forEach { s ->
                    FilterChip(selected = source == s, onClick = { source = s }, label = { Text(bondsSourceLabel(s)) })
                }
            }
            OutlinedTextField(value = purpose, onValueChange = { purpose = it.take(100) }, label = { Text("查驗用途（會顯示給出示者）") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            Button(
                onClick = {
                    val flow = model.taiwan.ageVerifier
                    when (route) {
                        AgeRoute.BLUETOOTH -> flow.startNearby(age!!, source, purpose.trim())
                        AgeRoute.QR -> flow.startNearby(age!!, source, purpose.trim(), bluetooth = false)
                        AgeRoute.LAN -> flow.startLan(age!!, source, purpose.trim())
                        AgeRoute.HOST -> flow.start(age!!, source, purpose.trim())
                    }
                },
                // Bonds refuses a request without a purpose.
                enabled = age != null && purpose.isNotBlank() && available[route] == true,
            ) {
                Text("產生年齡查驗 QR Code")
            }
        }
    }
}
