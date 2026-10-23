package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import diw.wallet.app.OfflineUi
import diw.wallet.app.WalletModel
import diw.wallet.app.ZkChoiceKind
import diw.wallet.app.ZkJobPhase
import diw.wallet.app.ZkProofKind
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsCredentialSource
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
private fun AgeRequestCard(request: BondsAgeRequest) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("${request.responseHost} 要求證明你年滿 ${request.minimumAge} 歲", style = MaterialTheme.typography.titleMedium)
            if (request.purpose.isNotEmpty()) Text("用途：${request.purpose}")
            Text("送出位置：${request.responseUrl}", style = MaterialTheme.typography.bodySmall)
            if (!request.knownHost) {
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
        AgeRequestCard(s.request)
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
            Button(onClick = { stage = if (s.request.knownHost) 2 else 1 }, enabled = left > 0) { Text("產生並送出證明") }
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
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        AgeRequestCard(s.request)
        Text(
            when {
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
