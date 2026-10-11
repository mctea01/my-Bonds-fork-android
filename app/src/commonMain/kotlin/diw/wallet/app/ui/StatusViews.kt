package diw.wallet.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import diw.wallet.app.StatusTexts
import diw.wallet.app.WalletModel
import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.status.StatusDecision
import diw.wallet.core.status.StatusVerdict
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import org.multipaz.document.Document
import kotlin.time.Instant

fun verdictOf(v: StatusVerdict): Verdict = when (v) {
    StatusVerdict.ACCEPT -> Verdict.PASS
    StatusVerdict.CAUTION -> Verdict.CAUTION
    StatusVerdict.REJECT -> Verdict.FAIL
}

/** Local date and time to the minute. */
fun localTime(i: Instant): String {
    val t = i.toLocalDateTime(TimeZone.currentSystemDefault())
    fun two(n: Int) = n.toString().padStart(2, '0')
    return "${t.year}-${two(t.month.ordinal + 1)}-${two(t.day)} ${two(t.hour)}:${two(t.minute)}"
}

/** The status value in the specification's own terms (W3C statusPurpose and value, or the Token Status List name). */
fun specStatus(s: CredentialStatus?): String? = s?.label ?: s?.specName

/** A small verdict pill: symbol, colour and words, on a surface so it reads on any card colour. */
@Composable
fun VerdictPill(verdict: Verdict, text: String, modifier: Modifier = Modifier) {
    val shape = RoundedCornerShape(50)
    Row(
        modifier.background(MaterialTheme.colorScheme.surface, shape).background(verdict.color.copy(alpha = 0.14f), shape)
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Icon(verdict.icon, contentDescription = null, tint = verdict.color, modifier = Modifier.size(16.dp))
        Text(text, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}

/** The document's status judged at its own risk, for its card in the documents list. */
@Composable
fun StatusChip(model: WalletModel, doc: Document) {
    val statuses by model.statuses.collectAsState()
    val checking by model.status.checking.collectAsState()
    if (statuses[doc.identifier] == null && doc.identifier in checking) {
        Row(
            Modifier.background(MaterialTheme.colorScheme.surface, RoundedCornerShape(50)).padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            CircularProgressIndicator(Modifier.size(12.dp), strokeWidth = 2.dp)
            Text("查詢狀態中", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurface)
        }
        return
    }
    val d = model.status.decision(doc)
    VerdictPill(verdictOf(d.verdict), StatusTexts.finding(d.finding) + StatusTexts.qualifiers(d))
}

/** The status block of a document's page: verdict, explanation, the specification's value, time and the query button. */
@Composable
fun StatusPanel(model: WalletModel, doc: Document) {
    val statuses by model.statuses.collectAsState()
    val checking by model.status.checking.collectAsState()
    val current = statuses[doc.identifier]
    val d = model.status.decision(doc)
    val v = verdictOf(d.verdict)
    Column(
        Modifier.fillMaxWidth().background(v.color.copy(alpha = 0.14f), RoundedCornerShape(Tokens.ContainerRadius)).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(v.icon, contentDescription = null, tint = v.color, modifier = Modifier.size(28.dp))
            Column(Modifier.weight(1f)) {
                Text(StatusTexts.finding(d.finding), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text("依證件用途（${StatusTexts.risk(d.risk)}）：${StatusTexts.verdict(d.verdict)}" + StatusTexts.qualifiers(d),
                    style = MaterialTheme.typography.bodySmall)
            }
            if (doc.identifier in checking) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
            else TextButton(onClick = { model.checkStatus(doc) }) { Text("查詢") }
        }
        Text(StatusTexts.explain(d.finding), style = MaterialTheme.typography.bodyMedium)
        specStatus(current?.status)?.let { Text("規格狀態值：$it", style = MaterialTheme.typography.bodySmall) }
        current?.let {
            Text(
                "查詢時間：${localTime(it.status.checkedAt)}" + if (d.stale) "（超過${StatusTexts.risk(d.risk)}證件允許的時間，需重新查詢）" else "",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        current?.lastError?.let {
            Text("最近一次查詢失敗（${localTime(current.attemptedAt)}）：$it。上方是前一次的結果。", style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** One line per document of a request: its status judged at the request's risk. */
@Composable
fun RequestStatusLine(d: StatusDecision) {
    VerdictPill(verdictOf(d.verdict), StatusTexts.finding(d.finding) + "，" + StatusTexts.verdict(d.verdict) + StatusTexts.qualifiers(d))
}

/** Picks the risk of a purpose: low, medium or high, with examples. */
@Composable
fun RiskSelector(selected: RiskLevel, onSelect: (RiskLevel) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            RiskLevel.entries.forEach { r ->
                FilterChip(selected = r == selected, onClick = { onSelect(r) }, label = { Text(StatusTexts.risk(r)) })
            }
        }
        Text("例如" + StatusTexts.riskExamples(selected) + "。" + riskRule(selected), style = MaterialTheme.typography.bodySmall)
    }
}

private fun riskRule(r: RiskLevel): String = when (r) {
    RiskLevel.LOW -> "狀態無法確認（例如離線）時仍接受，已撤銷則拒絕。"
    RiskLevel.MEDIUM -> "狀態無法確認或清單未經驗證時標示需留意，暫停或撤銷則拒絕。"
    RiskLevel.HIGH -> "必須在線上確認狀態有效，發行端也必須在信任清單內，否則拒絕。"
}
