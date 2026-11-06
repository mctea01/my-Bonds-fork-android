package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
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
            Text(stringResource(Res.string.reader_request, s.request.title, s.request.detail), style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
            OutlinedButton(onClick = { model.reader.again() }) { Text(stringResource(Res.string.action_cancel)) }
        }
        is ReaderUi.Result -> ResultView(model, s)
        is ReaderUi.Failed -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.FAIL, stringResource(Res.string.reader_failed), listOf(s.message))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { model.reader.again() }) { Text(stringResource(Res.string.action_try_again)) }
                OutlinedButton(onClick = { model.reader.close(); model.showTab(HomeTab.VERIFY) }) { Text(stringResource(Res.string.action_leave)) }
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
                Text(stringResource(Res.string.reader_title), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(Res.string.reader_text),
                    style = MaterialTheme.typography.bodyMedium)
            }
        }
        SectionTitle(stringResource(Res.string.reader_requested_data))
        ReaderRequest.entries.forEach { r ->
            Row(Modifier.fillMaxWidth().clickable { request = r }, verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = request == r, onClick = { request = r })
                Column {
                    Text(r.title, style = MaterialTheme.typography.bodyLarge)
                    Text(r.detail, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        SectionTitle(stringResource(Res.string.reader_purpose_risk))
        RiskSelector(risk) { risk = it }
        SectionTitle(stringResource(Res.string.prox_reader_device))
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
                                r.external -> stringResource(Res.string.reader_external)
                                r.bluetooth -> stringResource(Res.string.reader_phone_nfc)
                                else -> stringResource(Res.string.reader_device_nfc)
                            },
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
            list?.problem?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            TextButton(onClick = { model.reader.refreshReaders() }) { Text(stringResource(Res.string.reader_find_again)) }
        }
        Button(onClick = { selected?.let { model.reader.start(it, request, risk) } }, enabled = selected != null) {
            Icon(WalletIcons.Nfc, contentDescription = null, modifier = Modifier.size(18.dp))
            Text(stringResource(Res.string.reader_start))
        }
        Text(stringResource(Res.string.reader_no_auth), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun ResultView(model: WalletModel, s: ReaderUi.Result) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (s.integrityError != null) {
            VerdictCard(Verdict.FAIL, stringResource(Res.string.reader_invalid), listOf(s.integrityError, stringResource(Res.string.reader_invalid_text)))
        }
        s.documents.forEach { d -> DocumentResult(model, d, s.risk) }
        Text(stringResource(Res.string.reader_summary, s.request.title, StatusTexts.risk(s.risk), s.transport), style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.reader.again() }) { Text(stringResource(Res.string.reader_again)) }
            OutlinedButton(onClick = { model.reader.close(); model.showTab(HomeTab.VERIFY) }) { Text(stringResource(Res.string.action_done)) }
        }
    }
}

/** The verdict for one document: integrity passed, so it depends on the issuer's trust and the status. */
internal fun readVerdictOf(d: ReadDocument, risk: RiskLevel): Verdict {
    val official = (d.issuerTrust.tier == TrustTier.T1 || d.issuerTrust.tier == TrustTier.T2) && d.issuerTrust.environment != TrustEnvironment.TEST
    return when {
        d.statusDecision.verdict == StatusVerdict.REJECT -> Verdict.FAIL
        risk == RiskLevel.HIGH && !official -> Verdict.FAIL
        official && d.statusDecision.verdict == StatusVerdict.ACCEPT -> Verdict.PASS
        else -> Verdict.CAUTION
    }
}

@Composable
internal fun readVerdict(d: ReadDocument, risk: RiskLevel): Triple<Verdict, String, List<String>> {
    val tier = d.issuerTrust.tier
    val test = d.issuerTrust.environment == TrustEnvironment.TEST
    val official = (tier == TrustTier.T1 || tier == TrustTier.T2) && !test
    val status = d.statusDecision
    val statusLine = StatusTexts.summary(status) + stringResource(Res.string.sentence_end) + StatusTexts.explain(status.finding)
    val issuerLine = (if (test) "" else stringResource(Res.string.reader_all_match)) + issuerTrustLine(d.issuerTrust)
    return when {
        status.verdict == StatusVerdict.REJECT -> Triple(
            Verdict.FAIL, stringResource(Res.string.reader_status_failed),
            listOf(statusLine, stringResource(Res.string.reader_purpose_risk_line, StatusTexts.risk(risk)) + StatusTexts.verdict(StatusVerdict.REJECT) + stringResource(Res.string.reader_this_credential), issuerLine),
        )
        risk == RiskLevel.HIGH && !official -> Triple(Verdict.FAIL, stringResource(Res.string.reader_issuer_failed), listOf(issuerLine, stringResource(Res.string.reader_high_needs_official), statusLine))
        official && status.verdict == StatusVerdict.ACCEPT -> Triple(Verdict.PASS, stringResource(Res.string.reader_passed), listOf(issuerLine, statusLine))
        official -> Triple(Verdict.CAUTION, stringResource(Res.string.reader_status_caution), listOf(issuerLine, statusLine))
        else -> Triple(Verdict.CAUTION, stringResource(Res.string.reader_issuer_caution), listOf(issuerLine, statusLine))
    }
}

@Composable
private fun DocumentResult(model: WalletModel, d: ReadDocument, risk: RiskLevel) {
    val (verdict, title, caveats) = readVerdict(d, risk)
    VerdictCard(verdict, title, caveats)
    Text(d.title, style = MaterialTheme.typography.titleMedium)
    TrustCard(stringResource(Res.string.role_issuer), d.issuer, d.issuerTrust)
    if (d.chain.isNotEmpty()) {
        LabelValue(stringResource(Res.string.reader_issuer_cert), d.chain.first().displaySubject(), small = true) {
            model.screen.value = Screen.Certificate(d.chain, 0, Screen.Reader)
        }
    }
    val now = Clock.System.now()
    LabelValue(stringResource(Res.string.reader_validity), localTime(d.validFrom) + stringResource(Res.string.range_to) + localTime(d.validUntil) + if (d.validUntil < now) stringResource(Res.string.reader_expired) else "", small = true)
    LabelValue(stringResource(Res.string.reader_signed), localTime(d.signedAt), small = true)
    specStatus(d.status)?.let { LabelValue(stringResource(Res.string.reader_status_value), it, small = true) }
    SectionTitle(stringResource(Res.string.reader_disclosed))
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
    if (d.claims.isEmpty()) Text(stringResource(Res.string.reader_nothing_disclosed), style = MaterialTheme.typography.bodySmall)
    if (d.withheld.isNotEmpty()) Text(stringResource(Res.string.reader_not_given) + d.withheld.joinToString(stringResource(Res.string.sep_list)), style = MaterialTheme.typography.bodySmall)
}
