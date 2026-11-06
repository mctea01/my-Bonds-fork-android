package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
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
            Text(stringResource(Res.string.prox_keep_near), style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
            OutlinedButton(onClick = { model.proximity.again() }) { Text(stringResource(Res.string.action_cancel)) }
        }
        is ProximityUi.Consent -> ConsentView(model, s)
        is ProximityUi.Done -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.PASS, stringResource(Res.string.flow_presented), listOf(stringResource(Res.string.prox_handed, s.documents.joinToString(stringResource(Res.string.sep_list)), s.verifier), stringResource(Res.string.flow_presented_history)))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { model.back() }) { Text(stringResource(Res.string.action_done)) }
                // "Present again" restarts the in-person listening flow; a DC API request is driven by the browser, not retriable here.
                if (s.channel != diw.wallet.app.ProximityChannel.DC_API) {
                    OutlinedButton(onClick = { model.proximity.again() }) { Text(stringResource(Res.string.prox_again)) }
                }
            }
        }
        is ProximityUi.Failed -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.FAIL, stringResource(Res.string.flow_failed), listOf(s.message))
            // A DC API request cannot be retried inside the wallet (the browser owns it); "再試一次" would otherwise drop
            // the user onto the NFC sensing screen, which never answers the original online request.
            if (s.channel == diw.wallet.app.ProximityChannel.DC_API) {
                Button(onClick = { model.back() }) { Text(stringResource(Res.string.action_leave)) }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { model.proximity.again() }) { Text(stringResource(Res.string.action_try_again)) }
                    OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_leave)) }
                }
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
                Text(stringResource(Res.string.prox_hold_near), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(Res.string.prox_hold_text),
                    style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
                if (nfcReason == null) VerdictPill(Verdict.PASS, stringResource(Res.string.prox_nfc_ready))
                else VerdictPill(Verdict.CAUTION, nfcReason)
            }
        }
        bleReason?.let { Text(stringResource(Res.string.prox_bluetooth, it), style = MaterialTheme.typography.bodySmall) }
        if (mdocs == 0) {
            Text(stringResource(Res.string.prox_no_mdoc),
                style = MaterialTheme.typography.bodySmall)
        }
        SectionTitle(stringResource(Res.string.prox_no_nfc))
        val qr = s.qr
        if (qr == null) {
            OutlinedButton(onClick = { model.proximity.showQr() }) {
                Icon(WalletIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(stringResource(Res.string.prox_use_qr))
            }
        } else {
            Text(stringResource(Res.string.prox_qr_text), style = MaterialTheme.typography.bodyMedium)
            QrImage(qr, Modifier.fillMaxWidth().widthIn(max = 360.dp).align(Alignment.CenterHorizontally), ecc = QrEncoder.Ecc.L)
        }
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

@Composable
private fun ConsentView(model: WalletModel, s: ProximityUi.Consent) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        val extra = buildList {
            add(stringResource(Res.string.prox_channel, s.channel.title, s.channel.spec))
            if (s.chain.isEmpty()) add(stringResource(Res.string.prox_no_reader_auth))
            if (s.retained.isNotEmpty()) add(stringResource(Res.string.prox_will_retain) + s.retained.joinToString(stringResource(Res.string.sep_list)))
        }
        TrustCard(if (s.channel == diw.wallet.app.ProximityChannel.DC_API) stringResource(Res.string.role_verifier) else stringResource(Res.string.prox_reader), s.verifier, s.trust, extra)
        if (s.chain.isNotEmpty()) {
            LabelValue(stringResource(Res.string.prox_reader_cert), s.chain.first().displaySubject(), small = true) {
                model.screen.value = Screen.Certificate(s.chain, 0, Screen.Proximity)
            }
        }
        val statusOk = requestedDocuments(model, s.items, s.risk, s.trust.tier, s)
        val ok = riskAcknowledgement(s.trust)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.proximity.approve(s) }, enabled = ok && statusOk) { Text(stringResource(Res.string.flow_agree_share)) }
            OutlinedButton(onClick = { model.proximity.decline(s) }) { Text(stringResource(Res.string.action_decline)) }
        }
    }
}
