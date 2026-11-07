package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
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
import androidx.compose.material3.AlertDialog
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
import diw.wallet.app.QrScanStep
import diw.wallet.app.Screen
import diw.wallet.app.OfflineUi
import diw.wallet.app.StatusTexts
import diw.wallet.app.WalletModel
import diw.wallet.app.legal.LegalStrings
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
 * or from a picture where [hasCamera] is false; [streamQr] keeps the camera open for frame after frame.
 */
@Composable
fun OfflineScreen(
    model: WalletModel,
    readQr: suspend () -> String?,
    hasCamera: Boolean,
    streamQr: (suspend (onCode: (String) -> QrScanStep) -> Unit)? = null,
) {
    val state by model.taiwan.offline.collectAsState()
    when (val s = state) {
        is OfflineUi.Working -> Busy(s.message.ifEmpty { stringResource(Res.string.state_processing) })
        is OfflineUi.Failed -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.FAIL, stringResource(Res.string.flow_failed), listOf(s.message))
            Button(onClick = { model.back() }) { Text(stringResource(Res.string.action_back)) }
        }
        is OfflineUi.Unlisted -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.FAIL, stringResource(Res.string.offline_t4_title), listOf(s.message, stringResource(Res.string.offline_t4_text)))
            if (riskOverride(s.service.vpUid, stringResource(Res.string.action_continue_at_risk), stringResource(Res.string.offline_unlisted_title),
                    listOf(stringResource(Res.string.offline_unlisted_text, s.service.name), stringResource(Res.string.offline_unlisted_risk)))) {
                Button(onClick = { model.taiwan.startPickup(s.service, allowUnlisted = true) }) { Text(stringResource(Res.string.offline_continue)) }
            }
            TextButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_back)) }
        }
        is OfflineUi.Barcode -> BarcodeView(model, s)
        is OfflineUi.BondsChoose -> BondsChooseView(model, s)
        is OfflineUi.AgeChoose -> BondsAgeChooseView(model, s)
        is OfflineUi.AgeWorking -> BondsAgeWorkingView(model, s)
        is OfflineUi.AgeResult -> BondsAgeResultView(model, s)
        is OfflineUi.AgeVerifierWaiting -> BondsAgeVerifierWaitingView(model, s, streamQr)
        is OfflineUi.AgeVerifierResult -> BondsAgeVerifierResultView(model, s)
        is OfflineUi.BondsFrames -> BondsFramesView(model, s)
        is OfflineUi.VerifierChallenge -> VerifierChallengeView(model, s, readQr, hasCamera, streamQr)
        is OfflineUi.VerifierResult -> VerifierResultView(model, s)
        is OfflineUi.ZkTlsConsent -> ZkTlsConsentView(model, s)
        is OfflineUi.ZkTlsProving -> ZkTlsProvingView(model, s)
        is OfflineUi.ZkTlsHolderResult -> ZkTlsHolderResultView(model, s)
        is OfflineUi.ZkTlsSelfPick -> ZkTlsSelfPickView(model, s)
        is OfflineUi.ZkTlsSelf -> ZkTlsSelfView(model, s)
        is OfflineUi.ZkTlsSelfResult -> ZkTlsSelfResultView(model, s)
        is OfflineUi.ZkTlsVerifierSetup -> ZkTlsVerifierSetupView(model, s)
        is OfflineUi.ZkTlsVerifierWaiting -> ZkTlsVerifierWaitingView(model, s)
        is OfflineUi.ZkTlsVerifierResult -> ZkTlsVerifierResultView(model, s)
        is OfflineUi.ZkPassportSetup -> ZkPassportSetupView(model, s)
        is OfflineUi.ZkPassportWaiting -> ZkPassportWaitingView(model, s)
        is OfflineUi.ZkPassportVerified -> ZkPassportResultView(model, s)
        is OfflineUi.ZkPassportAnswerConnecting -> ZkPassportAnswerConnectingView(model, s)
        is OfflineUi.ZkPassportAnswerConsent -> ZkPassportAnswerConsentView(model, s)
        is OfflineUi.ZkPassportAnswerProving -> ZkPassportAnswerProvingView(model, s)
        is OfflineUi.ZkPassportAnswerDone -> ZkPassportAnswerDoneView(model, s)
    }
}

@Composable
private fun BarcodeView(model: WalletModel, s: OfflineUi.Barcode) {
    val left = secondsLeft(s.expiresAt)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        Text(s.serviceName, style = MaterialTheme.typography.titleLarge)
        Text(stringResource(Res.string.offline_show_clerk), style = MaterialTheme.typography.bodyMedium)
        if (s.image != null && left > 0) {
            Image(s.image, contentDescription = stringResource(Res.string.offline_barcode), contentScale = ContentScale.FillWidth, modifier = Modifier.fillMaxWidth().widthIn(max = 480.dp))
        } else if (s.image == null) {
            Text(stringResource(Res.string.offline_barcode_broken), color = MaterialTheme.colorScheme.error)
        }
        Text(if (left > 0) stringResource(Res.string.offline_time_left, mmss(left)) else stringResource(Res.string.offline_barcode_expired), style = MaterialTheme.typography.titleMedium,
            color = if (left > 30) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        Text(stringResource(Res.string.offline_barcode_note), style = MaterialTheme.typography.bodySmall)
        Button(onClick = { model.back() }) { Text(stringResource(Res.string.action_done)) }
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
                Text(stringResource(Res.string.offline_request), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(Res.string.age_purpose, s.request.purpose))
                s.request.audience?.let { Text(stringResource(Res.string.offline_verifier, it)) }
                Text(stringResource(Res.string.offline_challenge_time, s.request.createdAt), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(Res.string.offline_unsigned),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                Text(LegalStrings.BONDS_UNENCRYPTED_WARNING, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
        }
        Text(stringResource(Res.string.offline_choose), style = MaterialTheme.typography.titleSmall)
        s.cards.forEachIndexed { i, c ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = i == cardIndex, onClick = { cardIndex = i })
                Column {
                    Text(c.name)
                    Text(bondsKindLabel(c.kind), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Text(stringResource(Res.string.offline_fields), style = MaterialTheme.typography.titleSmall)
        val record = card.document?.issuanceRecord
        if (!card.selective) {
            Text(stringResource(Res.string.offline_no_sd), style = MaterialTheme.typography.bodySmall)
        }
        card.claims.forEach { (name, value) ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                val locked = card.kind == BondsCardKind.MOICA && name in BondsOfflinePresentation.CLAIMS_ALWAYS_DISCLOSED
                if (card.selective) Checkbox(checked = locked || name in chosen, enabled = !locked, onCheckedChange = { on -> chosen = if (on) chosen + name else chosen - name })
                Column(if (card.selective) Modifier else Modifier.padding(start = 12.dp)) {
                    val label = model.claimLabel(name.split('.'), null, record)
                    Text(label, style = MaterialTheme.typography.bodyMedium)
                    ClaimValueView(model, label, value)
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.taiwan.presentBonds(s.request, card, chosen) }) { Text(stringResource(Res.string.action_present)) }
            OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
        }
    }
}

@Composable
private fun bondsKindLabel(kind: BondsCardKind): String = when (kind) {
    BondsCardKind.W3C_SD_JWT -> stringResource(Res.string.bonds_kind_w3c_sd)
    BondsCardKind.SD_JWT_VC -> stringResource(Res.string.bonds_kind_sd_jwt)
    BondsCardKind.JWT_VC -> stringResource(Res.string.bonds_kind_jwt)
    BondsCardKind.MOICA -> stringResource(Res.string.bonds_kind_moica)
}

/** What a verifier's challenge accepts, in the holder's and the verifier's words. */
@Composable
internal fun bondsSourceLabel(source: BondsCredentialSource): String = when (source) {
    BondsCredentialSource.TWDIW -> stringResource(Res.string.bonds_source_twdiw)
    BondsCredentialSource.ANY -> stringResource(Res.string.bonds_source_any)
    BondsCredentialSource.SELF_ISSUED -> stringResource(Res.string.bonds_source_self)
}

@Composable
private fun BondsFramesView(model: WalletModel, s: OfflineUi.BondsFrames) {
    var index by remember(s.frames) { mutableStateOf(0) }
    var paused by remember(s.frames) { mutableStateOf(false) }
    var confirmLink by remember(s.frames) { mutableStateOf(false) }
    val left = secondsLeft(s.expiresAt)
    LaunchedEffect(s.frames, paused) {
        while (!paused && s.frames.size > 1) {
            delay(FRAME_INTERVAL_MS)
            index = (index + 1) % s.frames.size
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        Text(if (s.showQr) stringResource(Res.string.offline_let_scan) else stringResource(Res.string.offline_sending), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(Res.string.age_purpose, s.request.purpose), style = MaterialTheme.typography.bodyMedium)
        s.lan?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary) }
        if (left > 0 && !s.showQr) {
            Text(stringResource(Res.string.offline_direct, mmss(left)), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { model.taiwan.showFramesQr() }) { Text(stringResource(Res.string.offline_show_qr)) }
        } else if (left > 0 && s.fountain != null) {
            AnimatedQr(s.fountain, Modifier.fillMaxWidth().widthIn(max = 420.dp))
            Text(stringResource(Res.string.offline_frames, mmss(left)), style = MaterialTheme.typography.bodySmall)
        } else if (left > 0) {
            QrImage(s.frames[index], Modifier.fillMaxWidth().widthIn(max = 420.dp), QrEncoder.Ecc.Q)
            Text(stringResource(Res.string.offline_frame_n, index + 1, s.frames.size, mmss(left)), style = MaterialTheme.typography.bodySmall)
            if (s.frames.size > 1) OutlinedButton(onClick = { paused = !paused }) { Text(if (paused) stringResource(Res.string.offline_resume) else stringResource(Res.string.offline_pause)) }
        } else {
            Text(stringResource(Res.string.offline_timeout), color = MaterialTheme.colorScheme.error)
        }
        val link = model.platform.bondsLink
        if (s.request.linkServiceId != null && link != null && left > 0) {
            OutlinedButton(onClick = { confirmLink = true }) {
                Icon(WalletIcons.Bluetooth, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(stringResource(Res.string.offline_use_bluetooth))
            }
        }
        s.link?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        Text(stringResource(Res.string.offline_bound), style = MaterialTheme.typography.bodySmall)
        TechDetails(s.details, "frames-${s.request.challenge}")
        Button(onClick = { model.back() }) { Text(stringResource(Res.string.action_done)) }
    }
    if (confirmLink) {
        AlertDialog(
            onDismissRequest = { confirmLink = false },
            title = { Text(LegalStrings.BONDS_LINK_TITLE) },
            text = { Text(LegalStrings.BONDS_UNENCRYPTED_WARNING) },
            confirmButton = { TextButton(onClick = { confirmLink = false; model.taiwan.sendOverLink(s) }) { Text(LegalStrings.BONDS_LINK_SEND) } },
            dismissButton = { TextButton(onClick = { confirmLink = false }) { Text(LegalStrings.CANCEL) } },
        )
    }
}

@Composable
private fun VerifierChallengeView(
    model: WalletModel,
    s: OfflineUi.VerifierChallenge,
    readQr: suspend () -> String?,
    hasCamera: Boolean,
    streamQr: (suspend (onCode: (String) -> QrScanStep) -> Unit)?,
) {
    var scanning by remember { mutableStateOf(false) }
    var pasted by remember { mutableStateOf("") }
    // The scanner callback runs outside composition, so it fills a pattern resolved here.
    val receivedPattern = stringResource(Res.string.offline_received, "{1}", "{2}")
    LaunchedEffect(scanning) {
        if (scanning) {
            if (streamQr != null) {
                // The camera stays open across the rotating frames until the presentation is complete.
                streamQr { code ->
                    model.handleUri(code)
                    val now = model.taiwan.offline.value as? OfflineUi.VerifierChallenge
                    QrScanStep(!model.taiwan.verifying, now?.takeIf { it.total > 0 }?.let { receivedPattern.replace("{1}", it.received.toString()).replace("{2}", it.total.toString()) })
                }
            } else {
                // One scan per frame until the presentation is complete or the user closes the scanner; a picture
                // holds one frame per pick.
                do {
                    val text = readQr() ?: break
                    model.handleUri(text)
                } while (hasCamera && model.taiwan.verifying)
            }
            scanning = false
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        Text(stringResource(Res.string.offline_scan_with), style = MaterialTheme.typography.titleMedium)
        QrImage(s.request.encode(), Modifier.fillMaxWidth().widthIn(max = 360.dp))
        Text(stringResource(Res.string.offline_purpose_risk, s.request.purpose, StatusTexts.risk(s.risk)), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(Res.string.age_accepts) + bondsSourceLabel(s.request.source), style = MaterialTheme.typography.bodySmall)
        if (s.request.source == BondsCredentialSource.ANY) {
            Text(stringResource(Res.string.offline_extension), style = MaterialTheme.typography.bodySmall)
        }
        s.request.audience?.let { Text(stringResource(Res.string.offline_verifier, it), style = MaterialTheme.typography.bodyMedium) }
        if (s.total > 0) {
            LinearProgressIndicator(progress = { (s.received.toFloat() / s.total).coerceAtMost(1f) }, modifier = Modifier.fillMaxWidth())
            Text(progressText(s), style = MaterialTheme.typography.bodySmall)
        }
        s.lan?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        s.link?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        TechDetails(s.details, "challenge-${s.request.challenge}")
        Button(onClick = { scanning = true }, enabled = !scanning) {
            Icon(if (hasCamera) WalletIcons.Scan else WalletIcons.Image, contentDescription = null, modifier = Modifier.size(18.dp))
            Text(if (hasCamera) stringResource(Res.string.offline_scan_other) else stringResource(Res.string.offline_scan_other_image))
        }
        if (!hasCamera) {
            OutlinedTextField(value = pasted, onValueChange = { pasted = it.trim() }, label = { Text(stringResource(Res.string.offline_paste)) },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedButton(onClick = { model.handleUri(pasted); pasted = "" }, enabled = pasted.isNotEmpty()) { Text(stringResource(Res.string.action_add)) }
        }
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

/** Pictures for BTWVP1 frames, blocks for a fountain QR (the holder picks which), so the unit is left out. */
@Composable
private fun progressText(s: OfflineUi.VerifierChallenge): String = stringResource(Res.string.offline_received, s.received, s.total)

@Composable
private fun VerifierResultView(model: WalletModel, s: OfflineUi.VerifierResult) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        val r = s.result
        if (r == null) {
            VerdictCard(Verdict.FAIL, stringResource(Res.string.age_failed), listOf(s.error ?: stringResource(Res.string.offline_invalid)))
        } else {
            val official = s.issuerTrust?.tier == TrustTier.T1 || s.issuerTrust?.tier == TrustTier.T2
            val test = s.issuerTrust?.environment == TrustEnvironment.TEST
            val status = s.statusDecision
            val statusLine = status?.let { StatusTexts.summary(it) + stringResource(Res.string.sentence_end) + StatusTexts.explain(it.finding) }
            val issuerLine = (if (official && !test) stringResource(Res.string.offline_challenge_match) else "") + issuerTrustLine(s.issuerTrust)
            when {
                status?.verdict == StatusVerdict.REJECT -> VerdictCard(
                    Verdict.FAIL, stringResource(Res.string.reader_status_failed),
                    listOfNotNull(statusLine, stringResource(Res.string.reader_purpose_risk_line, StatusTexts.risk(s.risk)) + StatusTexts.verdict(StatusVerdict.REJECT) + stringResource(Res.string.reader_this_credential), issuerLine),
                )
                s.risk == RiskLevel.HIGH && (!official || test) -> VerdictCard(
                    Verdict.FAIL, stringResource(Res.string.reader_issuer_failed),
                    listOfNotNull(issuerLine, stringResource(Res.string.reader_high_needs_official), statusLine),
                )
                official && !test && status?.verdict != StatusVerdict.CAUTION -> VerdictCard(
                    Verdict.PASS, stringResource(Res.string.reader_passed), listOfNotNull(issuerLine, statusLine),
                )
                official && !test -> VerdictCard(Verdict.CAUTION, stringResource(Res.string.reader_status_caution), listOfNotNull(issuerLine, statusLine))
                else -> VerdictCard(
                    Verdict.CAUTION, stringResource(Res.string.reader_issuer_caution),
                    listOfNotNull(stringResource(Res.string.offline_holder_match), issuerLine, statusLine),
                )
            }
            Text(stringResource(Res.string.offline_purpose_risk, s.request.purpose, StatusTexts.risk(s.risk)))
            specStatus(s.status)?.let { Text(stringResource(Res.string.status_spec_value, it), style = MaterialTheme.typography.bodySmall) }
            Text(stringResource(Res.string.offline_presented_at, r.created), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(Res.string.offline_holder, r.holder), style = MaterialTheme.typography.bodySmall)
            val issuer = r.moica?.let { stringResource(Res.string.offline_moica_holder, it.cardholderName, it.certificateSerialHex) } ?: r.issuer ?: stringResource(Res.string.state_unknown)
            if (s.issuerTrust != null) TrustCard(stringResource(Res.string.role_issuer), issuer, s.issuerTrust)
            else Text(stringResource(Res.string.offline_issuer_unknown, issuer), color = tierColor(diw.wallet.core.trust.TrustTier.T3))
            Text(stringResource(Res.string.offline_presented_data), style = MaterialTheme.typography.titleSmall)
            r.credentialType?.let { LabelValue(stringResource(Res.string.credential_kind), it, small = true) }
            r.issuerChain?.let { chain ->
                LabelValue(stringResource(Res.string.reader_issuer_cert), chain.first().displaySubject(), small = true) {
                    model.screen.value = Screen.Certificate(chain, 0, Screen.Offline)
                }
            }
            r.claims.forEach { (k, v) -> ClaimRow(model, model.claimLabel(k.split('.'), null, null), v) }
            if (r.claims.isEmpty()) Text(stringResource(Res.string.reader_nothing_disclosed), style = MaterialTheme.typography.bodySmall)
            r.moica?.let { if (it.withheldClaims > 0) Text(stringResource(Res.string.offline_withheld, it.withheldClaims), style = MaterialTheme.typography.bodySmall) }
            EvidenceRows(r.evidence)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.taiwan.startVerifier(s.request.purpose, s.risk, s.request.source) }) { Text(stringResource(Res.string.reader_again)) }
            OutlinedButton(onClick = { model.taiwan.closeOffline(); model.showTab(HomeTab.VERIFY) }) { Text(stringResource(Res.string.action_done)) }
        }
    }
}

private const val FRAME_INTERVAL_MS = 400L
