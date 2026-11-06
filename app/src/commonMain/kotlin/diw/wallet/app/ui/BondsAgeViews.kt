package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
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
import diw.wallet.app.ServerStrings
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
            Text(stringResource(Res.string.age_request_title, if (request.lan) stringResource(Res.string.age_lan_verifier) + request.responseHost else request.responseHost ?: BondsAgeFlow.NEARBY, request.minimumAge),
                style = MaterialTheme.typography.titleMedium)
            if (request.purpose.isNotEmpty()) Text(stringResource(Res.string.age_purpose, request.purpose))
            Text(
                when {
                    request.nearby && request.qr -> stringResource(Res.string.age_route_nearby)
                    request.nearby -> stringResource(Res.string.age_route_bluetooth)
                    request.lan -> stringResource(Res.string.age_route_lan)
                    else -> stringResource(Res.string.age_route_url, request.responseUrl.toString())
                },
                style = MaterialTheme.typography.bodySmall,
            )
            if (!known && !request.nearby && !request.lan) {
                Text(stringResource(Res.string.age_not_listed), style = MaterialTheme.typography.bodySmall,
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
        Text(stringResource(Res.string.age_only_proof, s.request.cutoff),
            style = MaterialTheme.typography.bodyMedium)
        Text(
            if (s.request.source == BondsCredentialSource.SELF_ISSUED) stringResource(Res.string.age_self_stated)
            else stringResource(Res.string.age_issuer_did),
            style = MaterialTheme.typography.bodySmall,
        )
        Text(if (left > 0) stringResource(Res.string.age_time_left, clock(left)) else stringResource(Res.string.age_expired), style = MaterialTheme.typography.bodySmall,
            color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        Text(stringResource(Res.string.age_choose_card), style = MaterialTheme.typography.titleSmall)
        s.cards.forEachIndexed { i, c ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = i == index, onClick = { index = i })
                Column {
                    Text(c.name)
                    Text(stringResource(Res.string.age_by_claim, c.claim), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { stage = if (s.known) 2 else 1 }, enabled = left > 0) { Text(stringResource(Res.string.age_make_send)) }
            OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
        }
    }
    when (stage) {
        1 -> RiskConfirmDialog(
            title = stringResource(Res.string.age_unlisted_title),
            lines = listOf(
                stringResource(Res.string.age_unlisted_text, s.request.responseHost.toString()),
                stringResource(Res.string.age_unlisted_tracking),
            ),
            confirm = stringResource(Res.string.age_send_anyway),
            onConfirm = { stage = 2 },
            onDismiss = { stage = 0 },
        )
        2 -> { val useDesktop = stringResource(Res.string.age_use_desktop); ZkProofGate(
            zk = model.zk,
            kind = ZkProofKind.AGE,
            onDecision = { choice, extended ->
                stage = 0
                if (choice == ZkChoiceKind.ON_DEVICE) model.taiwan.age.prove(s.request, card, extended)
                else model.message.value = useDesktop
            },
            onDismiss = { stage = 0 },
        ) }
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
            Text(stringResource(Res.string.age_show_frames), style = MaterialTheme.typography.titleMedium)
            AnimatedQr(qr, Modifier.fillMaxWidth().widthIn(max = 420.dp))
            Text(stringResource(Res.string.age_frames_text),
                style = MaterialTheme.typography.bodySmall)
            s.link?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            Text(stringResource(Res.string.age_frames_note, clock(left)), style = MaterialTheme.typography.bodySmall,
                color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
            Button(onClick = { model.taiwan.age.qrDone() }) { Text(stringResource(Res.string.age_scanned)) }
        }
        return
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        AgeRequestCard(s.request)
        Text(
            when {
                s.sending && s.request.nearby -> s.link ?: stringResource(Res.string.age_wait_bluetooth)
                s.sending -> stringResource(Res.string.age_sending, s.request.responseHost.toString())
                job?.step != null -> job.step!!
                job?.phase == ZkJobPhase.QUEUED -> stringResource(Res.string.zkpdf_waiting)
                else -> stringResource(Res.string.age_preparing)
            },
            style = MaterialTheme.typography.titleMedium,
        )
        LinearProgressIndicator(Modifier.fillMaxWidth())
        Text(stringResource(Res.string.age_made_with, s.card.name), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(Res.string.age_time_left, clock(left)), style = MaterialTheme.typography.bodySmall,
            color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        if (!s.sending) OutlinedButton(onClick = { model.taiwan.age.cancel(s) }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

/** Cycles through the fountain frames; any [AnimatedQrTransport.Encoder.count] plus a few of them rebuild the payload. */
@Composable
internal fun AnimatedQr(encoder: AnimatedQrTransport.Encoder, modifier: Modifier) {
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
                Button(onClick = { model.taiwan.age.prove(s.request, s.card, false) }) { Text(stringResource(Res.string.action_retry)) }
            }
            OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_done)) }
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
        Text(if (s.request.nearby && !qrOnly) stringResource(Res.string.age_scan_with_bonds) else stringResource(Res.string.age_scan_with_wallet), style = MaterialTheme.typography.titleMedium)
        QrImage(s.request.encode(), Modifier.fillMaxWidth().widthIn(max = 360.dp))
        Text(stringResource(Res.string.age_proves, s.request.minimumAge, s.request.cutoff), style = MaterialTheme.typography.bodyLarge)
        Text(stringResource(Res.string.age_accepts) + bondsSourceLabel(s.request.source) + stringResource(Res.string.age_purpose_inline) + s.request.purpose.ifEmpty { stringResource(Res.string.age_unstated) }, style = MaterialTheme.typography.bodySmall)
        Text(
            when {
                qrOnly -> stringResource(Res.string.age_verify_frames)
                s.request.nearby -> stringResource(Res.string.age_verify_bluetooth)
                s.request.lan -> stringResource(Res.string.age_verify_lan, s.host)
                s.relay -> stringResource(Res.string.age_verify_relay, s.host)
                else -> stringResource(Res.string.age_verify_host, s.host)
            },
            style = MaterialTheme.typography.bodySmall,
        )
        s.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        if (!s.request.nearby) Text(stringResource(Res.string.age_bonds_web_only), style = MaterialTheme.typography.bodySmall)
        if (s.checking) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(if (s.relay) stringResource(Res.string.age_received_verifying) else stringResource(Res.string.age_received_waiting, s.host), style = MaterialTheme.typography.titleSmall)
        } else {
            Text(if (left > 0) stringResource(Res.string.age_waiting, clock(left)) else stringResource(Res.string.age_expired_waiting), style = MaterialTheme.typography.bodySmall,
                color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        }
        s.link?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        s.scanned?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        TechDetails(s.details, "age-${s.request.requestId}")
        if (s.peerable && !s.checking) PeerServerButton(model)
        if (s.request.qr && !s.checking) {
            if (streamQr != null) Button(onClick = { scanning = true }, enabled = !scanning) { Text(stringResource(Res.string.age_scan_frames)) }
            else Text(stringResource(Res.string.age_no_camera), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

@Composable
internal fun BondsAgeVerifierResultView(model: WalletModel, s: OfflineUi.AgeVerifierResult) {
    val v = s.verification
    val age = s.request.minimumAge
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            v != null && !v.proofValid -> VerdictCard(Verdict.FAIL, stringResource(Res.string.age_failed), listOfNotNull(v.reason))
            v != null && v.selfIssued -> VerdictCard(Verdict.CAUTION, stringResource(Res.string.age_valid_self, age),
                listOf(stringResource(Res.string.age_valid_self_text)))
            v != null && v.accepted -> VerdictCard(Verdict.PASS, stringResource(Res.string.age_passed, age), listOf(issuerTrustLine(v.issuerTrust)))
            v != null -> VerdictCard(Verdict.CAUTION, stringResource(Res.string.age_issuer_unknown), listOfNotNull(v.reason, issuerTrustLine(v.issuerTrust)))
            s.remote != null -> VerdictCard(
                if (s.remote.accepted) Verdict.CAUTION else Verdict.FAIL,
                if (s.remote.accepted) stringResource(Res.string.age_host_reports, s.host, age) else stringResource(Res.string.age_host_failed, s.host),
                listOfNotNull(s.remote.reason, stringResource(Res.string.age_host_trust, s.host)),
            )
            else -> VerdictCard(Verdict.FAIL, stringResource(Res.string.age_not_finished), listOfNotNull(s.error))
        }
        if (v != null && v.proofValid) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(Res.string.age_evidence), style = MaterialTheme.typography.titleSmall)
                    BondsAgeVerifierFlow.summary(v).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    Text(stringResource(Res.string.age_card_issuer, BondsAgeVerifierFlow.shortDid(v.issuerDid)), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Text(stringResource(Res.string.age_purpose, s.request.purpose.ifEmpty { stringResource(Res.string.age_unstated) }), style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_done)) }
    }
}

/** How the holder's proof reaches the verifying phone. */
private enum class AgeRoute(val label: org.jetbrains.compose.resources.StringResource) {
    BLUETOOTH(Res.string.age_route_label_bluetooth),
    QR(Res.string.age_route_label_qr),
    LAN(Res.string.age_route_label_lan),
    HOST(Res.string.age_route_label_host),
}

/**
 * The Verify tab's age check: how the proof arrives, minimum age, accepted cards and purpose, then the request QR.
 * The animated QR route needs a camera that keeps scanning ([canScanFrames]).
 */
@Composable
internal fun BondsAgeVerifierSetup(model: WalletModel, canScanFrames: Boolean) {
    var ageText by remember { mutableStateOf("18") }
    var source by remember { mutableStateOf(BondsCredentialSource.TWDIW) }
    val defaultPurpose = stringResource(Res.string.age_default_purpose)
    var purpose by remember { mutableStateOf(defaultPurpose) }
    val peer by model.server.peer.collectAsState()
    val host = remember(peer) { model.server.ageHost() }
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
            Text(stringResource(Res.string.age_verify_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(Res.string.age_verify_text), style = MaterialTheme.typography.bodySmall)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AgeRoute.entries.forEach { r ->
                    FilterChip(selected = route == r, onClick = { route = r }, enabled = r == AgeRoute.HOST || available[r] == true,
                        label = { Text(stringResource(r.label)) })
                }
            }
            Text(
                when (route) {
                    AgeRoute.BLUETOOTH -> stringResource(Res.string.age_route_bluetooth_text)
                    AgeRoute.QR -> stringResource(Res.string.age_route_qr_text)
                    AgeRoute.LAN -> stringResource(Res.string.age_route_lan_text)
                    AgeRoute.HOST -> host?.let { stringResource(Res.string.age_route_host_text, it) } ?: ServerStrings.AGE_NO_HOST
                },
                style = MaterialTheme.typography.bodySmall,
                color = if (route == AgeRoute.HOST && host == null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (route == AgeRoute.HOST) PeerServerButton(model)
            OutlinedTextField(value = ageText, onValueChange = { t -> ageText = t.filter { it.isDigit() }.take(3) },
                label = { Text(stringResource(Res.string.age_minimum)) }, singleLine = true, modifier = Modifier.width(140.dp), isError = age == null)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(BondsCredentialSource.TWDIW, BondsCredentialSource.SELF_ISSUED).forEach { s ->
                    FilterChip(selected = source == s, onClick = { source = s }, label = { Text(bondsSourceLabel(s)) })
                }
            }
            OutlinedTextField(value = purpose, onValueChange = { purpose = it.take(100) }, label = { Text(stringResource(Res.string.age_purpose_label)) },
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
                Text(stringResource(Res.string.age_make_qr))
            }
        }
    }
}
