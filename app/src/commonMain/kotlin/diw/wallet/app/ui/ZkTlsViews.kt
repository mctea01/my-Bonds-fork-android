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
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
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
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import diw.wallet.app.OfflineUi
import diw.wallet.app.WalletModel
import diw.wallet.app.ZkJobPhase
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.zktls.WebProofCredentials
import diw.wallet.core.zktls.ZkTlsOutcome
import diw.wallet.core.zktls.ZkTlsPrepare
import diw.wallet.core.zktls.ZkTlsProfile
import diw.wallet.core.zktls.ZkTlsSessionRequest
import diw.wallet.core.zktls.ZkTlsTransport
import kotlinx.coroutines.delay
import kotlin.time.Clock

/** Seconds until the request expires, refreshed every second. */
@Composable
private fun secondsLeft(request: ZkTlsSessionRequest): Long {
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

private fun site(profile: ZkTlsProfile): String = profile.host + if (profile.port == 443) "" else ":${profile.port}"

/** The page and what it reveals: the status and the requested fields, never the inputs or the rest of the page. */
@Composable
private fun PageCard(profile: ZkTlsProfile, fields: List<String>, test: Boolean) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(profile.title, style = MaterialTheme.typography.titleMedium)
            Text(stringResource(Res.string.zktls_site, site(profile), profile.request.path) + if (profile.official) stringResource(Res.string.zktls_government) else "", style = MaterialTheme.typography.bodySmall)
            Text(stringResource(Res.string.zktls_discloses) + fields.mapNotNull { profile.field(it)?.label }.joinToString(stringResource(Res.string.sep_list)), style = MaterialTheme.typography.bodyMedium)
            if (profile.request.inputs.isNotEmpty()) {
                Text(stringResource(Res.string.zktls_hides) + profile.request.inputs.joinToString(stringResource(Res.string.sep_list)) { it.label } + stringResource(Res.string.zktls_hides_tail),
                    style = MaterialTheme.typography.bodySmall)
            }
            if (test) Text(stringResource(Res.string.zktls_attached_page), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error)
        }
    }
}

/** Every input filled, and the picture fetched where the page uses one. */
private fun inputsComplete(profile: ZkTlsProfile, inputs: Map<String, String>, captcha: ZkTlsPrepare.Session?): Boolean =
    profile.request.inputs.all { !inputs[it.name].isNullOrEmpty() } && (!ZkTlsPrepare.needed(profile) || captcha != null)

/** The page's inputs, with the picture code above its answer where the page uses one. */
@Composable
private fun QueryInputs(
    model: WalletModel,
    profile: ZkTlsProfile,
    inputs: MutableMap<String, String>,
    captcha: ZkTlsPrepare.Session?,
    preparing: Boolean,
    forFile: String?,
    onRefresh: () -> Unit,
) {
    val captchaInput = profile.prepare.input.takeIf { ZkTlsPrepare.needed(profile) }
    val fromFiles by model.taiwan.zkTls.documentValues.collectAsState()
    // Each picture takes its own answer.
    LaunchedEffect(captcha) { captchaInput?.let { inputs.remove(it) } }
    // A query started from a file takes that file's values; other files' values are offered below their input.
    LaunchedEffect(fromFiles, forFile) {
        fromFiles.filter { it.fileId == forFile }.forEach { v -> if (inputs[v.input].isNullOrEmpty()) inputs[v.input] = v.value }
    }
    profile.request.inputs.forEach { input ->
        if (input.name == captchaInput) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val picture = remember(captcha) { captcha?.let { model.platform.decodeImage(it.image) } }
                when {
                    picture != null -> Image(picture, contentDescription = stringResource(Res.string.zktls_captcha), contentScale = ContentScale.Fit,
                        modifier = Modifier.height(64.dp).widthIn(max = 200.dp))
                    preparing -> Text(stringResource(Res.string.zktls_captcha_loading), style = MaterialTheme.typography.bodySmall)
                    else -> Text(stringResource(Res.string.zktls_captcha_none), style = MaterialTheme.typography.bodySmall)
                }
                OutlinedButton(onClick = onRefresh, enabled = !preparing) { Text(stringResource(Res.string.zktls_captcha_new)) }
            }
        }
        OutlinedTextField(
            value = inputs[input.name].orEmpty(),
            onValueChange = { inputs[input.name] = it.trim().take(200) },
            label = { Text(input.label + if (input.isPrivate) stringResource(Res.string.zktls_not_disclosed) else "") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        fromFiles.filter { it.input == input.name && it.value != inputs[input.name] }.forEach { v ->
            TextButton(onClick = { inputs[input.name] = v.value }) { Text(stringResource(Res.string.zktls_fill_from, v.fileName, input.label)) }
        }
    }
}

@Composable
internal fun ZkTlsConsentView(model: WalletModel, s: OfflineUi.ZkTlsConsent) {
    val request = s.session.request
    val inputs = remember(s.session.jws) { mutableStateMapOf<String, String>() }
    var confirm by remember(s) { mutableStateOf(false) }
    // A query started from a file keeps its result by default, as that file's evidence.
    var keep by remember(s.session.jws) { mutableStateOf(s.forFile != null) }
    val left = secondsLeft(request)
    val captchaInput = s.profile.prepare.input.takeIf { ZkTlsPrepare.needed(s.profile) }
    val complete = inputsComplete(s.profile, inputs, s.captcha)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        TrustCard(stringResource(Res.string.role_verifier), s.verifier, s.trust, listOf(stringResource(Res.string.zktls_purpose_inline) + request.purpose.ifEmpty { stringResource(Res.string.age_unstated) }))
        PageCard(s.profile, request.fields, s.inline)
        Text(stringResource(Res.string.zktls_consent_text),
            style = MaterialTheme.typography.bodySmall)
        if (captchaInput != null) {
            Text(stringResource(Res.string.zktls_captcha_note), style = MaterialTheme.typography.bodySmall)
        }
        QueryInputs(model, s.profile, inputs, s.captcha, s.preparing, s.forFile) { model.taiwan.zkTls.refreshCaptcha(s) }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = keep, onCheckedChange = { keep = it })
            Column {
                Text(stringResource(Res.string.zktls_save_result), style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(Res.string.zktls_save_result_text),
                    style = MaterialTheme.typography.bodySmall)
            }
        }
        s.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        s.routeHint?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        HolderServerButton(model)
        Text(if (left > 0) stringResource(Res.string.age_time_left, clock(left)) else stringResource(Res.string.age_expired), style = MaterialTheme.typography.bodySmall,
            color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { if (s.trust.tier == TrustTier.T4) confirm = true else model.taiwan.zkTls.prove(s, inputs.toMap(), keep) },
                enabled = left > 0 && complete,
            ) { Text(stringResource(Res.string.zktls_query_prove)) }
            OutlinedButton(onClick = { model.taiwan.zkTls.leave(s.forFile) }) { Text(stringResource(Res.string.action_cancel)) }
        }
    }
    if (confirm) {
        RiskConfirmDialog(
            title = stringResource(Res.string.zktls_untrusted_title),
            lines = listOf(stringResource(Res.string.zktls_untrusted_text), stringResource(Res.string.zktls_untrusted_sees)),
            confirm = stringResource(Res.string.flow_present_anyway_short),
            onConfirm = { confirm = false; model.taiwan.zkTls.prove(s, inputs.toMap(), keep) },
            onDismiss = { confirm = false },
        )
    }
}

@Composable
internal fun ZkTlsProvingView(model: WalletModel, s: OfflineUi.ZkTlsProving) {
    val jobs by model.zk.jobs.collectAsState()
    val job = jobs[s.jobId]
    val left = secondsLeft(s.consent.session.request)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        PageCard(s.consent.profile, s.consent.session.request.fields, s.consent.inline)
        Text(
            when {
                job?.step != null -> job.step!!
                job?.phase == ZkJobPhase.QUEUED -> stringResource(Res.string.zkpdf_waiting)
                else -> stringResource(Res.string.zktls_connecting)
            },
            style = MaterialTheme.typography.titleMedium,
        )
        LinearProgressIndicator(Modifier.fillMaxWidth())
        Text(stringResource(Res.string.zktls_querying_with, s.consent.verifier, s.consent.profile.host), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(Res.string.age_time_left, clock(left)), style = MaterialTheme.typography.bodySmall,
            color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        OutlinedButton(onClick = { model.taiwan.zkTls.cancel(s) }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

/** The values the verifier reads back, under the page's labels. */
@Composable
private fun outcomeLines(o: ZkTlsOutcome, fields: List<String>): List<String> = buildList {
    add(stringResource(Res.string.zktls_status_line) + (o.statusText?.let { WebProofCredentials.plainStatus(it) } ?: stringResource(Res.string.zktls_status_hidden)) + if (o.found) stringResource(Res.string.zktls_found) else "")
    fields.forEach { name ->
        val label = o.profile.field(name)?.label ?: name
        add(stringResource(Res.string.label_colon, label) + (o.fields[name] ?: stringResource(Res.string.zktls_no_field)))
    }
}

@Composable
private fun serverLines(name: String, time: Long, trust: TrustDecision?): List<String> = buildList {
    add(stringResource(Res.string.zktls_site_verified, name))
    if (time > 0) add(stringResource(Res.string.zktls_queried_at, localTime(time)))
    trust?.let { add(stringResource(Res.string.zktls_site_trust, WalletModel.tierTitle(it.tier)) + (it.anchorName?.let { a -> stringResource(Res.string.parenthesized, a) } ?: "")) }
}

@Composable
internal fun ZkTlsHolderResultView(model: WalletModel, s: OfflineUi.ZkTlsHolderResult) {
    val proved = s.proved
    val fields = s.consent.session.request.fields
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            proved == null -> VerdictCard(Verdict.FAIL, stringResource(Res.string.zktls_not_finished), listOfNotNull(s.error))
            proved.outcome.passed -> VerdictCard(Verdict.PASS, stringResource(Res.string.zktls_proved_to, s.consent.verifier), listOf(stringResource(Res.string.zktls_proved_sees)))
            else -> VerdictCard(Verdict.CAUTION, stringResource(Res.string.zktls_sent_failed), proved.outcome.problems.ifEmpty { listOf(stringResource(Res.string.zktls_sent_failed_text)) })
        }
        if (proved != null) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(Res.string.zktls_seen), style = MaterialTheme.typography.titleSmall)
                    outcomeLines(proved.outcome, fields).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    serverLines(proved.serverName, proved.time, s.serverTrust).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            }
            s.kept?.let { k ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(if (k.receipt) stringResource(Res.string.zktls_saved_proof) else stringResource(Res.string.zktls_saved_local), style = MaterialTheme.typography.titleSmall)
                        Text(
                            if (k.receipt) stringResource(Res.string.zktls_saved_proof_text, s.consent.verifier)
                            else stringResource(Res.string.zktls_saved_local_text),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        k.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
                    }
                }
            }
            s.keepError?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            TechDetails(listOf(
                stringResource(Res.string.zktls_transport) + when (val t = proved.transport) {
                    is ZkTlsTransport.Lan -> stringResource(Res.string.zktls_transport_lan, t.host, t.port)
                    is ZkTlsTransport.Relay -> stringResource(Res.string.zktls_transport_relay, t.url)
                    is ZkTlsTransport.Wss -> stringResource(Res.string.zktls_transport_host, t.url)
                },
                stringResource(Res.string.zktls_cipher, proved.cipherSuite),
                stringResource(Res.string.zktls_chain, proved.certChainDer.size),
                stringResource(Res.string.zktls_disclosed_bytes) + proved.plan.received.joinToString(", ") { "${it.start}-${it.end}" },
            ), "zktls-holder-${s.consent.session.request.sessionId}")
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (s.retry) Button(onClick = { model.taiwan.zkTls.retry(s.consent) }) { Text(stringResource(Res.string.action_retry)) }
            OutlinedButton(onClick = { model.taiwan.zkTls.leave(s.consent.forFile) }) { Text(if (s.consent.forFile != null) stringResource(Res.string.zktls_back_to_document) else stringResource(Res.string.action_done)) }
        }
    }
}

@Composable
internal fun ZkTlsVerifierSetupView(model: WalletModel, s: OfflineUi.ZkTlsVerifierSetup) {
    var index by remember(s) { mutableStateOf(0) }
    val page = s.pages.getOrNull(index)
    val chosen = remember(page) { mutableStateMapOf<String, Boolean>().apply { page?.fields?.forEach { put(it.name, true) } } }
    val purposeDefault = stringResource(Res.string.zktls_eligibility)
    var purpose by remember { mutableStateOf(purposeDefault) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.zktls_verifier_text),
            style = MaterialTheme.typography.bodyMedium)
        s.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        PeerServerButton(model)
        if (s.pages.isEmpty()) {
            OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_back)) }
            return@Column
        }
        Text(stringResource(Res.string.zktls_page), style = MaterialTheme.typography.titleSmall)
        s.pages.forEachIndexed { i, p ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = i == index, onClick = { index = i })
                Column {
                    Text(p.title + if (p.id in s.testPages) stringResource(Res.string.test_suffix) else "")
                    Text(site(p), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        if (page != null) {
            Text(stringResource(Res.string.zktls_fields_to_disclose), style = MaterialTheme.typography.titleSmall)
            page.fields.forEach { f ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = chosen[f.name] == true, onCheckedChange = { chosen[f.name] = it })
                    Text(f.label)
                }
            }
        }
        OutlinedTextField(value = purpose, onValueChange = { purpose = it.take(ZkTlsSessionRequest.MAX_PURPOSE) },
            label = { Text(stringResource(Res.string.age_purpose_label)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        val fields = page?.fields?.map { it.name }?.filter { chosen[it] == true }.orEmpty()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.taiwan.zkTls.startVerifier(page!!, fields, purpose.trim()) }, enabled = page != null && fields.isNotEmpty() && purpose.isNotBlank()) {
                Text(stringResource(Res.string.zktls_make_qr))
            }
            OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
        }
    }
}

@Composable
internal fun ZkTlsVerifierWaitingView(model: WalletModel, s: OfflineUi.ZkTlsVerifierWaiting) {
    val left = secondsLeft(s.request)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        Text(stringResource(Res.string.age_scan_with_wallet), style = MaterialTheme.typography.titleMedium)
        QrImage(s.link, Modifier.fillMaxWidth().widthIn(max = 420.dp))
        PageCard(s.profile, s.request.fields, s.request.profileDefinition != null)
        Text(
            if (s.local) stringResource(Res.string.zktls_verify_local, s.where)
            else stringResource(Res.string.age_verify_host, s.where),
            style = MaterialTheme.typography.bodySmall,
        )
        s.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        if (s.step != null) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(s.step, style = MaterialTheme.typography.titleSmall)
        } else {
            Text(if (left > 0) stringResource(Res.string.age_waiting, clock(left)) else stringResource(Res.string.zktls_expired), style = MaterialTheme.typography.bodySmall,
                color = if (left > 60) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
        }
        TechDetails(s.details, "zktls-${s.request.sessionId}")
        if (s.local && s.step == null) PeerServerButton(model)
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

@Composable
internal fun ZkTlsVerifierResultView(model: WalletModel, s: OfflineUi.ZkTlsVerifierResult) {
    val o = s.outcome
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            o == null -> VerdictCard(Verdict.FAIL, stringResource(Res.string.zktls_not_finished), listOfNotNull(s.error))
            o.passed && s.local -> VerdictCard(Verdict.PASS, stringResource(Res.string.zktls_passed, s.profile.title), listOf(stringResource(Res.string.zktls_passed_local)))
            o.passed -> VerdictCard(Verdict.CAUTION, stringResource(Res.string.zktls_host_passed, s.where), listOf(stringResource(Res.string.age_host_trust, s.where)))
            else -> VerdictCard(Verdict.FAIL, stringResource(Res.string.age_failed), o.problems + o.missing.map { stringResource(Res.string.zktls_missing) + (s.profile.field(it)?.label ?: it) } +
                listOfNotNull(stringResource(Res.string.zktls_status_was, (o.statusText?.let { WebProofCredentials.plainStatus(it) }).toString()).takeIf { o.statusText != null && !o.found }))
        }
        if (o != null) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(Res.string.zktls_evidence), style = MaterialTheme.typography.titleSmall)
                    outcomeLines(o, s.request.fields).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    serverLines(o.serverName, o.time, s.serverTrust).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    Text(stringResource(Res.string.zktls_values_note), style = MaterialTheme.typography.bodySmall)
                    if (s.receipt) Text(stringResource(Res.string.zktls_receipt_issued), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Text(stringResource(Res.string.age_purpose, s.request.purpose.ifEmpty { stringResource(Res.string.age_unstated) }), style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_done)) }
    }
}

@Composable
internal fun ZkTlsSelfPickView(model: WalletModel, s: OfflineUi.ZkTlsSelfPick) {
    var index by remember(s) { mutableStateOf(0) }
    val page = s.pages.getOrNull(index)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.zktls_self_intro) + if (s.fileId != null) stringResource(Res.string.zktls_self_intro_doc) else stringResource(Res.string.zktls_self_intro_save), style = MaterialTheme.typography.bodyMedium)
        s.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        if (s.pages.isEmpty()) {
            OutlinedButton(onClick = { model.taiwan.zkTls.leave(s.fileId) }) { Text(stringResource(Res.string.action_back)) }
            return@Column
        }
        Text(stringResource(Res.string.zktls_page), style = MaterialTheme.typography.titleSmall)
        s.pages.forEachIndexed { i, p ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = i == index, onClick = { index = i })
                Column {
                    Text(p.title + if (p.id in s.testPages) stringResource(Res.string.test_suffix) else "")
                    Text(site(p), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        if (page != null) {
            Text(stringResource(Res.string.zktls_saved_fields) + page.fields.joinToString(stringResource(Res.string.sep_list)) { it.label }, style = MaterialTheme.typography.bodySmall)
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(Res.string.zktls_via_host), style = MaterialTheme.typography.titleSmall)
                    Text(
                        s.host?.let { stringResource(Res.string.zktls_via_host_text, it) }
                            ?: stringResource(Res.string.zktls_no_host),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(Res.string.zktls_phone_only), style = MaterialTheme.typography.titleSmall)
                    Text(stringResource(Res.string.zktls_phone_only_text),
                        style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Button(onClick = { model.taiwan.zkTls.selfThroughHost(s, page!!) }, enabled = page != null && s.host != null) { Text(stringResource(Res.string.zktls_make_via_host)) }
        OutlinedButton(onClick = { model.taiwan.zkTls.selfDirect(s, page!!) }, enabled = page != null) { Text(stringResource(Res.string.zktls_query_save_phone)) }
        OutlinedButton(onClick = { model.taiwan.zkTls.leave(s.fileId) }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

@Composable
internal fun ZkTlsSelfView(model: WalletModel, s: OfflineUi.ZkTlsSelf) {
    val inputs = remember(s.profile.id) { mutableStateMapOf<String, String>() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        PageCard(s.profile, s.profile.fields.map { it.name }, false)
        Text(stringResource(Res.string.zktls_self_text), style = MaterialTheme.typography.bodySmall)
        QueryInputs(model, s.profile, inputs, s.captcha, s.preparing, s.fileId) { model.taiwan.zkTls.refreshSelfCaptcha(s) }
        s.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        if (s.working) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(stringResource(Res.string.zktls_querying, s.profile.host), style = MaterialTheme.typography.bodySmall)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.taiwan.zkTls.queryDirect(s, inputs.toMap()) }, enabled = !s.working && inputsComplete(s.profile, inputs, s.captcha)) {
                Text(stringResource(Res.string.zktls_query_save))
            }
            OutlinedButton(onClick = { model.taiwan.zkTls.leave(s.fileId) }) { Text(stringResource(Res.string.action_cancel)) }
        }
    }
}

@Composable
internal fun ZkTlsSelfResultView(model: WalletModel, s: OfflineUi.ZkTlsSelfResult) {
    val o = s.outcome
    val fields = s.state.profile.fields.map { it.name }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            o == null -> VerdictCard(Verdict.FAIL, stringResource(Res.string.zktls_query_not_finished), listOfNotNull(s.error))
            o.passed -> VerdictCard(Verdict.PASS, stringResource(Res.string.zktls_found_data, s.state.profile.title), listOf(stringResource(Res.string.zktls_found_data_text)))
            else -> VerdictCard(Verdict.FAIL, stringResource(Res.string.zktls_no_data), o.problems + o.missing.map { stringResource(Res.string.zktls_page_lacks) + (s.state.profile.field(it)?.label ?: it) } +
                listOfNotNull(stringResource(Res.string.zktls_status_was, (o.statusText?.let { WebProofCredentials.plainStatus(it) }).toString()).takeIf { o.statusText != null && !o.found }))
        }
        if (o != null) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(Res.string.zktls_read), style = MaterialTheme.typography.titleSmall)
                    outcomeLines(o, fields).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                    serverLines(o.serverName, o.time, s.serverTrust).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
        s.kept?.let { k ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(Res.string.zktls_saved_local), style = MaterialTheme.typography.titleSmall)
                    Text(stringResource(Res.string.zktls_saved_local_text_short) +
                        if (s.state.fileId != null) stringResource(Res.string.zktls_also_evidence) else stringResource(Res.string.sentence_end), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        s.fetched?.let { f ->
            TechDetails(listOf(
                stringResource(Res.string.zktls_version, f.protocol.toString()),
                stringResource(Res.string.zktls_cipher, f.cipherSuite.toString()),
                stringResource(Res.string.zktls_chain, f.certChainDer.size),
                stringResource(Res.string.zktls_size, f.received.size),
            ), "zktls-self-${s.state.profile.id}")
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (s.kept == null) Button(onClick = { model.taiwan.zkTls.retrySelf(s) }) { Text(stringResource(Res.string.action_retry)) }
            OutlinedButton(onClick = { model.taiwan.zkTls.leave(s.state.fileId) }) { Text(if (s.state.fileId != null) stringResource(Res.string.zktls_back_to_document) else stringResource(Res.string.action_done)) }
        }
    }
}
