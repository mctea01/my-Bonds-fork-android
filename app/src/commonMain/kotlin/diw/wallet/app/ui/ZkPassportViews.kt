package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import diw.wallet.app.OfflineUi
import diw.wallet.app.WalletModel
import diw.wallet.app.ZkPassportFlow
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.zkpassport.ZkPassport
import diw.wallet.core.zkpassport.ZkPassportAnswerProgress
import diw.wallet.core.zkpassport.ZkPassportField
import diw.wallet.core.zkpassport.ZkPassportProverTarget
import diw.wallet.core.zkpassport.ZkPassportPairingLink
import kotlinx.coroutines.launch
import diw.wallet.core.zkpassport.ZkPassportRequest
import diw.wallet.core.zkpassport.ZkPassportState
import org.jetbrains.compose.resources.stringResource

@Composable
internal fun ZkPassportSetupView(model: WalletModel, s: OfflineUi.ZkPassportSetup) {
    var domain by remember(s) { mutableStateOf(s.domain) }
    val purposeDefault = stringResource(Res.string.verify_identity)
    var purpose by remember { mutableStateOf(purposeDefault) }
    val nameDefault = stringResource(Res.string.zkp_service_default)
    var name by remember { mutableStateOf(nameDefault) }
    val chosen = remember { mutableStateMapOf<ZkPassportField, Boolean>() }
    var age by remember { mutableStateOf("") }
    var nationalityIn by remember { mutableStateOf("") }
    var nationalityOut by remember { mutableStateOf("") }
    var issuingIn by remember { mutableStateOf("") }
    var custom by remember { mutableStateOf("") }
    var dev by remember { mutableStateOf(false) }
    val domainProblem = if (domain.isBlank()) null else ZkPassportFlow.domainProblem(domain)
    val minAge = age.trim().takeIf { it.isNotEmpty() }?.toIntOrNull()
    val ageProblem = age.isNotBlank() && (minAge == null || minAge !in 1..120)
    val inList = ZkPassportFlow.countries(nationalityIn)
    val outList = ZkPassportFlow.countries(nationalityOut)
    val issuingList = ZkPassportFlow.countries(issuingIn)
    val countryProblem = stringResource(Res.string.zkp_countries_invalid)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.zkp_setup_text), style = MaterialTheme.typography.bodyMedium)
        s.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        OutlinedTextField(
            value = domain, onValueChange = { domain = it.trim().take(253) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(Res.string.zkp_domain)) }, isError = domainProblem != null,
            supportingText = { Text(domainProblem ?: stringResource(Res.string.zkp_domain_note)) },
        )
        OutlinedTextField(value = name, onValueChange = { name = it.take(60) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(Res.string.zkp_service_name)) })
        OutlinedTextField(value = purpose, onValueChange = { purpose = it.take(200) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(Res.string.age_purpose_label)) })
        Text(stringResource(Res.string.zkp_disclose), style = MaterialTheme.typography.titleSmall)
        Text(stringResource(Res.string.zkp_always_disclosed), style = MaterialTheme.typography.bodySmall)
        ZkPassportFlow.OPTIONAL_FIELDS.forEach { f ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = chosen[f] == true, onCheckedChange = { chosen[f] = it })
                Text(ZkPassportFlow.fieldTitle(f))
            }
        }
        Text(stringResource(Res.string.zkp_conditions), style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(
            value = age, onValueChange = { age = it.filter(Char::isDigit).take(3) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            label = { Text(stringResource(Res.string.zkp_min_age)) }, isError = ageProblem,
        )
        OutlinedTextField(
            value = nationalityIn, onValueChange = { nationalityIn = it.take(1200) }, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(Res.string.zkp_nationality_in_label)) }, isError = inList == null,
            supportingText = { Text(if (inList == null) countryProblem else stringResource(Res.string.zkp_countries_note)) },
        )
        OutlinedTextField(
            value = nationalityOut, onValueChange = { nationalityOut = it.take(1200) }, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(Res.string.zkp_nationality_out_label)) }, isError = outList == null,
            supportingText = if (outList == null) { { Text(countryProblem) } } else null,
        )
        OutlinedTextField(
            value = issuingIn, onValueChange = { issuingIn = it.take(1200) }, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(Res.string.zkp_issuing_in_label)) }, isError = issuingList == null,
            supportingText = if (issuingList == null) { { Text(countryProblem) } } else null,
        )
        OutlinedTextField(
            value = custom, onValueChange = { custom = it.take(400) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(Res.string.zkp_custom_data)) },
            supportingText = { Text(stringResource(Res.string.zkp_custom_data_note)) },
        )
        if (s.test) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Switch(checked = dev, onCheckedChange = { dev = it })
                Column {
                    Text(stringResource(Res.string.zkp_dev_mode))
                    Text(stringResource(Res.string.zkp_dev_mode_note), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        val ready = domain.isNotBlank() && domainProblem == null && name.isNotBlank() && purpose.isNotBlank() && !ageProblem &&
            inList != null && outList != null && issuingList != null && s.note == null
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    model.taiwan.zkPassport.start(
                        ZkPassportRequest(
                            domain = domain, name = name.trim(), purpose = purpose.trim(),
                            disclose = chosen.filterValues { it }.keys,
                            minAge = minAge,
                            nationalityIn = inList.orEmpty(), nationalityOut = outList.orEmpty().sorted(),
                            issuingCountryIn = issuingList.orEmpty(),
                            customData = custom.trim().ifEmpty { null },
                            devMode = s.test && dev,
                        ),
                    )
                },
                enabled = ready,
            ) { Text(stringResource(Res.string.zktls_make_qr)) }
            OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
        }
    }
}

@Composable
internal fun ZkPassportWaitingView(model: WalletModel, s: OfflineUi.ZkPassportWaiting) {
    val showQr = s.url != null && (s.state is ZkPassportState.Waiting || s.state is ZkPassportState.Scanned)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally) {
        if (showQr) {
            Text(stringResource(Res.string.zkp_scan_with_app), style = MaterialTheme.typography.titleMedium)
            QrImage(s.url!!, Modifier.fillMaxWidth().widthIn(max = 420.dp))
            val noApp = stringResource(Res.string.zkp_no_app)
            TextButton(onClick = { if (!model.platform.openExternal(s.url)) model.message.value = noApp }) {
                Text(stringResource(Res.string.zkp_open_here))
            }
        }
        Text(ZkPassport.normalizeDomain(s.request.domain) + stringResource(Res.string.zkp_unverified_suffix), style = MaterialTheme.typography.bodySmall)
        when (val st = s.state) {
            is ZkPassportState.Receiving -> LinearProgressIndicator(
                progress = { if (st.total <= 0) 0f else st.received.toFloat() / st.total }, modifier = Modifier.fillMaxWidth(),
            )
            is ZkPassportState.Waiting -> {}
            else -> LinearProgressIndicator(Modifier.fillMaxWidth())
        }
        Text(
            when (val st = s.state) {
                ZkPassportState.Connecting -> stringResource(Res.string.zkp_state_connecting)
                is ZkPassportState.Waiting -> stringResource(Res.string.zkp_state_waiting)
                is ZkPassportState.Scanned -> stringResource(Res.string.zkp_state_scanned)
                ZkPassportState.Generating -> stringResource(Res.string.zkp_state_generating)
                is ZkPassportState.Receiving -> stringResource(Res.string.zkp_state_receiving, st.received, st.total)
                ZkPassportState.Verifying -> stringResource(Res.string.zkp_state_verifying)
                else -> stringResource(Res.string.state_processing)
            },
            style = MaterialTheme.typography.titleSmall,
        )
        TechDetails(listOfNotNull(s.url), "zkpassport-request")
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

@Composable
internal fun ZkPassportResultView(model: WalletModel, s: OfflineUi.ZkPassportVerified) {
    val r = s.result
    val domain = ZkPassport.normalizeDomain(s.request.domain)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            r == null -> VerdictCard(Verdict.FAIL, stringResource(Res.string.zkp_not_finished), listOfNotNull(s.error))
            !r.verified && r.errors.any { it.startsWith("backend_legacy:") } -> {
                VerdictCard(Verdict.CAUTION, stringResource(Res.string.zkp_not_checked), ZkPassportFlow.problems(r.errors))
                ZkPassportLegacyComponent(model, status = false)
            }
            !r.verified -> VerdictCard(Verdict.FAIL, stringResource(Res.string.zkp_failed), ZkPassportFlow.problems(r.errors))
            else -> {
                val caveats = buildList {
                    if (r.devMode) add(stringResource(Res.string.zkp_test_caveat))
                    if (r.viaVerifierApi) add(stringResource(Res.string.zkp_api_caveat))
                    add(ZkPassportFlow.trust(r.csca))
                    add(stringResource(Res.string.zkp_domain_caveat, domain))
                }
                VerdictCard(
                    if (r.devMode || r.viaVerifierApi || r.csca?.allAnchored != true) Verdict.CAUTION else Verdict.PASS,
                    if (r.devMode) stringResource(Res.string.zkp_passed_test) else stringResource(Res.string.zkp_passed),
                    caveats,
                )
            }
        }
        if (r != null && r.verified) {
            SectionTitle(stringResource(Res.string.zkp_proved))
            ZkPassportFlow.claims(r).forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
            r.proofDate?.let { Text(stringResource(Res.string.zkp_proof_date, isoDate(it)), style = MaterialTheme.typography.bodySmall) }
            r.uniqueIdentifier?.let {
                Text(stringResource(Res.string.zkp_identifier, it.take(12) + "…"), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(Res.string.zkp_identifier_note), style = MaterialTheme.typography.bodySmall)
            }
        }
        TechDetails(
            buildList {
                r?.version?.let { add(stringResource(Res.string.zkp_tech_version, it)) }
                r?.identifierType?.let { add(stringResource(Res.string.zkp_tech_identifier_type, it)) }
                r?.uniqueIdentifier?.let { add(stringResource(Res.string.zkp_tech_identifier, it)) }
                if (r != null && r.errors.isNotEmpty()) add(stringResource(Res.string.zkp_tech_errors, r.errors.joinToString(", ")))
                add(stringResource(Res.string.zkp_tech_domain, domain))
                s.request.scope?.let { add(stringResource(Res.string.zkp_tech_scope, it)) }
            },
            "zkpassport-result",
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.taiwan.zkPassport.start(s.request) }) { Text(stringResource(Res.string.zkp_again)) }
            OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_back)) }
        }
    }
}

@Composable
internal fun ZkPassportAnswerConnectingView(model: WalletModel, s: OfflineUi.ZkPassportAnswerConnecting) {
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(Res.string.zkp_answer_title), style = MaterialTheme.typography.titleMedium)
        Text(s.incoming.domain + stringResource(Res.string.zkp_answer_unverified), style = MaterialTheme.typography.bodyMedium)
        LinearProgressIndicator(Modifier.fillMaxWidth())
        Text(stringResource(Res.string.zkp_answer_connecting), style = MaterialTheme.typography.titleSmall)
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

/**
 * The holder's consent to a zkPassport request: who asks (as the link and the bridge say, neither verified), what the
 * proofs would establish, and the stored passport to prove it from. A relayed link (another origin) needs a risk
 * confirmation before the proofs are made.
 */
@Composable
internal fun ZkPassportAnswerConsentView(model: WalletModel, s: OfflineUi.ZkPassportAnswerConsent) {
    val incoming = s.incoming
    var chosen by remember(s) { mutableStateOf(s.passports.firstOrNull()?.id) }
    var risk by remember(s) { mutableStateOf(false) }
    val paired by model.taiwan.zkPassport.paired.collectAsState()
    val targets = remember(s, paired) { model.taiwan.zkPassport.targets() }
    val deviceCan = model.taiwan.zkPassport.deviceCanProve()
    // A paired prover was set up for this; otherwise this device, unless it cannot prove.
    var target by remember(s, paired) {
        mutableStateOf(
            targets.firstOrNull { it is ZkPassportProverTarget.Paired }
                ?: if (deviceCan == false) targets.firstOrNull { it != ZkPassportProverTarget.Device } ?: ZkPassportProverTarget.Device
                else ZkPassportProverTarget.Device,
        )
    }
    val unverified = stringResource(Res.string.zkp_answer_unverified)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.zkp_answer_title), style = MaterialTheme.typography.titleMedium)
        // Another page of the same site (zkPassport's demo answers through verify.zkpassport.id) is a caution only.
        val sameSite = !s.originMatches && incoming.sameSite(s.origin)
        if (sameSite) {
            VerdictCard(Verdict.CAUTION, stringResource(Res.string.zkp_answer_origin_same_site), listOf(stringResource(Res.string.zkp_answer_origin_same_site_detail, s.origin, incoming.expectedOrigin)))
        } else if (!s.originMatches) {
            VerdictCard(Verdict.FAIL, stringResource(Res.string.zkp_answer_origin_mismatch), listOf(stringResource(Res.string.zkp_answer_origin_detail, s.origin, incoming.expectedOrigin)))
        }
        if (incoming.devMode) Text(stringResource(Res.string.zkp_answer_dev), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        Text(stringResource(Res.string.zkp_answer_from, incoming.domain) + unverified, style = MaterialTheme.typography.bodyLarge)
        incoming.name?.takeIf { it.isNotBlank() }?.let { Text(stringResource(Res.string.zkp_answer_service, it) + unverified, style = MaterialTheme.typography.bodyMedium) }
        incoming.purpose?.takeIf { it.isNotBlank() }?.let { Text(stringResource(Res.string.zkp_answer_purpose, it) + unverified, style = MaterialTheme.typography.bodyMedium) }
        SectionTitle(stringResource(Res.string.zkp_answer_asks))
        ZkPassportFlow.asks(incoming.query).forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
        s.unsupported?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error) }
        if (s.unsupported == null) {
            SectionTitle(stringResource(Res.string.zkp_answer_choose))
            if (s.passports.isEmpty()) Text(stringResource(Res.string.zkp_answer_no_passport), style = MaterialTheme.typography.bodyMedium)
            s.passports.forEach { f ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = chosen == f.id, onClick = { chosen = f.id })
                    Text(f.name, style = MaterialTheme.typography.bodyMedium)
                }
            }
            // The values the chosen passport would send, read as zkPassport reads them.
            val picked = s.passports.firstOrNull { it.id == chosen }
            val preview by produceState(emptyList<String>() to false, picked) {
                value = picked?.let { model.taiwan.zkPassport.preview(it, incoming.query) } ?: (emptyList<String>() to false)
            }
            if (preview.first.isNotEmpty()) {
                SectionTitle(stringResource(Res.string.zkp_answer_preview))
                preview.first.forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
                if (preview.second) Text(stringResource(Res.string.zkp_answer_firstname_cut), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            if (targets.size > 1 || deviceCan == false) {
                SectionTitle(stringResource(Res.string.zkp_answer_where))
                targets.forEach { t ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = target == t, onClick = { target = t })
                        Text(
                            when (t) {
                                ZkPassportProverTarget.Device -> stringResource(Res.string.zkp_answer_where_device)
                                is ZkPassportProverTarget.Host -> stringResource(Res.string.zkp_answer_where_host, t.url)
                                is ZkPassportProverTarget.Paired -> stringResource(Res.string.zkp_answer_where_paired, t.prover.url)
                            },
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
                if (deviceCan == false && target == ZkPassportProverTarget.Device) {
                    Text(stringResource(Res.string.zkp_answer_where_device_missing), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
            // Passport data leaves this device only to the owner's prover the holder picked here.
            ZkPassportFlow.targetAddress(target)?.let { address ->
                Text(stringResource(Res.string.zkp_answer_where_note, address), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
            }
            Text(stringResource(Res.string.zkp_answer_note), style = MaterialTheme.typography.bodySmall)
        }
        TechDetails(
            listOf(
                stringResource(Res.string.zkp_tech_domain, incoming.domain),
                stringResource(Res.string.zkp_answer_tech_origin, s.origin),
                stringResource(Res.string.zkp_answer_tech_mode, incoming.mode, incoming.sdkVersion ?: "-"),
            ) + listOfNotNull(incoming.scope?.let { stringResource(Res.string.zkp_tech_scope, it) }) + incoming.query.toString(),
            "zkpassport-answer",
        )
        val file = s.passports.firstOrNull { it.id == chosen }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { if (s.originMatches || sameSite) model.taiwan.zkPassport.accept(file!!, target) else risk = true },
                enabled = s.unsupported == null && file != null,
            ) { Text(stringResource(Res.string.zkp_answer_accept)) }
            OutlinedButton(onClick = { model.taiwan.zkPassport.reject() }) { Text(stringResource(Res.string.zkp_answer_reject)) }
        }
    }
    if (risk) {
        RiskConfirmDialog(
            stringResource(Res.string.zkp_answer_risk_title),
            listOf(stringResource(Res.string.zkp_answer_origin_detail, s.origin, incoming.expectedOrigin)),
            stringResource(Res.string.zkp_answer_risk_confirm),
            onConfirm = {
                risk = false
                s.passports.firstOrNull { it.id == chosen }?.let { model.taiwan.zkPassport.accept(it, target) }
            },
            onDismiss = { risk = false },
        )
    }
}

@Composable
internal fun ZkPassportAnswerProvingView(model: WalletModel, s: OfflineUi.ZkPassportAnswerProving) {
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(Res.string.zkp_answer_title), style = MaterialTheme.typography.titleMedium)
        when (val p = s.progress) {
            is ZkPassportAnswerProgress.Proving -> LinearProgressIndicator(
                progress = { if (p.total <= 0) 0f else p.index.toFloat() / p.total }, modifier = Modifier.fillMaxWidth(),
            )
            else -> LinearProgressIndicator(Modifier.fillMaxWidth())
        }
        Text(
            when (val p = s.progress) {
                null, ZkPassportAnswerProgress.Registry -> stringResource(Res.string.zkp_answer_registry)
                is ZkPassportAnswerProgress.Circuits -> stringResource(Res.string.zkp_answer_circuits, p.count)
                is ZkPassportAnswerProgress.Proving -> stringResource(Res.string.zkp_answer_proving, p.index + 1, p.total, p.name)
                ZkPassportAnswerProgress.Sending -> stringResource(Res.string.zkp_answer_sending)
            },
            style = MaterialTheme.typography.titleSmall,
        )
        Text(stringResource(Res.string.zkp_answer_wait), style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
    }
}

@Composable
internal fun ZkPassportAnswerDoneView(model: WalletModel, s: OfflineUi.ZkPassportAnswerDone) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            s.sent -> VerdictCard(Verdict.PASS, stringResource(Res.string.zkp_answer_sent), listOf(stringResource(Res.string.zkp_answer_sent_note, s.incoming.domain)))
            s.error != null -> VerdictCard(Verdict.FAIL, stringResource(Res.string.zkp_answer_failed), listOf(s.error))
            else -> VerdictCard(Verdict.CAUTION, stringResource(Res.string.zkp_answer_declined))
        }
        OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_back)) }
    }
}

/** Unix seconds as YYYY-MM-DD (UTC; the proofs carry a date, not a time). */
private fun isoDate(epochSeconds: Long): String =
    kotlin.time.Instant.fromEpochSeconds(epochSeconds).toString().substringBefore('T')

/**
 * zkPassport settings: the domain requests are made for, the Ethereum nodes the registries are read from (empty uses
 * the built-in public nodes) and whether zkPassport's verifier service may decide when this device cannot.
 */
@Composable
internal fun ZkPassportSettingsSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    var domain by remember(settings.zkPassportDomain) { mutableStateOf(settings.zkPassportDomain) }
    var mainnet by remember(settings.zkPassportMainnetRpc) { mutableStateOf(settings.zkPassportMainnetRpc) }
    var sepolia by remember(settings.zkPassportSepoliaRpc) { mutableStateOf(settings.zkPassportSepoliaRpc) }
    val domainProblem = if (domain.isBlank()) null else ZkPassportFlow.domainProblem(domain)
    val rpcProblem = stringResource(Res.string.zkp_rpc_invalid)
    fun bad(url: String) = url.isNotEmpty() && !(url.startsWith("https://") && url.length > 8)
    Text(stringResource(Res.string.zkp_settings_text), style = MaterialTheme.typography.bodySmall)
    ZkPassportReadiness(model)
    OutlinedTextField(
        value = domain, onValueChange = { domain = it.trim().take(253) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(Res.string.zkp_domain)) }, isError = domainProblem != null,
        supportingText = {
            val server = model.taiwan.zkPassport.serverDomain()
            Text(domainProblem ?: if (server.isEmpty()) stringResource(Res.string.zkp_domain_none) else stringResource(Res.string.zkp_domain_server, server))
        },
    )
    OutlinedTextField(
        value = mainnet, onValueChange = { mainnet = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(Res.string.zkp_rpc_mainnet)) }, isError = bad(mainnet),
        supportingText = { Text(if (bad(mainnet)) rpcProblem else stringResource(Res.string.zkp_rpc_default, ZkPassport.MAINNET_RPC)) },
    )
    OutlinedTextField(
        value = sepolia, onValueChange = { sepolia = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(Res.string.zkp_rpc_sepolia)) }, isError = bad(sepolia),
        supportingText = { Text(if (bad(sepolia)) rpcProblem else stringResource(Res.string.zkp_rpc_default, ZkPassport.SEPOLIA_RPC)) },
    )
    val changed = domain != settings.zkPassportDomain || mainnet != settings.zkPassportMainnetRpc || sepolia != settings.zkPassportSepoliaRpc
    OutlinedButton(
        onClick = {
            model.updateSettings {
                it.copy(zkPassportDomain = ZkPassport.normalizeDomain(domain), zkPassportMainnetRpc = mainnet, zkPassportSepoliaRpc = sepolia)
            }
        },
        enabled = changed && domainProblem == null && !bad(mainnet) && !bad(sepolia),
    ) { Text(stringResource(Res.string.action_save)) }
    ZkPassportRemoteSection(model)
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Switch(checked = settings.zkPassportVerifierApi, onCheckedChange = { on -> model.updateSettings { it.copy(zkPassportVerifierApi = on) } })
        Column {
            Text(stringResource(Res.string.zkp_verifier_api))
            Text(stringResource(Res.string.zkp_verifier_api_note), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * Proving answers on the owner's own computer: the self-hosted prover from the advanced settings, and a temporary
 * prover (diw-server prover) paired by scanning its one-time code. Each request's consent screen picks the place.
 */
@Composable
private fun ZkPassportRemoteSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    val paired by model.taiwan.zkPassport.paired.collectAsState()
    val readQr = LocalQrReader.current
    val scope = rememberCoroutineScope()
    SectionTitle(stringResource(Res.string.zkp_remote_title))
    Text(stringResource(Res.string.zkp_remote_text), style = MaterialTheme.typography.bodySmall)
    Text(
        if (settings.zkProverUrl.isNotEmpty() && settings.zkProverToken.isNotEmpty()) stringResource(Res.string.zkp_remote_host, settings.zkProverUrl)
        else stringResource(Res.string.zkp_remote_host_none),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        paired?.let { stringResource(Res.string.zkp_remote_paired, it.url) } ?: stringResource(Res.string.zkp_remote_paired_none),
        style = MaterialTheme.typography.bodyMedium,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(onClick = {
            scope.launch {
                readQr()?.let { text ->
                    if (ZkPassportPairingLink.looksLike(text)) model.taiwan.zkPassport.pair(text.trim()) else model.handleUri(text)
                }
            }
        }) { Text(stringResource(Res.string.zkp_remote_scan)) }
        if (paired != null) OutlinedButton(onClick = { model.taiwan.zkPassport.endPairing() }) { Text(stringResource(Res.string.zkp_remote_end)) }
    }
}

/**
 * What answering zkPassport requests on this phone needs: the UltraHonk engine, the proof parameters shared with
 * zkPDF (offered for download here), and the circuits, which are fetched per request and checked on the registry.
 */
@Composable
private fun ZkPassportReadiness(model: WalletModel) {
    val zk = model.zk
    val capability by zk.capability.collectAsState()
    val statuses by zk.assetStatus.collectAsState()
    val downloads by zk.downloads.collectAsState()
    val crs = zk.catalog.filter { it.id in diw.wallet.core.zk.ZkPdfAssets.CRS }
    val engine = capability?.let { diw.wallet.core.zk.ZkBackend.NOIR_ULTRAHONK in it.backends }
    val crsReady = crs.isNotEmpty() && crs.all { statuses[it.id] == diw.wallet.core.zk.ZkAssetStatus.READY }
    val busy = crs.any { downloads[it.id]?.let { d -> d.error == null } == true }
    Text(
        stringResource(Res.string.zkp_needs_engine) + when (engine) {
            null -> stringResource(Res.string.zk_not_assessed)
            true -> stringResource(Res.string.zkp_needs_ok)
            false -> stringResource(Res.string.zkp_needs_engine_missing)
        },
        style = MaterialTheme.typography.bodySmall,
    )
    Text(
        stringResource(Res.string.zkp_needs_crs, sizeText(crs.sumOf { it.installedBytes })) +
            if (crsReady) stringResource(Res.string.zkp_needs_ok) else stringResource(Res.string.zkp_needs_crs_missing),
        style = MaterialTheme.typography.bodySmall,
        color = if (crsReady || crs.isEmpty()) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error,
    )
    crs.mapNotNull { downloads[it.id]?.error }.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    if (!crsReady && crs.isNotEmpty()) {
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        else OutlinedButton(onClick = { zk.download(crs.filter { statuses[it.id] != diw.wallet.core.zk.ZkAssetStatus.READY }.map { it.id }) }) {
            Text(stringResource(Res.string.zkp_needs_crs_download, sizeText(crs.sumOf { it.gzipBytes })))
        }
    }
    Text(stringResource(Res.string.zkp_needs_circuits, ZkPassport.CIRCUIT_VERSION), style = MaterialTheme.typography.bodySmall)
    ZkPassportLegacyComponent(model, status = true)
}

/**
 * Barretenberg 5, which verifies proofs of circuits before 0.22.0: its state with [status], and an install button
 * where the app can fetch it (Google Play). Shows nothing where the platform has no such component.
 */
@Composable
internal fun ZkPassportLegacyComponent(model: WalletModel, status: Boolean) {
    val zk = model.zk
    LaunchedEffect(Unit) { zk.checkLegacy() }
    val c = zk.legacy.collectAsState().value ?: return
    if (status) {
        Text(
            stringResource(Res.string.zkp_needs_legacy, ZkPassport.CIRCUIT_VERSION) + when {
                c.present -> stringResource(Res.string.zkp_needs_ok)
                c.installable -> stringResource(Res.string.zkp_needs_legacy_missing)
                else -> stringResource(Res.string.zkp_needs_legacy_unavailable)
            },
            style = MaterialTheme.typography.bodySmall,
        )
    } else if (c.present) {
        Text(stringResource(Res.string.zkp_legacy_installed), style = MaterialTheme.typography.bodySmall)
    }
    c.error?.let { Text(stringResource(Res.string.zkp_legacy_error, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    val progress = c.progress
    when {
        progress != null -> {
            Text(stringResource(Res.string.zkp_legacy_installing, (progress * 100).toInt()), style = MaterialTheme.typography.bodySmall)
            LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
        }
        !c.present && c.installable -> OutlinedButton(onClick = { zk.installLegacy() }) { Text(stringResource(Res.string.zkp_legacy_install)) }
    }
}
