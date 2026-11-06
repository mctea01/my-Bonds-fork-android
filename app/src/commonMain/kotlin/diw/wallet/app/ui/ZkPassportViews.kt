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
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
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
import diw.wallet.core.zkpassport.ZkPassportField
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
            !r.verified -> VerdictCard(Verdict.FAIL, stringResource(Res.string.zkp_failed), ZkPassportFlow.problems(r.errors))
            else -> {
                val caveats = buildList {
                    if (r.devMode) add(stringResource(Res.string.zkp_test_caveat))
                    if (r.viaVerifierApi) add(stringResource(Res.string.zkp_api_caveat))
                    add(stringResource(Res.string.zkp_trust_registry))
                    add(stringResource(Res.string.zkp_domain_caveat, domain))
                }
                VerdictCard(
                    if (r.devMode || r.viaVerifierApi) Verdict.CAUTION else Verdict.PASS,
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
    OutlinedTextField(
        value = domain, onValueChange = { domain = it.trim().take(253) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(Res.string.zkp_domain)) }, isError = domainProblem != null,
        supportingText = { Text(domainProblem ?: stringResource(Res.string.zkp_domain_default, model.taiwan.zkPassport.defaultDomain().ifEmpty { "-" })) },
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
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Switch(checked = settings.zkPassportVerifierApi, onCheckedChange = { on -> model.updateSettings { it.copy(zkPassportVerifierApi = on) } })
        Column {
            Text(stringResource(Res.string.zkp_verifier_api))
            Text(stringResource(Res.string.zkp_verifier_api_note), style = MaterialTheme.typography.bodySmall)
        }
    }
}
