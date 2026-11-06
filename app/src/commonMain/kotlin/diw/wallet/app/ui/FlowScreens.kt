package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import diw.wallet.core.oid4vp.WalletTransactionTypes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import diw.wallet.app.ConsentItem
import diw.wallet.app.CredentialDetails
import diw.wallet.app.HomeTab
import diw.wallet.app.IssuanceUi
import diw.wallet.app.PresentationUi
import diw.wallet.app.Screen
import diw.wallet.app.StatusTexts
import diw.wallet.app.WalletModel
import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.pick
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.status.StatusFinding
import diw.wallet.core.status.StatusPolicy
import diw.wallet.core.status.StatusVerdict
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.trust.highlyTrusted
import diw.wallet.core.oid4vp.AttestationVerdict
import diw.wallet.core.oid4vp.ConsentTerms
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.profile.twdiw.TwdiwAssurance

@Composable
internal fun Busy(text: String) {
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator()
        Text(text, Modifier.padding(top = 12.dp))
    }
}

@Composable
internal fun Failure(text: String, onClose: () -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        VerdictCard(Verdict.FAIL, stringResource(Res.string.flow_failed), listOf(text))
        Button(onClick = onClose) { Text(stringResource(Res.string.action_home)) }
    }
}

/**
 * Parties led to a trust root (T1, T2) need no acknowledgement. A party that reaches no trust root (T3) needs a ticked
 * box; one whose verification failed (T4) needs the strong confirmation, which still leaves the decision to the user.
 */
@Composable
internal fun riskAcknowledgement(trust: TrustDecision): Boolean {
    val tier = trust.tier
    var ack by remember(trust) { mutableStateOf(false) }
    if (tier.highlyTrusted) return true
    if (tier == TrustTier.T4) {
        return riskOverride(trust, stringResource(Res.string.flow_untrusted_continue), stringResource(Res.string.flow_untrusted_title), listOf(
            stringResource(Res.string.flow_untrusted_text),
            stringResource(Res.string.flow_untrusted_hint),
        ) + trust.reasons.take(3))
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = ack, onCheckedChange = { ack = it })
        Text(stringResource(Res.string.flow_untrusted_ack))
    }
    return ack
}

@Composable
fun IssuanceScreen(model: WalletModel) {
    val state by model.issuance.collectAsState()
    when (val s = state) {
        IssuanceUi.Loading -> Busy(stringResource(Res.string.flow_reading_issuer))
        is IssuanceUi.Working -> Busy(s.message)
        is IssuanceUi.WaitingForBrowser -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Text(stringResource(Res.string.flow_browser_login), Modifier.padding(vertical = 12.dp))
            OutlinedButton(onClick = { model.cancelBrowserWait() }) { Text(stringResource(Res.string.action_cancel)) }
        }
        is IssuanceUi.Failed -> Failure(s.message) { model.screen.value = Screen.Home }
        is IssuanceUi.Review -> {
            var txCode by remember { mutableStateOf("") }
            // Offers start with everything selected; a wallet-initiated list starts empty.
            var selected by remember(s) { mutableStateOf(if (s.walletInitiated) emptySet() else s.configurations.map { it.id }.toSet()) }
            val tx = s.session.txCode
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                TrustCard(stringResource(Res.string.role_issuer), s.issuerName, s.trust, listOf(s.session.issuer.credentialIssuer))
                s.requestedBy?.let { Text(stringResource(Res.string.flow_dc_requested_by, it), style = MaterialTheme.typography.bodySmall) }
                Text(if (s.walletInitiated) stringResource(Res.string.flow_pick_offers) else stringResource(Res.string.flow_will_add), style = MaterialTheme.typography.titleSmall)
                if (s.walletInitiated) {
                    Text(stringResource(Res.string.flow_waltid_hint), style = MaterialTheme.typography.bodySmall)
                }
                s.configurations.forEach { c ->
                    Card(Modifier.fillMaxWidth()) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = c.id in selected, onCheckedChange = { on -> selected = if (on) selected + c.id else selected - c.id })
                            Column(Modifier.weight(1f)) {
                                Text(c.display.pick(model.locales)?.name ?: c.id, style = MaterialTheme.typography.titleMedium)
                                Text("${c.raw["format"]?.toString()?.trim('"') ?: c.format.wire}  ${c.docType ?: c.vct ?: ""}", style = MaterialTheme.typography.bodySmall)
                                if (c.proofTypes.values.any { it.keyAttestationsRequired != null }) {
                                    Text(stringResource(Res.string.flow_key_attestation), style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }
                if (s.unsupported.isNotEmpty()) {
                    Text(stringResource(Res.string.flow_unsupported_formats, s.unsupported.size), style = MaterialTheme.typography.bodySmall)
                    s.unsupported.take(20).forEach { (id, reason) ->
                        Text(stringResource(Res.string.pair_colon, id, reason), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                    }
                    if (s.unsupported.size > 20) Text("…", style = MaterialTheme.typography.bodySmall)
                }
                if (tx != null) {
                    OutlinedTextField(
                        value = txCode,
                        onValueChange = { v -> txCode = if (tx.inputMode == "numeric") v.filter { it.isDigit() } else v },
                        label = { Text(tx.description ?: stringResource(Res.string.flow_tx_code)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = if (tx.inputMode == "numeric") KeyboardType.Number else KeyboardType.Text),
                    )
                }
                val ok = riskAcknowledgement(s.trust)
                val txOk = tx == null || (tx.length == null && txCode.isNotEmpty()) || txCode.length == tx.length
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { model.acceptOffer(s, txCode.ifEmpty { null }, selected.toList()) }, enabled = ok && txOk && selected.isNotEmpty()) {
                        Text(if (s.preAuthorized) stringResource(Res.string.action_add) else stringResource(Res.string.flow_go_login))
                    }
                    OutlinedButton(onClick = { model.screen.value = Screen.Home }) { Text(stringResource(Res.string.action_cancel)) }
                }
            }
        }
        is IssuanceUi.Done -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            val issued = s.results.count { it is IssuanceResult.Issued }
            when {
                s.failures.isEmpty() && issued == s.results.size -> VerdictCard(Verdict.PASS, stringResource(Res.string.flow_added_count, issued))
                issued > 0 -> VerdictCard(Verdict.CAUTION, stringResource(Res.string.flow_partly_added), listOf(stringResource(Res.string.flow_partly_added_text, issued)))
                else -> VerdictCard(Verdict.CAUTION, stringResource(Res.string.flow_issuer_pending), listOf(stringResource(Res.string.flow_issuer_pending_text)))
            }
            if (issued > 0) Text(stringResource(Res.string.flow_tap_to_view), style = MaterialTheme.typography.bodySmall)
            s.results.forEach { r ->
                when (r) {
                    is IssuanceResult.Issued -> TrustCard(
                        stringResource(Res.string.flow_added),
                        r.document.displayName ?: "",
                        r.trust,
                        listOf(stringResource(Res.string.flow_credential_count, r.credentials.size)),
                        onClick = { model.screen.value = Screen.DocumentDetail(r.document.identifier, from = Screen.Issuance) },
                    )
                    is IssuanceResult.Deferred -> Text(stringResource(Res.string.flow_pending_line, r.document.displayName.toString()))
                }
            }
            s.failures.forEach { (name, reason) ->
                Text(stringResource(Res.string.flow_not_added_line, name, reason), color = MaterialTheme.colorScheme.error)
            }
            Button(onClick = { model.showTab(HomeTab.DOCUMENTS) }) { Text(stringResource(Res.string.action_done)) }
        }
    }
}

@Composable
fun PresentationScreen(model: WalletModel) {
    val state by model.presentation.collectAsState()
    when (val s = state) {
        PresentationUi.Loading -> Busy(stringResource(Res.string.flow_checking_request))
        is PresentationUi.Working -> Busy(s.message)
        // Leaving through back() also ends a pending DC API request, returning the caller to its page.
        is PresentationUi.Failed -> Failure(s.message) { model.back() }
        is PresentationUi.Done -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(
                Verdict.PASS, stringResource(Res.string.flow_presented),
                listOf(
                    when (val o = s.outcome) {
                        is PresentationOutcome.Posted -> if (o.redirectUri != null) stringResource(Res.string.flow_presented_redirect) else stringResource(Res.string.flow_presented_received)
                        is PresentationOutcome.DcApi -> stringResource(Res.string.flow_presented_returned)
                        is PresentationOutcome.Redirect -> stringResource(Res.string.flow_presented_handed)
                    },
                    stringResource(Res.string.flow_presented_history),
                ),
            )
            Button(onClick = { model.screen.value = Screen.Home }) { Text(stringResource(Res.string.action_done)) }
        }
        is PresentationUi.Consent -> {
            val req = s.request
            val v = req.verifier
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                val extra = buildList {
                    add(stringResource(Res.string.flow_verifier_id_scheme, v.clientId.prefix.wire.toString()))
                    if (v.dnsNames.isNotEmpty()) add(stringResource(Res.string.flow_verifier_domain, v.dnsNames.joinToString()))
                    v.did?.let { add(stringResource(Res.string.flow_verifier_did, it)) }
                    req.origin?.let { add(stringResource(Res.string.flow_verifier_origin, it)) }
                    req.target?.let { add(stringResource(Res.string.flow_verifier_response, it)) }
                    if (req.specs.isNotEmpty()) add(stringResource(Res.string.flow_verifier_specs) + req.specs.joinToString(stringResource(Res.string.sep_list)))
                    s.offline?.let { add(stringResource(Res.string.flow_counter_service, it.service.name)) }
                    addAll(req.warnings)
                }
                TrustCard(stringResource(Res.string.role_verifier), v.displayName, v.trust, extra)
                s.terms?.let { ConsentTermsCard(model, it) }
                s.attestations.forEach { VerifierAttestationCard(it) }
                val settings by model.settingsFlow.collectAsState()
                var showDetails by remember(settings.showDetails) { mutableStateOf(settings.showDetails) }
                TextButton(onClick = { showDetails = !showDetails }) { Text(if (showDetails) stringResource(Res.string.flow_hide_info) else stringResource(Res.string.flow_show_info)) }
                if (showDetails) DetailSections(model, CredentialDetails.request(req))
                val statusOk = requestedDocuments(model, s.items, s.risk, v.trust.tier, s) { i, id -> model.changeCredential(s, i, id) }
                if (s.items.isEmpty()) Text(stringResource(Res.string.flow_holder_only), style = MaterialTheme.typography.bodyMedium)
                if (req.transactionData.isNotEmpty()) {
                    Text(stringResource(Res.string.flow_transactions, req.transactionData.size))
                    req.transactionData.forEach { entry ->
                        WalletTransactionTypes.describe(entry).forEachIndexed { i, line ->
                            Text(line, style = if (i == 0) MaterialTheme.typography.titleSmall else MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
                // Kept when the holder changes a credential, which replaces the consent state of the same request.
                val values = remember(req) { androidx.compose.runtime.mutableStateMapOf<String, String>() }
                if (s.fields.isNotEmpty()) Text(stringResource(Res.string.flow_fill_in), style = MaterialTheme.typography.titleSmall)
                s.fields.forEach { f ->
                    val value = values[f.ename].orEmpty()
                    val bad = value.isNotEmpty() && f.regex != null && runCatching { !Regex(f.regex!!).matches(value) }.getOrDefault(false)
                    OutlinedTextField(
                        value = value,
                        onValueChange = { values[f.ename] = it },
                        label = { Text(f.cname) },
                        supportingText = { Text(if (bad) stringResource(Res.string.flow_bad_format) else f.description ?: f.ename) },
                        isError = bad,
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                val fieldsOk = s.fields.all { f ->
                    val v = values[f.ename].orEmpty()
                    v.isNotEmpty() && (f.regex == null || runCatching { Regex(f.regex!!).matches(v) }.getOrDefault(true))
                }
                val ok = riskAcknowledgement(v.trust)
                val failed = s.attestations.filter { it.verdict == AttestationVerdict.INVALID }
                val attestationsOk = failed.isEmpty() || riskOverride(s, stringResource(Res.string.flow_registration_continue), stringResource(Res.string.flow_registration_title),
                    failed.flatMap { it.problems }.distinct().take(5) + stringResource(Res.string.flow_registration_text))
                if (s.terms?.termsUri != null) {
                    Text(stringResource(Res.string.flow_terms_agree_note), style = MaterialTheme.typography.bodySmall)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { model.approve(s, values.toMap()) }, enabled = ok && fieldsOk && statusOk && attestationsOk) { Text(stringResource(Res.string.flow_agree_share)) }
                    OutlinedButton(onClick = { model.decline(s) }) { Text(stringResource(Res.string.action_decline)) }
                }
            }
        }
    }
}

/** Who receives the data, the occasion and purpose of the request, and the terms page (TWDIW 知情同意書). */
@Composable
private fun ConsentTermsCard(model: WalletModel, terms: ConsentTerms) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            terms.recipient?.let { LabelValue(stringResource(Res.string.flow_recipient), it) }
            terms.scenario?.let { LabelValue(stringResource(Res.string.flow_occasion), it) }
            terms.purpose?.let { LabelValue(stringResource(Res.string.flow_purpose), it) }
            terms.termsUri?.let { uri ->
                val title = (terms.scenario?.let { stringResource(Res.string.quoted, it) } ?: "") + stringResource(Res.string.flow_terms)
                TextButton(onClick = { model.platform.openBrowser(uri) }) { Text(stringResource(Res.string.flow_read_terms, title)) }
                Text(stringResource(Res.string.flow_terms_source, uri), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/**
 * The request's risk and the documents asked for, each with its status judged at that risk. A document whose status
 * the request rejects (revoked; suspended or unconfirmed for the risk) is shared only after the strong confirmation;
 * a new status query is offered first where it may help. Returns whether the user may go on. [key] identifies the
 * request. With [onChange], a line that other held documents can also answer offers to change the credential.
 */
@Composable
internal fun requestedDocuments(
    model: WalletModel,
    items: List<ConsentItem>,
    risk: RiskLevel,
    verifierTier: TrustTier,
    key: Any,
    onChange: ((index: Int, documentId: String) -> Unit)? = null,
): Boolean {
    val statuses by model.statuses.collectAsState()
    val documents by model.documents.collectAsState()
    val decisions = items.map { item -> item.documentId?.let { StatusPolicy.decide(statuses[it]?.status, risk) } }
    Text(stringResource(Res.string.flow_request_risk) + StatusTexts.risk(risk), style = MaterialTheme.typography.titleSmall)
    Text(requestRiskReason(risk, items, verifierTier), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(Res.string.flow_requested_data), style = MaterialTheme.typography.titleSmall)
    items.forEachIndexed { i, item ->
        Card(Modifier.fillMaxWidth()) {
            Box(Modifier.padding(12.dp)) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(item.documentName, style = MaterialTheme.typography.titleMedium)
                    val current = documents.firstOrNull { it.identifier == item.documentId }
                    assuranceText(current?.issuanceRecord)?.let {
                        Text(stringResource(Res.string.flow_ial, it), style = MaterialTheme.typography.bodySmall)
                    }
                    decisions[i]?.let { RequestStatusLine(it) }
                    if (onChange != null && item.alternatives.isNotEmpty() && current != null) {
                        CredentialChooser(item, current, documents.filter { it.identifier in item.alternatives }) { onChange(i, it) }
                    }
                    if (item.whole) {
                        Text(stringResource(Res.string.flow_whole_credential), style = MaterialTheme.typography.bodySmall)
                    }
                    item.claims.forEach { Text("・$it", style = MaterialTheme.typography.bodyMedium) }
                }
            }
        }
    }
    val rejected = decisions.filterNotNull().filter { it.verdict == StatusVerdict.REJECT }
    val checking by model.status.checking.collectAsState()
    var overridden = false
    if (rejected.isNotEmpty()) {
        VerdictCard(Verdict.FAIL, stringResource(Res.string.flow_status_mismatch), rejected.map { d -> statusWarning(d.finding, risk) }.distinct())
        // Unconfirmed states may clear with a fresh query; a revocation never does.
        if (rejected.any { it.finding != StatusFinding.REVOKED }) {
            val ids = items.mapIndexedNotNull { i, item -> item.documentId.takeIf { decisions[i]?.verdict == StatusVerdict.REJECT } }
            val busy = ids.any { it in checking }
            OutlinedButton(onClick = {
                model.documents.value.filter { it.identifier in ids }.forEach { model.checkStatus(it) }
            }, enabled = !busy) { Text(if (busy) stringResource(Res.string.state_checking) else stringResource(Res.string.flow_recheck_status)) }
        }
        val revoked = rejected.any { it.finding == StatusFinding.REVOKED }
        overridden = riskOverride(key, stringResource(Res.string.flow_present_anyway), if (revoked) stringResource(Res.string.flow_present_revoked) else stringResource(Res.string.flow_present_mismatch),
            rejected.map { d -> statusWarning(d.finding, risk) }.distinct() + listOfNotNull(
                stringResource(Res.string.flow_present_mismatch_text),
                if (revoked) stringResource(Res.string.flow_present_revoked_text) else null,
            ))
    } else if (decisions.any { it?.verdict == StatusVerdict.CAUTION }) {
        Text(stringResource(Res.string.flow_status_partly), style = MaterialTheme.typography.bodySmall)
    }
    return rejected.isEmpty() || overridden
}

/**
 * Changes the credential of a consent line, like the official TWDIW wallet's 更改憑證: the current document is checked;
 * picking another one presents it instead. Cards with a higher identity assurance level come first.
 */
@Composable
private fun CredentialChooser(item: ConsentItem, current: org.multipaz.document.Document, others: List<org.multipaz.document.Document>, onPick: (String) -> Unit) {
    var open by remember(item.documentId) { mutableStateOf(false) }
    TextButton(onClick = { open = !open }) { Text(if (open) stringResource(Res.string.action_collapse) else stringResource(Res.string.flow_change_credential, others.size)) }
    if (!open) return
    Text(stringResource(Res.string.flow_change_credential_text), style = MaterialTheme.typography.bodySmall)
    val options = (listOf(current) + others).sortedByDescending { TwdiwAssurance.rank(it.issuanceRecord?.displayDescription) }
    options.forEach { doc ->
        val record = doc.issuanceRecord
        val detail = listOfNotNull(
            assuranceText(record)?.let { stringResource(Res.string.flow_ial_short, it) },
            record?.anchorName ?: record?.credentialIssuer,
        ).joinToString("・")
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            androidx.compose.material3.RadioButton(selected = doc.identifier == current.identifier, onClick = {
                if (doc.identifier != current.identifier) { open = false; onPick(doc.identifier) }
            })
            Column(Modifier.weight(1f)) {
                Text(doc.displayName ?: stringResource(Res.string.credential_fallback), style = MaterialTheme.typography.bodyMedium)
                if (detail.isNotEmpty()) Text(detail, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** Why a request has its risk: the most sensitive field asked for, or a verifier that is not on an official list. */
@Composable
private fun requestRiskReason(risk: RiskLevel, items: List<ConsentItem>, verifier: TrustTier): String {
    val fields = items.maxOfOrNull { it.sensitivity } ?: RiskLevel.LOW
    val named = items.filter { it.sensitivity == fields }.flatMap { it.notable }.distinct()
    val which = if (named.isEmpty()) "" else stringResource(Res.string.quote_open) + named.take(4).joinToString(stringResource(Res.string.sep_list)) + stringResource(Res.string.quote_close) + if (named.size > 4) stringResource(Res.string.list_more) else ""
    val whole = if (items.any { it.whole && it.sensitivity == fields }) stringResource(Res.string.flow_whole_note) else ""
    return when {
        risk == RiskLevel.LOW -> stringResource(Res.string.risk_reason_low)
        fields == risk && fields == RiskLevel.HIGH ->
            (if (which.isEmpty()) stringResource(Res.string.risk_reason_high) else stringResource(Res.string.risk_reason_high_named, which)) + whole + stringResource(Res.string.risk_reason_high_tail)
        fields == risk -> (if (which.isEmpty()) stringResource(Res.string.risk_reason_medium) else stringResource(Res.string.risk_reason_medium_named, which)) + whole + stringResource(Res.string.sentence_end)
        verifier == TrustTier.T4 -> stringResource(Res.string.risk_reason_t4)
        verifier == TrustTier.T3 -> stringResource(Res.string.risk_reason_t3)
        else -> stringResource(Res.string.risk_reason_registration)
    }
}

@Composable
private fun statusWarning(f: StatusFinding, risk: RiskLevel): String = when (f) {
    StatusFinding.REVOKED -> stringResource(Res.string.status_warning_revoked)
    StatusFinding.SUSPENDED -> stringResource(Res.string.status_warning_suspended)
    else -> stringResource(Res.string.status_warning_online, StatusTexts.finding(f), StatusTexts.risk(risk))
}
