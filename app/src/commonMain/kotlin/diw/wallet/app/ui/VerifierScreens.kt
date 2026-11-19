package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import diw.wallet.app.HomeTab
import diw.wallet.app.OnlineAsk
import diw.wallet.app.OnlineCredential
import diw.wallet.app.OnlineRoute
import diw.wallet.app.OnlineVerifyUi
import diw.wallet.app.StatusTexts
import diw.wallet.app.VerifierModel
import diw.wallet.app.VerifierProfile
import diw.wallet.app.WalletModel
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.verifier.AssuranceLevel
import diw.wallet.core.verifier.CheckStatus
import diw.wallet.core.verifier.VerificationPolicy
import diw.wallet.core.verifier.declaration.PartyId
import diw.wallet.core.verifier.declaration.VerifierKind
import kotlinx.coroutines.launch

/** Online verification as an OpenID4VP verifier (docs/design/p5-verifier.md section 6). */
@Composable
fun OnlineVerifyScreen(model: WalletModel) {
    val state by model.verifier.online.collectAsState()
    when (val s = state) {
        OnlineVerifyUi.Setup -> OnlineSetup(model)
        is OnlineVerifyUi.Working -> Column(
            Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            CircularProgressIndicator()
            Text(s.message, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
            OutlinedButton(onClick = { model.verifier.again() }) { Text(stringResource(Res.string.action_cancel)) }
        }
        is OnlineVerifyUi.Waiting -> OnlineWaiting(model, s)
        is OnlineVerifyUi.Result -> OnlineResult(model, s)
        is OnlineVerifyUi.Failed -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.FAIL, stringResource(Res.string.ov_failed_title), listOf(s.message))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { model.verifier.again() }) { Text(stringResource(Res.string.action_try_again)) }
                OutlinedButton(onClick = { model.verifier.close(); model.showTab(HomeTab.VERIFY) }) { Text(stringResource(Res.string.action_leave)) }
            }
        }
    }
}

@Composable
private fun OnlineSetup(model: WalletModel) {
    val profiles by model.verifier.profiles.collectAsState()
    val asks = remember { OnlineAsk.all() }
    var ask by remember { mutableStateOf(asks.first()) }
    var profileId by remember { mutableStateOf<String?>(null) }
    val profile = profiles.firstOrNull { it.id == profileId }
    var purpose by remember { mutableStateOf("") }
    var risk by remember { mutableStateOf(RiskLevel.MEDIUM) }
    var accepted by remember { mutableStateOf(VerificationPolicy.DEFAULT) }
    var requireZk by remember { mutableStateOf(false) }
    val server = model.verifier.serverRoute()
    val lan = model.platform.bondsLan != null
    var route by remember { mutableStateOf(if (server != null) OnlineRoute.SERVER else OnlineRoute.LAN) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(Tokens.ContainerRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(WalletIcons.Link, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                Text(stringResource(Res.string.ov_title), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(Res.string.ov_text), style = MaterialTheme.typography.bodyMedium)
            }
        }
        SectionTitle(stringResource(Res.string.ov_as_whom))
        Row(Modifier.fillMaxWidth().clickable { profileId = null }, verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = profileId == null, onClick = { profileId = null })
            Column {
                Text(stringResource(Res.string.ov_anonymous), style = MaterialTheme.typography.bodyLarge)
                Text(stringResource(Res.string.ov_anonymous_text), style = MaterialTheme.typography.bodySmall)
            }
        }
        profiles.forEach { p ->
            Row(Modifier.fillMaxWidth().clickable { profileId = p.id; if (purpose.isBlank()) purpose = p.purpose }, verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = profileId == p.id, onClick = { profileId = p.id; if (purpose.isBlank()) purpose = p.purpose })
                Column {
                    Text(p.partyName, style = MaterialTheme.typography.bodyLarge)
                    Text(profileLine(p), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        TextButton(onClick = { model.verifier.openProfiles() }) { Text(stringResource(Res.string.ov_manage_profiles)) }
        SectionTitle(stringResource(Res.string.reader_requested_data))
        asks.forEach { a ->
            Row(Modifier.fillMaxWidth().clickable { ask = a }, verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = ask.id == a.id, onClick = { ask = a })
                Text(a.title, style = MaterialTheme.typography.bodyLarge)
            }
        }
        OutlinedTextField(
            value = purpose,
            onValueChange = { purpose = it.take(200) },
            label = { Text(stringResource(Res.string.verify_purpose)) },
            modifier = Modifier.fillMaxWidth(),
        )
        if (profile == null) Text(stringResource(Res.string.ov_purpose_anonymous), style = MaterialTheme.typography.bodySmall)
        SectionTitle(stringResource(Res.string.reader_purpose_risk))
        RiskSelector(risk) { risk = it }
        SectionTitle(stringResource(Res.string.ov_policy))
        AssuranceLevel.entries.forEach { level ->
            Row(Modifier.fillMaxWidth().clickable { accepted = if (level in accepted) accepted - level else accepted + level }, verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = level in accepted, onCheckedChange = { accepted = if (it) accepted + level else accepted - level })
                Text(level.title, style = MaterialTheme.typography.bodyMedium)
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Switch(checked = requireZk, onCheckedChange = { requireZk = it })
            Text(stringResource(Res.string.ov_require_zk), style = MaterialTheme.typography.bodyMedium)
        }
        SectionTitle(stringResource(Res.string.ov_route))
        Row(Modifier.fillMaxWidth().clickable(enabled = server != null) { route = OnlineRoute.SERVER }, verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = route == OnlineRoute.SERVER, onClick = { route = OnlineRoute.SERVER }, enabled = server != null)
            Column {
                Text(stringResource(Res.string.ov_route_server_title), style = MaterialTheme.typography.bodyLarge)
                Text(server?.let { stringResource(Res.string.ov_route_server_text, it) } ?: stringResource(Res.string.ov_no_server), style = MaterialTheme.typography.bodySmall)
            }
        }
        Row(Modifier.fillMaxWidth().clickable(enabled = lan) { route = OnlineRoute.LAN }, verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = route == OnlineRoute.LAN, onClick = { route = OnlineRoute.LAN }, enabled = lan)
            Column {
                Text(stringResource(Res.string.ov_route_lan_title), style = MaterialTheme.typography.bodyLarge)
                Text(if (lan) stringResource(Res.string.ov_route_lan_text) else stringResource(Res.string.ov_no_lan), style = MaterialTheme.typography.bodySmall)
            }
        }
        Button(
            onClick = { model.verifier.start(ask, profile, purpose, risk, VerificationPolicy(accepted, requireZk), route) },
            enabled = accepted.isNotEmpty() && (route == OnlineRoute.SERVER && server != null || route == OnlineRoute.LAN && lan),
        ) {
            Icon(WalletIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
            Text(stringResource(Res.string.ov_start))
        }
    }
}

@Composable
private fun OnlineWaiting(model: WalletModel, s: OnlineVerifyUi.Waiting) {
    val clipboard = LocalClipboardManager.current
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(Res.string.ov_scan), style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
        QrImage(s.invocation, Modifier.size(280.dp))
        Text(s.route, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
        s.profile?.let { Text(stringResource(Res.string.ov_as_profile, it), style = MaterialTheme.typography.bodySmall) }
        Text(stringResource(Res.string.ov_valid_until, localTime(s.expiresAt)), style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { clipboard.setText(AnnotatedString(s.invocation)) }) { Text(stringResource(Res.string.ov_copy_link)) }
            OutlinedButton(onClick = { model.verifier.again() }) { Text(stringResource(Res.string.action_cancel)) }
        }
        s.details.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
    }
}

@Composable
private fun OnlineResult(model: WalletModel, s: OnlineVerifyUi.Result) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        val v = s.verification
        when {
            v.error != null -> VerdictCard(Verdict.FAIL, stringResource(Res.string.ov_invalid), listOfNotNull(v.errorDescription ?: v.error))
            s.passed -> VerdictCard(Verdict.PASS, stringResource(Res.string.ov_passed), listOf(stringResource(Res.string.ov_passed_text)))
            else -> VerdictCard(Verdict.CAUTION, stringResource(Res.string.ov_not_passed), listOf(stringResource(Res.string.ov_not_passed_text)))
        }
        v.sessionChecks.filter { it.status != CheckStatus.PASS }.forEach {
            Text(it.name + stringResource(Res.string.sep_comma) + it.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        s.credentials.forEach { CredentialResult(it) }
        Text(stringResource(Res.string.ov_summary, s.ask, s.policy.accepted.joinToString(stringResource(Res.string.sep_list)) { it.title }) +
            (s.profile?.let { stringResource(Res.string.ov_note_as, it) } ?: ""), style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.verifier.again() }) { Text(stringResource(Res.string.reader_again)) }
            OutlinedButton(onClick = { model.verifier.close(); model.showTab(HomeTab.VERIFY) }) { Text(stringResource(Res.string.action_done)) }
        }
    }
}

@Composable
private fun CredentialResult(c: OnlineCredential) {
    val v = c.verification
    Text(v.typeName, style = MaterialTheme.typography.titleMedium)
    TrustCard(stringResource(Res.string.role_issuer), v.issuerTrust.anchorName ?: v.typeName, v.issuerTrust)
    LabelValue(stringResource(Res.string.ov_assurance), c.level?.title ?: stringResource(Res.string.ov_unjudged), small = true)
    val ruleColor = when (c.rule.status) {
        CheckStatus.PASS -> MaterialTheme.colorScheme.onSurface
        CheckStatus.FAIL -> MaterialTheme.colorScheme.error
        else -> tierColor(diw.wallet.core.trust.TrustTier.T3)
    }
    Text(c.rule.name + stringResource(Res.string.sep_comma) + c.rule.detail, style = MaterialTheme.typography.bodyMedium, color = ruleColor)
    SectionTitle(stringResource(Res.string.reader_disclosed))
    v.claims.forEach { (k, value) -> LabelValue(k, value) }
    if (v.claims.isEmpty()) Text(stringResource(Res.string.reader_nothing_disclosed), style = MaterialTheme.typography.bodySmall)
    (v.checks + v.evidence).forEach { k ->
        Text(k.name + (if (k.detail.isNotEmpty()) stringResource(Res.string.sep_comma) + k.detail else ""), style = MaterialTheme.typography.bodySmall,
            color = if (k.status == CheckStatus.FAIL) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
    }
}

@Composable
private fun kindTitle(k: VerifierKind): String = when (k) {
    VerifierKind.NATURAL_PERSON -> stringResource(Res.string.vd_kind_natural)
    VerifierKind.LEGAL_PERSON -> stringResource(Res.string.vd_kind_legal)
    VerifierKind.FOR_LEGAL_PERSON -> stringResource(Res.string.vd_kind_for_legal)
    VerifierKind.FOR_NATURAL_PERSON -> stringResource(Res.string.vd_kind_for_natural)
}

@Composable
private fun profileLine(p: VerifierProfile): String = kindTitle(p.verifierKind) +
    (p.agentName?.takeIf { p.verifierKind.representative && it.isNotBlank() }?.let { stringResource(Res.string.sep_comma) + stringResource(Res.string.vd_agent, it) } ?: "") +
    stringResource(Res.string.sep_comma) + stringResource(Res.string.vp_evidence_count, p.partyEvidence.size + p.agentEvidence.size + p.mandates.size)

/** The verifier profiles: who this wallet says it is when it verifies, with its evidence and mandates. */
@Composable
fun VerifierProfilesScreen(model: WalletModel) {
    val profiles by model.verifier.profiles.collectAsState()
    val editing by model.verifier.editing.collectAsState()
    editing?.let {
        ProfileEditor(model, it)
        return
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(Res.string.vp_text), style = MaterialTheme.typography.bodyMedium)
        if (profiles.isEmpty()) Text(stringResource(Res.string.vp_empty), style = MaterialTheme.typography.bodySmall)
        profiles.forEach { p ->
            ActionRow(WalletIcons.Person, p.partyName, profileLine(p)) { model.verifier.edit(p) }
        }
        Button(onClick = { model.verifier.newProfile() }) { Text(stringResource(Res.string.vp_add)) }
    }
}

@Composable
private fun ProfileEditor(model: WalletModel, initial: VerifierProfile) {
    var p by remember(initial.id, initial.mandates) { mutableStateOf(initial) }
    val documents by model.documents.collectAsState()
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    var clientId by remember(initial.id) { mutableStateOf<String?>(null) }
    LaunchedEffect(initial.id) { clientId = model.verifier.clientId(initial) }
    var mandateText by remember { mutableStateOf("") }
    var issued by remember { mutableStateOf<String?>(null) }
    var agentForMandate by remember { mutableStateOf("") }
    var agentRoleForMandate by remember { mutableStateOf("") }
    var agentClientId by remember { mutableStateOf("") }
    var mandateDays by remember { mutableStateOf("180") }
    val kind = p.verifierKind
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        SectionTitle(stringResource(Res.string.vp_kind))
        VerifierKind.entries.forEach { k ->
            Row(Modifier.fillMaxWidth().clickable { p = p.copy(kind = k.wire) }, verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = kind == k, onClick = { p = p.copy(kind = k.wire) })
                Text(kindTitle(k), style = MaterialTheme.typography.bodyLarge)
            }
        }
        OutlinedTextField(
            value = p.partyName, onValueChange = { p = p.copy(partyName = it.take(120)) },
            label = { Text(if (kind.partyLegal) stringResource(Res.string.vp_party_legal) else stringResource(Res.string.vp_party_natural)) },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
        )
        Text(stringResource(Res.string.vp_party_id), style = MaterialTheme.typography.titleSmall)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = p.partyScheme == null, onClick = { p = p.copy(partyScheme = null, partyValue = null) }, label = { Text(stringResource(Res.string.vp_no_id)) })
            listOf(PartyId.TW_UBN, PartyId.EUID, PartyId.LEI, PartyId.TW_ID).forEach { scheme ->
                FilterChip(selected = p.partyScheme == scheme, onClick = { p = p.copy(partyScheme = scheme) }, label = { Text(scheme) })
            }
        }
        if (p.partyScheme != null) {
            OutlinedTextField(value = p.partyValue.orEmpty(), onValueChange = { p = p.copy(partyValue = it.take(64)) },
                label = { Text(stringResource(Res.string.vp_id_value)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            if (p.partyScheme == PartyId.TW_ID) Text(stringResource(Res.string.vp_tw_id_warning), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        if (kind.partyLegal) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = p.publicBody, onCheckedChange = { p = p.copy(publicBody = it) })
                Text(stringResource(Res.string.attestation_public_body))
            }
        }
        if (kind.representative) {
            OutlinedTextField(value = p.agentName.orEmpty(), onValueChange = { p = p.copy(agentName = it.take(80)) },
                label = { Text(stringResource(Res.string.vp_agent_name)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = p.agentRole.orEmpty(), onValueChange = { p = p.copy(agentRole = it.take(80)) },
                label = { Text(stringResource(Res.string.vp_agent_role)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        }
        SectionTitle(stringResource(Res.string.vp_purpose_defaults))
        OutlinedTextField(value = p.purpose, onValueChange = { p = p.copy(purpose = it.take(200)) },
            label = { Text(stringResource(Res.string.verify_purpose)) }, modifier = Modifier.fillMaxWidth())
        Text(stringResource(Res.string.vp_legal_basis), style = MaterialTheme.typography.titleSmall)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = p.legalBasis == null, onClick = { p = p.copy(legalBasis = null) }, label = { Text(stringResource(Res.string.vp_unstated)) })
            VerifierModel.LEGAL_BASES.forEach { b -> FilterChip(selected = p.legalBasis == b, onClick = { p = p.copy(legalBasis = b) }, label = { Text(legalBasisText(b)) }) }
        }
        Text(stringResource(Res.string.vp_retention), style = MaterialTheme.typography.titleSmall)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = p.retention == null, onClick = { p = p.copy(retention = null) }, label = { Text(stringResource(Res.string.vp_unstated)) })
            VerifierModel.RETENTIONS.forEach { r ->
                FilterChip(selected = p.retention == r, onClick = { p = p.copy(retention = r) },
                    label = { Text(if (r == "none") stringResource(Res.string.vp_not_kept) else retentionText(r)) })
            }
        }
        OutlinedTextField(value = p.privacyPolicy.orEmpty(), onValueChange = { p = p.copy(privacyPolicy = it.take(300)) },
            label = { Text(stringResource(Res.string.vp_privacy)) }, singleLine = true, modifier = Modifier.fillMaxWidth())

        SectionTitle(stringResource(Res.string.vp_evidence))
        Text(stringResource(Res.string.vp_evidence_text), style = MaterialTheme.typography.bodySmall)
        documents.forEach { d ->
            val name = d.displayName ?: d.identifier
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = d.identifier in p.partyEvidence, onCheckedChange = {
                    p = p.copy(partyEvidence = if (it) p.partyEvidence + d.identifier else p.partyEvidence - d.identifier)
                })
                Text(stringResource(Res.string.vp_evidence_party, name), style = MaterialTheme.typography.bodyMedium)
            }
            if (kind.representative) Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = d.identifier in p.agentEvidence, onCheckedChange = {
                    p = p.copy(agentEvidence = if (it) p.agentEvidence + d.identifier else p.agentEvidence - d.identifier)
                })
                Text(stringResource(Res.string.vp_evidence_agent, name), style = MaterialTheme.typography.bodyMedium)
            }
        }

        SectionTitle(stringResource(Res.string.vp_key))
        clientId?.let { id ->
            Text(id, style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { clipboard.setText(AnnotatedString(id)) }) { Text(stringResource(Res.string.vp_copy_client_id)) }
        }
        if (kind.representative) {
            SectionTitle(stringResource(Res.string.vp_mandates))
            Text(stringResource(Res.string.vp_mandates_text, p.mandates.size), style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(value = mandateText, onValueChange = { mandateText = it.take(32 * 1024) },
                label = { Text(stringResource(Res.string.vp_mandate_paste)) }, modifier = Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { model.verifier.importMandate(p, mandateText); mandateText = "" }, enabled = mandateText.isNotBlank()) { Text(stringResource(Res.string.vp_mandate_import)) }
                if (p.mandates.isNotEmpty()) TextButton(onClick = { p = p.copy(mandates = emptyList()) }) { Text(stringResource(Res.string.vp_mandates_clear)) }
            }
        }
        if (!kind.representative) {
            SectionTitle(stringResource(Res.string.vp_issue_mandate))
            Text(stringResource(Res.string.vp_issue_mandate_text), style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(value = agentForMandate, onValueChange = { agentForMandate = it.take(80) },
                label = { Text(stringResource(Res.string.vp_agent_name)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = agentRoleForMandate, onValueChange = { agentRoleForMandate = it.take(80) },
                label = { Text(stringResource(Res.string.vp_agent_role)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = agentClientId, onValueChange = { agentClientId = it.trim().take(400) },
                label = { Text(stringResource(Res.string.vp_agent_client_id)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = mandateDays, onValueChange = { mandateDays = it.filter(Char::isDigit).take(3) },
                label = { Text(stringResource(Res.string.vp_mandate_days)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedButton(
                onClick = {
                    scope.launch {
                        issued = runCatching {
                            model.verifier.issueMandate(p, agentForMandate, agentRoleForMandate, agentClientId,
                                listOfNotNull(p.purpose.takeIf { it.isNotBlank() }), mandateDays.toIntOrNull() ?: 180)
                        }.getOrElse { e -> model.message.value = model.describe(e); null }
                    }
                },
                enabled = p.partyName.isNotBlank() && agentForMandate.isNotBlank() &&
                    (agentClientId.startsWith("decentralized_identifier:") || agentClientId.startsWith("x509_hash:")),
            ) { Text(stringResource(Res.string.vp_issue)) }
            issued?.let { jws ->
                Text(stringResource(Res.string.vp_issued), style = MaterialTheme.typography.bodySmall)
                OutlinedButton(onClick = { clipboard.setText(AnnotatedString(jws)) }) { Text(stringResource(Res.string.vp_copy_mandate)) }
            }
        }
        SectionTitle(stringResource(Res.string.vp_registration))
        OutlinedTextField(value = p.registration.orEmpty(), onValueChange = { p = p.copy(registration = it.trim().take(64 * 1024).ifEmpty { null }) },
            label = { Text(stringResource(Res.string.vp_registration_paste)) }, modifier = Modifier.fillMaxWidth())
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.verifier.save(p) }, enabled = p.partyName.isNotBlank()) { Text(stringResource(Res.string.action_save)) }
            if (model.verifier.profiles.value.any { it.id == p.id }) OutlinedButton(onClick = { model.verifier.delete(p) }) { Text(stringResource(Res.string.action_delete)) }
            TextButton(onClick = { model.verifier.editing.value = null }) { Text(stringResource(Res.string.action_cancel)) }
        }
    }
}
