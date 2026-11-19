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
import diw.wallet.app.OpenPgpProof
import diw.wallet.app.Screen
import diw.wallet.app.SignerChoice
import diw.wallet.app.VerifierKeys
import diw.wallet.app.VerifierProfile
import androidx.compose.runtime.produceState
import diw.wallet.core.document.pgp.OpenPgpTrust
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.verifier.declaration.DeclarationEvidence
import diw.wallet.core.verifier.declaration.EvidenceClaim
import diw.wallet.core.verifier.declaration.EvidenceQueries
import org.multipaz.document.Document
import org.multipaz.util.fromBase64
import org.multipaz.util.toBase64
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
    var keys by remember(profileId) { mutableStateOf(VerifierKeys()) }
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
        profile?.let { pr -> SessionKeys(model, pr, keys) { keys = it } }
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
            onClick = { model.verifier.start(ask, profile, purpose, risk, VerificationPolicy(accepted, requireZk), route, keys) },
            enabled = accepted.isNotEmpty() && keys.complete(profile) && (route == OnlineRoute.SERVER && server != null || route == OnlineRoute.LAN && lan),
        ) {
            Icon(WalletIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
            Text(stringResource(Res.string.ov_start))
        }
    }
}

/** The keys [p] needs for this verification: its X.509 key and each OpenPGP card; PINs are kept for this run only. */
@Composable
private fun SessionKeys(model: WalletModel, p: VerifierProfile, keys: VerifierKeys, onChange: (VerifierKeys) -> Unit) {
    if (!p.usesX509 && p.openPgp.isEmpty()) return
    SectionTitle(stringResource(Res.string.ov_keys))
    Text(stringResource(Res.string.ov_keys_text), style = MaterialTheme.typography.bodySmall)
    if (p.usesX509) {
        Text(stringResource(Res.string.ov_x509_key), style = MaterialTheme.typography.titleSmall)
        p.x509Certificate?.let { Text(stringResource(Res.string.vp_x509_last, certificateName(it)), style = MaterialTheme.typography.bodySmall) }
        SignerPicker(model) { onChange(keys.copy(x509 = it)) }
    }
    p.openPgp.forEach { proof ->
        Text(stringResource(Res.string.ov_pgp_card, proof.name), style = MaterialTheme.typography.titleSmall)
        OpenPgpKeyPicker(model, x509 = false) { c ->
            val card = c as? SignerChoice.OpenPgp
            onChange(keys.copy(openPgp = if (card == null) keys.openPgp - proof.fingerprint else keys.openPgp + (proof.fingerprint to card)))
        }
    }
}

/** The subject name of a certificate stored as base64 DER. */
internal fun certificateName(base64: String): String =
    runCatching { DocumentSigning.certificateSummary(base64.fromBase64())?.first }.getOrNull() ?: "X.509"

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
    stringResource(Res.string.sep_comma) + stringResource(Res.string.vp_evidence_count, p.evidenceCount) +
    (if (p.usesX509) stringResource(Res.string.sep_comma) + stringResource(Res.string.vp_signs_x509) else "")

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
    LaunchedEffect(initial.id, p.signingKey, p.x509Certificate) { clientId = model.verifier.clientId(p) }
    var x509Choice by remember(initial.id) { mutableStateOf<SignerChoice?>(null) }
    var x509Problem by remember(initial.id) { mutableStateOf<String?>(null) }
    var x509Busy by remember(initial.id) { mutableStateOf(false) }
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
            EvidenceDocument(model, d, DeclarationEvidence.ROLE_PARTY, p) { p = it }
            if (kind.representative) EvidenceDocument(model, d, DeclarationEvidence.ROLE_AGENT, p) { p = it }
        }
        if (documents.isEmpty()) Text(stringResource(Res.string.vp_no_documents), style = MaterialTheme.typography.bodySmall)
        OpenPgpProofs(model, p) { p = it }

        SectionTitle(stringResource(Res.string.vp_key))
        Row(Modifier.fillMaxWidth().clickable { p = p.copy(signingKey = VerifierProfile.SIGN_WALLET) }, verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = !p.usesX509, onClick = { p = p.copy(signingKey = VerifierProfile.SIGN_WALLET) })
            Column {
                Text(stringResource(Res.string.vp_key_wallet), style = MaterialTheme.typography.bodyLarge)
                Text(stringResource(Res.string.vp_key_wallet_text), style = MaterialTheme.typography.bodySmall)
            }
        }
        Row(Modifier.fillMaxWidth().clickable { p = p.copy(signingKey = VerifierProfile.SIGN_X509) }, verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = p.usesX509, onClick = { p = p.copy(signingKey = VerifierProfile.SIGN_X509) })
            Column {
                Text(stringResource(Res.string.vp_key_x509), style = MaterialTheme.typography.bodyLarge)
                Text(stringResource(Res.string.vp_key_x509_text), style = MaterialTheme.typography.bodySmall)
            }
        }
        if (p.usesX509) {
            p.x509Certificate?.let { Text(stringResource(Res.string.vp_x509_last, certificateName(it)), style = MaterialTheme.typography.bodyMedium) }
            SignerPicker(model) { x509Choice = it }
            OutlinedButton(
                onClick = {
                    val choice = x509Choice ?: return@OutlinedButton
                    x509Busy = true
                    x509Problem = null
                    scope.launch {
                        runCatching { model.verifier.readX509(choice) }
                            .onSuccess { p = p.copy(x509Certificate = it.certificateChain.first().toBase64()) }
                            .onFailure { x509Problem = model.describe(it) }
                        x509Busy = false
                    }
                },
                enabled = x509Choice != null && !x509Busy,
            ) { Text(if (x509Busy) stringResource(Res.string.state_reading) else stringResource(Res.string.vp_x509_read)) }
            x509Problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        }
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
                                listOfNotNull(p.purpose.takeIf { it.isNotBlank() }), mandateDays.toIntOrNull() ?: 180, VerifierKeys(x509 = x509Choice))
                        }.getOrElse { e -> model.message.value = model.describe(e); null }
                    }
                },
                enabled = p.partyName.isNotBlank() && agentForMandate.isNotBlank() && (!p.usesX509 || x509Choice != null) &&
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

/**
 * One wallet credential as evidence for [role]: whether it is used, and which of its claims are disclosed. Without a
 * choice the claims that name who the verifier is are disclosed.
 */
@Composable
private fun EvidenceDocument(model: WalletModel, d: Document, role: String, p: VerifierProfile, onChange: (VerifierProfile) -> Unit) {
    val name = d.displayName ?: d.identifier
    val ids = if (role == DeclarationEvidence.ROLE_PARTY) p.partyEvidence else p.agentEvidence
    val used = d.identifier in ids
    val key = VerifierProfile.claimKey(role, d.identifier)
    val claims by produceState<List<EvidenceClaim>?>(null, d.identifier) {
        value = runCatching { d.getCertifiedCredentials().firstOrNull()?.let { EvidenceQueries.claims(it, model.documentTypes) } }.getOrNull().orEmpty()
    }
    var open by remember(d.identifier, role) { mutableStateOf(false) }
    val supported = claims?.isNotEmpty() == true
    fun setUsed(on: Boolean) {
        val next = if (on) ids + d.identifier else ids - d.identifier
        onChange(if (role == DeclarationEvidence.ROLE_PARTY) p.copy(partyEvidence = next) else p.copy(agentEvidence = next))
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = used, enabled = supported || used, onCheckedChange = { setUsed(it) })
        Column(Modifier.weight(1f)) {
            Text(stringResource(if (role == DeclarationEvidence.ROLE_PARTY) Res.string.vp_evidence_party else Res.string.vp_evidence_agent, name),
                style = MaterialTheme.typography.bodyMedium)
            if (claims != null && !supported) Text(stringResource(Res.string.vp_evidence_unsupported), style = MaterialTheme.typography.bodySmall)
        }
    }
    val all = claims.orEmpty()
    if (!used || all.isEmpty()) return
    val chosen = p.evidenceClaims[key] ?: all.filter { it.identifying }.map { it.path }
    TextButton(onClick = { open = !open }) { Text(stringResource(Res.string.vp_claims_choose, chosen.size, all.size)) }
    if (!open) return
    Column(Modifier.padding(start = 24.dp)) {
        all.forEach { c ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = c.path in chosen, onCheckedChange = { on ->
                    val next = if (on) chosen + listOf(c.path) else chosen.filter { it != c.path }
                    onChange(p.copy(evidenceClaims = p.evidenceClaims + (key to next)))
                })
                Column {
                    Text(c.label + if (c.identifying) stringResource(Res.string.vp_claim_identifying) else "", style = MaterialTheme.typography.bodyMedium)
                    Text(c.value, style = MaterialTheme.typography.bodySmall, maxLines = 1)
                }
            }
        }
        if (all.none { it.identifying && it.path in chosen }) {
            Text(stringResource(Res.string.vp_claims_no_identity), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        if (chosen.isEmpty()) Text(stringResource(Res.string.vp_claims_empty), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        TextButton(onClick = { onChange(p.copy(evidenceClaims = p.evidenceClaims - key)) }) { Text(stringResource(Res.string.vp_claims_default)) }
    }
}

/** The holder's own OpenPGP cards whose signature over each request is added as evidence (a DIW extension). */
@Composable
private fun OpenPgpProofs(model: WalletModel, p: VerifierProfile, onChange: (VerifierProfile) -> Unit) {
    val keys by model.openPgp.keys.collectAsState()
    val own = keys.filter { it.trust == OpenPgpTrust.OWN_CARD && it.info.canSign }
    Text(stringResource(Res.string.vp_pgp), style = MaterialTheme.typography.titleSmall)
    Text(stringResource(Res.string.vp_pgp_text), style = MaterialTheme.typography.bodySmall)
    if (own.isEmpty()) {
        Text(stringResource(Res.string.vp_pgp_none), style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = { model.screen.value = Screen.OpenPgpKeys(null, Screen.VerifierProfiles) }) { Text(stringResource(Res.string.pgp_manage)) }
        return
    }
    val roles = listOfNotNull(DeclarationEvidence.ROLE_PARTY, DeclarationEvidence.ROLE_AGENT.takeIf { p.verifierKind.representative })
    own.forEach { e ->
        roles.forEach { role ->
            val on = p.openPgp.any { it.fingerprint == e.fingerprint && it.role == role }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = on, onCheckedChange = { checked ->
                    val rest = p.openPgp.filterNot { it.fingerprint == e.fingerprint && it.role == role }
                    onChange(p.copy(openPgp = if (checked) rest + OpenPgpProof(role, e.fingerprint, e.info.name) else rest))
                })
                Column {
                    Text(stringResource(if (role == DeclarationEvidence.ROLE_PARTY) Res.string.vp_evidence_party else Res.string.vp_evidence_agent, e.info.name),
                        style = MaterialTheme.typography.bodyMedium)
                    Text(e.fingerprint.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

