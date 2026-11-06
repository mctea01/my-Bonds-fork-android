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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import diw.wallet.app.HomeTab
import diw.wallet.app.MsIssuanceUi
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.core.profile.msvid.MsIssuanceRequest
import diw.wallet.core.w3c.W3cVcCredential
import org.multipaz.document.Document

/** Microsoft Entra Verified ID issuance: the contract's requirements, sign-ins, PIN and consent. */
@Composable
fun MsIssuanceScreen(model: WalletModel) {
    val state by model.ms.state.collectAsState()
    when (val s = state) {
        MsIssuanceUi.Loading -> Busy(stringResource(Res.string.ms_reading))
        is MsIssuanceUi.Working -> Busy(s.message)
        is MsIssuanceUi.Failed -> Failure(s.message) { model.screen.value = Screen.Home }
        is MsIssuanceUi.WaitingForLogin -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Text(stringResource(Res.string.ms_login, hostOf(s.requirement.configuration)), Modifier.padding(vertical = 12.dp))
            OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
        }
        is MsIssuanceUi.Done -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.PASS, stringResource(Res.string.ms_added))
            CredentialCard(model, s.document) { model.screen.value = Screen.DocumentDetail(s.document.identifier) }
            Button(onClick = { model.showTab(HomeTab.DOCUMENTS) }) { Text(stringResource(Res.string.action_done)) }
        }
        // A new revision (after a sign-in) recomposes the review with the request's new tokens.
        is MsIssuanceUi.Review -> androidx.compose.runtime.key(s.revision) { ReviewView(model, s.request) }
    }
}

private fun hostOf(url: String) = url.substringAfter("://").substringBefore('/')

@Composable
private fun ReviewView(model: WalletModel, request: MsIssuanceRequest) {
    val selfIssued = remember(request) { mutableStateMapOf<String, String>() }
    val chosen = remember(request) { mutableStateMapOf<String, W3cVcCredential>() }
    var pin by remember(request) { mutableStateOf("") }
    var candidates by remember(request) { mutableStateOf<Map<String, List<Pair<Document, W3cVcCredential>>>>(emptyMap()) }
    LaunchedEffect(request) {
        candidates = request.presentationRequirements.associate { it.credentialType to model.ms.candidates(it) }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TrustCard(stringResource(Res.string.role_issuer), request.issuedBy ?: request.clientName ?: request.issuerDid, request.trust,
            listOf(stringResource(Res.string.flow_verifier_did, request.issuerDid), stringResource(Res.string.ms_endpoint, request.credentialIssuer)))
        Text(request.cardTitle ?: stringResource(Res.string.ms_credential), style = MaterialTheme.typography.titleLarge)
        request.consentTitle?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        if (request.selfIssuedClaims.isNotEmpty()) Text(stringResource(Res.string.ms_fill), style = MaterialTheme.typography.titleSmall)
        request.selfIssuedClaims.forEach { c ->
            OutlinedTextField(
                value = selfIssued[c.claim].orEmpty(),
                onValueChange = { selfIssued[c.claim] = it },
                label = { Text(c.claim + if (c.required) stringResource(Res.string.ms_required) else "") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        request.tokenRequirements.forEach { t ->
            when {
                t.injected -> Text(stringResource(Res.string.ms_token_given, hostOf(t.configuration)), style = MaterialTheme.typography.bodySmall)
                request.tokens[t.configuration] != null -> Text(stringResource(Res.string.ms_signed_in, hostOf(t.configuration)), color = MaterialTheme.colorScheme.primary)
                else -> OutlinedButton(onClick = { model.ms.login(request, t) }) {
                    Text(stringResource(Res.string.ms_sign_in, hostOf(t.configuration)) + if (t.required) stringResource(Res.string.ms_needed) else "")
                }
            }
        }
        request.presentationRequirements.forEach { p ->
            Text(stringResource(Res.string.ms_present_needed, p.credentialType) + if (p.required) stringResource(Res.string.ms_needed) else "", style = MaterialTheme.typography.titleSmall)
            val list = candidates[p.credentialType].orEmpty()
            if (list.isEmpty()) Text(stringResource(Res.string.ms_no_match), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            list.forEach { (doc, cred) ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = chosen[p.credentialType] === cred, onClick = { chosen[p.credentialType] = cred })
                    Text(doc.displayName ?: p.credentialType)
                }
            }
        }
        request.pinRequirement?.let { r ->
            OutlinedTextField(
                value = pin,
                onValueChange = { v -> pin = (if (r.type == "numeric") v.filter { it.isDigit() } else v).take(r.length) },
                label = { Text(stringResource(Res.string.ms_pin, r.length)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = if (r.type == "numeric") KeyboardType.NumberPassword else KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        val ready = request.selfIssuedClaims.all { !it.required || !selfIssued[it.claim].isNullOrEmpty() } &&
            request.tokenRequirements.all { !it.required || it.injected || request.tokens[it.configuration] != null } &&
            request.presentationRequirements.all { !it.required || chosen[it.credentialType] != null } &&
            (request.pinRequirement == null || pin.length == request.pinRequirement!!.length)
        val ok = riskAcknowledgement(request.trust)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.ms.complete(request, selfIssued.toMap(), pin, chosen.toMap()) }, enabled = ready && ok) { Text(stringResource(Res.string.action_add)) }
            OutlinedButton(onClick = { model.back() }) { Text(stringResource(Res.string.action_cancel)) }
        }
    }
}
