package diw.wallet.app.ui

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
        MsIssuanceUi.Loading -> Busy("讀取發行要求")
        is MsIssuanceUi.Working -> Busy(s.message)
        is MsIssuanceUi.Failed -> Failure(s.message) { model.screen.value = Screen.Home }
        is MsIssuanceUi.WaitingForLogin -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Text("請在瀏覽器登入 ${hostOf(s.requirement.configuration)}，完成後會自動返回", Modifier.padding(vertical = 12.dp))
            OutlinedButton(onClick = { model.back() }) { Text("取消") }
        }
        is MsIssuanceUi.Done -> Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            VerdictCard(Verdict.PASS, "已加入證件")
            CredentialCard(model, s.document) { model.screen.value = Screen.DocumentDetail(s.document.identifier) }
            Button(onClick = { model.showTab(HomeTab.DOCUMENTS) }) { Text("完成") }
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
        TrustCard("發行端", request.issuedBy ?: request.clientName ?: request.issuerDid, request.trust,
            listOf("DID：${request.issuerDid}", "發證端點：${request.credentialIssuer}"))
        Text(request.cardTitle ?: "Verified ID 憑證", style = MaterialTheme.typography.titleLarge)
        request.consentTitle?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        if (request.selfIssuedClaims.isNotEmpty()) Text("請填寫：", style = MaterialTheme.typography.titleSmall)
        request.selfIssuedClaims.forEach { c ->
            OutlinedTextField(
                value = selfIssued[c.claim].orEmpty(),
                onValueChange = { selfIssued[c.claim] = it },
                label = { Text(c.claim + if (c.required) "（必填）" else "") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        request.tokenRequirements.forEach { t ->
            when {
                t.injected -> Text("已由發行端提供登入資訊（${hostOf(t.configuration)}）", style = MaterialTheme.typography.bodySmall)
                request.tokens[t.configuration] != null -> Text("已登入 ${hostOf(t.configuration)}", color = MaterialTheme.colorScheme.primary)
                else -> OutlinedButton(onClick = { model.ms.login(request, t) }) {
                    Text("登入 ${hostOf(t.configuration)}" + if (t.required) "（必要）" else "")
                }
            }
        }
        request.presentationRequirements.forEach { p ->
            Text("需要出示：${p.credentialType}" + if (p.required) "（必要）" else "", style = MaterialTheme.typography.titleSmall)
            val list = candidates[p.credentialType].orEmpty()
            if (list.isEmpty()) Text("錢包內沒有符合的憑證", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
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
                label = { Text("發行端提供的 ${r.length} 位 PIN 碼") },
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
        val ok = riskAcknowledgement(request.trust.tier)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.ms.complete(request, selfIssued.toMap(), pin, chosen.toMap()) }, enabled = ready && ok) { Text("加入") }
            OutlinedButton(onClick = { model.back() }) { Text("取消") }
        }
    }
}
