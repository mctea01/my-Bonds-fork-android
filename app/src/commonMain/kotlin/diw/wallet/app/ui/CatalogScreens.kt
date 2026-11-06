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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.unit.dp
import diw.wallet.app.DocumentSources
import diw.wallet.app.HomeTab
import diw.wallet.app.MyDataFiles
import diw.wallet.app.Screen
import diw.wallet.app.TwdiwTrustRow
import diw.wallet.app.WalletModel
import diw.wallet.core.document.DocumentFormat
import diw.wallet.app.legal.Integration
import diw.wallet.core.profile.twdiw.AnchorState
import diw.wallet.core.profile.twdiw.TwdiwPlatform

/**
 * Adding a document: cards the government wallet issuers offer, cards the holder makes from their own documents with
 * the citizen certificate (as Bonds does), and any other OpenID4VCI issuer by its address.
 */
@Composable
fun AddDocumentScreen(model: WalletModel) {
    val cards by model.taiwan.cardServices.collectAsState()
    val error by model.taiwan.servicesError.collectAsState()
    val files by model.files.files.collectAsState()
    var issuer by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { if (cards == null && error == null) model.taiwan.loadServices() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(Res.string.catalog_intro), style = MaterialTheme.typography.bodyMedium)
        if (model.twdiwPlatform != TwdiwPlatform.PRODUCTION) {
            Text(stringResource(Res.string.catalog_test_platform, model.twdiwPlatform.frontendUrl), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        SectionTitle(stringResource(Res.string.catalog_government))
        Text(stringResource(Res.string.catalog_government_text), style = MaterialTheme.typography.bodySmall)
        when {
            !model.legal.enabled(Integration.TWDIW) -> IntegrationOffRow(model, Integration.TWDIW, stringResource(Res.string.catalog_government))
            error != null -> InlineError(error!!) { model.taiwan.loadServices() }
            cards == null -> CircularProgressIndicator(Modifier.size(24.dp))
            cards!!.isEmpty() -> Text(stringResource(Res.string.catalog_none), style = MaterialTheme.typography.bodySmall)
            else -> cards!!.forEach { c ->
                ActionRow(
                    WalletIcons.Government, c.name,
                    when {
                        c.issuerServiceUrl == null -> stringResource(Res.string.catalog_no_page)
                        c.opensExternally -> stringResource(Res.string.catalog_apply)
                        else -> stringResource(Res.string.catalog_apply_text)
                    },
                    enabled = c.issuerServiceUrl != null,
                    leading = c.logoUrl?.let { logo -> { CardLogo(model, logo, WalletIcons.Government, MaterialTheme.colorScheme.primary, size = 28) } },
                ) { model.taiwan.applyFor(c) }
            }
        }
        SectionTitle(stringResource(Res.string.catalog_self_made))
        Text(stringResource(Res.string.catalog_self_made_text), style = MaterialTheme.typography.bodySmall)
        val idSource = DocumentSources.byId("mydata-id")!!
        val idPdf = files.firstOrNull { f ->
            f.nationalId == null && f.report?.format == DocumentFormat.PDF && (MyDataFiles.recognize(f.name)?.nationalId == true || f.source?.contains(stringResource(Res.string.catalog_national_id_data)) == true)
        }
        val hasCard = files.any { it.nationalId != null }
        if (!model.legal.enabled(Integration.MYDATA)) IntegrationOffRow(model, Integration.MYDATA, stringResource(Res.string.catalog_national_id_card))
        else ActionRow(
            WalletIcons.Person, stringResource(Res.string.catalog_national_id_card),
            if (hasCard) stringResource(Res.string.catalog_national_id_exists) else stringResource(Res.string.catalog_national_id_text),
        ) {
            if (model.platform.embeddedBrowser) model.screen.value = Screen.Portal(idSource.id) else model.platform.openBrowser(idSource.url)
        }
        idPdf?.let { f ->
            ActionRow(WalletIcons.Document, stringResource(Res.string.catalog_national_id_saved), f.name) { model.screen.value = Screen.NationalIdCreate(f.id) }
        }
        ActionRow(
            WalletIcons.Card, stringResource(Res.string.catalog_derived),
            stringResource(Res.string.catalog_derived_text),
        ) { model.showTab(HomeTab.FILES) }
        ActionRow(
            WalletIcons.Shield, stringResource(Res.string.catalog_age),
            stringResource(Res.string.catalog_age_text),
        ) { model.showTab(HomeTab.USE) }
        SectionTitle(stringResource(Res.string.catalog_other_issuers))
        Text(stringResource(Res.string.catalog_other_issuers_text), style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = issuer,
                onValueChange = { issuer = it.trim() },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text(stringResource(Res.string.catalog_issuer_url)) },
            )
            Button(onClick = { model.handleUri(issuer) }, enabled = issuer.isNotEmpty()) { Text(stringResource(Res.string.action_query)) }
        }
    }
}

@Composable
private fun anchorText(anchor: String?): String = when (anchor?.let { runCatching { AnchorState.valueOf(it) }.getOrNull() }) {
    AnchorState.VERIFIED -> stringResource(Res.string.anchor_verified)
    AnchorState.NOT_ANCHORED -> stringResource(Res.string.anchor_not_anchored)
    AnchorState.MISMATCH -> stringResource(Res.string.anchor_mismatch)
    AnchorState.UNAVAILABLE -> stringResource(Res.string.anchor_unavailable)
    AnchorState.DEVELOPMENT_SANDBOX -> stringResource(Res.string.anchor_sandbox)
    null -> stringResource(Res.string.anchor_unchecked)
}

/** The TWDIW trust list: listed issuers and verifiers, their DID documents and Arbitrum registrations. */
@Composable
fun TrustListScreen(model: WalletModel) {
    val rows by model.taiwan.trustRows.collectAsState()
    val error by model.taiwan.trustError.collectAsState()
    val progress by model.taiwan.trustProgress.collectAsState()
    var filter by remember { mutableStateOf("") }
    // Opening the list checks every organisation not checked in the last day, without a tap per entry.
    LaunchedEffect(Unit) { if (rows == null) model.taiwan.loadTrust() else model.taiwan.verifyAll(force = false) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.trust_list_text),
            style = MaterialTheme.typography.bodyMedium)
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = filter,
                onValueChange = { filter = it },
                leadingIcon = { Icon(WalletIcons.Search, contentDescription = null) },
                label = { Text(stringResource(Res.string.trust_list_search)) },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { model.taiwan.loadTrust(refresh = true) }) { Text(stringResource(Res.string.action_refresh)) }
        }
        error?.let { InlineError(it) { model.taiwan.loadTrust(refresh = true) } }
        progress?.let { (done, total) ->
            LinearProgressIndicator(progress = { if (total == 0) 0f else done.toFloat() / total }, modifier = Modifier.fillMaxWidth())
            Text(stringResource(Res.string.trust_list_checking, done, total), style = MaterialTheme.typography.bodySmall)
        }
        val list = rows
        if (list == null && error == null) CircularProgressIndicator(Modifier.size(24.dp))
        list?.filter { r ->
            filter.isBlank() || listOfNotNull(r.entry.name, r.entry.nameEn, r.entry.taxId).any { it.contains(filter.trim(), ignoreCase = true) }
        }?.forEach { row -> TrustRowCard(model, row) }
    }
}

@Composable
private fun TrustRowCard(model: WalletModel, row: TwdiwTrustRow) {
    val e = row.entry
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(if (2 in e.orgTypes && 1 !in e.orgTypes) WalletIcons.Scan else WalletIcons.Government, contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                Column(Modifier.weight(1f)) {
                    Text(e.displayName, style = MaterialTheme.typography.titleSmall)
                    e.nameEn?.takeIf { it != e.name }?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            }
            val roles = buildList { if (1 in e.orgTypes) add(stringResource(Res.string.role_issuer)); if (2 in e.orgTypes) add(stringResource(Res.string.role_verifier)) }
            Text(roles.joinToString(stringResource(Res.string.sep_list)) + (e.taxId?.let { stringResource(Res.string.trust_list_tax_id, it) } ?: ""), style = MaterialTheme.typography.bodySmall)
            Text(e.did, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            if (e.hosts.isNotEmpty()) Text(stringResource(Res.string.trust_list_hosts) + e.hosts.joinToString(), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(Res.string.trust_list_anchor) + anchorText(row.anchor) + (row.checkedAt?.let { stringResource(Res.string.trust_list_checked_at, localTime(kotlin.time.Instant.fromEpochMilliseconds(it))) } ?: ""),
                style = MaterialTheme.typography.bodySmall)
            row.decision?.let { TierBadge(it) }
            TextButton(onClick = { model.taiwan.verifyEntry(row) }) { Text(if (row.decision == null) stringResource(Res.string.action_verify) else stringResource(Res.string.action_verify_again)) }
        }
    }
}
