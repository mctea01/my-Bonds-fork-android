package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
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
import diw.wallet.app.HistoryEntry
import diw.wallet.app.HistoryKind
import diw.wallet.app.HomeTab
import diw.wallet.app.Screen
import diw.wallet.app.StatusMonitor
import diw.wallet.app.WalletModel
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.trust.TrustTier
import org.multipaz.revocation.RevocationCheckState
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Clock
import kotlin.time.Instant

@Composable
fun HomeNavigationBar(selected: HomeTab, onSelect: (HomeTab) -> Unit) {
    NavigationBar {
        listOf(
            Triple(HomeTab.DOCUMENTS, stringResource(Res.string.tab_documents), WalletIcons.Wallet),
            Triple(HomeTab.FILES, stringResource(Res.string.tab_files), WalletIcons.Document),
            Triple(HomeTab.USE, stringResource(Res.string.tab_use), WalletIcons.Scan),
            Triple(HomeTab.VERIFY, stringResource(Res.string.tab_verify), WalletIcons.Shield),
            Triple(HomeTab.HISTORY, stringResource(Res.string.tab_history), WalletIcons.History),
        ).forEach { (tab, label, icon) ->
            NavigationBarItem(
                selected = tab == selected,
                onClick = { onSelect(tab) },
                icon = { Icon(icon, contentDescription = null) },
                label = { Text(label) },
            )
        }
    }
}

/** Add a document: from the list of documents that can be requested, or by reading the issuer's QR Code. */
@Composable
fun AddDocumentSheet(model: WalletModel, onDismiss: () -> Unit, onList: () -> Unit, scan: ScanActions) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 32.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(Res.string.action_add_credential), style = MaterialTheme.typography.titleLarge)
            Text(stringResource(Res.string.add_sheet_text), style = MaterialTheme.typography.bodyMedium)
            ActionRow(WalletIcons.Document, stringResource(Res.string.screen_add_document), stringResource(Res.string.add_sheet_list_text)) { onList() }
            scan.camera?.let { camera ->
                ActionRow(WalletIcons.Scan, stringResource(Res.string.action_scan_qr), stringResource(Res.string.add_sheet_scan_text)) { camera() }
            }
            ActionRow(WalletIcons.Image, stringResource(Res.string.action_qr_from_image), stringResource(Res.string.add_sheet_image_text)) { scan.image() }
        }
    }
}

// ---------------------------------------------------------------- documents

/** Every document in one list, grouped by category, with search and category filters. */
@Composable
fun DocumentsTab(model: WalletModel, onAdd: () -> Unit) {
    val docs by model.documents.collectAsState()
    val files by model.files.files.collectAsState()
    val hasNationalId = files.any { it.nationalId != null }
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf<DocumentCategory?>(null) }
    if (docs.isEmpty() && !hasNationalId) {
        EmptyState(WalletIcons.Wallet, stringResource(Res.string.documents_empty_title), stringResource(Res.string.documents_empty_text), stringResource(Res.string.action_add_credential), onAdd)
        return
    }
    val categories = docs.map { categoryOf(it.issuanceRecord) }.distinct().sortedBy { it.ordinal }
    val q = query.trim()
    val shown = docs.filter { d ->
        (filter == null || categoryOf(d.issuanceRecord) == filter) &&
            (q.isEmpty() || listOfNotNull(d.displayName, d.typeDisplayName, d.issuanceRecord?.credentialIssuer).any { it.contains(q, ignoreCase = true) })
    }
    val groups = shown.groupBy { categoryOf(it.issuanceRecord) }.entries.sortedBy { it.key.ordinal }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (docs.size > 3) item(key = "search") {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                leadingIcon = { Icon(WalletIcons.Search, contentDescription = null) },
                placeholder = { Text(stringResource(Res.string.documents_search)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        if (categories.size > 1) item(key = "filters") {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = filter == null, onClick = { filter = null }, label = { Text(stringResource(Res.string.filter_all)) })
                categories.forEach { c -> FilterChip(selected = filter == c, onClick = { filter = if (filter == c) null else c }, label = { Text(stringResource(c.title)) }) }
            }
        }
        // The Bonds national ID card lives with the MyData PDF it was made from; it is listed here with the cards.
        if (hasNationalId && filter == null && q.isEmpty()) item(key = "national-id") {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (groups.isNotEmpty()) SectionTitle(stringResource(Res.string.documents_filter_moica))
                NationalIdCards(model)
            }
        }
        groups.forEach { (category, list) ->
            if (groups.size > 1 || hasNationalId) item(key = "h-" + category.name) { SectionTitle(stringResource(category.title)) }
            items(list, key = { it.identifier }) { doc ->
                CredentialCard(model, doc) { model.screen.value = Screen.DocumentDetail(doc.identifier) }
            }
        }
        if (shown.isEmpty() && !(hasNationalId && filter == null && q.isEmpty())) item(key = "none") {
            Text(stringResource(Res.string.documents_no_match), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 16.dp))
        }
    }
}

// ---------------------------------------------------------------- use

/**
 * What the holder does: read a QR Code (one entry, the code decides the flow: a presentation request, a credential
 * offer or a Bonds challenge), present by NFC, counter services, and adding documents.
 */
@Composable
fun UseTab(model: WalletModel, scan: ScanActions) {
    val docs by model.documents.collectAsState()
    val services by model.taiwan.offlineServices.collectAsState()
    val error by model.taiwan.servicesError.collectAsState()
    var input by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { if (services == null && error == null) model.taiwan.loadServices() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(Tokens.ContainerRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(WalletIcons.Qr, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                Text(stringResource(Res.string.use_read_qr), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(Res.string.use_read_qr_text),
                    style = MaterialTheme.typography.bodyMedium)
                if (docs.isEmpty()) Text(stringResource(Res.string.use_no_credentials), style = MaterialTheme.typography.bodySmall)
                if (scan.camera == null) Text(stringResource(Res.string.use_no_camera), style = MaterialTheme.typography.bodySmall)
                ScanButtons(scan)
            }
        }
        ActionRow(
            WalletIcons.Nfc, stringResource(Res.string.use_proximity),
            stringResource(Res.string.use_proximity_text),
            enabled = docs.isNotEmpty(),
        ) { model.proximity.open() }
        ActionRow(
            WalletIcons.Shield, stringResource(Res.string.use_age_proof),
            stringResource(Res.string.use_age_proof_text),
        ) { scan.primary() }
        SectionTitle(stringResource(Res.string.use_counter))
        Text(stringResource(Res.string.use_counter_text), style = MaterialTheme.typography.bodySmall)
        when {
            !model.legal.enabled(diw.wallet.app.legal.Integration.TWDIW) -> IntegrationOffRow(model, diw.wallet.app.legal.Integration.TWDIW, stringResource(Res.string.use_counter_services))
            error != null -> InlineError(error!!) { model.taiwan.loadServices() }
            services == null -> CircularProgressIndicator(Modifier.size(24.dp))
            services!!.isEmpty() -> Text(stringResource(Res.string.use_counter_none), style = MaterialTheme.typography.bodySmall)
            else -> services!!.forEach { s ->
                ActionRow(WalletIcons.Store, s.name, if (docs.isEmpty()) stringResource(Res.string.use_counter_need_credential) else stringResource(Res.string.use_counter_barcode), enabled = docs.isNotEmpty()) {
                    model.withTwdiwNotice { model.taiwan.startPickup(s) }
                }
            }
        }
        SectionTitle(stringResource(Res.string.action_add_credential))
        ActionRow(WalletIcons.Document, stringResource(Res.string.screen_add_document), stringResource(Res.string.add_sheet_list_text)) { model.screen.value = Screen.AddDocument }
        SectionTitle(stringResource(Res.string.use_paste))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text(stringResource(Res.string.use_paste_label)) },
            )
            Button(onClick = { model.handleUri(input); input = "" }, enabled = input.isNotBlank()) { Text(stringResource(Res.string.action_open)) }
        }
    }
}

// ---------------------------------------------------------------- verify

/**
 * The wallet as a verifier: the offline check of a Bonds or TWDIW presentation, and in-person reading of an mdoc
 * by NFC. The rest of the verifier is laid out and stays disabled until its design is implemented.
 */
@Composable
fun VerifyTab(model: WalletModel, canScanFrames: Boolean = false) {
    val defaultPurpose = stringResource(Res.string.verify_identity)
    var purpose by remember { mutableStateOf(defaultPurpose) }
    var risk by remember { mutableStateOf(RiskLevel.MEDIUM) }
    var source by remember { mutableStateOf(BondsCredentialSource.TWDIW) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(Tokens.ContainerRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(WalletIcons.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                Text(stringResource(Res.string.verify_others), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(Res.string.verify_others_text),
                    style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(Res.string.verify_accepted), style = MaterialTheme.typography.titleSmall)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(BondsCredentialSource.TWDIW, BondsCredentialSource.SELF_ISSUED, BondsCredentialSource.ANY).forEach { s ->
                        FilterChip(selected = source == s, onClick = { source = s }, label = { Text(bondsSourceLabel(s)) })
                    }
                }
                if (source == BondsCredentialSource.SELF_ISSUED) {
                    Text(stringResource(Res.string.verify_accepted_moica),
                        style = MaterialTheme.typography.bodySmall)
                }
                if (source == BondsCredentialSource.ANY) {
                    Text(stringResource(Res.string.verify_accepted_any),
                        style = MaterialTheme.typography.bodySmall)
                }
                OutlinedTextField(
                    value = purpose,
                    onValueChange = { purpose = it.take(100) },
                    label = { Text(stringResource(Res.string.verify_purpose)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(stringResource(Res.string.verify_purpose_risk), style = MaterialTheme.typography.titleSmall)
                RiskSelector(risk) { risk = it }
                Button(onClick = { model.taiwan.startVerifier(purpose.trim(), risk, source) }, enabled = purpose.isNotBlank()) {
                    Icon(WalletIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(Res.string.verify_make_challenge))
                }
            }
        }
        BondsAgeVerifierSetup(model, canScanFrames)
        ActionRow(
            WalletIcons.Link, stringResource(Res.string.verify_zktls),
            stringResource(Res.string.verify_zktls_text),
        ) { model.taiwan.zkTls.openSetup() }
        SectionTitle(stringResource(Res.string.verify_verifier_identity))
        ActionRow(WalletIcons.Person, stringResource(Res.string.verify_as_whom), stringResource(Res.string.verify_as_whom_text), enabled = false) {}
        SectionTitle(stringResource(Res.string.verify_other_methods))
        ActionRow(WalletIcons.Link, stringResource(Res.string.verify_online), stringResource(Res.string.verify_online_text), enabled = false) {}
        ActionRow(WalletIcons.Nfc, stringResource(Res.string.verify_reader), stringResource(Res.string.verify_reader_text)) { model.reader.open() }
    }
}

// ---------------------------------------------------------------- history

private enum class HistoryFilter(val title: org.jetbrains.compose.resources.StringResource, val kinds: Set<HistoryKind>) {
    PRESENTED(Res.string.history_filter_presented, setOf(HistoryKind.PRESENTED, HistoryKind.DECLINED)),
    ISSUED(Res.string.history_filter_issued, setOf(HistoryKind.ISSUED)),
    VERIFIED(Res.string.history_filter_verified, setOf(HistoryKind.VERIFIED)),
    STATUS(Res.string.history_filter_status, setOf(HistoryKind.STATUS)),
    SIGNED(Res.string.history_filter_signed, setOf(HistoryKind.SIGNED)),
}

/** Who received what and when, newest first; tapping an entry shows the documents and claim names. */
@Composable
fun HistoryTab(model: WalletModel) {
    val entries by model.history.collectAsState()
    var filter by remember { mutableStateOf<HistoryFilter?>(null) }
    var open by remember { mutableStateOf<String?>(null) }
    var confirmClear by remember { mutableStateOf(false) }
    if (entries.isEmpty()) {
        EmptyState(WalletIcons.History, stringResource(Res.string.history_empty_title), stringResource(Res.string.history_empty_text))
        return
    }
    val zone = TimeZone.currentSystemDefault()
    val today = Clock.System.now().toLocalDateTime(zone).date
    val shown = entries.filter { filter == null || it.kind in filter!!.kinds }
    val days = shown.groupBy { Instant.fromEpochSeconds(it.epochSeconds).toLocalDateTime(zone).date }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item(key = "filters") {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = filter == null, onClick = { filter = null }, label = { Text(stringResource(Res.string.filter_all)) })
                HistoryFilter.entries.forEach { f -> FilterChip(selected = filter == f, onClick = { filter = if (filter == f) null else f }, label = { Text(stringResource(f.title)) }) }
            }
        }
        days.forEach { (day, list) ->
            item(key = "d-$day") {
                val diff = today.toEpochDays().toLong() - day.toEpochDays().toLong()
                SectionTitle(when (diff) { 0L -> stringResource(Res.string.history_today); 1L -> stringResource(Res.string.history_yesterday); else -> day.toString() })
            }
            items(list, key = { it.id }) { e -> HistoryRow(e, expanded = open == e.id, zone) { open = if (open == e.id) null else e.id } }
        }
        if (shown.isEmpty()) item(key = "none") { Text(stringResource(Res.string.history_no_match), style = MaterialTheme.typography.bodyMedium) }
        item(key = "clear") {
            TextButton(onClick = { confirmClear = true }, modifier = Modifier.padding(top = 8.dp)) { Text(stringResource(Res.string.settings_clear_history)) }
        }
    }
    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(Res.string.settings_clear_history_title)) },
            text = { Text(stringResource(Res.string.settings_clear_history_text)) },
            confirmButton = {
                TextButton(onClick = { confirmClear = false; model.clearHistory() }) { Text(stringResource(Res.string.settings_clear_history_confirm), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
}

@Composable
private fun historyTitle(e: HistoryEntry): String = when (e.kind) {
    HistoryKind.ISSUED -> stringResource(Res.string.history_issued_from, e.party)
    HistoryKind.PRESENTED -> stringResource(Res.string.history_presented_to, e.party)
    HistoryKind.DECLINED -> stringResource(Res.string.history_declined, e.party)
    HistoryKind.VERIFIED -> stringResource(Res.string.history_verified, e.party)
    HistoryKind.STATUS -> (e.documents.firstOrNull() ?: stringResource(Res.string.history_credential)) + if (e.status == StatusMonitor.TRUST_CHANGE) stringResource(Res.string.history_trust_change) else stringResource(Res.string.history_status_change)
    HistoryKind.SIGNED -> stringResource(Res.string.history_signed_with, e.party)
}

private fun hhmm(t: LocalDateTime) = t.hour.toString().padStart(2, '0') + ":" + t.minute.toString().padStart(2, '0')

@Composable
private fun HistoryRow(e: HistoryEntry, expanded: Boolean, zone: TimeZone, onClick: () -> Unit) {
    val (verdict, status) = when {
        e.failure != null -> Verdict.FAIL to stringResource(Res.string.history_incomplete)
        e.kind == HistoryKind.DECLINED -> Verdict.CAUTION to stringResource(Res.string.history_declined_short)
        e.kind == HistoryKind.STATUS -> when (e.status) {
            RevocationCheckState.VALID.name -> Verdict.PASS to stringResource(Res.string.status_valid)
            RevocationCheckState.INVALID.name -> Verdict.FAIL to stringResource(Res.string.status_revoked)
            RevocationCheckState.SUSPENDED.name -> Verdict.CAUTION to stringResource(Res.string.status_suspended)
            else -> when (e.tier?.let { runCatching { TrustTier.valueOf(it) }.getOrNull() }) {
                TrustTier.T1 -> Verdict.PASS to "T1"
                TrustTier.T2 -> Verdict.PASS to "T2"
                TrustTier.T3 -> Verdict.CAUTION to "T3"
                else -> Verdict.FAIL to "T4"
            }
        }
        else -> Verdict.PASS to stringResource(Res.string.history_done)
    }
    val icon = when (e.kind) {
        HistoryKind.ISSUED -> WalletIcons.Receive
        HistoryKind.PRESENTED -> WalletIcons.Send
        HistoryKind.DECLINED -> WalletIcons.Fail
        HistoryKind.VERIFIED -> WalletIcons.Shield
        HistoryKind.STATUS -> WalletIcons.Caution
        HistoryKind.SIGNED -> WalletIcons.Document
    }
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                Column(Modifier.weight(1f)) {
                    Text(historyTitle(e), style = MaterialTheme.typography.titleSmall)
                    Text(
                        hhmm(Instant.fromEpochSeconds(e.epochSeconds).toLocalDateTime(zone)) +
                            (if (e.documents.isNotEmpty()) stringResource(Res.string.sep_wide) + e.documents.joinToString(stringResource(Res.string.sep_list)) else ""),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Icon(verdict.icon, contentDescription = null, tint = verdict.color, modifier = Modifier.size(16.dp))
                    Text(status, style = MaterialTheme.typography.labelMedium)
                }
            }
            if (expanded) {
                e.tier?.let { t ->
                    val tier = runCatching { TrustTier.valueOf(t) }.getOrNull()
                    if (tier != null) Text((if (e.kind == HistoryKind.STATUS) stringResource(Res.string.history_issuer) else stringResource(Res.string.history_other_party)) + stringResource(Res.string.history_trust_level) + WalletModel.tierTitle(tier) + (if (e.test) stringResource(Res.string.trust_test_suffix) else ""), style = MaterialTheme.typography.bodySmall)
                }
                e.note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                if (e.claims.isNotEmpty()) {
                    Text(if (e.kind == HistoryKind.VERIFIED) stringResource(Res.string.history_disclosed_fields) else stringResource(Res.string.history_fields), style = MaterialTheme.typography.labelLarge)
                    Text(e.claims.joinToString(stringResource(Res.string.sep_list)), style = MaterialTheme.typography.bodySmall)
                }
                e.failure?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            }
        }
    }
}
