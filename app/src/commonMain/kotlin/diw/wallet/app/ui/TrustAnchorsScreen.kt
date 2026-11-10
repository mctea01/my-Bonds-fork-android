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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedButton
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
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.StoredAnchor
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.UserTrustedDid
import diw.wallet.core.x509.displaySubject
import kotlin.time.Instant

@Composable
private fun roleName(r: TrustRole): String = when (r) {
    TrustRole.ISSUER -> stringResource(Res.string.role_issuer)
    TrustRole.VERIFIER -> stringResource(Res.string.role_verifier)
    TrustRole.STATUS_LIST -> stringResource(Res.string.role_status_list)
    TrustRole.WALLET_PROVIDER -> stringResource(Res.string.role_wallet_provider)
    TrustRole.TRUST_LIST_PROVIDER -> stringResource(Res.string.role_list_signer)
    TrustRole.TSA -> stringResource(Res.string.role_timestamp)
    TrustRole.DOCUMENT -> stringResource(Res.string.role_document_signing)
    TrustRole.CONTENT -> stringResource(Res.string.role_c2pa)
    TrustRole.TRAVEL_DOCUMENT -> stringResource(Res.string.role_travel_document)
}

@Composable
private fun environmentTitle(e: TrustEnvironment): String = when (e) {
    TrustEnvironment.PRODUCTION -> stringResource(Res.string.env_production)
    TrustEnvironment.USER -> stringResource(Res.string.env_user)
    TrustEnvironment.TEST -> stringResource(Res.string.env_test)
    TrustEnvironment.SYSTEM -> stringResource(Res.string.env_system)
}

/** One certificate in one environment with every role it is an anchor for. */
private data class AnchorGroup(val environment: TrustEnvironment, val anchors: List<StoredAnchor>) {
    val first: StoredAnchor get() = anchors.first()
}

/**
 * Trust anchors of every kind, not only TWDIW: X.509 roots by environment and role, the DID trust sources (the
 * TWDIW list anchored on Arbitrum, Linked Domains) and DIDs the user trusts. Imported anchors and trusted DIDs are
 * the user's own (T2): accepted, never shown as official. Intermediates only complete chains.
 */
@Composable
fun TrustAnchorsScreen(model: WalletModel) {
    val anchors by model.anchors.collectAsState()
    val dids by model.trustedDids.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    var removing by remember { mutableStateOf<AnchorGroup?>(null) }
    LaunchedEffect(Unit) { model.loadAnchors() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.anchors_intro),
            style = MaterialTheme.typography.bodyMedium)
        CollapsibleSection(stringResource(Res.string.anchors_levels), initiallyExpanded = true, key = "tier-legend") { TierLegend() }
        CustomTrustRow(model)

        SectionTitle(stringResource(Res.string.anchors_did_sources))
        ActionRow(WalletIcons.Government, stringResource(Res.string.anchors_twdiw_list), stringResource(Res.string.anchors_twdiw_list_text)) {
            model.screen.value = Screen.TrustList
        }
        Row(Modifier.padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(WalletIcons.Link, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
            Column(Modifier.weight(1f)) {
                Text(stringResource(Res.string.anchors_linked_domains), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(Res.string.anchors_linked_domains_text),
                    style = MaterialTheme.typography.bodySmall)
            }
        }
        Text(stringResource(Res.string.anchors_custom_dids, dids.size), style = MaterialTheme.typography.bodySmall)

        HorizontalDivider()
        SectionTitle(stringResource(Res.string.anchors_x509))
        val list = anchors
        if (list == null) CircularProgressIndicator(Modifier.size(24.dp))
        else {
            val groups = list.groupBy { it.environment to it.certificate }.map { (k, v) -> AnchorGroup(k.first, v) }
            TrustEnvironment.entries.filter { it != TrustEnvironment.SYSTEM }.forEach { env ->
                val inEnv = groups.filter { it.environment == env }
                // Long lists start folded; the user's own imports stay open so a new import is seen at once.
                CollapsibleSection(environmentTitle(env), inEnv.size, initiallyExpanded = env == TrustEnvironment.USER || inEnv.size <= 3, key = "anchors-$env") {
                    if (inEnv.isEmpty()) Text(
                        when (env) {
                            TrustEnvironment.PRODUCTION -> stringResource(Res.string.anchors_none_builtin)
                            TrustEnvironment.USER -> stringResource(Res.string.anchors_none_user)
                            TrustEnvironment.TEST -> stringResource(Res.string.anchors_none_test)
                            TrustEnvironment.SYSTEM -> ""
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                    inEnv.forEach { g -> AnchorCard(g) { removing = g } }
                }
            }
        }
        SystemStoreSection(model)
        CscaSection(model)
        TrustListsSection(model)
        IntermediateSection(model)
    }
    removing?.let { g -> RemoveAnchorDialog(model, g) { removing = null } }
}

/** Entry to the user's own trust, with what it holds now. */
@Composable
internal fun CustomTrustRow(model: WalletModel) {
    val anchors by model.anchors.collectAsState()
    val dids by model.trustedDids.collectAsState()
    val intermediates by model.intermediates.collectAsState()
    val lists by model.mdocLists.collectAsState()
    val federation by model.federationAnchorList.collectAsState()
    val roots = anchors?.filter { it.environment == TrustEnvironment.USER }?.map { it.certificate }?.distinct()?.size ?: 0
    ActionRow(WalletIcons.Shield, stringResource(Res.string.screen_custom_trust_row),
        stringResource(Res.string.custom_trust_summary, roots, intermediates.size, dids.size, lists.size) +
            stringResource(Res.string.custom_trust_hint)) {
        model.screen.value = Screen.CustomTrust
    }
}

/**
 * Everything the user added to trust in one place: imported roots (T2, never official), imported intermediates
 * (chain completion only) and trusted DIDs, with the forms that add them.
 */
@Composable
fun CustomTrustScreen(model: WalletModel) {
    val anchors by model.anchors.collectAsState()
    val dids by model.trustedDids.collectAsState()
    val intermediates by model.intermediates.collectAsState()
    var removing by remember { mutableStateOf<AnchorGroup?>(null) }
    LaunchedEffect(Unit) { model.loadAnchors() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.custom_trust_intro) +
            stringResource(Res.string.custom_trust_rejudge),
            style = MaterialTheme.typography.bodyMedium)

        SectionTitle(stringResource(Res.string.custom_roots))
        val list = anchors
        if (list == null) CircularProgressIndicator(Modifier.size(24.dp))
        else {
            val groups = list.filter { it.environment == TrustEnvironment.USER }
                .groupBy { it.certificate }.map { (_, v) -> AnchorGroup(TrustEnvironment.USER, v) }
            if (groups.isEmpty()) Text(stringResource(Res.string.custom_roots_none),
                style = MaterialTheme.typography.bodySmall)
            groups.forEach { g -> AnchorCard(g) { removing = g } }
        }

        HorizontalDivider()
        SectionTitle(stringResource(Res.string.custom_intermediates))
        if (intermediates.isEmpty()) Text(stringResource(Res.string.custom_intermediates_none), style = MaterialTheme.typography.bodySmall)
        intermediates.forEach { i ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    IntermediateRow(model, i.name, i.certificate.displaySubject(), i.certificate, i.source ?: stringResource(Res.string.custom_user_imported), Screen.CustomTrust)
                }
                TextButton(onClick = { model.removeIntermediate(i) }) { Text(stringResource(Res.string.action_remove)) }
            }
        }

        HorizontalDivider()
        SectionTitle(stringResource(Res.string.custom_dids))
        TrustedDidSection(model, dids)

        HorizontalDivider()
        FederationSection(model)

        HorizontalDivider()
        SignedListSection(model)

        ImportAnchorSection(model)
    }
    removing?.let { g -> RemoveAnchorDialog(model, g) { removing = null } }
}

/**
 * mdoc VICAL (issuer CAs) and RICAL (reader CAs) downloaded from an HTTPS address. A list counts only when it is
 * signed under a root imported for the list-publisher role; its CAs are then the user's own trust (T2).
 */
@Composable
private fun SignedListSection(model: WalletModel) {
    val lists by model.mdocLists.collectAsState()
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var kind by remember { mutableStateOf("vical") }
    SectionTitle(stringResource(Res.string.signed_lists))
    Text(stringResource(Res.string.signed_lists_text_1) +
        stringResource(Res.string.signed_lists_text_2),
        style = MaterialTheme.typography.bodySmall)
    if (lists.isEmpty()) Text(stringResource(Res.string.signed_lists_none), style = MaterialTheme.typography.bodySmall)
    lists.forEach { l ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(l.name, style = MaterialTheme.typography.titleSmall)
                Text((if (l.kind == "vical") stringResource(Res.string.signed_list_vical) else stringResource(Res.string.signed_list_rical)) + stringResource(Res.string.signed_list_detail, l.certificates, l.issue ?: stringResource(Res.string.not_marked)),
                    style = MaterialTheme.typography.bodySmall)
                Text(
                    if (l.expired) stringResource(Res.string.signed_list_expired) + (l.notAfter?.let { stringResource(Res.string.paren_open) + localTime(it) + stringResource(Res.string.paren_close) } ?: "")
                    else stringResource(Res.string.valid_until) + (l.notAfter?.let { localTime(it) } ?: stringResource(Res.string.not_marked)) + (l.nextUpdate?.let { stringResource(Res.string.signed_list_next) + localTime(it) } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (l.expired) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                l.source?.let { Text(stringResource(Res.string.source_line, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
            }
            TextButton(onClick = { model.removeMdocTrustList(l) }) { Text(stringResource(Res.string.action_remove)) }
        }
    }
    if (lists.isNotEmpty()) TextButton(onClick = { model.refreshMdocTrustLists() }) { Text(stringResource(Res.string.signed_lists_refresh)) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(selected = kind == "vical", onClick = { kind = "vical" }, label = { Text(stringResource(Res.string.signed_list_vical)) })
        FilterChip(selected = kind == "rical", onClick = { kind = "rical" }, label = { Text(stringResource(Res.string.signed_list_rical)) })
    }
    OutlinedTextField(
        value = url,
        onValueChange = { url = it.trim().take(1024) },
        modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(Res.string.signed_list_url)) },
        singleLine = true,
    )
    OutlinedTextField(
        value = name,
        onValueChange = { name = it.take(80) },
        modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(Res.string.display_name_optional)) },
        singleLine = true,
    )
    Button(onClick = { model.importMdocTrustList(kind, url, name); url = ""; name = "" }, enabled = url.startsWith("https://")) {
        Text(stringResource(Res.string.signed_list_import))
    }
}

@Composable
private fun RemoveAnchorDialog(model: WalletModel, g: AnchorGroup, onDone: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(stringResource(Res.string.anchor_remove_title)) },
        text = { Text(stringResource(Res.string.anchor_remove_text, g.first.metadata.displayName ?: g.first.certificate.displaySubject())) },
        confirmButton = {
            TextButton(onClick = { g.anchors.forEach { model.removeAnchor(it) }; onDone() }) {
                Text(stringResource(Res.string.action_remove), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDone) { Text(stringResource(Res.string.action_cancel)) } },
    )
}

@Composable
private fun AnchorCard(g: AnchorGroup, onRemove: () -> Unit) {
    val a = g.first
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(WalletIcons.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                Column(Modifier.weight(1f)) {
                    Text(a.metadata.displayName ?: a.certificate.displaySubject(), style = MaterialTheme.typography.titleSmall)
                    Text(stringResource(Res.string.label_uses) + g.anchors.map { roleName(it.role) }.distinct().joinToString(stringResource(Res.string.sep_list)), style = MaterialTheme.typography.bodySmall)
                }
                if (g.environment != TrustEnvironment.PRODUCTION) TextButton(onClick = onRemove) { Text(stringResource(Res.string.action_remove)) }
            }
            Text(a.certificate.displaySubject(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            Text(stringResource(Res.string.valid_until) + localTime(a.certificate.validityNotAfter), style = MaterialTheme.typography.bodySmall)
            a.source?.takeIf { it != "pasted" }?.let { Text(stringResource(Res.string.source_line, it), style = MaterialTheme.typography.bodySmall) }
            if (a.official) Text(stringResource(Res.string.anchor_official), style = MaterialTheme.typography.bodySmall)
            if (a.metadata.extensions[diw.wallet.core.trust.TrustMetadataKeys.IDENTITY] == "true") {
                Text(stringResource(Res.string.anchor_identity), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** The platform's certificate store: on or off, and how many authorities it holds. */
@Composable
private fun SystemStoreSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    var count by remember { mutableStateOf<Int?>(null) }
    LaunchedEffect(Unit) { count = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) { diw.wallet.core.trust.SystemTrustStore.anchors().size } }
    HorizontalDivider()
    SectionTitle(environmentTitle(TrustEnvironment.SYSTEM))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(stringResource(Res.string.system_store_trust), style = MaterialTheme.typography.titleSmall)
            Text(stringResource(Res.string.system_store_text) +
                (count?.let { stringResource(Res.string.system_store_count, it) } ?: ""), style = MaterialTheme.typography.bodySmall)
        }
        androidx.compose.material3.Switch(checked = settings.systemTrustStore, onCheckedChange = { v -> model.updateSettings { it.copy(systemTrustStore = v) } })
    }
    val services = diw.wallet.core.trust.BuiltInPublicRoots.services
    CollapsibleSection(stringResource(Res.string.system_common_roots), services.size, key = "roots-services") { BuiltInRootList(model, services) }

    HorizontalDivider()
    SectionTitle(stringResource(Res.string.china_title))
    val mainland = diw.wallet.core.trust.BuiltInPublicRoots.mainlandChina
    val national = mainland.count { it.national }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(stringResource(Res.string.china_trust), style = MaterialTheme.typography.titleSmall)
            Text(stringResource(Res.string.china_count, mainland.size) + (if (national > 0) stringResource(Res.string.china_sm2_count, national) else "") +
                stringResource(Res.string.china_text),
                style = MaterialTheme.typography.bodySmall)
        }
        androidx.compose.material3.Switch(checked = settings.mainlandChinaRoots, onCheckedChange = { v -> model.updateSettings { it.copy(mainlandChinaRoots = v) } })
    }
    val programs = mainland.filter { !it.national }
    val sm2 = mainland.filter { it.national }
    CollapsibleSection(stringResource(Res.string.china_programs), programs.size, key = "roots-mainland") { BuiltInRootList(model, programs) }
    if (sm2.isNotEmpty()) CollapsibleSection(stringResource(Res.string.china_sm2), sm2.size, key = "roots-sm2") { BuiltInRootList(model, sm2) }
    Text(stringResource(Res.string.china_updated, diw.wallet.core.trust.BuiltInPublicRoots.UPDATED),
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
}

/** The built-in country signing CAs for travel documents, by country; a tap opens the certificate. */
@Composable
private fun CscaSection(model: WalletModel) {
    val cscas = diw.wallet.core.trust.BuiltInCscas
    val byCountry = remember { cscas.all.groupBy { it.country }.toList().sortedBy { it.first } }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.csca_title))
    Text(stringResource(Res.string.csca_text, cscas.all.size, byCountry.size, cscas.PUBLISHER), style = MaterialTheme.typography.bodySmall)
    CollapsibleSection(stringResource(Res.string.csca_countries), byCountry.size, key = "csca-countries") {
        byCountry.forEach { (country, list) ->
            CollapsibleSection(country, list.size, key = "csca-$country") {
                list.forEach { c ->
                    Column(Modifier.fillMaxWidth().clickable {
                        model.screen.value = Screen.Certificate(listOf(c.certificate), 0, Screen.TrustAnchors)
                    }.padding(vertical = 4.dp)) {
                        Text(c.name, style = MaterialTheme.typography.bodyMedium)
                        Text(c.algorithm + "・" + stringResource(Res.string.valid_until) + localTime(c.certificate.validityNotAfter),
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                    }
                }
            }
        }
    }
    Text(stringResource(Res.string.csca_updated, cscas.UPDATED, cscas.LIST),
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
}

/** The public trust lists for document signers and time-stamp authorities: on or off, what is stored, and updates. */
@Composable
private fun TrustListsSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    val states by model.trustLists.states.collectAsState()
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.signing_lists_title))
    Text(stringResource(Res.string.signing_lists_text),
        style = MaterialTheme.typography.bodySmall)
    for (kind in diw.wallet.core.trust.TrustListKind.entries) {
        val st = states[kind] ?: continue
        val on = when (kind) {
            diw.wallet.core.trust.TrustListKind.AATL -> settings.aatlTrustList
            diw.wallet.core.trust.TrustListKind.EUTL -> settings.eutlTrustList
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(kind.title, style = MaterialTheme.typography.titleSmall)
                Text(when (kind) {
                    diw.wallet.core.trust.TrustListKind.AATL -> stringResource(Res.string.aatl_text)
                    diw.wallet.core.trust.TrustListKind.EUTL -> stringResource(Res.string.eutl_text)
                }, style = MaterialTheme.typography.bodySmall)
            }
            androidx.compose.material3.Switch(checked = on, onCheckedChange = { v ->
                model.updateSettings {
                    when (kind) {
                        diw.wallet.core.trust.TrustListKind.AATL -> it.copy(aatlTrustList = v)
                        diw.wallet.core.trust.TrustListKind.EUTL -> it.copy(eutlTrustList = v)
                    }
                }
            })
        }
        val lines = buildList {
            if (st.fetchedAt != null) add(stringResource(Res.string.trust_list_services, st.services, localTime(st.fetchedAt)))
            else add(if (st.running) stringResource(Res.string.zk_templates_downloading) else stringResource(Res.string.zk_templates_not_downloaded))
            st.issued?.let { add(stringResource(Res.string.trust_list_issued, localTime(it))) }
            st.nextUpdate?.let { add(stringResource(Res.string.trust_list_next, localTime(it))) }
            st.signer?.let { add(stringResource(Res.string.trust_list_signer, it)) }
            st.error?.let { add(stringResource(Res.string.trust_list_failed, it)) }
        }
        lines.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
        if (st.partErrors.isNotEmpty()) {
            CollapsibleSection(stringResource(Res.string.trust_list_failed_countries), st.partErrors.size, key = "list-errors-${kind.id}") {
                st.partErrors.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(enabled = on && !st.running, onClick = { model.trustLists.refresh(kind) }) { Text(stringResource(Res.string.zk_update_now)) }
            if (st.fetchedAt != null) TextButton(enabled = !st.running, onClick = { model.trustLists.clear(kind) }) { Text(stringResource(Res.string.trust_list_delete)) }
            if (st.running) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
        }
    }
}

/** Built-in public roots: name, owner, algorithm and purpose; a tap opens the certificate. */
@Composable
private fun BuiltInRootList(model: WalletModel, roots: List<diw.wallet.core.trust.BuiltInPublicRoots.Root>) {
    roots.forEach { r ->
        Column(Modifier.fillMaxWidth().clickable {
            model.screen.value = Screen.Certificate(listOf(r.certificate), 0, Screen.TrustAnchors)
        }.padding(vertical = 4.dp)) {
            Text(r.name + if (r.national) stringResource(Res.string.sm2_suffix) else "", style = MaterialTheme.typography.bodyMedium)
            Text("${r.owner}・${r.algorithm}・${r.purposes}", style = MaterialTheme.typography.bodySmall)
            Text(stringResource(Res.string.valid_until) + localTime(r.certificate.validityNotAfter) + stringResource(Res.string.source_inline) + r.source, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline)
        }
    }
}

@Composable
internal fun RoleChips(options: List<TrustRole>, selected: Set<TrustRole>, onChange: (Set<TrustRole>) -> Unit) {
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        options.forEach { r ->
            FilterChip(selected = r in selected, onClick = { onChange(if (r in selected) selected - r else selected + r) }, label = { Text(roleName(r)) })
        }
    }
}

@Composable
private fun ImportAnchorSection(model: WalletModel) {
    var pem by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var roles by remember { mutableStateOf(setOf(TrustRole.ISSUER, TrustRole.STATUS_LIST)) }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.import_anchor_title))
    Text(stringResource(Res.string.import_anchor_text),
        style = MaterialTheme.typography.bodySmall)
    OutlinedTextField(
        value = pem,
        onValueChange = { pem = it },
        label = { Text(stringResource(Res.string.import_anchor_hint)) },
        minLines = 3,
        maxLines = 8,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = name,
        onValueChange = { name = it.take(80) },
        label = { Text(stringResource(Res.string.import_anchor_name)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Text(stringResource(Res.string.import_anchor_uses), style = MaterialTheme.typography.labelLarge)
    RoleChips(listOf(TrustRole.ISSUER, TrustRole.STATUS_LIST, TrustRole.VERIFIER, TrustRole.DOCUMENT, TrustRole.TSA, TrustRole.CONTENT, TrustRole.TRAVEL_DOCUMENT, TrustRole.WALLET_PROVIDER, TrustRole.TRUST_LIST_PROVIDER), roles) { roles = it }
    Button(onClick = { model.importAnchor(pem, name, roles); pem = ""; name = "" }, enabled = pem.isNotBlank() && roles.isNotEmpty()) {
        Text(stringResource(Res.string.action_import))
    }
    Text(stringResource(Res.string.master_list_text), style = MaterialTheme.typography.bodySmall)
    OutlinedButton(onClick = { model.importMasterList() }) { Text(stringResource(Res.string.master_list_import)) }
}

/**
 * Intermediates never set a tier: built-in ones (document signing services such as BJCA DocSign and e簽寶) and the
 * user's own fill the gap between a signer and its root. Importable roots are built in but not trusted until the
 * user chooses to trust one.
 */
@Composable
private fun IntermediateSection(model: WalletModel) {
    val user by model.intermediates.collectAsState()
    val anchors by model.anchors.collectAsState()
    var trusting by remember { mutableStateOf<diw.wallet.core.trust.BuiltInPublicRoots.Intermediate?>(null) }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.intermediates_title))
    Text(stringResource(Res.string.intermediates_text),
        style = MaterialTheme.typography.bodySmall)
    val builtIn = diw.wallet.core.trust.BuiltInPublicRoots.intermediates
    CollapsibleSection(stringResource(Res.string.intermediates_builtin), builtIn.size, key = "intermediates-builtin") {
        builtIn.forEach { i -> IntermediateRow(model, i.name, stringResource(Res.string.intermediate_line, i.owner, i.issuer, i.purposes), i.certificate, i.source, Screen.TrustAnchors) }
    }
    val importable = diw.wallet.core.trust.BuiltInPublicRoots.importableRoots
    if (importable.isNotEmpty()) CollapsibleSection(stringResource(Res.string.platform_roots), importable.size, key = "intermediates-importable") {
        Text(stringResource(Res.string.platform_roots_text),
            style = MaterialTheme.typography.bodySmall)
        importable.forEach { r ->
            val trusted = anchors?.any { it.certificate == r.certificate } == true
            IntermediateRow(model, r.name, "${r.owner}・${r.purposes}", r.certificate, r.source, Screen.TrustAnchors)
            if (trusted) Text(stringResource(Res.string.platform_root_trusted), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
            else TextButton(onClick = { trusting = r }) { Text(stringResource(Res.string.platform_root_trust)) }
        }
    }
    Text(stringResource(Res.string.intermediates_user, user.size), style = MaterialTheme.typography.bodySmall)
    trusting?.let { r ->
        RiskConfirmDialog(
            title = stringResource(Res.string.platform_trust_title, r.name),
            lines = listOf(
                stringResource(Res.string.platform_trust_text, r.owner),
                stringResource(Res.string.platform_trust_effect),
                stringResource(Res.string.platform_trust_remove),
            ),
            confirm = stringResource(Res.string.zk_server_trust),
            onConfirm = { model.trustRootCertificate(r.certificate.encoded.toByteArray()); trusting = null },
            onDismiss = { trusting = null },
        )
    }
}

@Composable
private fun IntermediateRow(model: WalletModel, name: String, detail: String, cert: org.multipaz.crypto.X509Cert, source: String?, from: Screen) {
    Column(Modifier.fillMaxWidth().clickable { model.screen.value = Screen.Certificate(listOf(cert), 0, from) }.padding(vertical = 4.dp)) {
        Text(name, style = MaterialTheme.typography.bodyMedium)
        Text(detail, style = MaterialTheme.typography.bodySmall)
        Text(stringResource(Res.string.valid_until) + localTime(cert.validityNotAfter) + (source?.let { stringResource(Res.string.source_inline_value, it) } ?: ""), style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline)
    }
}

@Composable
private fun TrustedDidSection(model: WalletModel, dids: List<UserTrustedDid>) {
    var did by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var roles by remember { mutableStateOf(setOf(TrustRole.ISSUER)) }
    if (dids.isEmpty()) Text(stringResource(Res.string.dids_none), style = MaterialTheme.typography.bodySmall)
    dids.forEach { d ->
        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(d.name, style = MaterialTheme.typography.titleSmall)
                    Text(d.did, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                    Text(stringResource(Res.string.label_uses) + d.roles.mapNotNull { id -> TrustRole.entries.firstOrNull { it.id == id }?.let { roleName(it) } }.joinToString(stringResource(Res.string.sep_list)) +
                        stringResource(Res.string.added_at) + localTime(Instant.fromEpochSeconds(d.addedAt)), style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onClick = { model.untrustDid(d.did) }) { Text(stringResource(Res.string.action_remove)) }
            }
        }
    }
    OutlinedTextField(value = did, onValueChange = { did = it.trim() }, label = { Text(stringResource(Res.string.did_hint)) }, singleLine = true,
        modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = name, onValueChange = { name = it.take(80) }, label = { Text(stringResource(Res.string.organization_name)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
    RoleChips(listOf(TrustRole.ISSUER, TrustRole.VERIFIER), roles) { roles = it }
    Button(onClick = { model.trustDid(did, name, roles); did = ""; name = "" }, enabled = did.startsWith("did:") && roles.isNotEmpty()) {
        Text(stringResource(Res.string.did_trust))
    }
}

/**
 * OpenID Federation Trust Anchors: a Verifier whose client_id is openid_federation:<entity> is accepted when its
 * trust chain ends at one of these. The anchor's keys come from its own Entity Configuration and are trusted only
 * after the user compares the thumbprints with what the federation publishes.
 */
@Composable
private fun FederationSection(model: WalletModel) {
    val anchors by model.federationAnchorList.collectAsState()
    val pending by model.pendingFederationAnchor.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    var entityId by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var test by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf<diw.wallet.core.federation.FederationAnchor?>(null) }
    SectionTitle(stringResource(Res.string.federation_title))
    Text(stringResource(Res.string.federation_text) +
        stringResource(Res.string.federation_levels),
        style = MaterialTheme.typography.bodySmall)
    if (anchors.isEmpty()) Text(stringResource(Res.string.federation_none), style = MaterialTheme.typography.bodySmall)
    anchors.forEach { a ->
        Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(a.name, style = MaterialTheme.typography.titleSmall)
                    Text(a.entityId, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                    Text((if (a.trustEnvironment == TrustEnvironment.TEST) stringResource(Res.string.federation_test) else stringResource(Res.string.federation_user)) +
                        stringResource(Res.string.federation_keys, a.keys.size) + localTime(Instant.fromEpochSeconds(a.addedAt)),
                        style = MaterialTheme.typography.bodySmall)
                    if (a.trustEnvironment == TrustEnvironment.TEST && !settings.testEnvironment) {
                        Text(stringResource(Res.string.federation_test_off), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
                TextButton(onClick = { removing = a }) { Text(stringResource(Res.string.action_remove)) }
            }
        }
    }
    OutlinedTextField(value = entityId, onValueChange = { entityId = it.trim().take(512) }, label = { Text(stringResource(Res.string.federation_entity)) },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = name, onValueChange = { name = it.take(80) }, label = { Text(stringResource(Res.string.display_name_optional)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(selected = !test, onClick = { test = false }, label = { Text(stringResource(Res.string.federation_production)) })
        FilterChip(selected = test, onClick = { test = true }, enabled = settings.testEnvironment, label = { Text(stringResource(Res.string.federation_test)) })
    }
    Button(onClick = {
        model.fetchFederationAnchor(entityId, name, if (test && settings.testEnvironment) TrustEnvironment.TEST else TrustEnvironment.USER)
    }, enabled = entityId.startsWith("https://") || (settings.testEnvironment && entityId.startsWith("http://"))) {
        Text(stringResource(Res.string.federation_fetch))
    }
    pending?.let { p ->
        AlertDialog(
            onDismissRequest = { model.pendingFederationAnchor.value = null },
            title = { Text(stringResource(Res.string.federation_trust_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(p.anchor.name, style = MaterialTheme.typography.titleSmall)
                    Text(p.anchor.entityId, style = MaterialTheme.typography.bodySmall)
                    p.organization?.let { Text(stringResource(Res.string.organization_line, it), style = MaterialTheme.typography.bodySmall) }
                    Text(stringResource(Res.string.federation_compare),
                        style = MaterialTheme.typography.bodySmall)
                    p.thumbprints.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
                    if (p.authorityHints.isNotEmpty()) {
                        Text(stringResource(Res.string.federation_superiors) + p.authorityHints.joinToString(stringResource(Res.string.sep_list)) + stringResource(Res.string.federation_superiors_tail),
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { model.confirmFederationAnchor(); entityId = ""; name = "" }) { Text(stringResource(Res.string.federation_match_add)) } },
            dismissButton = { TextButton(onClick = { model.pendingFederationAnchor.value = null }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
    removing?.let { a ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text(stringResource(Res.string.federation_remove_title)) },
            text = { Text(stringResource(Res.string.federation_remove_text, a.name)) },
            confirmButton = { TextButton(onClick = { model.removeFederationAnchor(a); removing = null }) { Text(stringResource(Res.string.action_remove), color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { removing = null }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
}
