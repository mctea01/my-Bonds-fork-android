package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.AppLanguage
import diw.wallet.app.KeyProtection
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import diw.wallet.app.AppBuild
import diw.wallet.app.Screen
import diw.wallet.app.SettingsSection
import diw.wallet.app.WalletModel
import diw.wallet.app.WalletSettings
import diw.wallet.app.legal.Integration
import diw.wallet.app.legal.LegalStrings
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.document.sign.SignatureLevel
import diw.wallet.core.document.sign.TsaServices
import diw.wallet.core.profile.bonds.MyDataProfile
import diw.wallet.core.profile.twdiw.TwdiwPlatform
import diw.wallet.core.profile.twdiw.TwdiwDeviceKeyRecord
import androidx.compose.material3.Card
import kotlinx.coroutines.launch
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.produceState
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults

@Composable
private fun Toggle(title: String, detail: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(detail, style = MaterialTheme.typography.bodySmall)
        }
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
    }
}

@Composable
private fun SettingsColumn(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp), content = content)
}

@Composable
private fun onOff(v: Boolean) = if (v) stringResource(Res.string.state_on) else stringResource(Res.string.state_off)

private val SettingsSection.icon: ImageVector
    get() = when (this) {
        SettingsSection.SECURITY -> WalletIcons.Shield
        SettingsSection.CREDENTIALS -> WalletIcons.Card
        SettingsSection.DOCUMENTS -> WalletIcons.Document
        SettingsSection.TRUST -> WalletIcons.Organization
        SettingsSection.INTEROP -> WalletIcons.Link
        SettingsSection.DEVELOPER -> WalletIcons.Phone
        SettingsSection.GENERAL -> WalletIcons.Settings
        SettingsSection.LEGAL -> WalletIcons.Pass
        SettingsSection.ABOUT -> WalletIcons.Info
    }

/** The settings list: one row per group, each saying what it holds and how it is set now. */
@Composable
fun SettingsScreen(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    val history by model.history.collectAsState()
    val lang by model.appLanguage.collectAsState()
    val reg by model.dcApiRegistration.collectAsState()
    val zkCapability by model.zk.capability.collectAsState()
    LaunchedEffect(Unit) { model.zk.probe() }
    SettingsColumn {
        SettingsSection.entries.forEach { section ->
            val summary = when (section) {
                SettingsSection.SECURITY -> listOfNotNull(
                    model.backends.firstOrNull()?.let { stringResource(Res.string.settings_key_protection_prefix) + it.protection.label() },
                    stringResource(Res.string.settings_user_auth_prefix) + onOff(s.requireUserAuth),
                    zkSummary(zkCapability),
                    stringResource(Res.string.settings_history_count, history.size),
                ).joinToString("・")
                SettingsSection.CREDENTIALS -> listOfNotNull(
                    stringResource(Res.string.settings_auto_status_prefix) + onOff(s.autoStatus),
                    reg?.let { r -> if (r.error != null) stringResource(Res.string.settings_dc_failed) else stringResource(Res.string.settings_dc_count, r.registered) },
                ).joinToString("・")
                SettingsSection.DOCUMENTS -> listOfNotNull(
                    stringResource(Res.string.settings_tsa_prefix) + TsaServices.byId(s.tsaId).name,
                    stringResource(Res.string.settings_sign_default_prefix) + padesLevel(s).short,
                    if (s.myDataIdNumber != null) stringResource(Res.string.settings_mydata_set) else null,
                ).joinToString("・")
                SettingsSection.TRUST -> listOf(
                    stringResource(Res.string.settings_system_store_prefix) + onOff(s.systemTrustStore),
                    stringResource(Res.string.settings_china_prefix) + onOff(s.mainlandChinaRoots),
                    stringResource(Res.string.settings_aatl_prefix) + onOff(s.aatlTrustList),
                    stringResource(Res.string.settings_eutl_prefix) + onOff(s.eutlTrustList),
                ).joinToString("・")
                SettingsSection.INTEROP -> stringResource(Res.string.settings_twdiw_prefix) + onOff(model.legal.enabled(Integration.TWDIW)) +
                    stringResource(Res.string.settings_msvid_prefix) + onOff(model.legal.enabled(Integration.MS_VERIFIED_ID)) +
                    stringResource(Res.string.settings_provider_prefix) + if (s.walletProviderUrl.isNullOrBlank()) stringResource(Res.string.state_not_set) else stringResource(Res.string.state_set)
                SettingsSection.DEVELOPER -> stringResource(Res.string.settings_test_server_prefix) + onOff(s.testEnvironment) + if (s.manualMobileMoicaSp) stringResource(Res.string.settings_manual_sp) else ""
                SettingsSection.GENERAL -> stringResource(Res.string.settings_language_prefix) + languageName(AppLanguage.of(lang)) + stringResource(Res.string.settings_show_details_middle) + onOff(s.showDetails)
                SettingsSection.LEGAL -> legalSummary(model)
                SettingsSection.ABOUT -> stringResource(Res.string.settings_version_prefix) + appVersion() + stringResource(Res.string.settings_about_summary)
            }
            ActionRow(section.icon, stringResource(section.title), summary) { model.screen.value = Screen.SettingsPage(section) }
        }
    }
}

/** One group of settings on its own page. */
@Composable
fun SettingsPageScreen(model: WalletModel, section: SettingsSection) {
    SettingsColumn {
        when (section) {
            SettingsSection.SECURITY -> SecurityPage(model)
            SettingsSection.CREDENTIALS -> CredentialsPage(model)
            SettingsSection.DOCUMENTS -> DocumentsPage(model)
            SettingsSection.TRUST -> TrustPage(model)
            SettingsSection.INTEROP -> InteropPage(model)
            SettingsSection.DEVELOPER -> DeveloperPage(model)
            SettingsSection.GENERAL -> GeneralPage(model)
            SettingsSection.LEGAL -> LegalSettingsPage(model)
            SettingsSection.ABOUT -> AboutPage(model)
        }
    }
}

private fun padesLevel(s: WalletSettings) = SignatureLevel.of(s.padesLevel)

@Composable
private fun SecurityPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    val history by model.history.collectAsState()
    var confirmClear by remember { mutableStateOf(false) }
    SectionTitle(stringResource(Res.string.settings_keys))
    model.backends.forEachIndexed { i, b ->
        Text((if (i == 0) stringResource(Res.string.settings_key_protection_prefix) else stringResource(Res.string.settings_key_backup_prefix)) + b.protection.label(), style = MaterialTheme.typography.bodyMedium)
    }
    Toggle(stringResource(Res.string.settings_user_auth), stringResource(Res.string.settings_user_auth_text), s.requireUserAuth) { v ->
        model.updateSettings { it.copy(requireUserAuth = v) }
    }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_privacy))
    ZkSettingsRow(model) { model.screen.value = Screen.ZkSettings }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.tab_history))
    Text(stringResource(Res.string.settings_history_text, history.size), style = MaterialTheme.typography.bodySmall)
    OutlinedButton(onClick = { confirmClear = true }, enabled = history.isNotEmpty()) { Text(stringResource(Res.string.settings_clear_history)) }
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
private fun CredentialsPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    SectionTitle(stringResource(Res.string.settings_credential_status))
    Toggle(
        stringResource(Res.string.settings_auto_status),
        stringResource(Res.string.settings_auto_status_text),
        s.autoStatus,
    ) { v -> model.updateSettings { it.copy(autoStatus = v) } }
    val issuerCheck by model.status.issuerCheck.collectAsState()
    issuerCheck?.let { (done, total) -> Text(stringResource(Res.string.settings_issuer_check, done, total), style = MaterialTheme.typography.bodySmall) }
    OutlinedButton(onClick = { model.status.refreshDue(force = true) }) { Text(stringResource(Res.string.settings_status_now)) }
    DigitalCredentialsSection(model)
}

@Composable
private fun DocumentsPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    SectionTitle(stringResource(Res.string.settings_timestamps))
    Text(stringResource(Res.string.settings_tsa_text), style = MaterialTheme.typography.bodySmall)
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TsaServices.all.forEach { t ->
            FilterChip(selected = s.tsaId == t.id, onClick = { model.updateSettings { it.copy(tsaId = t.id) } }, label = { Text(t.name) })
        }
    }
    val tsa = TsaServices.byId(s.tsaId)
    Text(tsa.url + if (tsa.publicRoot) stringResource(Res.string.settings_tsa_public_root) else stringResource(Res.string.settings_tsa_import_root),
        style = MaterialTheme.typography.bodySmall)
    Toggle(stringResource(Res.string.settings_timestamp_on_save), stringResource(Res.string.settings_timestamp_on_save_text), s.timestampOnSave) { v ->
        model.updateSettings { it.copy(timestampOnSave = v) }
    }
    Toggle(stringResource(Res.string.settings_timestamp_revocation), stringResource(Res.string.settings_timestamp_revocation_text), s.timestampRevocation) { v ->
        model.updateSettings { it.copy(timestampRevocation = v) }
    }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_signature_level))
    val level = padesLevel(s)
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SignatureLevel.entries.forEach { l ->
            FilterChip(selected = l == level, onClick = { model.updateSettings { it.copy(padesLevel = l.name) } }, label = { Text(l.short) })
        }
    }
    Text(level.detail + stringResource(Res.string.settings_signature_level_text), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(Res.string.settings_csc_hint), style = MaterialTheme.typography.bodySmall)
    HorizontalDivider()
    MyDataProfileSection(model)
}

@Composable
private fun TrustPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    Text(stringResource(Res.string.settings_trust_levels),
        style = MaterialTheme.typography.bodySmall)
    CustomTrustRow(model)
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_trust_sources))
    Toggle(stringResource(Res.string.settings_system_store), stringResource(Res.string.settings_system_store_text), s.systemTrustStore) { v ->
        model.updateSettings { it.copy(systemTrustStore = v) }
    }
    Toggle(stringResource(Res.string.settings_china), stringResource(Res.string.settings_china_text), s.mainlandChinaRoots) { v ->
        model.updateSettings { it.copy(mainlandChinaRoots = v) }
    }
    Toggle("Adobe AATL", stringResource(Res.string.settings_aatl_text), s.aatlTrustList) { v -> model.updateSettings { it.copy(aatlTrustList = v) } }
    Toggle(stringResource(Res.string.settings_eutl), stringResource(Res.string.settings_eutl_text), s.eutlTrustList) { v -> model.updateSettings { it.copy(eutlTrustList = v) } }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_lists_anchors))
    if (model.legal.enabled(Integration.TWDIW)) {
        ActionRow(WalletIcons.Shield, stringResource(Res.string.settings_twdiw_trust_list), stringResource(Res.string.settings_twdiw_trust_list_text)) {
            model.screen.value = Screen.TrustList
        }
    } else IntegrationOffRow(model, Integration.TWDIW, stringResource(Res.string.settings_twdiw_trust_list))
    ActionRow(WalletIcons.Shield, stringResource(Res.string.screen_trust_anchors), stringResource(Res.string.settings_trust_anchors_text)) {
        model.screen.value = Screen.TrustAnchors
    }
    ActionRow(WalletIcons.Shield, stringResource(Res.string.screen_openpgp_keys), stringResource(Res.string.settings_openpgp_text)) {
        model.screen.value = Screen.OpenPgpKeys()
    }
}

@Composable
private fun InteropPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    var twdiwClientId by remember(s.twdiwClientId) { mutableStateOf(s.twdiwClientId) }
    var walletClientId by remember(s.clientId) { mutableStateOf(s.clientId) }
    var providerUrl by remember(s.walletProviderUrl) { mutableStateOf(s.walletProviderUrl.orEmpty()) }
    var twdiwUserAgent by remember(s.twdiwUserAgent) { mutableStateOf(s.twdiwUserAgent) }
    var twdiwFrontend by remember(s.twdiwFrontendUrl) { mutableStateOf(s.twdiwFrontendUrl) }
    Text(stringResource(Res.string.settings_interop_text) +
        stringResource(Res.string.settings_interop_central_text),
        style = MaterialTheme.typography.bodySmall)
    if (!model.legal.enabled(Integration.TWDIW)) IntegrationOffRow(model, Integration.TWDIW)
    if (!model.legal.enabled(Integration.MS_VERIFIED_ID)) IntegrationOffRow(model, Integration.MS_VERIFIED_ID)
    SectionTitle(stringResource(Res.string.settings_proximity))
    Toggle(
        stringResource(Res.string.settings_nfc_static),
        stringResource(Res.string.settings_nfc_static_text),
        s.nfcStaticHandover,
    ) { v -> model.updateSettings { it.copy(nfcStaticHandover = v) } }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_wallet_identity))
    Text(stringResource(Res.string.settings_wallet_identity_text),
        style = MaterialTheme.typography.bodySmall)
    OutlinedTextField(
        value = walletClientId,
        onValueChange = { walletClientId = it.trim().take(256) },
        label = { Text(stringResource(Res.string.settings_wallet_client_id)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = providerUrl,
        onValueChange = { providerUrl = it.trim().take(500) },
        label = { Text(stringResource(Res.string.settings_provider_url)) },
        supportingText = { Text(stringResource(Res.string.settings_provider_url_text)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    val validProvider = providerUrl.isBlank() ||
        (providerUrl.startsWith("https://") && !providerUrl.contains('#') && !providerUrl.contains('?') &&
            providerUrl.substringAfter("https://").substringBefore('/').isNotBlank())
    val walletChanged = walletClientId != s.clientId || providerUrl.ifBlank { null } != s.walletProviderUrl
    OutlinedButton(
        enabled = validProvider && walletClientId.isNotBlank() && walletChanged,
        onClick = { model.updateSettings { it.copy(clientId = walletClientId, walletProviderUrl = providerUrl.ifBlank { null }) } },
    ) { Text(stringResource(Res.string.settings_save_wallet_identity)) }
    if (!validProvider) Text(stringResource(Res.string.settings_provider_url_invalid), color = MaterialTheme.colorScheme.error)
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_twdiw))
    OutlinedTextField(
        value = twdiwClientId,
        onValueChange = { twdiwClientId = it.trim() },
        label = { Text(stringResource(Res.string.settings_twdiw_client_id)) },
        supportingText = { Text(stringResource(Res.string.settings_twdiw_client_id_text)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = twdiwUserAgent,
        onValueChange = { twdiwUserAgent = it },
        label = { Text(stringResource(Res.string.settings_twdiw_user_agent)) },
        supportingText = { Text(stringResource(Res.string.settings_twdiw_user_agent_text)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = twdiwFrontend,
        onValueChange = { twdiwFrontend = it.trim() },
        label = { Text(stringResource(Res.string.settings_twdiw_frontend)) },
        supportingText = { Text(stringResource(Res.string.settings_twdiw_frontend_text, TwdiwPlatform.PRODUCTION_FRONTEND, TwdiwPlatform.UAT_FRONTEND)) },
        singleLine = true,
        enabled = s.testEnvironment,
        modifier = Modifier.fillMaxWidth(),
    )
    val changed = twdiwClientId != s.twdiwClientId || twdiwUserAgent != s.twdiwUserAgent || twdiwFrontend != s.twdiwFrontendUrl
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = {
            model.updateSettings {
                it.copy(
                    twdiwClientId = twdiwClientId.ifEmpty { TwdiwDialect.DEFAULT_CLIENT_ID },
                    twdiwUserAgent = twdiwUserAgent.ifBlank { TwdiwPlatform.DEFAULT_USER_AGENT },
                    twdiwFrontendUrl = twdiwFrontend.ifEmpty { TwdiwPlatform.PRODUCTION_FRONTEND },
                )
            }
        }, enabled = changed) { Text(stringResource(Res.string.action_save)) }
        OutlinedButton(onClick = {
            twdiwClientId = TwdiwDialect.DEFAULT_CLIENT_ID
            twdiwUserAgent = TwdiwPlatform.DEFAULT_USER_AGENT
            twdiwFrontend = TwdiwPlatform.PRODUCTION_FRONTEND
        }) { Text(stringResource(Res.string.action_restore_defaults)) }
    }
    TwdiwDeviceKeySection(model)
}

/**
 * Current application key and optional historical device-registration records, retained for deletion only.
 */
@Composable
private fun TwdiwDeviceKeySection(model: WalletModel) {
    val scope = rememberCoroutineScope()
    var reload by remember { mutableStateOf(0) }
    val records by produceState(emptyList<TwdiwDeviceKeyRecord>(), reload) {
        value = runCatching { model.twdiwDeviceKeys.records() }.getOrDefault(emptyList())
    }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_twdiw_app_key))
    Text(stringResource(Res.string.settings_twdiw_app_key_text),
        style = MaterialTheme.typography.bodySmall)
    LabelValue(stringResource(Res.string.settings_key_source), if (model.twdiwApplicationKeySource == "provided") stringResource(Res.string.settings_key_source_build) else stringResource(Res.string.settings_key_source_generated))
    LabelValue(stringResource(Res.string.settings_app_key_id), model.twdiwApplicationKeyId ?: stringResource(Res.string.state_not_loaded))
    if (records.isNotEmpty()) Text(stringResource(Res.string.settings_old_device_keys), style = MaterialTheme.typography.bodySmall)
    records.forEach { r ->
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(r.host, style = MaterialTheme.typography.titleSmall)
                LabelValue(stringResource(Res.string.settings_key_location), when (r.protection) { "strongbox" -> stringResource(Res.string.key_strongbox); "tee" -> stringResource(Res.string.key_tee); else -> stringResource(Res.string.key_software) })
                LabelValue(stringResource(Res.string.settings_key_did), r.did)
                LabelValue(stringResource(Res.string.settings_old_record), r.keyId?.let { stringResource(Res.string.settings_key_id, it) } ?: stringResource(Res.string.settings_key_id_missing))
                r.lastHttpStatus?.let { LabelValue(stringResource(Res.string.settings_last_response), "HTTP $it" + (r.lastAttemptAt?.let { t -> "・" + localTime(t) } ?: "")) }
                r.lastError?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                r.lastResponse?.takeIf { it.isNotBlank() }?.let { body ->
                    var open by remember(r.host) { mutableStateOf(false) }
                    TextButton(onClick = { open = !open }) { Text(if (open) stringResource(Res.string.settings_hide_response) else stringResource(Res.string.settings_show_response)) }
                    if (open) SelectionContainer { Text(body, style = MaterialTheme.typography.bodySmall) }
                }
                OutlinedButton(onClick = { scope.launch { runCatching { model.twdiwDeviceKeys.reset(r.host) }; reload++ } }) {
                    Text(stringResource(Res.string.settings_delete_old_keys))
                }
            }
        }
    }
}

@Composable
private fun DeveloperPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    var url by remember(s.testServerUrl) { mutableStateOf(s.testServerUrl) }
    Text(stringResource(Res.string.settings_test_text),
        style = MaterialTheme.typography.bodySmall)
    SectionTitle(stringResource(Res.string.settings_test_server))
    Toggle(stringResource(Res.string.settings_use_test_server), stringResource(Res.string.settings_use_test_server_text), s.testEnvironment) { v ->
        model.updateSettings { it.copy(testEnvironment = v, allowLoopbackHttp = v && it.allowLoopbackHttp) }
    }
    Toggle(stringResource(Res.string.settings_local_http), stringResource(Res.string.settings_local_http_text), s.allowLoopbackHttp, enabled = s.testEnvironment) { v ->
        model.updateSettings { it.copy(allowLoopbackHttp = v) }
    }
    Toggle(stringResource(Res.string.settings_test_provider), stringResource(Res.string.settings_test_provider_text), s.useWalletProvider, enabled = s.testEnvironment) { v ->
        model.updateSettings { it.copy(useWalletProvider = v) }
    }
    OutlinedTextField(
        value = url,
        onValueChange = { url = it.trim() },
        label = { Text(stringResource(Res.string.settings_test_server_url)) },
        singleLine = true,
        enabled = s.testEnvironment,
        modifier = Modifier.fillMaxWidth(),
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = { model.updateSettings { it.copy(testServerUrl = url) } }, enabled = s.testEnvironment && url != s.testServerUrl) {
            Text(stringResource(Res.string.settings_save_url))
        }
        OutlinedButton(onClick = { model.importTestAnchors() }, enabled = s.testEnvironment) { Text(stringResource(Res.string.settings_import_test_anchors)) }
    }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_test_anchors))
    OutlinedButton(onClick = { model.importEudiTestAnchors() }) { Text(stringResource(Res.string.settings_import_eudi_anchors)) }
    OutlinedButton(onClick = { model.importMultipazTestAnchors() }) { Text(stringResource(Res.string.settings_update_multipaz_anchors)) }
    Toggle(
        stringResource(Res.string.settings_multipaz_identity),
        stringResource(Res.string.settings_multipaz_identity_text) +
            stringResource(Res.string.settings_multipaz_identity_note),
        s.multipazTestIdentity,
        enabled = s.testEnvironment,
    ) { v -> model.updateSettings { it.copy(multipazTestIdentity = v) } }
    Toggle(
        stringResource(Res.string.settings_self_attestation),
        stringResource(Res.string.settings_self_attestation_text) +
            stringResource(Res.string.settings_self_attestation_note),
        s.selfAttestationFallback,
    ) { v -> model.updateSettings { it.copy(selfAttestationFallback = v) } }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_mobile_moica))
    if (!model.legal.enabled(Integration.MOBILE_MOICA)) IntegrationOffRow(model, Integration.MOBILE_MOICA)
    Toggle(
        stringResource(Res.string.settings_manual_sp_title),
        stringResource(Res.string.settings_manual_sp_text) +
            stringResource(Res.string.settings_manual_sp_note) +
            if (model.files.builtInMobileMoicaSp == null) stringResource(Res.string.settings_no_builtin_sp) + LegalStrings.MOICA_SP_FORK_ONLY else "",
        s.manualMobileMoicaSp,
    ) { v -> model.updateSettings { it.copy(manualMobileMoicaSp = v) } }
}

/** Where credential keys live, in the interface language. */
@Composable
fun KeyProtection.label(): String = stringResource(
    when (this) {
        KeyProtection.STRONGBOX -> Res.string.key_strongbox
        KeyProtection.TEE -> Res.string.key_tee
        KeyProtection.SOFTWARE -> Res.string.key_software_pin
    },
)

/** A credential's recorded key storage ([KeyProtection.wire]) in the interface language. */
@Composable
fun keyStorageLabel(wire: String): String = KeyProtection.entries.firstOrNull { it.wire == wire }?.label() ?: wire

@Composable
private fun languageName(l: AppLanguage) = if (l == AppLanguage.SYSTEM) stringResource(Res.string.settings_language_system) else l.name

/**
 * The interface language as a menu: the system's, then every language a translation file provides, each named in
 * itself; Android 13 and later keep it as the per-app language.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LanguageChooser(model: WalletModel) {
    val tag by model.appLanguage.collectAsState()
    val current = AppLanguage.of(tag)
    var open by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = open, onExpandedChange = { open = it }) {
        OutlinedTextField(
            value = languageName(current), onValueChange = {}, readOnly = true, singleLine = true,
            label = { Text(stringResource(Res.string.settings_language)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = open) },
            modifier = Modifier.fillMaxWidth().menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            (listOf(AppLanguage.SYSTEM) + AppLanguage.all).forEach { l ->
                DropdownMenuItem(
                    text = { Text(languageName(l)) },
                    onClick = { open = false; model.setAppLanguage(l) },
                )
            }
        }
    }
}

@Composable
private fun GeneralPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    LanguageChooser(model)
    Text(stringResource(Res.string.settings_language_text), style = MaterialTheme.typography.bodySmall)
    HorizontalDivider()
    Toggle(stringResource(Res.string.settings_show_details), stringResource(Res.string.settings_show_details_text), s.showDetails) { v ->
        model.updateSettings { it.copy(showDetails = v) }
    }
}

private const val SOURCE_URL = "https://github.com/mctea01/my-Bonds-fork-android"

@Composable
private fun appVersion(): String = AppBuild.version ?: stringResource(Res.string.settings_dev_build)

/** Third-party software shipped in the app, as NOTICE lists it. */
@Composable
private fun thirdParty() = listOf(
    "Multipaz" to "Apache License 2.0",
    "Kotlin, kotlinx.coroutines, kotlinx.serialization, kotlinx-io, kotlinx-datetime" to "Apache License 2.0",
    "Ktor" to "Apache License 2.0",
    "Compose Multiplatform, AndroidX" to "Apache License 2.0",
    "Google Play services identity credentials" to "Android Software Development Kit License",
    "Bouncy Castle" to stringResource(Res.string.settings_license_bc),
    "Apache Xerces2, xml-apis" to "Apache License 2.0",
    stringResource(Res.string.settings_component_pdfbox) to "Apache License 2.0",
    stringResource(Res.string.settings_component_sqlite) to stringResource(Res.string.settings_license_sqlite),
    stringResource(Res.string.settings_component_cmwallet) to "Apache License 2.0",
)

@Composable
private fun AboutPage(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    Text("DIW MY WALLET", style = MaterialTheme.typography.titleLarge)
    Text(stringResource(Res.string.settings_about_text) +
        stringResource(Res.string.settings_about_text_2),
        style = MaterialTheme.typography.bodySmall)
    SectionTitle(stringResource(Res.string.settings_version))
    LabelValue(stringResource(Res.string.settings_version), appVersion())
    AppBuild.commit?.let { LabelValue(stringResource(Res.string.settings_build_source), it) }
    LabelValue(stringResource(Res.string.settings_platform), model.platform.platformName)
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_identifiers))
    LabelValue("Client ID", s.clientId, small = true)
    LabelValue(stringResource(Res.string.settings_twdiw_client_id_label), s.twdiwClientId, small = true)
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_license))
    Text("Copyright 2026 " + diw.wallet.app.legal.LegalTexts.DEVELOPER + stringResource(Res.string.settings_license_text), style = MaterialTheme.typography.bodyMedium)
    Text(stringResource(Res.string.settings_anchor_note) +
        stringResource(Res.string.settings_bonds_note),
        style = MaterialTheme.typography.bodySmall)
    SectionTitle(stringResource(Res.string.settings_third_party))
    thirdParty().forEach { (name, license) -> LabelValue(name, license, small = true) }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_source))
    LabelValue("GitHub", SOURCE_URL, small = true) { model.platform.openBrowser(SOURCE_URL) }
    OutlinedButton(onClick = { model.platform.openBrowser("$SOURCE_URL/blob/main/LICENSE") }) { Text(stringResource(Res.string.settings_license_full)) }
    OutlinedButton(onClick = { model.platform.openBrowser("$SOURCE_URL/blob/main/NOTICE") }) { Text(stringResource(Res.string.settings_notice)) }
}

/** Registration with the system credential picker (Android Digital Credentials API); hidden where there is none. */
@Composable
private fun DigitalCredentialsSection(model: WalletModel) {
    val reg by model.dcApiRegistration.collectAsState()
    val r = reg ?: return
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.settings_dc_title))
    val summary = when {
        r.error != null -> stringResource(Res.string.settings_dc_error, r.error)
        r.registered == 0 -> stringResource(Res.string.settings_dc_none)
        else -> stringResource(Res.string.settings_dc_registered, r.registered)
    }
    Text(summary, style = MaterialTheme.typography.bodySmall,
        color = if (r.error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
    // What the system matcher compares a request against: the doctype or vct and the claims of each credential.
    for (entry in r.entries) Text(entry, style = MaterialTheme.typography.bodySmall)
    if (r.notListable > 0) {
        Text(stringResource(Res.string.settings_dc_w3c, r.notListable),
            style = MaterialTheme.typography.bodySmall)
    }
    when {
        r.issuance -> Text(stringResource(Res.string.settings_dc_issuance), style = MaterialTheme.typography.bodySmall)
        r.issuanceError != null -> Text(stringResource(Res.string.settings_dc_issuance_error, r.issuanceError), style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error)
    }
    OutlinedButton(onClick = { model.reregisterDigitalCredentials() }) { Text(stringResource(Res.string.settings_dc_register)) }
}

/**
 * The MyData details the holder may save (Bonds MyDataAutofillProfile): filled into MyData's own sign-in pages in the
 * app and tried as the open password of MyData PDFs. Nothing is learned from pages; the holder types and removes them.
 */
@Composable
private fun MyDataProfileSection(model: WalletModel) {
    val s by model.settingsFlow.collectAsState()
    var id by remember { mutableStateOf("") }
    var birth by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }
    SectionTitle(stringResource(Res.string.settings_mydata_autofill))
    if (!model.legal.enabled(Integration.MYDATA)) IntegrationOffRow(model, Integration.MYDATA)
    Text(stringResource(Res.string.settings_mydata_autofill_text),
        style = MaterialTheme.typography.bodySmall)
    val saved = s.myDataIdNumber
    if (saved != null) {
        LabelValue(stringResource(Res.string.settings_national_id_number), saved.take(1) + "*".repeat(6) + saved.takeLast(3))
        s.myDataBirthDate?.let { LabelValue(stringResource(Res.string.settings_birth_date), it.take(4) + "-" + it.substring(4, 6) + "-" + it.substring(6)) }
        OutlinedButton(onClick = { model.updateSettings { it.copy(myDataIdNumber = null, myDataBirthDate = null) } }) { Text(stringResource(Res.string.settings_mydata_remove)) }
        return
    }
    OutlinedTextField(
        value = id, onValueChange = { v -> id = v.filter { it.isLetterOrDigit() }.take(10); problem = null },
        label = { Text(stringResource(Res.string.settings_national_id_number)) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = birth, onValueChange = { v -> birth = v.filter { it.isDigit() }.take(8); problem = null },
        label = { Text(stringResource(Res.string.settings_birth_date_input)) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
    )
    problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    val idInvalid = stringResource(Res.string.settings_national_id_invalid)
    val birthInvalid = stringResource(Res.string.settings_birth_date_invalid)
    OutlinedButton(
        onClick = {
            val today = kotlin.time.Clock.System.now().toString().take(10).replace("-", "")
            val date = MyDataProfile.normalizeBirthDate(birth, today)
            when {
                !MyDataProfile.isValidId(id) -> problem = idInvalid
                date == null -> problem = birthInvalid
                else -> {
                    model.updateSettings { it.copy(myDataIdNumber = MyDataProfile.normalizeId(id), myDataBirthDate = date) }
                    id = ""
                    birth = ""
                }
            }
        },
        enabled = id.isNotBlank() && birth.isNotBlank(),
    ) { Text(stringResource(Res.string.action_store)) }
}
