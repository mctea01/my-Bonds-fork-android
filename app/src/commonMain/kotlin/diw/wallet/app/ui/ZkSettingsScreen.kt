package diw.wallet.app.ui

import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import diw.wallet.app.res.*
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import diw.wallet.app.ServerStrings
import diw.wallet.app.WalletModel
import diw.wallet.app.ZkJobPhase
import diw.wallet.app.ZkMeasurement
import diw.wallet.core.zk.ZkAsset
import diw.wallet.core.zk.ZkAssetStatus
import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.RemoteZkPdfEngine
import diw.wallet.core.zk.ZkCapability
import diw.wallet.core.zk.ZkPdfStatement
import diw.wallet.core.zk.ZkProverHost
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.ZkTier
import kotlinx.coroutines.launch

internal val ZkBackend.title: String
    @Composable get() = when (this) {
        ZkBackend.NOIR_ULTRAHONK -> stringResource(Res.string.zk_backend_pdf)
        ZkBackend.TLSN -> stringResource(Res.string.zk_backend_tls)
        ZkBackend.OPENAC_SPARTAN2 -> stringResource(Res.string.zk_backend_openac)
        ZkBackend.LONGFELLOW -> stringResource(Res.string.zk_backend_longfellow)
    }

internal val ZkTier.title: String
    @Composable get() = when (this) {
        ZkTier.A -> stringResource(Res.string.zk_tier_a)
        ZkTier.B -> stringResource(Res.string.zk_tier_b)
        ZkTier.C -> stringResource(Res.string.zk_tier_c)
    }

/** The settings-list summary: the device tier once it is known. */
@androidx.compose.runtime.Composable
internal fun zkSummary(capability: ZkCapability?): String =
    capability?.let { org.jetbrains.compose.resources.stringResource(diw.wallet.app.res.Res.string.zk_summary_tier, it.tier.name) }
        ?: org.jetbrains.compose.resources.stringResource(diw.wallet.app.res.Res.string.zk_summary_unknown)

private val ZkAssetStatus.title: String
    @Composable get() = when (this) {
        ZkAssetStatus.MISSING -> stringResource(Res.string.zk_asset_missing)
        ZkAssetStatus.PARTIAL -> stringResource(Res.string.zk_asset_partial)
        ZkAssetStatus.READY -> stringResource(Res.string.zk_asset_ready)
        ZkAssetStatus.CORRUPT -> stringResource(Res.string.zk_asset_corrupt)
    }

/**
 * Zero-knowledge proofs in the security settings: the device tier and why, each engine and whether it is in this
 * build, the circuit assets with their sizes (downloaded only after the user agrees to the size, deletable), and the
 * self-hosted prover, which opens with zkPDF.
 */
@Composable
fun ZkSettingsScreen(model: WalletModel) {
    val zk = model.zk
    val capability by zk.capability.collectAsState()
    val native by zk.native.collectAsState()
    val problem by zk.nativeProblem.collectAsState()
    val info by zk.platformInfo.collectAsState()
    val statuses by zk.assetStatus.collectAsState()
    val downloads by zk.downloads.collectAsState()
    val refreshing by zk.refreshing.collectAsState()
    val scope = rememberCoroutineScope()
    var confirmDownload by remember { mutableStateOf<List<ZkAsset>?>(null) }
    var confirmDelete by remember { mutableStateOf<List<ZkAsset>?>(null) }
    LaunchedEffect(Unit) { zk.refresh() }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text(
            stringResource(Res.string.zk_intro_1) +
                stringResource(Res.string.zk_intro_2),
            style = MaterialTheme.typography.bodySmall,
        )
        SectionTitle(stringResource(Res.string.zk_this_device))
        val cap = capability
        if (cap == null) Text(if (refreshing) stringResource(Res.string.zk_assessing) else stringResource(Res.string.zk_not_assessed), style = MaterialTheme.typography.bodyMedium)
        else {
            Text(cap.tier.title, style = MaterialTheme.typography.titleSmall)
            info?.let { i ->
                Text(
                    stringResource(Res.string.zk_device_info, i.abi, i.totalRamMb, i.availableRamMb, i.freeDiskMb),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Text(stringResource(Res.string.zk_tier_note),
                style = MaterialTheme.typography.bodySmall)
        }
        problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }

        HorizontalDivider()
        SectionTitle(stringResource(Res.string.zk_engines))
        native?.version?.takeIf { it.isNotEmpty() }?.let { Text(stringResource(Res.string.zk_native_version, it), style = MaterialTheme.typography.bodySmall) }
        ZkBackend.entries.forEach { backend ->
            val available = cap != null && backend in cap.backends
            val reason = cap?.reasons?.get(backend)
            Column {
                Text(backend.title, style = MaterialTheme.typography.titleSmall)
                Text(
                    when {
                        cap == null -> stringResource(Res.string.zk_not_assessed)
                        available && reason == null -> stringResource(Res.string.zk_engine_ok)
                        available -> stringResource(Res.string.zk_engine_reason, reason.toString())
                        else -> reason ?: stringResource(Res.string.zk_engine_missing)
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        HorizontalDivider()
        SectionTitle(stringResource(Res.string.zk_circuits))
        if (zk.catalog.isEmpty()) Text(stringResource(Res.string.zk_no_manifest), style = MaterialTheme.typography.bodySmall)
        zk.catalog.groupBy { it.backend }.forEach { (backend, assets) ->
            val installed = assets.filter { statuses[it.id] == ZkAssetStatus.READY }
            val missing = assets - installed.toSet()
            Text(backend.title, style = MaterialTheme.typography.titleSmall)
            Text(
                stringResource(Res.string.zk_installed, installed.size, assets.size, sizeText(installed.sumOf { it.installedBytes })) +
                    if (missing.isNotEmpty()) stringResource(Res.string.zk_to_download, sizeText(missing.sumOf { it.gzipBytes })) else "",
                style = MaterialTheme.typography.bodySmall,
            )
            assets.forEach { asset ->
                val download = downloads[asset.id]
                Column(Modifier.fillMaxWidth().padding(start = 8.dp)) {
                    Text(
                        stringResource(Res.string.zk_asset_line, asset.id, if ("verifier" in asset.role) "產生與查驗" else "產生", sizeText(asset.installedBytes)) +
                            (statuses[asset.id]?.title ?: if (refreshing) stringResource(Res.string.zk_checking) else stringResource(Res.string.zk_unchecked)),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (download != null && download.error == null) {
                        LinearProgressIndicator(
                            progress = { if (download.total <= 0) 0f else download.received.toFloat() / download.total },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    download?.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                val busy = assets.any { downloads[it.id]?.error == null && it.id in downloads }
                if (busy) OutlinedButton(onClick = { zk.cancelDownload() }) { Text(stringResource(Res.string.zk_stop_download)) }
                else if (missing.isNotEmpty()) OutlinedButton(onClick = { confirmDownload = missing }) { Text(stringResource(Res.string.action_download)) }
                if (installed.isNotEmpty() && !busy) OutlinedButton(onClick = { confirmDelete = installed }) { Text(stringResource(Res.string.action_delete)) }
            }
        }
        OutlinedButton(onClick = { zk.refresh() }, enabled = !refreshing) { Text(if (refreshing) stringResource(Res.string.zk_checking_dots) else stringResource(Res.string.zk_check_again)) }

        HorizontalDivider()
        SectionTitle(stringResource(Res.string.zk_templates))
        ZkTemplatesSection(model)

        HorizontalDivider()
        SectionTitle(stringResource(Res.string.zk_server))
        ServerSection(model)
        HorizontalDivider()
        SectionTitle(stringResource(Res.string.zk_self_host))
        ProverSection(model)
        if (info?.isDesktop == true) {
            HorizontalDivider()
            SectionTitle(stringResource(Res.string.zk_phone_requests))
            PhoneRequestSection(model)
        }
        HorizontalDivider()
        SectionTitle(stringResource(Res.string.zk_measurements))
        MeasurementSection(model)
    }

    confirmDownload?.let { assets ->
        AlertDialog(
            onDismissRequest = { confirmDownload = null },
            title = { Text(stringResource(Res.string.zk_download_title)) },
            text = {
                Text(
                    stringResource(Res.string.zk_download_will, sizeText(assets.sumOf { it.gzipBytes }), sizeText(assets.sumOf { it.installedBytes })) +
                        stringResource(Res.string.zk_download_hint_delete),
                )
            },
            confirmButton = { TextButton(onClick = { confirmDownload = null; zk.download(assets.map { it.id }) }) { Text(stringResource(Res.string.action_download)) } },
            dismissButton = { TextButton(onClick = { confirmDownload = null }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
    confirmDelete?.let { assets ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text(stringResource(Res.string.zk_delete_title)) },
            text = { Text(stringResource(Res.string.zk_delete_text, sizeText(assets.sumOf { it.installedBytes }))) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = null
                    scope.launch { assets.forEach { zk.delete(it.id) } }
                }) { Text(stringResource(Res.string.action_delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
}

/** The signed page templates from the release: what is installed, when it was checked, and a manual update. */
@Composable
private fun ZkTemplatesSection(model: WalletModel) {
    val st by model.zkTemplates.state.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    Text(stringResource(Res.string.zk_templates_text_1) +
        stringResource(Res.string.zk_templates_text_2), style = MaterialTheme.typography.bodySmall)
    val lines = buildList {
        if (!st.keyConfigured) add(stringResource(Res.string.zk_templates_no_key))
        if (st.version != null) add(stringResource(Res.string.zk_templates_installed, st.pages, st.documents, localTime(st.issuedAt!!)) + (st.source?.let { stringResource(Res.string.zk_templates_source, it) } ?: ""))
        else if (st.keyConfigured) add(if (st.running) stringResource(Res.string.zk_templates_downloading) else stringResource(Res.string.zk_templates_not_downloaded))
        st.checkedAt?.let { add(stringResource(Res.string.zk_templates_checked, localTime(it))) }
        st.error?.let { add(stringResource(Res.string.zk_templates_failed, it) + if (st.version != null) stringResource(Res.string.zk_templates_still) else "") }
    }
    lines.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(enabled = st.keyConfigured && !st.running, onClick = { model.zkTemplates.refresh() }) { Text(stringResource(Res.string.zk_update_now)) }
        OutlinedButton(enabled = !st.running, onClick = { model.zkTemplates.importFiles() }) { Text(stringResource(Res.string.zk_import_file)) }
    }
    Text(
        stringResource(Res.string.zk_import_text) +
            if (settings.testEnvironment) stringResource(Res.string.zk_import_test_text) else "",
        style = MaterialTheme.typography.bodySmall,
    )
    st.notice?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
    if (st.testPages.isNotEmpty() || st.testDocuments.isNotEmpty()) {
        Text(stringResource(Res.string.zk_test_templates) + if (settings.testEnvironment) "" else stringResource(Res.string.zk_test_off), style = MaterialTheme.typography.titleSmall)
        st.testPages.forEach { p ->
            Text(stringResource(Res.string.zk_test_page, p.title, p.id, p.host) + if (p.port != 443) ":${p.port}" else "", style = MaterialTheme.typography.bodySmall)
        }
        st.testDocuments.forEach { d ->
            Text(stringResource(Res.string.zk_test_document, d.title, d.id, d.fields.size), style = MaterialTheme.typography.bodySmall)
        }
        OutlinedButton(onClick = { model.zkTemplates.clearTestPages() }) { Text(stringResource(Res.string.zk_clear_test)) }
    }
}

/** The proofs' row on the security page. */
@Composable
internal fun ZkSettingsRow(model: WalletModel, onOpen: () -> Unit) {
    val capability by model.zk.capability.collectAsState()
    val tier = capability?.let { org.jetbrains.compose.resources.stringResource(diw.wallet.app.res.Res.string.zk_row_tier, it.tier.name) }
        ?: org.jetbrains.compose.resources.stringResource(diw.wallet.app.res.Res.string.zk_row_unknown)
    ActionRow(
        WalletIcons.Shield,
        org.jetbrains.compose.resources.stringResource(diw.wallet.app.res.Res.string.screen_zk_settings),
        tier + org.jetbrains.compose.resources.stringResource(diw.wallet.app.res.Res.string.zk_row_assets),
        onClick = onOpen,
    )
}

/**
 * The production server (diw-wallet-server, or the test server's API) used as relay, zkTLS verifier host and age
 * host: its address, the access token its zkTLS host asks for, and trusting the root that signs its requests and
 * receipts after the user compares the fingerprint.
 */
@Composable
private fun ServerSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    val server by model.server.state.collectAsState()
    var url by remember(settings.zkVerifierUrl) { mutableStateOf(settings.zkVerifierUrl) }
    var token by remember(settings.serverToken) { mutableStateOf(settings.serverToken) }
    val valid = url.isEmpty() || url.startsWith("https://") || settings.testEnvironment && url.startsWith("http://")
    val saved = settings.zkVerifierUrl.isNotEmpty()
    val trustedAny = settings.serverRootSha256.isNotEmpty() || settings.serverVerifierDid.isNotEmpty()
    LaunchedEffect(settings.zkVerifierUrl) { if (saved && trustedAny) model.server.check(confirm = false) }
    Text(
        stringResource(Res.string.zk_server_text) +
            stringResource(Res.string.zk_server_deploy),
        style = MaterialTheme.typography.bodySmall,
    )
    OutlinedTextField(
        value = url, onValueChange = { url = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(Res.string.zk_server_url)) }, isError = !valid,
    )
    OutlinedTextField(
        value = token, onValueChange = { token = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(Res.string.zk_server_token)) }, visualTransformation = PasswordVisualTransformation(),
    )
    Text(stringResource(Res.string.zk_server_token_note), style = MaterialTheme.typography.bodySmall)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(
            onClick = {
                val changedUrl = url.trimEnd('/') != settings.zkVerifierUrl
                model.updateSettings {
                    it.copy(
                        zkVerifierUrl = url.trimEnd('/'), serverToken = token,
                        serverRootSha256 = if (changedUrl) "" else it.serverRootSha256,
                        serverVerifierDid = if (changedUrl) "" else it.serverVerifierDid,
                    )
                }
            },
            enabled = valid && (url != settings.zkVerifierUrl || token != settings.serverToken),
        ) { Text(stringResource(Res.string.action_save)) }
        OutlinedButton(onClick = { model.server.check(confirm = true) }, enabled = saved && !server.checking && url == settings.zkVerifierUrl) {
            Text(if (server.checking) stringResource(Res.string.state_loading) else if (!trustedAny) stringResource(Res.string.zk_server_add_trust) else stringResource(Res.string.zk_server_retrust))
        }
    }
    if (settings.serverRootSha256.isNotEmpty()) {
        Text(stringResource(Res.string.zk_server_root, fingerprint(settings.serverRootSha256)), style = MaterialTheme.typography.bodySmall)
    }
    if (settings.serverVerifierDid.isNotEmpty()) {
        Text(stringResource(Res.string.zk_server_verifier, settings.serverVerifierDid), style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
    if (server.changed) {
        Text(
            stringResource(Res.string.zk_server_changed),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
        )
    }
    server.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    server.addressWarning?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    ServerShareSection(model)
    HorizontalDivider()
    ServerPolicySection(model)

    server.pending?.let { info ->
        AlertDialog(
            onDismissRequest = { model.server.dismiss() },
            title = { Text(stringResource(Res.string.zk_server_trust_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(Res.string.zk_server_line, info.url), style = MaterialTheme.typography.bodySmall)
                    if (info.sha256 != null) {
                        Text(stringResource(Res.string.zk_server_root_subject, info.subject.toString()), style = MaterialTheme.typography.bodySmall)
                        Text(stringResource(Res.string.sha256_line, fingerprint(info.sha256)), style = MaterialTheme.typography.bodySmall)
                    }
                    info.verifierDid?.let { Text(stringResource(Res.string.zk_server_verifier_did, it), style = MaterialTheme.typography.bodySmall) }
                    if (info.features.isNotEmpty()) Text(stringResource(Res.string.zk_server_features, info.features.joinToString("、")), style = MaterialTheme.typography.bodySmall)
                    info.federation?.let {
                        Text(ServerStrings.FEDERATION_CONFIRMED + ServerStrings.federationVerified(it), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary)
                    }
                    if (info.sharedFingerprint) Text(ServerStrings.shareFingerprintMatches(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                    info.settingsSha256?.let { Text(ServerStrings.SETTINGS_DIGEST + it.take(16), style = MaterialTheme.typography.bodySmall) }
                    info.addressWarning?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                    Text(
                        stringResource(Res.string.zk_server_trust_text_1) +
                            stringResource(Res.string.zk_server_trust_text_2) +
                            stringResource(Res.string.zk_server_trust_text_3),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            },
            confirmButton = { TextButton(onClick = { model.server.confirm(info) }) { Text(if (info.sha256 != null) stringResource(Res.string.zk_server_trust_match) else stringResource(Res.string.zk_server_trust)) } },
            dismissButton = { TextButton(onClick = { model.server.dismiss() }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
}

/**
 * The self-hosted zkPDF prover (tools/zk-prover-server): its address and access token, and a check that it answers
 * and which circuit compositions it can prove. Proofs it returns are verified on this device before they are used.
 */
@Composable
private fun ProverSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    var url by remember(settings.zkProverUrl) { mutableStateOf(settings.zkProverUrl) }
    var token by remember(settings.zkProverToken) { mutableStateOf(settings.zkProverToken) }
    var result by remember(settings.zkProverUrl, settings.zkProverToken) { mutableStateOf<String?>(null) }
    var checking by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val urlProblem = url.takeIf { it.isNotEmpty() }?.let { ZkProverHost.problem(it, model.platform::cleartextPermitted) }
    val tokenProblem = if (url.isNotEmpty() && token.length < ZkProverHost.MIN_TOKEN) stringResource(Res.string.zk_token_min, ZkProverHost.MIN_TOKEN) else null
    Text(
        stringResource(Res.string.zk_prover_text_1) +
            stringResource(Res.string.zk_prover_text_2),
        style = MaterialTheme.typography.bodySmall,
    )
    OutlinedTextField(
        value = url, onValueChange = { url = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(if (model.platform.cleartextPermitted("192.168.0.1")) stringResource(Res.string.zk_prover_url_lan) else stringResource(Res.string.zk_prover_url)) }, isError = urlProblem != null,
        supportingText = urlProblem?.let { { Text(it) } },
    )
    OutlinedTextField(
        value = token, onValueChange = { token = it.trim() }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        label = { Text(stringResource(Res.string.zk_prover_token)) }, visualTransformation = PasswordVisualTransformation(), isError = tokenProblem != null,
        supportingText = tokenProblem?.let { { Text(it) } },
    )
    Text(stringResource(Res.string.zk_prover_token_note), style = MaterialTheme.typography.bodySmall)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(
            onClick = { model.updateSettings { it.copy(zkProverUrl = url.trimEnd('/'), zkProverToken = if (url.isEmpty()) "" else token) } },
            enabled = urlProblem == null && tokenProblem == null && (url.trimEnd('/') != settings.zkProverUrl || token != settings.zkProverToken),
        ) { Text(stringResource(Res.string.action_save)) }
        OutlinedButton(
            onClick = {
                checking = true
                scope.launch {
                    result = try {
                        val local = model.zk.pdf()
                        if (local == null) model.text(Res.string.zk_prover_no_engine)
                        else when (val r = RemoteZkPdfEngine(ZkProverHost(model.text(Res.string.zk_self_host), settings.zkProverUrl, settings.zkProverToken), local, model.http).compositions()) {
                            is ZkResult.Ok -> if (r.value.isEmpty()) model.text(Res.string.zk_prover_no_circuits)
                                else model.text(Res.string.zk_prover_can) + r.value.joinToString(model.text(Res.string.sep_list)) { compositionTitle(it) }
                            is ZkResult.Failed -> r.reason
                            ZkResult.Cancelled -> null
                        }
                    } finally {
                        checking = false
                    }
                }
            },
            enabled = settings.zkProverUrl.isNotEmpty() && !checking && url.trimEnd('/') == settings.zkProverUrl,
        ) { Text(if (checking) stringResource(Res.string.state_connecting) else stringResource(Res.string.zk_test_connection)) }
        if (settings.zkProverUrl.isNotEmpty()) {
            TextButton(onClick = { model.updateSettings { it.copy(zkProverUrl = "", zkProverToken = "") } }) { Text(stringResource(Res.string.action_remove)) }
        }
    }
    result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
}

/**
 * Desktop wallet: proves a request file (.zkpdfreq) a phone exported and saves the proof file (.zkpdf) for the phone
 * to import. The request is used once and not kept; the phone verifies the proof before it uses it.
 */
@Composable
private fun PhoneRequestSection(model: WalletModel) {
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val jobs by model.zk.jobs.collectAsState()
    val running = jobs[diw.wallet.app.FilesModel.PHONE_JOB]?.active == true
    Text(
        stringResource(Res.string.zk_phone_text_1, diw.wallet.core.zk.ZkPdfRemote.REQUEST_EXTENSION) +
            stringResource(Res.string.zk_phone_text_2, diw.wallet.core.zk.ZkPdfRemote.RESPONSE_EXTENSION),
        style = MaterialTheme.typography.bodySmall,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(onClick = { model.files.proveForPhone() }, enabled = busy == null) { Text(stringResource(Res.string.zk_open_request)) }
        if (running) TextButton(onClick = { model.zk.cancel(diw.wallet.app.FilesModel.PHONE_JOB) }) { Text(stringResource(Res.string.action_stop)) }
    }
    busy?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
    error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
}

/**
 * The latest proofs of this session with their time and memory peak, so a holder can report how a device performs.
 * The text holds no proof input, only the device class, the composition and the numbers.
 */
@Composable
private fun MeasurementSection(model: WalletModel) {
    val entries by model.zk.measurements.collectAsState()
    @Suppress("DEPRECATION")
    val clipboard = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }
    Text(
        stringResource(Res.string.zk_measurements_text),
        style = MaterialTheme.typography.bodySmall,
    )
    if (entries.isEmpty()) {
        Text(stringResource(Res.string.zk_no_measurements), style = MaterialTheme.typography.bodySmall)
        return
    }
    entries.forEach { Text(measurementLine(it), style = MaterialTheme.typography.bodySmall) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(onClick = {
            clipboard.setText(AnnotatedString(measurementReport(entries)))
            copied = true
        }) { Text(stringResource(Res.string.zk_copy_log)) }
        if (copied) Text(stringResource(Res.string.zk_copied), style = MaterialTheme.typography.bodySmall)
    }
}

internal fun measurementLine(m: ZkMeasurement): String {
    val outcome = when (m.phase) {
        ZkJobPhase.DONE -> "完成"
        ZkJobPhase.FAILED -> "失敗"
        ZkJobPhase.TIMED_OUT -> "逾時"
        ZkJobPhase.CANCELLED -> "已停止"
        else -> m.phase.name
    }
    val peak = m.peakMemoryMb?.let { "，記憶體峰值 $it MB" } ?: ""
    val note = m.note?.let { "（$it）" } ?: ""
    val step = m.lastStep?.takeIf { m.phase != ZkJobPhase.DONE }?.let { "，停在「$it」" } ?: ""
    return "${m.kind.label}$note：$outcome，${m.seconds} 秒$peak$step"
}

/** Plain lines for a report: device class first, then one line per proof. */
internal fun measurementReport(entries: List<ZkMeasurement>): String {
    val device = entries.firstNotNullOfOrNull { it.platform }?.let {
        "裝置：${it.abi}，記憶體 ${it.totalRamMb} MB（偵測時可用 ${it.availableRamMb} MB），${if (it.isDesktop) "電腦版" else "手機版"}"
    } ?: "裝置：未知"
    return (listOf(device) + entries.map { "${it.at} ${it.kind.name} ${measurementLine(it)}" }).joinToString("\n")
}

internal fun compositionTitle(id: String): String = when (id) {
    ZkPdfStatement.PHONE -> "手機版電路"
    ZkPdfStatement.DESKTOP -> "電腦版電路"
    else -> id
}

/** A SHA-256 hex in groups of four for comparing by eye. */
private fun fingerprint(hex: String): String = hex.uppercase().chunked(4).joinToString(" ")
