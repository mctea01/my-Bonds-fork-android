package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import diw.wallet.app.CredentialDetails
import diw.wallet.app.DetailSection
import diw.wallet.app.HomeTab
import diw.wallet.app.QrScanStep
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.core.credential.ClaimPictures
import diw.wallet.core.credential.ClaimReader
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.x509.displaySubject
import org.multipaz.document.Document
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.DerivedEvidence
import diw.wallet.core.w3c.SdJwtDisclosures
import diw.wallet.core.document.derived.EvidenceResult
import diw.wallet.core.zktls.WebProofCredentials
import diw.wallet.core.trust.TrustRole
import org.multipaz.crypto.X509Cert
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.util.fromBase64Url

/**
 * Root composable shared by Android and desktop. [scanQr] is offered when the platform has a camera
 * scanner; it returns the scanned text or null. [scanQrStream] keeps that camera open for an animated code, handing
 * each new code to its callback until the callback says done. Reading a QR Code from a picture is offered everywhere.
 * [scanMrz] reads a travel document's machine readable zone with the camera and returns its lines, or null.
 *
 * The home screen has five tabs: the documents list and the history log as in the EUDI wallet, Use as in Bonds
 * (present, counter services, add), Files for signed files and official documents, and Verify for the wallet
 * acting as a verifier. Settings sit behind the gear at the top right.
 */
@Composable
fun WalletApp(
    model: WalletModel,
    scanQr: (suspend () -> String?)? = null,
    scanQrStream: (suspend (onCode: (String) -> QrScanStep) -> Unit)? = null,
    scanMrz: (suspend () -> String?)? = null,
) {
    AppLocaleScope(model.platform.languageStore) { WalletAppContent(model, scanQr, scanQrStream, scanMrz) }
}

@Composable
private fun WalletAppContent(
    model: WalletModel,
    scanQr: (suspend () -> String?)?,
    scanQrStream: (suspend (onCode: (String) -> QrScanStep) -> Unit)?,
    scanMrz: (suspend () -> String?)?,
) {
    val ready by model.ready.collectAsState()
    val screen by model.screen.collectAsState()
    val tab by model.tab.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    val msg by model.message.collectAsState()
    val proximityListening by model.proximity.listening.collectAsState()
    val pin by model.pinRequest.collectAsState()
    val notice by model.integrationNotice.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    var addSheet by remember { mutableStateOf(false) }
    var scanning by remember { mutableStateOf<Boolean?>(null) }
    val consent by model.legal.consent.collectAsState()
    // Shown at the first start and after a legal text changed; stays up on its summary page until the holder leaves it.
    var onboarding by remember { mutableStateOf(false) }
    LaunchedEffect(ready, consent.complete) { if (ready && !consent.complete) onboarding = true }

    LaunchedEffect(msg) {
        msg?.let { snackbar.showSnackbar(it); model.message.value = null }
    }
    // true: the camera, false: a picture. One reader for every entry: the code decides the flow (offer, request,
    // Bonds challenge, static code).
    LaunchedEffect(scanning) {
        val camera = scanning ?: return@LaunchedEffect
        try {
            (if (camera) scanQr?.invoke() else model.qrFromImage())?.let { model.handleUri(it) }
        } finally {
            scanning = null
        }
    }
    val scan = ScanActions(camera = scanQr?.let { { scanning = true } }, image = { scanning = false })
    val readQr: suspend () -> String? = scanQr ?: { model.qrFromImage() }

    WalletTheme {
        CompositionLocalProvider(LocalQrReader provides readQr) {
            if (ready && onboarding) {
                Scaffold(snackbarHost = { SnackbarHost(snackbar) }) { padding ->
                    Box(Modifier.padding(padding).fillMaxSize()) { OnboardingScreen(model) { onboarding = false } }
                }
            } else {
                Scaffold(
                    topBar = {
                        Column {
                            TopAppBar(
                                title = { Text(if (screen == Screen.Proximity && !proximityListening) stringResource(Res.string.screen_presentation) else titleFor(screen, tab)) },
                                navigationIcon = {
                                    if (screen != Screen.Home) IconButton(onClick = { model.back() }) { Icon(WalletIcons.Back, contentDescription = stringResource(Res.string.action_back)) }
                                },
                                actions = {
                                    if (screen == Screen.Home) {
                                        if (tab == HomeTab.DOCUMENTS) IconButton(onClick = { addSheet = true }) { Icon(WalletIcons.Add, contentDescription = stringResource(Res.string.action_add_credential)) }
                                        IconButton(onClick = { model.screen.value = Screen.Settings }) { Icon(WalletIcons.Settings, contentDescription = stringResource(Res.string.screen_settings)) }
                                    }
                                },
                            )
                            if (settings.testEnvironment) TestEnvironmentBanner()
                        }
                    },
                    bottomBar = { if (ready && screen == Screen.Home) HomeNavigationBar(tab) { model.tab.value = it } },
                    snackbarHost = { SnackbarHost(snackbar) },
                ) { padding ->
                    Box(Modifier.padding(padding).fillMaxSize()) {
                        if (!ready) {
                            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                        } else when (val s = screen) {
                            Screen.Home -> when (tab) {
                                HomeTab.DOCUMENTS -> DocumentsTab(model) { addSheet = true }
                                HomeTab.FILES -> FilesTab(model)
                                HomeTab.USE -> UseTab(model, scan)
                                HomeTab.VERIFY -> VerifyTab(model, canScanFrames = scanQrStream != null)
                                HomeTab.HISTORY -> HistoryTab(model)
                            }
                            Screen.Settings -> SettingsScreen(model)
                            is Screen.SettingsPage -> SettingsPageScreen(model, s.section)
                            Screen.Issuance -> IssuanceScreen(model)
                            Screen.Presentation -> PresentationScreen(model)
                            is Screen.DocumentDetail -> DocumentScreen(model, s, scan)
                            is Screen.Certificate -> CertificateScreen(model, s)
                            Screen.AddDocument -> AddDocumentScreen(model)
                            Screen.TrustList -> TrustListScreen(model)
                            Screen.TrustAnchors -> TrustAnchorsScreen(model)
                            Screen.CustomTrust -> CustomTrustScreen(model)
                            Screen.ZkSettings -> ZkSettingsScreen(model)
                            is Screen.OpenPgpKeys -> OpenPgpKeysScreen(model, s)
                            Screen.Offline -> OfflineScreen(model, readQr, hasCamera = scanQr != null, streamQr = scanQrStream)
                            Screen.MsIssuance -> MsIssuanceScreen(model)
                            Screen.Proximity -> ProximityScreen(model)
                            Screen.Reader -> ReaderScreen(model)
                            is Screen.FileDetail -> FileDetailScreen(model, s)
                            is Screen.FileSign -> FileSignScreen(model, s)
                            is Screen.FileDerive -> FileDeriveScreen(model, s)
                            is Screen.OpenCertRender -> OpenCertRenderScreen(model, s)
                            is Screen.NationalIdCreate -> NationalIdCreateScreen(model, s)
                            is Screen.NationalId -> NationalIdScreen(model, s)
                            Screen.DocumentSources -> DocumentSourcesScreen(model)
                            Screen.PassportRead -> PassportReadScreen(model, scanMrz)
                            is Screen.Portal -> PortalScreen(model, s)
                            is Screen.OfficialBundle -> OfficialBundleScreen(model, s)
                            is Screen.LegalText -> LegalTextScreen(model, s)
                            is Screen.IntegrationStatement -> IntegrationStatementScreen(model, s)
                        }
                    }
                }
                if (addSheet) {
                    AddDocumentSheet(
                        model = model,
                        onDismiss = { addSheet = false },
                        onList = { addSheet = false; model.screen.value = Screen.AddDocument },
                        scan = ScanActions(
                            camera = scan.camera?.let { start -> { addSheet = false; start() } },
                            image = { addSheet = false; scan.image() },
                        ),
                    )
                }
                pin?.let { PinDialog(it.reason, onResult = { v -> it.result.complete(v) }) }
                NfcScanSheet(model)
                PendingShareDialog(model)
                notice?.let { n -> IntegrationNoticeDialog(model, n) }
            }
        }
    }
}

@Composable
private fun titleFor(s: Screen, tab: HomeTab) = when (s) {
    Screen.Home -> when (tab) {
        HomeTab.DOCUMENTS -> stringResource(Res.string.tab_documents)
        HomeTab.FILES -> stringResource(Res.string.tab_files)
        HomeTab.USE -> stringResource(Res.string.tab_use)
        HomeTab.VERIFY -> stringResource(Res.string.tab_verify)
        HomeTab.HISTORY -> stringResource(Res.string.tab_history)
    }
    Screen.Settings -> stringResource(Res.string.screen_settings)
    is Screen.SettingsPage -> stringResource(s.section.title)
    Screen.Issuance -> stringResource(Res.string.action_add_credential)
    Screen.Presentation -> stringResource(Res.string.screen_presentation)
    is Screen.DocumentDetail -> stringResource(Res.string.screen_document_detail)
    is Screen.Certificate -> stringResource(Res.string.screen_certificate)
    Screen.AddDocument -> stringResource(Res.string.screen_add_document)
    Screen.TrustList -> stringResource(Res.string.screen_trust_list)
    Screen.TrustAnchors -> stringResource(Res.string.screen_trust_anchors)
    Screen.CustomTrust -> stringResource(Res.string.screen_custom_trust)
    Screen.ZkSettings -> stringResource(Res.string.screen_zk_settings)
    is Screen.OpenPgpKeys -> stringResource(Res.string.screen_openpgp_keys)
    Screen.Offline -> stringResource(Res.string.screen_offline)
    Screen.MsIssuance -> stringResource(Res.string.screen_ms_issuance)
    Screen.Proximity -> stringResource(Res.string.screen_proximity)
    Screen.Reader -> stringResource(Res.string.screen_reader)
    is Screen.FileDetail -> stringResource(Res.string.screen_file_detail)
    is Screen.FileSign -> stringResource(Res.string.screen_file_sign)
    is Screen.FileDerive -> stringResource(Res.string.screen_file_derive)
    is Screen.OpenCertRender -> if (s.offline) stringResource(Res.string.screen_opencert_offline) else stringResource(Res.string.screen_opencert_issuer)
    is Screen.NationalIdCreate -> stringResource(Res.string.screen_national_id_create)
    is Screen.NationalId -> stringResource(Res.string.screen_national_id)
    Screen.DocumentSources -> stringResource(Res.string.screen_document_sources)
    Screen.PassportRead -> stringResource(Res.string.screen_passport_read)
    is Screen.Portal -> stringResource(Res.string.screen_document_sources)
    is Screen.OfficialBundle -> stringResource(Res.string.screen_official_bundle)
    is Screen.LegalText -> diw.wallet.app.legal.LegalTexts.byId(s.documentId)?.title ?: diw.wallet.app.legal.LegalStrings.SETTINGS_SECTION
    is Screen.IntegrationStatement -> diw.wallet.app.legal.LegalStrings.STATEMENTS_TITLE
}

/** The one-time reminder before the first request of an integration; reading the statement leaves the request undone. */
@Composable
private fun IntegrationNoticeDialog(model: WalletModel, n: WalletModel.IntegrationNotice) {
    val cancel = { model.integrationNotice.value = null }
    AlertDialog(
        onDismissRequest = cancel,
        title = { Text(diw.wallet.app.legal.LegalStrings.TWDIW_COMPATIBILITY_TITLE) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(diw.wallet.app.legal.LegalStrings.TWDIW_COMPATIBILITY_WARNING)
                TextButton(onClick = {
                    cancel()
                    model.screen.value = Screen.IntegrationStatement(n.integration)
                }) { Text(diw.wallet.app.legal.LegalStrings.READ_STATEMENT) }
            }
        },
        confirmButton = { Button(onClick = { model.continueNotice() }) { Text(diw.wallet.app.legal.LegalStrings.TWDIW_COMPATIBILITY_CONTINUE) } },
        dismissButton = { TextButton(onClick = cancel) { Text(diw.wallet.app.legal.LegalStrings.CANCEL) } },
    )
}

@Composable
fun PinDialog(reason: String, onResult: (String?) -> Unit) {
    var value by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { onResult(null) },
        title = { Text(stringResource(Res.string.pin_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(reason)
                OutlinedTextField(
                    value = value,
                    onValueChange = { v -> value = v.filter { it.isDigit() }.take(12) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                )
            }
        },
        confirmButton = { Button(onClick = { onResult(value) }, enabled = value.length >= 6) { Text(stringResource(Res.string.action_confirm)) } },
        dismissButton = { TextButton(onClick = { onResult(null) }) { Text(stringResource(Res.string.action_cancel)) } },
    )
}

@Composable
fun LabelValue(label: String, value: String, small: Boolean = false, onClick: (() -> Unit)? = null) {
    val style = if (small) MaterialTheme.typography.bodySmall else MaterialTheme.typography.bodyMedium
    Row(Modifier.fillMaxWidth().then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)) {
        Text(label, Modifier.weight(0.4f), style = style)
        Text(
            if (onClick != null) "$value  >" else value,
            Modifier.weight(0.6f),
            style = style,
            color = if (onClick != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** A claim's value as shown: the picture when the value is an encoded image (base64, base64url, data: URL), else the text. */
@Composable
fun ClaimValueView(model: WalletModel, label: String, value: String, modifier: Modifier = Modifier, small: Boolean = true) {
    val picture = remember(value) { ClaimPictures.fromText(value)?.let { model.platform.decodeImage(it) } }
    if (picture != null) {
        Image(picture, contentDescription = label, contentScale = ContentScale.Fit,
            modifier = modifier.widthIn(max = 160.dp).aspectRatio(picture.width.toFloat() / picture.height.coerceAtLeast(1)).clip(RoundedCornerShape(8.dp)))
    } else {
        Text(value, modifier, style = if (small) MaterialTheme.typography.bodySmall else MaterialTheme.typography.bodyMedium)
    }
}

/** A labelled claim; an encoded image shows as the picture. */
@Composable
fun ClaimRow(model: WalletModel, label: String, value: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(label, Modifier.weight(0.4f), style = MaterialTheme.typography.bodyMedium)
        Box(Modifier.weight(0.6f)) { ClaimValueView(model, label, value, small = false) }
    }
}

/** Grouped details; rows holding certificates open the certificate view. */
@Composable
fun DetailSections(model: WalletModel, sections: List<DetailSection>) {
    sections.forEach { section ->
        Text(section.title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        section.rows.forEach { row ->
            val open = if (row.certs.isEmpty()) null else {
                { model.screen.value = Screen.Certificate(row.certs, row.certIndex, model.screen.value) }
            }
            LabelValue(row.label, row.value, small = true, onClick = open)
        }
    }
}

/** Rebuilds the trust decision stored with a document at issuance time. */
fun storedTrust(doc: Document): TrustDecision? = doc.issuanceRecord?.let { r ->
    TrustDecision(
        tier = r.trustTier,
        environment = r.trustEnvironment,
        official = r.official,
        anchorName = r.anchorName,
        // Credentials derived before the label existed are recognised by their type.
        labels = r.labels.mapNotNull { runCatching { TrustLabel.valueOf(it) }.getOrNull() }.toSet() +
            (if (DerivedCredentials.isDerived(r.vct)) setOf(TrustLabel.SELF_ISSUED) else emptySet()),
        reasons = r.reasons,
    )
}

/** One document: its card, trust, status, data and details, and how to present it. [scan] opens the camera. */
@Composable
fun DocumentScreen(model: WalletModel, screen: Screen.DocumentDetail, scan: ScanActions? = null) {
    val id = screen.documentId
    val docs by model.documents.collectAsState()
    val statuses by model.statuses.collectAsState()
    val doc = docs.firstOrNull { it.identifier == id } ?: return
    val record = doc.issuanceRecord
    val settings by model.settingsFlow.collectAsState()
    var claims by remember { mutableStateOf<List<Triple<String, String, ImageBitmap?>>>(emptyList()) }
    var details by remember { mutableStateOf<List<DetailSection>>(emptyList()) }
    var evidence by remember { mutableStateOf<List<EvidenceResult>>(emptyList()) }
    var source by remember { mutableStateOf<String?>(null) }
    var webSource by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var count by remember { mutableStateOf(0) }
    var showDetails by remember(settings.showDetails) { mutableStateOf(settings.showDetails) }
    var confirmDelete by remember { mutableStateOf(false) }
    LaunchedEffect(id) {
        val creds = doc.getCertifiedCredentials()
        count = creds.size
        val first = creds.firstOrNull()
        // A derived credential's document and evidence objects are shown as checked evidence, not as raw data.
        val derived = DerivedCredentials.isDerived(record?.vct)
        // A web query result's source, method and session are shown as where the values came from.
        val web = WebProofCredentials.isWebCredential(record?.vct)
        claims = first?.let { ClaimReader.read(it, model.documentTypes) }
            ?.filterNot { derived && (it.path.firstOrNull() in setOf("document", "evidence") || it.path.firstOrNull()?.let(DerivedCredentials::isTechnicalClaim) == true) }
            ?.filterNot { web && it.path.firstOrNull() in WebProofCredentials.SOURCE_CLAIMS }
            ?.map {
                val value = if (web && it.path == listOf(WebProofCredentials.CLAIM_STATUS)) WebProofCredentials.plainStatus(it.value) else it.value
                Triple(model.claimLabel(it.path, it.label, record), value, it.picture?.let { b -> model.platform.decodeImage(b) })
            }.orEmpty()
        if (web && first is SdJwtVcCredential) runCatching {
            val compact = first.issuerProvidedData.decodeToString()
            webSource = webSourceLines(model, Json.parseToJsonElement(compact.substringBefore('~').split('.')[1].fromBase64Url().decodeToString()).jsonObject)
        }
        details = runCatching { CredentialDetails.credential(record, first) }.getOrDefault(emptyList())
        if (derived && first is SdJwtVcCredential) runCatching {
            val compact = first.issuerProvidedData.decodeToString()
            val payload = Json.parseToJsonElement(compact.substringBefore('~').split('.')[1].fromBase64Url().decodeToString()).jsonObject
            payload["document"]?.jsonObject?.let { d ->
                val size = d["size"]?.jsonPrimitive?.content?.toLongOrNull()
                source = listOfNotNull(
                    d["mediaType"]?.jsonPrimitive?.content,
                    size?.let { sizeText(it) },
                    d["sha256"]?.jsonPrimitive?.content?.let { "SHA-256 " + it.take(16) + "..." },
                ).joinToString(model.text(Res.string.sep_comma))
            }
            val disclosed = SdJwtDisclosures.parse(compact).disclosures.mapNotNull { d -> d.name?.let { it to d.value } }.toMap()
            evidence = DerivedEvidence.verify(payload, model.files.trustSource, own = true, disclosed = disclosed, zk = model.zkPdfContext)
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        CredentialCard(model, doc) {}
        assuranceText(record)?.let { LabelValue(stringResource(Res.string.credential_ial), it) }
        storedTrust(doc)?.let { TrustCard(stringResource(Res.string.credential_issuer), doc.typeDisplayName ?: record?.credentialIssuer ?: "", it) }
        if (record?.pendingTransactionId == null) StatusPanel(model, doc)
        if (claims.isNotEmpty()) SectionTitle(stringResource(Res.string.credential_claims))
        claims.forEach { (k, v, picture) ->
            if (picture != null) {
                Text(k, style = MaterialTheme.typography.bodySmall)
                Image(picture, contentDescription = k, contentScale = ContentScale.Fit,
                    modifier = Modifier.widthIn(max = 240.dp).aspectRatio(picture.width.toFloat() / picture.height.coerceAtLeast(1)).clip(RoundedCornerShape(8.dp)))
            } else LabelValue(k, v)
        }
        source?.let { LabelValue(stringResource(Res.string.credential_source_document), it, small = true) }
        if (webSource.isNotEmpty()) {
            SectionTitle(stringResource(Res.string.credential_query_source))
            webSource.forEach { (k, v) -> LabelValue(k, v) }
        }
        if (evidence.isNotEmpty()) EvidenceRows(evidence)
        if (record?.pendingTransactionId == null) PresentThisDocument(model, doc, scan)
        SectionTitle(stringResource(Res.string.credential_info))
        record?.let {
            LabelValue(stringResource(Res.string.credential_format), CredentialDetails.formatName(it))
            (it.vct ?: it.docType)?.let { t -> LabelValue(stringResource(Res.string.credential_type), t) }
            LabelValue(stringResource(Res.string.credential_specs), CredentialDetails.specs(it).joinToString(stringResource(Res.string.sep_list)))
        }
        LabelValue(stringResource(Res.string.credential_uses), stringResource(Res.string.credential_uses_value, count))
        record?.keyStorage?.let { LabelValue(stringResource(Res.string.credential_key_protection), keyStorageLabel(it)) }
        TextButton(onClick = { showDetails = !showDetails }) { Text(if (showDetails) stringResource(Res.string.action_hide_details) else stringResource(Res.string.action_show_details)) }
        if (showDetails) {
            statuses[id]?.status?.let { DetailSections(model, CredentialDetails.status(it)) }
            DetailSections(model, details)
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { confirmDelete = true }) {
            Icon(WalletIcons.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(stringResource(Res.string.action_delete_credential), color = MaterialTheme.colorScheme.error)
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(Res.string.credential_delete_title)) },
            text = { Text(stringResource(Res.string.credential_delete_text)) },
            confirmButton = {
                TextButton(onClick = { confirmDelete = false; model.deleteDocument(doc) }) { Text(stringResource(Res.string.action_delete_credential), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
}

/** Where and how a web query result was read, from its payload's source, method and session. */
private suspend fun webSourceLines(model: WalletModel, payload: JsonObject): List<Pair<String, String>> {
    fun JsonObject.text(k: String) = (this[k] as? JsonPrimitive)?.contentOrNull
    val source = payload["source"] as? JsonObject
    val session = payload["session"] as? JsonObject
    return buildList {
        source?.text("profileTitle")?.let { add(model.text(Res.string.web_proof_page) to it) }
        source?.text("host")?.let { h ->
            add(model.text(Res.string.web_proof_site) to h + (source.text("port")?.let { ":$it" } ?: "") + if (source.text("official") == "true") model.text(Res.string.web_proof_government) else "")
        }
        source?.text("retrievedAt")?.let { t -> runCatching { Instant.parse(t) }.getOrNull()?.let { add(model.text(Res.string.web_proof_time) to localTime(it.epochSeconds)) } }
        payload.text("method")?.let { m ->
            add(model.text(Res.string.web_proof_method) to when (m) {
                WebProofCredentials.METHOD_PROXY -> model.text(Res.string.web_proof_proxy)
                WebProofCredentials.METHOD_MPC -> model.text(Res.string.web_proof_mpc)
                WebProofCredentials.METHOD_DEVICE -> model.text(Res.string.web_proof_device)
                else -> m
            })
        }
        session?.text("purpose")?.let { add(model.text(Res.string.web_proof_purpose) to it) }
        source?.let { s -> listOfNotNull(s.text("tlsVersion")?.let { "TLS $it" }, s.text("cipherSuite")) }
            ?.takeIf { it.isNotEmpty() }?.let { add(model.text(Res.string.web_proof_connection) to it.joinToString(model.text(Res.string.sep_comma))) }
    }
}

/**
 * Presenting this document on the holder's own initiative: an mdoc by NFC tap or QR code (ISO/IEC 18013-5); any
 * other document to the verifier whose QR code is scanned next, listed first when it is an offline challenge.
 */
@Composable
private fun PresentThisDocument(model: WalletModel, doc: Document, scan: ScanActions?) {
    val record = doc.issuanceRecord
    var pasted by remember(doc.identifier) { mutableStateOf("") }
    SectionTitle(stringResource(Res.string.present_this_title))
    if (record?.format == "mso_mdoc") {
        ActionRow(WalletIcons.Nfc, stringResource(Res.string.screen_proximity), stringResource(Res.string.present_proximity_detail)) { model.proximity.open() }
    }
    if (scan != null) {
        val detail = stringResource(Res.string.present_scan_detail)
        scan.camera?.let { camera ->
            ActionRow(WalletIcons.Scan, stringResource(Res.string.present_scan), detail) {
                model.taiwan.preferredDocument = doc.identifier
                camera()
            }
        }
        ActionRow(WalletIcons.Image, stringResource(Res.string.present_scan_image), if (scan.camera == null) detail else stringResource(Res.string.present_scan_image_detail)) {
            model.taiwan.preferredDocument = doc.identifier
            scan.image()
        }
    }
    if (scan?.camera == null) {
        Text(stringResource(Res.string.present_paste_hint), style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(value = pasted, onValueChange = { pasted = it }, label = { Text(stringResource(Res.string.present_paste_label)) }, singleLine = true,
            modifier = Modifier.fillMaxWidth())
        OutlinedButton(onClick = {
            model.taiwan.preferredDocument = doc.identifier
            model.handleUri(pasted.trim())
            pasted = ""
        }, enabled = pasted.isNotBlank()) { Text(stringResource(Res.string.action_present)) }
    }
}

/** One certificate of a chain, with the other certificates of the chain selectable. */
@Composable
fun CertificateScreen(model: WalletModel, screen: Screen.Certificate) {
    var index by remember(screen) { mutableStateOf(screen.index) }
    val cert = screen.chain[index]
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(cert.displaySubject(), style = MaterialTheme.typography.titleMedium)
        if (screen.chain.size > 1) {
            Text(stringResource(Res.string.certificate_chain), style = MaterialTheme.typography.titleSmall)
            screen.chain.forEachIndexed { i, c ->
                LabelValue(stringResource(Res.string.certificate_nth, i + 1), c.displaySubject(), small = true, onClick = if (i == index) null else ({ index = i }))
            }
        }
        DetailSections(model, CredentialDetails.certificate(cert))
        // The root of a chain that leads to no anchor (a foreign government or company CA) can be trusted from here.
        if (index == screen.chain.lastIndex && cert.subject == cert.issuer) TrustThisRoot(model, cert)
    }
}

/** Imports a self-signed root as the user's own anchor (T3, never official) for the roles the holder picks. */
@Composable
private fun TrustThisRoot(model: WalletModel, cert: X509Cert) {
    var roles by remember(cert) { mutableStateOf(setOf(TrustRole.DOCUMENT)) }
    SectionTitle(stringResource(Res.string.certificate_trust_root))
    Text(stringResource(Res.string.certificate_trust_root_text),
        style = MaterialTheme.typography.bodySmall)
    RoleChips(listOf(TrustRole.DOCUMENT, TrustRole.TSA, TrustRole.ISSUER, TrustRole.VERIFIER), roles) { roles = it }
    OutlinedButton(onClick = { model.importAnchor(cert.toPem(), "", roles) }, enabled = roles.isNotEmpty()) { Text(stringResource(Res.string.action_add_trust_anchor)) }
}
