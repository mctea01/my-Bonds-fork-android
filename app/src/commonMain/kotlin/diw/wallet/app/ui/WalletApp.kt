package diw.wallet.app.ui

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
) {
    val ready by model.ready.collectAsState()
    val screen by model.screen.collectAsState()
    val tab by model.tab.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    val msg by model.message.collectAsState()
    val proximityListening by model.proximity.listening.collectAsState()
    val pin by model.pinRequest.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    var addSheet by remember { mutableStateOf(false) }
    var scanning by remember { mutableStateOf<Boolean?>(null) }

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
        Scaffold(
            topBar = {
                Column {
                    TopAppBar(
                        title = { Text(if (screen == Screen.Proximity && !proximityListening) "出示證件" else titleFor(screen, tab)) },
                        navigationIcon = {
                            if (screen != Screen.Home) IconButton(onClick = { model.back() }) { Icon(WalletIcons.Back, contentDescription = "返回") }
                        },
                        actions = {
                            if (screen == Screen.Home) {
                                if (tab == HomeTab.DOCUMENTS) IconButton(onClick = { addSheet = true }) { Icon(WalletIcons.Add, contentDescription = "加入證件") }
                                IconButton(onClick = { model.screen.value = Screen.Settings }) { Icon(WalletIcons.Settings, contentDescription = "設定") }
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
                    is Screen.Portal -> PortalScreen(model, s)
                    is Screen.OfficialBundle -> OfficialBundleScreen(model, s)
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
    }
}

private fun titleFor(s: Screen, tab: HomeTab) = when (s) {
    Screen.Home -> when (tab) {
        HomeTab.DOCUMENTS -> "證件"
        HomeTab.FILES -> "文件"
        HomeTab.USE -> "使用"
        HomeTab.VERIFY -> "查驗"
        HomeTab.HISTORY -> "紀錄"
    }
    Screen.Settings -> "設定"
    is Screen.SettingsPage -> s.section.title
    Screen.Issuance -> "加入證件"
    Screen.Presentation -> "出示證件"
    is Screen.DocumentDetail -> "證件內容"
    is Screen.Certificate -> "證書詳情"
    Screen.AddDocument -> "從清單選擇"
    Screen.TrustList -> "信任清單"
    Screen.TrustAnchors -> "信任錨點"
    Screen.CustomTrust -> "自訂信任"
    Screen.ZkSettings -> "零知識證明"
    Screen.Offline -> "出示與查驗"
    Screen.MsIssuance -> "加入 Verified ID"
    Screen.Proximity -> "感應出示"
    Screen.Reader -> "感應查驗"
    is Screen.FileDetail -> "文件內容"
    is Screen.FileSign -> "簽署文件"
    is Screen.FileDerive -> "產生衍生憑證"
    is Screen.OpenCertRender -> if (s.offline) "離線顯示證書" else "發證機構樣式"
    is Screen.NationalIdCreate -> "製作身分證卡"
    is Screen.NationalId -> "身分證卡"
    Screen.DocumentSources -> "取得文件"
    is Screen.Portal -> "取得文件"
    is Screen.OfficialBundle -> "公文容器"
}

@Composable
fun PinDialog(reason: String, onResult: (String?) -> Unit) {
    var value by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { onResult(null) },
        title = { Text("輸入 App PIN") },
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
        confirmButton = { Button(onClick = { onResult(value) }, enabled = value.length >= 6) { Text("確認") } },
        dismissButton = { TextButton(onClick = { onResult(null) }) { Text("取消") } },
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
            (if (r.vct == DerivedCredentials.VCT) setOf(TrustLabel.SELF_ISSUED) else emptySet()),
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
        val derived = record?.vct == DerivedCredentials.VCT
        // A web query result's source, method and session are shown as where the values came from.
        val web = WebProofCredentials.isWebCredential(record?.vct)
        claims = first?.let { ClaimReader.read(it, model.documentTypes) }
            ?.filterNot { derived && it.path.firstOrNull() in setOf("document", "evidence") }
            ?.filterNot { web && it.path.firstOrNull() in WebProofCredentials.SOURCE_CLAIMS }
            ?.map {
                val value = if (web && it.path == listOf(WebProofCredentials.CLAIM_STATUS)) WebProofCredentials.plainStatus(it.value) else it.value
                Triple(model.claimLabel(it.path, it.label, record), value, it.picture?.let { b -> model.platform.decodeImage(b) })
            }.orEmpty()
        if (web && first is SdJwtVcCredential) runCatching {
            val compact = first.issuerProvidedData.decodeToString()
            webSource = webSourceLines(Json.parseToJsonElement(compact.substringBefore('~').split('.')[1].fromBase64Url().decodeToString()).jsonObject)
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
                ).joinToString("，")
            }
            evidence = DerivedEvidence.verify(payload, model.files.trustSource, own = true)
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        CredentialCard(model, doc) {}
        assuranceText(record)?.let { LabelValue("身分保證等級（IAL）", it) }
        storedTrust(doc)?.let { TrustCard("發行端", doc.typeDisplayName ?: record?.credentialIssuer ?: "", it) }
        if (record?.pendingTransactionId == null) StatusPanel(model, doc)
        if (claims.isNotEmpty()) SectionTitle("證件資料")
        claims.forEach { (k, v, picture) ->
            if (picture != null) {
                Text(k, style = MaterialTheme.typography.bodySmall)
                Image(picture, contentDescription = k, contentScale = ContentScale.Fit,
                    modifier = Modifier.widthIn(max = 240.dp).aspectRatio(picture.width.toFloat() / picture.height.coerceAtLeast(1)).clip(RoundedCornerShape(8.dp)))
            } else LabelValue(k, v)
        }
        source?.let { LabelValue("來源文件", it, small = true) }
        if (webSource.isNotEmpty()) {
            SectionTitle("查詢來源")
            webSource.forEach { (k, v) -> LabelValue(k, v) }
        }
        if (evidence.isNotEmpty()) EvidenceRows(evidence)
        if (record?.pendingTransactionId == null) PresentThisDocument(model, doc, scan)
        SectionTitle("證件資訊")
        record?.let {
            LabelValue("格式", CredentialDetails.formatName(it))
            (it.vct ?: it.docType)?.let { t -> LabelValue("類型", t) }
            LabelValue("規格", CredentialDetails.specs(it).joinToString("、"))
        }
        LabelValue("可用次數", "$count（批次憑證數）")
        record?.keyStorage?.let { LabelValue("金鑰保護", CredentialDetails.keyStorageName(it)) }
        TextButton(onClick = { showDetails = !showDetails }) { Text(if (showDetails) "隱藏技術細節" else "顯示技術細節") }
        if (showDetails) {
            statuses[id]?.status?.let { DetailSections(model, CredentialDetails.status(it)) }
            DetailSections(model, details)
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { confirmDelete = true }) {
            Icon(WalletIcons.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text("刪除證件", color = MaterialTheme.colorScheme.error)
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("刪除這張證件？") },
            text = { Text("證件與它的金鑰會從這支手機刪除，無法復原。需要時請向發行端重新申請。") },
            confirmButton = {
                TextButton(onClick = { confirmDelete = false; model.deleteDocument(doc) }) { Text("刪除證件", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("取消") } },
        )
    }
}

/** Where and how a web query result was read, from its payload's source, method and session. */
private fun webSourceLines(payload: JsonObject): List<Pair<String, String>> {
    fun JsonObject.text(k: String) = (this[k] as? JsonPrimitive)?.contentOrNull
    val source = payload["source"] as? JsonObject
    val session = payload["session"] as? JsonObject
    return buildList {
        source?.text("profileTitle")?.let { add("查驗頁" to it) }
        source?.text("host")?.let { h ->
            add("網站" to h + (source.text("port")?.let { ":$it" } ?: "") + if (source.text("official") == "true") "（政府網站）" else "")
        }
        source?.text("retrievedAt")?.let { t -> runCatching { Instant.parse(t) }.getOrNull()?.let { add("查詢時間" to localTime(it.epochSeconds)) } }
        payload.text("method")?.let { m ->
            add("證明方式" to when (m) {
                WebProofCredentials.METHOD_PROXY -> "zkTLS（查驗方以代理模式驗證後簽發）"
                WebProofCredentials.METHOD_MPC -> "zkTLS（查驗方以 MPC 模式驗證後簽發）"
                WebProofCredentials.METHOD_DEVICE -> "裝置證明（本錢包簽署，不是零知識證明）"
                else -> m
            })
        }
        session?.text("purpose")?.let { add("查驗用途" to it) }
        source?.let { s -> listOfNotNull(s.text("tlsVersion")?.let { "TLS $it" }, s.text("cipherSuite")) }
            ?.takeIf { it.isNotEmpty() }?.let { add("連線" to it.joinToString("，")) }
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
    SectionTitle("出示這張證件")
    if (record?.format == "mso_mdoc") {
        ActionRow(WalletIcons.Nfc, "感應出示", "手機靠近查驗設備，或讓對方掃描 QR Code（ISO/IEC 18013-5）") { model.proximity.open() }
    }
    if (scan != null) {
        val detail = "線上請求（OpenID4VP）或離線查驗挑戰；離線出示時這張證件排在最前面"
        scan.camera?.let { camera ->
            ActionRow(WalletIcons.Scan, "掃描查驗方的 QR Code", detail) {
                model.taiwan.preferredDocument = doc.identifier
                camera()
            }
        }
        ActionRow(WalletIcons.Image, "從圖片讀取查驗方的 QR Code", if (scan.camera == null) detail else "查驗方的 QR Code 在截圖或圖片裡時使用") {
            model.taiwan.preferredDocument = doc.identifier
            scan.image()
        }
    }
    if (scan?.camera == null) {
        Text("也可以貼上查驗方給的連結或查驗挑戰。", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(value = pasted, onValueChange = { pasted = it }, label = { Text("查驗方的連結或挑戰") }, singleLine = true,
            modifier = Modifier.fillMaxWidth())
        OutlinedButton(onClick = {
            model.taiwan.preferredDocument = doc.identifier
            model.handleUri(pasted.trim())
            pasted = ""
        }, enabled = pasted.isNotBlank()) { Text("出示") }
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
            Text("憑證鏈（由簽署憑證往根憑證）", style = MaterialTheme.typography.titleSmall)
            screen.chain.forEachIndexed { i, c ->
                LabelValue("第 ${i + 1} 張", c.displaySubject(), small = true, onClick = if (i == index) null else ({ index = i }))
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
    SectionTitle("信任這張根憑證")
    Text("如果這張根憑證不在內建清單（例如其他國家或企業的憑證機構），可以自行加入信任錨點。加入後屬於使用者自訂，信任等級為 T3，不會顯示為官方；請確認來源後再加入。",
        style = MaterialTheme.typography.bodySmall)
    RoleChips(listOf(TrustRole.DOCUMENT, TrustRole.TSA, TrustRole.ISSUER, TrustRole.VERIFIER), roles) { roles = it }
    OutlinedButton(onClick = { model.importAnchor(cert.toPem(), "", roles) }, enabled = roles.isNotEmpty()) { Text("加入信任錨點") }
}
