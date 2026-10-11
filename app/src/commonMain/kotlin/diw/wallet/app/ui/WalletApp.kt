package diw.wallet.app.ui

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
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.core.credential.ClaimReader
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.x509.displaySubject
import org.multipaz.document.Document

/**
 * Root composable shared by Android and desktop. [scanQr] is offered when the platform has a camera
 * scanner; it returns the scanned text or null.
 *
 * The home screen has five tabs: the documents list and the history log as in the EUDI wallet, Use as in Bonds
 * (present, counter services, add), Files for signed files and official documents, and Verify for the wallet
 * acting as a verifier. Settings sit behind the gear at the top right.
 */
@Composable
fun WalletApp(model: WalletModel, scanQr: (suspend () -> String?)? = null) {
    val ready by model.ready.collectAsState()
    val screen by model.screen.collectAsState()
    val tab by model.tab.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    val msg by model.message.collectAsState()
    val proximityListening by model.proximity.listening.collectAsState()
    val pin by model.pinRequest.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    var addSheet by remember { mutableStateOf(false) }
    var scanning by remember { mutableStateOf(false) }

    LaunchedEffect(msg) {
        msg?.let { snackbar.showSnackbar(it); model.message.value = null }
    }
    LaunchedEffect(scanning) {
        if (scanning && scanQr != null) {
            scanQr()?.let { model.handleUri(it) }
            scanning = false
        }
    }
    // One scanner for every entry: the scanned code decides the flow (offer, request, Bonds challenge, static code).
    val scan: (() -> Unit)? = if (scanQr != null) ({ scanning = true }) else null

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
                        HomeTab.FILES -> FilesTab()
                        HomeTab.USE -> UseTab(model, scan)
                        HomeTab.VERIFY -> VerifyTab(model)
                        HomeTab.HISTORY -> HistoryTab(model)
                    }
                    Screen.Settings -> SettingsScreen(model)
                    Screen.Issuance -> IssuanceScreen(model)
                    Screen.Presentation -> PresentationScreen(model)
                    is Screen.DocumentDetail -> DocumentScreen(model, s)
                    is Screen.Certificate -> CertificateScreen(model, s)
                    Screen.AddDocument -> AddDocumentScreen(model)
                    Screen.TrustList -> TrustListScreen(model)
                    Screen.TrustAnchors -> TrustAnchorsScreen(model)
                    Screen.Offline -> OfflineScreen(model, scanQr)
                    Screen.MsIssuance -> MsIssuanceScreen(model)
                    Screen.Proximity -> ProximityScreen(model)
                }
            }
        }
        if (addSheet) {
            AddDocumentSheet(
                onDismiss = { addSheet = false },
                onList = { addSheet = false; model.screen.value = Screen.AddDocument },
                onScan = scan?.let { start -> { addSheet = false; start() } },
            )
        }
        pin?.let { PinDialog(it.reason, onResult = { v -> it.result.complete(v) }) }
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
    Screen.Issuance -> "加入證件"
    Screen.Presentation -> "出示證件"
    is Screen.DocumentDetail -> "證件內容"
    is Screen.Certificate -> "證書詳情"
    Screen.AddDocument -> "從清單選擇"
    Screen.TrustList -> "信任清單"
    Screen.TrustAnchors -> "信任錨點"
    Screen.Offline -> "出示與查驗"
    Screen.MsIssuance -> "加入 Verified ID"
    Screen.Proximity -> "感應出示"
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
        labels = r.labels.mapNotNull { runCatching { TrustLabel.valueOf(it) }.getOrNull() }.toSet(),
        reasons = r.reasons,
    )
}

@Composable
fun DocumentScreen(model: WalletModel, screen: Screen.DocumentDetail) {
    val id = screen.documentId
    val docs by model.documents.collectAsState()
    val statuses by model.statuses.collectAsState()
    val doc = docs.firstOrNull { it.identifier == id } ?: return
    val record = doc.issuanceRecord
    val settings by model.settingsFlow.collectAsState()
    var claims by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var details by remember { mutableStateOf<List<DetailSection>>(emptyList()) }
    var count by remember { mutableStateOf(0) }
    var showDetails by remember(settings.showDetails) { mutableStateOf(settings.showDetails) }
    var confirmDelete by remember { mutableStateOf(false) }
    LaunchedEffect(id) {
        val creds = doc.getCertifiedCredentials()
        count = creds.size
        val first = creds.firstOrNull()
        claims = first?.let { ClaimReader.read(it, model.documentTypes) }
            ?.map { model.claimLabel(it.path, it.label, record) to it.value }.orEmpty()
        details = runCatching { CredentialDetails.credential(record, first) }.getOrDefault(emptyList())
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        CredentialCard(model, doc) {}
        storedTrust(doc)?.let { TrustCard("發行端", doc.typeDisplayName ?: record?.credentialIssuer ?: "", it) }
        if (record?.pendingTransactionId == null) StatusPanel(model, doc)
        if (claims.isNotEmpty()) SectionTitle("證件資料")
        claims.forEach { (k, v) -> LabelValue(k, v) }
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
    }
}
