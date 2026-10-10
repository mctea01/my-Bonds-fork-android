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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
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
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.core.credential.ClaimReader
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import org.multipaz.document.Document
import org.multipaz.revocation.RevocationCheckState

/**
 * Root composable shared by Android and desktop. [scanQr] is offered when the platform has a camera
 * scanner; it returns the scanned text or null.
 */
@Composable
fun WalletApp(model: WalletModel, scanQr: (suspend () -> String?)? = null) {
    val ready by model.ready.collectAsState()
    val screen by model.screen.collectAsState()
    val settings by model.settingsFlow.collectAsState()
    val msg by model.message.collectAsState()
    val pin by model.pinRequest.collectAsState()
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(msg) {
        msg?.let { snackbar.showSnackbar(it); model.message.value = null }
    }

    MaterialTheme {
        Scaffold(
            topBar = {
                Column {
                    TopAppBar(
                        title = { Text(titleFor(screen)) },
                        navigationIcon = {
                            if (screen != Screen.Home) TextButton(onClick = { model.screen.value = Screen.Home; model.cancelDcApi() }) { Text("返回") }
                        },
                        actions = {
                            if (screen == Screen.Home) TextButton(onClick = { model.screen.value = Screen.Settings }) { Text("設定") }
                        },
                    )
                    if (settings.testEnvironment) TestEnvironmentBanner()
                }
            },
            snackbarHost = { SnackbarHost(snackbar) },
        ) { padding ->
            Box(Modifier.padding(padding).fillMaxSize()) {
                if (!ready) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                } else when (val s = screen) {
                    Screen.Home -> HomeScreen(model, scanQr)
                    Screen.Settings -> SettingsScreen(model)
                    Screen.Issuance -> IssuanceScreen(model)
                    Screen.Presentation -> PresentationScreen(model)
                    is Screen.DocumentDetail -> DocumentScreen(model, s.documentId)
                }
            }
        }
        pin?.let { PinDialog(it.reason, onResult = { v -> it.result.complete(v) }) }
    }
}

private fun titleFor(s: Screen) = when (s) {
    Screen.Home -> "DIW MY WALLET"
    Screen.Settings -> "設定"
    Screen.Issuance -> "加入憑證"
    Screen.Presentation -> "分享資料"
    is Screen.DocumentDetail -> "憑證內容"
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
fun HomeScreen(model: WalletModel, scanQr: (suspend () -> String?)?) {
    val docs by model.documents.collectAsState()
    var input by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    LaunchedEffect(scanning) {
        if (scanning && scanQr != null) {
            scanQr()?.let { model.handleUri(it) }
            scanning = false
        }
    }
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text("貼上憑證邀請、驗證請求或發行端網址") },
            )
            Button(onClick = { model.handleUri(input); input = "" }, enabled = input.isNotBlank()) { Text("開啟") }
        }
        if (scanQr != null) OutlinedButton(onClick = { scanning = true }, modifier = Modifier.fillMaxWidth()) { Text("掃描 QR Code") }
        if (docs.isEmpty()) {
            Text("尚未加入任何憑證。", style = MaterialTheme.typography.bodyLarge)
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(docs, key = { it.identifier }) { doc -> DocumentCard(doc) { model.screen.value = Screen.DocumentDetail(doc.identifier) } }
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
    )
}

@Composable
fun DocumentCard(doc: Document, onClick: () -> Unit) {
    val record = doc.issuanceRecord
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Box {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(doc.displayName ?: "憑證", style = MaterialTheme.typography.titleMedium)
                Text(doc.typeDisplayName ?: record?.credentialIssuer ?: "", style = MaterialTheme.typography.bodySmall)
                storedTrust(doc)?.let { TierBadge(it) }
                if (record?.pendingTransactionId != null) Text("等待發行端完成（延遲發證）", style = MaterialTheme.typography.bodySmall)
            }
            if (record?.isTestEnvironment == true) TestWatermark(Modifier.align(Alignment.CenterEnd).padding(end = 12.dp))
        }
    }
}

@Composable
fun DocumentScreen(model: WalletModel, id: String) {
    val docs by model.documents.collectAsState()
    val statuses by model.statuses.collectAsState()
    val doc = docs.firstOrNull { it.identifier == id } ?: return
    val record = doc.issuanceRecord
    var claims by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var count by remember { mutableStateOf(0) }
    LaunchedEffect(id) {
        val creds = doc.getCertifiedCredentials()
        count = creds.size
        claims = creds.firstOrNull()?.let { ClaimReader.read(it, model.documentTypes) }?.map { it.label to it.value }.orEmpty()
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        storedTrust(doc)?.let { TrustCard("發行端", doc.typeDisplayName ?: record?.credentialIssuer ?: "", it) }
        if (record?.isTestEnvironment == true) TestWatermark()
        Text("可用次數（批次憑證數）：$count", style = MaterialTheme.typography.bodyMedium)
        record?.keyStorage?.let { Text("金鑰保護：$it", style = MaterialTheme.typography.bodyMedium) }
        claims.forEach { (k, v) ->
            Row(Modifier.fillMaxWidth()) {
                Text(k, Modifier.weight(0.4f), style = MaterialTheme.typography.bodyMedium)
                Text(v, Modifier.weight(0.6f), style = MaterialTheme.typography.bodyMedium)
            }
        }
        Spacer(Modifier.height(8.dp))
        val status = statuses[id]
        Text(
            when (status?.state) {
                null -> "狀態：尚未查詢"
                RevocationCheckState.VALID -> if (status.trusted) "狀態：有效" else "狀態：有效（狀態清單未經驗證）"
                RevocationCheckState.INVALID -> "狀態：已撤銷"
                RevocationCheckState.SUSPENDED -> "狀態：已暫停"
                RevocationCheckState.UNKNOWN -> "狀態：無法確認（${status.detail ?: ""}）"
            },
            color = if (status?.state == RevocationCheckState.VALID && status.trusted) MaterialTheme.colorScheme.primary else tierColor(TrustTier.T3),
        )
        OutlinedButton(onClick = { model.checkStatus(doc) }) { Text("查詢撤銷狀態") }
        OutlinedButton(onClick = { model.deleteDocument(doc) }) { Text("刪除此憑證") }
    }
}
