package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import diw.wallet.app.ServerPolicy
import diw.wallet.app.Screen
import diw.wallet.app.ServerStrings
import diw.wallet.app.WalletModel
import diw.wallet.core.server.ServerShare
import kotlinx.coroutines.launch

/** Reads one QR Code: the camera where there is one, else a picture. Provided by WalletApp. */
internal val LocalQrReader = staticCompositionLocalOf<suspend () -> String?> { { null } }

/** Which server a check between two wallets runs through when both have one. */
@Composable
internal fun ServerPolicySection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    val current = ServerPolicy.of(settings.serverPolicy)
    Text(ServerStrings.POLICY_TITLE, style = MaterialTheme.typography.titleSmall)
    ServerPolicy.entries.forEach { p ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = p == current, onClick = { model.updateSettings { it.copy(serverPolicy = p.id) } })
            Column {
                Text(ServerStrings.policyName(p), style = MaterialTheme.typography.bodyMedium)
                Text(ServerStrings.policyDetail(p), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    Text(ServerStrings.POLICY_NOTE, style = MaterialTheme.typography.bodySmall)
}

/** Sharing this wallet's server and importing a shared one, under the server settings. */
@Composable
internal fun ServerShareSection(model: WalletModel) {
    val settings by model.settingsFlow.collectAsState()
    var sharing by remember { mutableStateOf(false) }
    var importing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val readQr = LocalQrReader.current
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(onClick = { sharing = true }, enabled = settings.zkVerifierUrl.isNotEmpty()) { Text(ServerStrings.SHARE) }
        OutlinedButton(onClick = { importing = true }) { Text(ServerStrings.IMPORT) }
    }
    if (sharing) ServerShareDialog(model, peerOnly = false) { sharing = false }
    if (importing) {
        var link by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { importing = false },
            title = { Text(ServerStrings.IMPORT) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(value = link, onValueChange = { link = it.trim() }, label = { Text(ServerStrings.IMPORT_FIELD) },
                        modifier = Modifier.fillMaxWidth(), maxLines = 4)
                    OutlinedButton(onClick = {
                        scope.launch {
                            readQr()?.let { text ->
                                importing = false
                                if (ServerShare.looksLike(text)) model.server.receive(text) else model.handleUri(text)
                            }
                        }
                    }) { Text(ServerStrings.SCAN_PEER) }
                }
            },
            confirmButton = {
                TextButton(onClick = { importing = false; model.server.receive(link) }, enabled = ServerShare.looksLike(link)) { Text(ServerStrings.IMPORT) }
            },
            dismissButton = { TextButton(onClick = { importing = false }) { Text(ServerStrings.IMPORT_CANCEL) } },
        )
    }
}

/**
 * This wallet's server as a QR Code and link. [peerOnly] is the holder showing it to a verifier for one check: no
 * token and no choice about it.
 */
@Composable
internal fun ServerShareDialog(model: WalletModel, peerOnly: Boolean, onDismiss: () -> Unit) {
    var includeToken by remember { mutableStateOf(false) }
    val share = model.server.share(includeToken && !peerOnly)
    @Suppress("DEPRECATION")
    val clipboard = LocalClipboardManager.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (peerOnly) ServerStrings.SHOW_MY_SERVER else ServerStrings.SHARE_TITLE) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.CenterHorizontally) {
                if (share == null) {
                    Text(ServerStrings.SHARE_NOTHING, style = MaterialTheme.typography.bodyMedium)
                    return@Column
                }
                val link = share.link()
                QrImage(link, Modifier.fillMaxWidth().widthIn(max = 320.dp))
                Text(share.url, style = MaterialTheme.typography.bodyMedium)
                share.rootSha256?.let { Text(stringResource(Res.string.sha256_prefix) + it.uppercase().chunked(4).joinToString(" "), style = MaterialTheme.typography.bodySmall) }
                share.verifierDid?.let { Text(it, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis) }
                if (peerOnly) {
                    Text(ServerStrings.SHARE_PEER_NOTE, style = MaterialTheme.typography.bodySmall)
                } else {
                    if (model.settings.serverToken.isNotEmpty()) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = includeToken, onCheckedChange = { includeToken = it })
                            Text(ServerStrings.SHARE_INCLUDE_TOKEN, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    Text(ServerStrings.SHARE_NOTE, style = MaterialTheme.typography.bodySmall)
                }
                OutlinedButton(onClick = {
                    clipboard.setText(AnnotatedString(link))
                    model.message.value = ServerStrings.LINK_COPIED
                }) { Text(ServerStrings.COPY_LINK) }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(ServerStrings.CLOSE) } },
    )
}

/** A scanned or opened share link waiting for the user's choice; shown over every screen. */
@Composable
internal fun PendingShareDialog(model: WalletModel) {
    val pending by model.server.pendingShare.collectAsState()
    val share = pending ?: return
    val current = model.server.base()
    AlertDialog(
        onDismissRequest = { model.server.pendingShare.value = null },
        title = { Text(ServerStrings.IMPORT_TITLE) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                share.name?.let { Text(it, style = MaterialTheme.typography.titleSmall) }
                Text(share.url, style = MaterialTheme.typography.bodyMedium)
                share.rootSha256?.let { Text(stringResource(Res.string.sha256_prefix) + it.uppercase().chunked(4).joinToString(" "), style = MaterialTheme.typography.bodySmall) }
                share.verifierDid?.let { Text(it, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis) }
                share.federation?.let { Text(stringResource(Res.string.server_federation, it), style = MaterialTheme.typography.bodySmall) }
                if (share.features.isNotEmpty()) Text(stringResource(Res.string.server_features) + share.features.joinToString(stringResource(Res.string.sep_list)), style = MaterialTheme.typography.bodySmall)
                if (share.token != null) Text(ServerStrings.IMPORT_TOKEN, style = MaterialTheme.typography.bodySmall)
                if (current != null && current != share.url) {
                    Text(ServerStrings.IMPORT_REPLACES + current, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Text(ServerStrings.IMPORT_TRUST_NOTE, style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            Row {
                TextButton(onClick = { model.server.usePeer(share) }) { Text(ServerStrings.IMPORT_FOR_SESSION) }
                TextButton(onClick = {
                    model.server.adopt(share)
                    // The trust confirmation and any mismatch are shown with the server settings.
                    model.screen.value = Screen.ZkSettings
                }) { Text(ServerStrings.IMPORT_AS_MINE) }
            }
        },
        dismissButton = { TextButton(onClick = { model.server.pendingShare.value = null }) { Text(ServerStrings.IMPORT_CANCEL) } },
    )
}

/**
 * The verifier's way to the holder's server: scans the QR Code the holder shows with [HolderServerButton] and uses
 * that server for this check. The line under it names the server in use.
 */
@Composable
internal fun PeerServerButton(model: WalletModel) {
    val peer by model.server.peer.collectAsState()
    val scope = rememberCoroutineScope()
    val readQr = LocalQrReader.current
    peer?.let { Text(ServerStrings.peerInUse(it.host), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
    OutlinedButton(onClick = {
        scope.launch {
            val text = readQr() ?: return@launch
            if (ServerShare.looksLike(text)) model.server.scanPeer(text) else model.message.value = model.text(Res.string.server_not_share_qr)
        }
    }) { Text(ServerStrings.USE_PEER) }
    Text(ServerStrings.USE_PEER_NOTE, style = MaterialTheme.typography.bodySmall)
}

/** The holder's button that shows this wallet's server to the verifier, for a check the verifier cannot route alone. */
@Composable
internal fun HolderServerButton(model: WalletModel) {
    var showing by remember { mutableStateOf(false) }
    if (model.server.base() == null) return
    OutlinedButton(onClick = { showing = true }) { Text(ServerStrings.SHOW_MY_SERVER) }
    if (showing) ServerShareDialog(model, peerOnly = true) { showing = false }
}
