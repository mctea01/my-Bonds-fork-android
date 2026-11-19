package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import diw.wallet.app.Screen
import diw.wallet.app.SettingsSection
import diw.wallet.app.SignerChoice
import diw.wallet.app.WalletModel
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.verifier.declaration.x509HashClientId
import kotlinx.coroutines.launch
import kotlinx.io.bytestring.ByteString
import org.jetbrains.compose.resources.stringResource
import org.multipaz.crypto.X509Cert
import kotlin.time.Clock

/**
 * The settings page for certificates, keys and trust: the user's own keys (any signing source, OpenPGP cards, verifier
 * identities), then X.509 trust and OpenPGP trust. Every X.509 and OpenPGP screen is reached from here.
 */
@Composable
internal fun KeysAndTrustPage(model: WalletModel, x509Trust: @Composable () -> Unit) {
    val pgp by model.openPgp.keys.collectAsState()
    val profiles by model.verifier.profiles.collectAsState()
    SectionTitle(stringResource(Res.string.keys_mine))
    ActionRow(WalletIcons.Card, stringResource(Res.string.screen_key_viewer), stringResource(Res.string.keys_viewer_text)) {
        model.screen.value = Screen.KeyViewer
    }
    ActionRow(WalletIcons.Shield, stringResource(Res.string.screen_openpgp_keys), stringResource(Res.string.keys_pgp_text, pgp.size)) {
        model.screen.value = Screen.OpenPgpKeys(null, Screen.SettingsPage(SettingsSection.TRUST))
    }
    ActionRow(WalletIcons.Person, stringResource(Res.string.screen_verifier_profiles), stringResource(Res.string.keys_profiles_text, profiles.size)) {
        model.verifier.openProfiles()
    }
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.keys_x509_trust))
    x509Trust()
    HorizontalDivider()
    SectionTitle(stringResource(Res.string.keys_pgp_trust))
    Text(stringResource(Res.string.keys_pgp_trust_text), style = MaterialTheme.typography.bodySmall)
    OutlinedButton(onClick = { model.screen.value = Screen.OpenPgpKeys(null, Screen.SettingsPage(SettingsSection.TRUST)) }) {
        Text(stringResource(Res.string.pgp_manage))
    }
}

/** What a read signing key showed: its certificate chain, the key type and the trust of the chain for documents. */
private class ReadKey(val signer: DocumentSigner, val chain: List<X509Cert>, val trust: TrustDecision?)

/**
 * Reads any signing source the wallet supports and shows its certificate: subject, issuer, validity, key type, the
 * trust of its chain for document signatures, the SHA-256 fingerprint and the x509_hash client_id a verifier
 * identity with this key would have. Nothing is signed and the PIN is used only for this read.
 */
@Composable
fun KeyViewerScreen(model: WalletModel) {
    val busy by model.files.busy.collectAsState()
    var choice by remember { mutableStateOf<SignerChoice?>(null) }
    var read by remember { mutableStateOf<ReadKey?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    var reading by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.keys_viewer_intro), style = MaterialTheme.typography.bodyMedium)
        SignerPicker(model) { choice = it; read = null; problem = null }
        CscPromptPanel(model)
        Button(
            onClick = {
                val c = choice ?: return@Button
                reading = true
                problem = null
                scope.launch {
                    runCatching {
                        val signer = model.files.signer(c)
                        val chain = signer.certificateChain.map { X509Cert(ByteString(it)) }
                        val trust = runCatching { model.files.trustSource.decide(TrustRole.DOCUMENT, chain, Clock.System.now()) }.getOrNull()
                        ReadKey(signer, chain, trust)
                    }.onSuccess { read = it }.onFailure { problem = model.describe(it) }
                    model.files.busy.value = null
                    reading = false
                }
            },
            enabled = choice != null && !reading,
        ) { Text(if (reading) stringResource(Res.string.state_reading) else stringResource(Res.string.keys_read)) }
        if (reading) busy?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        read?.let { r ->
            val leaf = r.signer.certificateChain.first()
            val summary = runCatching { DocumentSigning.certificateSummary(leaf) }.getOrNull()
            val cert = r.chain.first()
            HorizontalDivider()
            r.trust?.let { TrustCard(stringResource(Res.string.keys_trust_title), summary?.first ?: cert.subject.name, it) }
            LabelValue(stringResource(Res.string.keys_subject), cert.subject.name, small = true)
            LabelValue(stringResource(Res.string.keys_issuer), cert.issuer.name, small = true)
            LabelValue(stringResource(Res.string.keys_validity), localTime(cert.validityNotBefore.epochSeconds) + " - " + localTime(cert.validityNotAfter.epochSeconds), small = true)
            LabelValue(stringResource(Res.string.keys_key_type), keyTypeName(r.signer.keyType) + stringResource(Res.string.sep_comma) + r.signer.source.title, small = true)
            if (r.signer.keyType == SignerKeyType.SM2) Text(stringResource(Res.string.keys_sm2_note), style = MaterialTheme.typography.bodySmall)
            if (r.signer.keyType == SignerKeyType.RSA) Text(stringResource(Res.string.keys_rsa_note), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(Res.string.keys_fingerprint), style = MaterialTheme.typography.titleSmall)
            SelectionContainer {
                Text(DocCryptoUtil.hex(PlatformCrypto.sha256(leaf)).uppercase().chunked(2).joinToString(":"),
                    style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            }
            if (r.signer.keyType != SignerKeyType.SM2) {
                val clientId = x509HashClientId(leaf)
                Text(stringResource(Res.string.keys_client_id), style = MaterialTheme.typography.titleSmall)
                SelectionContainer { Text(clientId, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
                OutlinedButton(onClick = { clipboard.setText(AnnotatedString(clientId)) }) { Text(stringResource(Res.string.vp_copy_client_id)) }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { model.screen.value = Screen.Certificate(r.chain, 0, Screen.KeyViewer) }) {
                    Text(stringResource(Res.string.keys_show_chain, r.chain.size))
                }
            }
        }
    }
}

private fun keyTypeName(t: SignerKeyType): String = when (t) {
    SignerKeyType.RSA -> "RSA"
    SignerKeyType.EC_P256 -> "EC P-256"
    SignerKeyType.SM2 -> "SM2"
}
