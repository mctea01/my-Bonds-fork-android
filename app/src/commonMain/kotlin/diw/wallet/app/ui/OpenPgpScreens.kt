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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import diw.wallet.app.NfcReaderList
import diw.wallet.app.NfcReaderOption
import diw.wallet.app.OpenPgpKeyEntry
import diw.wallet.app.Screen
import diw.wallet.app.SignerChoice
import diw.wallet.app.StoredFile
import diw.wallet.app.WalletModel
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.card.OpenPgpCard
import diw.wallet.core.document.card.OpenPgpCardInfo
import diw.wallet.core.document.card.OpenPgpKeySlot
import diw.wallet.core.document.pgp.OpenPgpKeyInfo
import diw.wallet.core.document.pgp.OpenPgpKind
import diw.wallet.core.document.pgp.OpenPgpReport
import diw.wallet.core.document.pgp.OpenPgpSubkeyInfo
import diw.wallet.core.document.pgp.OpenPgpTapSigner
import diw.wallet.core.document.pgp.OpenPgpTrust
import kotlinx.coroutines.launch

/** A fingerprint in groups of four, as GnuPG prints it. */
internal fun groupedFingerprint(hex: String): String = hex.chunked(4).joinToString(" ")

/**
 * The readers an OpenPGP card or security key can be used on (phone NFC, USB CCID readers and keys, PC/SC), with a
 * refresh for a key plugged in after the screen opened, and the card PIN (PW1) when [withPin].
 */
@Composable
internal fun OpenPgpReaderPin(model: WalletModel, withPin: Boolean = true, onChange: (NfcReaderOption?, String) -> Unit) {
    var readers by remember { mutableStateOf<NfcReaderList?>(null) }
    var reader by remember { mutableStateOf<NfcReaderOption?>(null) }
    var pin by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    suspend fun find() {
        readers = runCatching { model.platform.nfcReaders() }.getOrElse { NfcReaderList(emptyList(), model.describe(it)) }
        // A plugged-in key is preferred: it needs no tap.
        reader = readers?.readers?.let { list -> list.firstOrNull { it.external } ?: list.firstOrNull() }
        onChange(reader, pin)
    }
    LaunchedEffect(Unit) { find() }
    val list = readers
    when {
        list == null -> CircularProgressIndicator(Modifier.size(20.dp))
        else -> {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                list.readers.forEach { r -> FilterChip(selected = r === reader, onClick = { reader = r; onChange(r, pin) }, label = { Text(r.name) }) }
                TextButton(onClick = { scope.launch { find() } }) { Text(stringResource(Res.string.action_find_again)) }
            }
            list.problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = if (list.readers.isEmpty()) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
    if (withPin) {
        OutlinedTextField(
            value = pin,
            onValueChange = { v -> pin = v.filter { it.code in 0x20..0x7E }.take(OpenPgpCard.PIN_MAX); onChange(reader, pin) },
            label = { Text(stringResource(Res.string.pgp_pin, OpenPgpCard.PIN_MIN, OpenPgpCard.PIN_MAX)) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

/**
 * The OpenPGP card as a signer: reader and PIN, and an optional read of the card (no PIN) that shows its keys. For
 * the X.509 formats ([x509]) the signature key must be RSA or EC P-256.
 */
@Composable
internal fun OpenPgpKeyPicker(model: WalletModel, x509: Boolean, onChange: (SignerChoice?) -> Unit) {
    var reader by remember { mutableStateOf<NfcReaderOption?>(null) }
    val card by model.openPgp.card.collectAsState()
    val busy by model.openPgp.busy.collectAsState()
    val error by model.openPgp.error.collectAsState()
    OpenPgpReaderPin(model) { r, pin ->
        reader = r
        onChange(r?.takeIf { pin.length in OpenPgpCard.PIN_MIN..OpenPgpCard.PIN_MAX }?.let { SignerChoice.OpenPgp(it, pin) })
    }
    reader?.let { r -> OutlinedButton(onClick = { model.openPgp.readCard(r) }, enabled = busy == null) { Text(if (card == null) stringResource(Res.string.pgp_read_card) else stringResource(Res.string.pgp_read_again)) } }
    BusyLine(busy, error)
    card?.let { info ->
        OpenPgpCardView(model, info)
        val sig = info.key(OpenPgpKeySlot.SIGNATURE)
        when {
            sig == null -> Text(stringResource(Res.string.pgp_no_sig_key), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            x509 && !OpenPgpTapSigner.x509Capable(sig) -> Text(
                stringResource(Res.string.pgp_sig_key_only_pgp, sig.algorithm),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
            )
            !x509 && sig.packet == null -> Text(
                stringResource(Res.string.pgp_fingerprint_mismatch),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
            )
        }
    }
    Text(
        (if (x509) stringResource(Res.string.pgp_x509_text)
        else stringResource(Res.string.pgp_detached_text)) +
            stringResource(Res.string.pgp_support_text),
        style = MaterialTheme.typography.bodySmall,
    )
}

/** What a card holds: its identity, PIN counters and the three keys with their fingerprints. */
@Composable
internal fun OpenPgpCardView(model: WalletModel, info: OpenPgpCardInfo) {
    val keys by model.openPgp.keys.collectAsState()
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(info.label, style = MaterialTheme.typography.titleSmall)
            Text(listOfNotNull(stringResource(Res.string.pgp_spec, info.version), info.cardholder?.let { stringResource(Res.string.pgp_holder, it) }, info.signatureCount?.let { stringResource(Res.string.pgp_sig_count, it) }).joinToString("・"),
                style = MaterialTheme.typography.bodySmall)
            info.pinStatus?.let { p ->
                Text(stringResource(Res.string.pgp_tries, p.pw1Tries, p.resetTries, p.adminTries) + if (info.kdf != null) stringResource(Res.string.pgp_kdf) else "",
                    style = MaterialTheme.typography.bodySmall, color = if (p.pw1Tries == 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            }
            info.url?.let { Text(stringResource(Res.string.pgp_url, it), style = MaterialTheme.typography.bodySmall) }
            info.keys.forEach { k ->
                HorizontalDivider()
                Text(k.slot.title + if (k.present) stringResource(Res.string.pgp_key_algorithm, k.algorithm) else stringResource(Res.string.pgp_no_key), style = MaterialTheme.typography.bodyMedium)
                if (k.present) {
                    k.fingerprintText?.let { SelectionContainer { Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) } }
                    val fpr = k.fingerprint?.let { f -> f.joinToString("") { b -> (b.toInt() and 0xFF).toString(16).padStart(2, '0') }.uppercase() }
                    val listed = fpr?.let { f -> keys.firstOrNull { it.info.has(f) } }
                    Text(buildList {
                        if (k.created > 0) add(stringResource(Res.string.pgp_created) + localTime(k.created).substringBefore(' '))
                        add(if (k.packet != null) stringResource(Res.string.pgp_rebuilt) else stringResource(Res.string.pgp_mismatch))
                        if (k.certificate != null) add(stringResource(Res.string.pgp_has_cert))
                        add(listed?.let { stringResource(Res.string.pgp_list) + it.trust.title } ?: stringResource(Res.string.pgp_not_listed))
                    }.joinToString("・"), style = MaterialTheme.typography.bodySmall)
                }
            }
            TextButton(onClick = { model.openPgp.addReadCard() }) { Text(stringResource(Res.string.pgp_add_own)) }
        }
    }
}

// ---------------------------------------------------------------- key list

/**
 * The OpenPGP public keys and the user's trust in each. OpenPGP has no certification authorities: the user decides,
 * by comparing fingerprints with the owner, by reading their own card, or by trusting an introducer's certifications.
 */
@Composable
fun OpenPgpKeysScreen(model: WalletModel, screen: Screen.OpenPgpKeys) {
    val keys by model.openPgp.keys.collectAsState()
    val busy by model.openPgp.busy.collectAsState()
    val error by model.openPgp.error.collectAsState()
    val found by model.openPgp.found.collectAsState()
    val card by model.openPgp.card.collectAsState()
    var query by remember(screen.query) { mutableStateOf(screen.query.orEmpty()) }
    var reader by remember { mutableStateOf<NfcReaderOption?>(null) }
    var confirmFound by remember { mutableStateOf(false) }
    LaunchedEffect(screen.query) { screen.query?.let { model.openPgp.lookup(it) } }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.pgp_trust_intro), style = MaterialTheme.typography.bodyMedium)
        OpenPgpTrust.entries.forEach { t -> Text(stringResource(Res.string.pgp_tier_line, t.title, t.detail), style = MaterialTheme.typography.bodySmall) }
        Text(stringResource(Res.string.pgp_introducer_text), style = MaterialTheme.typography.bodySmall)
        BusyLine(busy, error)

        SectionTitle(stringResource(Res.string.pgp_add_key))
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.openPgp.pickAndImport() }, enabled = busy == null) { Text(stringResource(Res.string.pgp_import_file)) }
        }
        Text(stringResource(Res.string.pgp_import_text), style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(value = query, onValueChange = { query = it.take(200) }, label = { Text(stringResource(Res.string.pgp_lookup_label)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedButton(onClick = { model.openPgp.lookup(query) }, enabled = busy == null && query.isNotBlank()) { Text(stringResource(Res.string.action_query)) }
        Text(stringResource(Res.string.pgp_lookup_text),
            style = MaterialTheme.typography.bodySmall)
        found?.let { fd ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(stringResource(Res.string.pgp_lookup_result, fd.query, fd.source), style = MaterialTheme.typography.titleSmall)
                    if (fd.keys.isEmpty()) Text(stringResource(Res.string.pgp_lookup_none), style = MaterialTheme.typography.bodySmall)
                    fd.keys.forEach { (info, _) -> KeySummary(info) }
                    Row {
                        if (fd.keys.isNotEmpty()) TextButton(onClick = { confirmFound = true }) { Text(stringResource(Res.string.pgp_add_to_list)) }
                        TextButton(onClick = { model.openPgp.dismissFound() }) { Text(stringResource(Res.string.action_close)) }
                    }
                }
            }
            if (confirmFound) RiskConfirmDialog(
                title = stringResource(Res.string.pgp_add_found),
                lines = listOf(
                    stringResource(Res.string.pgp_found_from, fd.source) + if (fd.source.startsWith("Web Key Directory")) stringResource(Res.string.pgp_found_wkd) else stringResource(Res.string.pgp_found_keyserver),
                    stringResource(Res.string.pgp_found_unchecked),
                    stringResource(Res.string.pgp_found_verify),
                ),
                confirm = stringResource(Res.string.action_add),
                onConfirm = { confirmFound = false; model.openPgp.acceptFound() },
                onDismiss = { confirmFound = false },
            )
        }

        SectionTitle(stringResource(Res.string.pgp_own_card))
        OpenPgpReaderPin(model, withPin = false) { r, _ -> reader = r }
        reader?.let { r -> OutlinedButton(onClick = { model.openPgp.readCard(r) }, enabled = busy == null) { Text(stringResource(Res.string.pgp_read_card_short)) } }
        card?.let { OpenPgpCardView(model, it) }
        Text(stringResource(Res.string.pgp_own_card_text),
            style = MaterialTheme.typography.bodySmall)

        HorizontalDivider()
        SectionTitle(stringResource(Res.string.pgp_list_count, keys.size))
        if (keys.isEmpty()) Text(stringResource(Res.string.pgp_list_empty), style = MaterialTheme.typography.bodySmall)
        keys.forEach { e -> KeyEntryCard(model, e, busy == null) }
    }
}

@Composable
private fun KeySummary(info: OpenPgpKeyInfo) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(info.name, style = MaterialTheme.typography.bodyMedium)
        info.userIds.drop(1).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        SelectionContainer { Text(groupedFingerprint(info.fingerprint), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
        (listOf(info.primary) + info.subkeys).forEachIndexed { i, k -> Text((if (i == 0) stringResource(Res.string.pgp_primary) else stringResource(Res.string.pgp_subkey)) + stringResource(Res.string.sep_space) + subkeyLine(k), style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
private fun subkeyLine(k: OpenPgpSubkeyInfo): String = buildList {
    add(k.algorithm)
    val uses = listOfNotNull(stringResource(Res.string.pgp_use_sign).takeIf { k.canSign }, stringResource(Res.string.pgp_use_encrypt).takeIf { k.canEncrypt })
    if (uses.isNotEmpty()) add(uses.joinToString(stringResource(Res.string.sep_list)))
    if (k.created > 0) add(stringResource(Res.string.pgp_created_short) + localTime(k.created).substringBefore(' '))
    k.expires?.let { add(stringResource(Res.string.pgp_expires) + localTime(it).substringBefore(' ')) }
    if (k.revoked) add(stringResource(Res.string.pgp_revoked))
}.joinToString("・")

@Composable
private fun KeyEntryCard(model: WalletModel, e: OpenPgpKeyEntry, enabled: Boolean) {
    var confirmVerify by remember(e.fingerprint) { mutableStateOf(false) }
    var confirmRemove by remember(e.fingerprint) { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            KeySummary(e.info)
            if (e.info.revoked) Text(stringResource(Res.string.pgp_primary_revoked), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            Text(stringResource(Res.string.pgp_source) + e.source + stringResource(Res.string.pgp_added_at) + localTime(e.addedAt) + if (e.cardOnly) stringResource(Res.string.pgp_card_only) else "", style = MaterialTheme.typography.bodySmall)
            Text(stringResource(Res.string.pgp_trust) + e.trust.title + stringResource(Res.string.paren_open) + e.trust.detail + stringResource(Res.string.paren_close), style = MaterialTheme.typography.bodySmall)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                if (e.trust == OpenPgpTrust.OWN_CARD) FilterChip(selected = true, onClick = {}, label = { Text(OpenPgpTrust.OWN_CARD.title) })
                listOf(OpenPgpTrust.VERIFIED, OpenPgpTrust.UNVERIFIED, OpenPgpTrust.DISTRUSTED).forEach { t ->
                    FilterChip(selected = e.trust == t, enabled = enabled, onClick = {
                        if (t == OpenPgpTrust.VERIFIED && e.trust != t) confirmVerify = true else if (e.trust != t) model.openPgp.setTrust(e.fingerprint, t)
                    }, label = { Text(t.title) })
                }
            }
            val canIntroduce = e.trust == OpenPgpTrust.OWN_CARD || e.trust == OpenPgpTrust.VERIFIED
            Row(Modifier.clickable(enabled = canIntroduce && enabled) { model.openPgp.setIntroducer(e.fingerprint, !e.introducer) }, verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = e.introducer && canIntroduce, enabled = canIntroduce && enabled, onCheckedChange = { model.openPgp.setIntroducer(e.fingerprint, it) })
                Text(if (canIntroduce) stringResource(Res.string.pgp_set_introducer) else stringResource(Res.string.pgp_set_introducer_check), style = MaterialTheme.typography.bodySmall)
            }
            Row(Modifier.horizontalScroll(rememberScrollState())) {
                TextButton(onClick = { model.openPgp.export(e.fingerprint, share = false) }) { Text(stringResource(Res.string.action_export)) }
                if (model.platform.canShareFiles) TextButton(onClick = { model.openPgp.export(e.fingerprint, share = true) }) { Text(stringResource(Res.string.action_share)) }
                TextButton(onClick = { confirmRemove = true }, enabled = enabled) { Text(stringResource(Res.string.action_remove), color = MaterialTheme.colorScheme.error) }
            }
        }
    }
    if (confirmVerify) AlertDialog(
        onDismissRequest = { confirmVerify = false },
        title = { Text(stringResource(Res.string.pgp_checked_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(Res.string.pgp_checked_text))
                SelectionContainer { Text(groupedFingerprint(e.fingerprint), fontFamily = FontFamily.Monospace) }
                Text(stringResource(Res.string.pgp_checked_warning), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = { confirmVerify = false; model.openPgp.setTrust(e.fingerprint, OpenPgpTrust.VERIFIED) }) { Text(stringResource(Res.string.pgp_checked)) } },
        dismissButton = { TextButton(onClick = { confirmVerify = false }) { Text(stringResource(Res.string.action_cancel)) } },
    )
    if (confirmRemove) AlertDialog(
        onDismissRequest = { confirmRemove = false },
        title = { Text(stringResource(Res.string.pgp_remove_title)) },
        text = { Text(stringResource(Res.string.pgp_remove_text)) },
        confirmButton = { TextButton(onClick = { confirmRemove = false; model.openPgp.remove(e.fingerprint) }) { Text(stringResource(Res.string.action_remove), color = MaterialTheme.colorScheme.error) } },
        dismissButton = { TextButton(onClick = { confirmRemove = false }) { Text(stringResource(Res.string.action_cancel)) } },
    )
}

// ---------------------------------------------------------------- files

/** The OpenPGP part of a file: keys it holds, recipients and decryption, the content of a signed message, missing signers. */
@Composable
internal fun OpenPgpFileSection(model: WalletModel, f: StoredFile, report: DocumentReport, pgp: OpenPgpReport, busy: String?) {
    val keys by model.openPgp.keys.collectAsState()
    var reader by remember(f.id) { mutableStateOf<NfcReaderOption?>(null) }
    var pin by remember(f.id) { mutableStateOf("") }
    SectionTitle(pgp.kind.title)
    if (pgp.keys.isNotEmpty()) {
        pgp.keys.forEach { KeySummary(it) }
        if (pgp.kind == OpenPgpKind.SECRET_KEYS) Text(stringResource(Res.string.pgp_private_in_file),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        val missing = pgp.keys.count { k -> keys.none { it.fingerprint == k.fingerprint } }
        if (missing > 0) OutlinedButton(onClick = { model.openPgp.importFromFile(f) }) { Text(stringResource(Res.string.pgp_add_missing, missing)) }
        else Text(stringResource(Res.string.pgp_all_listed), style = MaterialTheme.typography.bodySmall)
    }
    if (pgp.kind == OpenPgpKind.ENCRYPTED) {
        pgp.encryption?.let { LabelValue(stringResource(Res.string.pgp_encryption), it, small = true) }
        pgp.recipients.forEach { r ->
            val hidden = r.key.all { it == '0' }
            val who = if (hidden || r.key == stringResource(Res.string.pgp_password)) null else keys.firstOrNull { it.info.has(r.key) }
            LabelValue(stringResource(Res.string.pgp_recipients), when {
                r.key == stringResource(Res.string.pgp_password) -> stringResource(Res.string.pgp_password_unsupported)
                hidden -> stringResource(Res.string.pgp_hidden_recipient, r.algorithm)
                else -> (who?.info?.name ?: stringResource(Res.string.pgp_not_listed)) + stringResource(Res.string.sep_space) + r.key + stringResource(Res.string.parenthesized, r.algorithm)
            }, small = true)
        }
        Text(stringResource(Res.string.pgp_decrypt_text), style = MaterialTheme.typography.bodySmall)
        OpenPgpReaderPin(model) { r, p -> reader = r; pin = p }
        Button(onClick = { reader?.let { model.files.decryptOpenPgp(f, it, pin) } },
            enabled = busy == null && reader != null && pin.length in OpenPgpCard.PIN_MIN..OpenPgpCard.PIN_MAX) { Text(stringResource(Res.string.pgp_decrypt)) }
    }
    if (pgp.kind == OpenPgpKind.SIGNED_MESSAGE || pgp.kind == OpenPgpKind.LITERAL) {
        pgp.literalName?.let { LabelValue(stringResource(Res.string.pgp_content_name), it, small = true) }
        pgp.literalSize?.let { LabelValue(stringResource(Res.string.pgp_content_size), sizeText(it), small = true) }
        OutlinedButton(onClick = { model.files.unwrapOpenPgp(f) }, enabled = busy == null) { Text(stringResource(Res.string.pgp_extract)) }
    }
    pgp.signers.filter { s -> keys.none { it.info.has(s) } }.distinct().forEach { s ->
        ActionRow(WalletIcons.Search, stringResource(Res.string.pgp_lookup_signer), stringResource(Res.string.pgp_signer_unlisted, s)) {
            model.screen.value = Screen.OpenPgpKeys(s, Screen.FileDetail(f.id))
        }
    }
    if (report.signatures.any { it.signer != null }) {
        Text(stringResource(Res.string.pgp_trust_from_list), style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = { model.screen.value = Screen.OpenPgpKeys(null, Screen.FileDetail(f.id)) }) { Text(stringResource(Res.string.pgp_manage)) }
    }
}

/** Picks the recipients of an OpenPGP encryption of [f] from the key list; the holder's own cards are chosen first. */
@Composable
internal fun OpenPgpEncryptDialog(model: WalletModel, f: StoredFile, onDismiss: () -> Unit) {
    val keys by model.openPgp.keys.collectAsState()
    val usable = keys.filter { it.info.canEncrypt && !it.info.revoked && it.trust != OpenPgpTrust.DISTRUSTED }
    var chosen by remember(f.id) { mutableStateOf(usable.filter { it.trust == OpenPgpTrust.OWN_CARD }.map { it.fingerprint }.toSet()) }
    var armor by remember(f.id) { mutableStateOf(true) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(Res.string.pgp_encrypt_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(stringResource(Res.string.pgp_encrypt_text), style = MaterialTheme.typography.bodySmall)
                if (usable.isEmpty()) Text(stringResource(Res.string.pgp_encrypt_none), style = MaterialTheme.typography.bodySmall)
                usable.forEach { e ->
                    Row(Modifier.fillMaxWidth().clickable { chosen = if (e.fingerprint in chosen) chosen - e.fingerprint else chosen + e.fingerprint },
                        verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = e.fingerprint in chosen, onCheckedChange = { chosen = if (it) chosen + e.fingerprint else chosen - e.fingerprint })
                        Column {
                            Text(e.info.name, style = MaterialTheme.typography.bodyMedium)
                            Text(e.trust.title + "・" + e.fingerprint.takeLast(16), style = MaterialTheme.typography.bodySmall,
                                color = if (e.trust == OpenPgpTrust.UNVERIFIED) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
                if (usable.any { it.fingerprint in chosen && it.trust == OpenPgpTrust.UNVERIFIED }) {
                    Text(stringResource(Res.string.pgp_encrypt_unchecked), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Row(Modifier.clickable { armor = !armor }, verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = armor, onCheckedChange = { armor = it })
                    Text(stringResource(Res.string.pgp_armor), style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onDismiss(); model.files.encryptOpenPgp(f, chosen.toList(), armor) }, enabled = chosen.isNotEmpty()) { Text(stringResource(Res.string.pgp_encrypt)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(Res.string.action_cancel)) } },
    )
}
