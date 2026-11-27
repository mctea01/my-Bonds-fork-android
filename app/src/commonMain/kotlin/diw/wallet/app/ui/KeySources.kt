package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import diw.wallet.app.CscPrompt
import diw.wallet.core.i18n.CoreText
import diw.wallet.core.zk.ZkPdfStatement
import diw.wallet.core.document.sign.CscEnvironment
import diw.wallet.core.document.sign.CscServices
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.produceState
import diw.wallet.app.FilesModel
import diw.wallet.app.ZkChoiceContext
import diw.wallet.app.ZkChoiceKind
import diw.wallet.app.ZkProofKind
import diw.wallet.core.zk.ZkPdfAssets
import androidx.compose.runtime.Composable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import diw.wallet.app.FilePreview
import diw.wallet.app.VisibleSignature
import diw.wallet.app.OfdSealChoice
import diw.wallet.app.SealPicture
import diw.wallet.core.document.ofd.OfdShading
import diw.wallet.core.document.c2pa.C2paInfo
import diw.wallet.core.document.official.OfficialDocument
import diw.wallet.core.document.official.OfficialEntry
import diw.wallet.core.document.official.OfficialItem
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import diw.wallet.app.DocumentSources
import diw.wallet.app.FileOrigin
import diw.wallet.app.HomeTab
import diw.wallet.app.NfcReaderList
import diw.wallet.app.NfcReaderOption
import diw.wallet.app.PickedFile
import diw.wallet.app.Screen
import diw.wallet.app.SignForm
import diw.wallet.core.document.official.ApprovalPoint
import diw.wallet.core.document.pdf.PdfSignatureAppearance
import diw.wallet.core.document.sign.SignatureLevel
import diw.wallet.app.SignerChoice
import diw.wallet.app.ExternalKeyOption
import diw.wallet.app.MobileMoicaSp
import diw.wallet.app.legal.LegalStrings
import diw.wallet.core.document.sign.MobileMoicaEnvironment
import diw.wallet.core.document.sign.MobileMoicaMode
import diw.wallet.app.StoredFile
import diw.wallet.app.WalletModel
import diw.wallet.app.CredentialDetails
import diw.wallet.core.document.official.OfficialBundles
import diw.wallet.core.profile.bonds.HouseholdTranscript
import diw.wallet.core.profile.bonds.MoicaVerification
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.profile.bonds.MyDataProfile
import diw.wallet.core.document.Check
import diw.wallet.core.document.CertInfo
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.LaterChanges
import diw.wallet.core.document.SignatureInfo
import diw.wallet.core.document.SignatureFormat
import diw.wallet.core.document.pgp.OpenPgpKind
import diw.wallet.core.document.SignaturePlacementInfo
import diw.wallet.core.document.TimestampInfo
import diw.wallet.core.document.card.GpkiCard
import diw.wallet.core.document.card.PivCard
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.derived.DerivedClaim
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.EvidenceResult
import androidx.compose.material3.HorizontalDivider
import kotlinx.datetime.LocalDate
import diw.wallet.core.document.derived.DocumentFields
import diw.wallet.core.document.derived.EntryExitCertificate
import diw.wallet.core.document.derived.MainlandEntryExitRecord
import diw.wallet.core.document.derived.MainlandPermitLink
import diw.wallet.core.document.derived.ChinaInvoice
import diw.wallet.core.document.derived.StudentStatusProof
import diw.wallet.core.document.sign.TsaServices
import kotlinx.coroutines.launch
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import diw.wallet.core.document.OpenCertInfo
import diw.wallet.core.document.opencerts.OaMethod
import diw.wallet.core.document.opencerts.OpenCertOffline
import diw.wallet.core.document.opencerts.OpenCertView
import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64
import kotlin.time.Instant

/*
 * Where a signing key comes from: the citizen certificate and other cards, PIV, OpenPGP cards, PKCS#11 tokens, the
 * system store, PKCS#12 files, the wallet's own key, the mobile citizen certificate and remote (CSC) services. One
 * picker serves document signing, the verifier's X.509 identity and the certificate viewer.
 */

internal enum class SignerKind(val title: org.jetbrains.compose.resources.StringResource) {
    HARDWARE(Res.string.signer_hardware), MOBILE(Res.string.signer_mobile), CSC(Res.string.signer_csc), SYSTEM(Res.string.signer_system),
    PKCS12(Res.string.signer_pkcs12), WALLET(Res.string.signer_wallet),
}

/**
 * The physical cards and hardware tokens grouped under [SignerKind.HARDWARE]: a citizen certificate card, a PIV card,
 * an OpenPGP card (or a YubiKey's OpenPGP applet), or a PKCS#11 token.
 */
internal enum class HardwareKind(val title: org.jetbrains.compose.resources.StringResource) {
    SMART_CARD(Res.string.hardware_moica), PIV(Res.string.hardware_piv), OPENPGP(Res.string.hardware_openpgp), PKCS11(Res.string.hardware_pkcs11),
}

/** Picks a reader for the citizen certificate card and takes its PIN; [onChange] gets the choice or null. */
@Composable
internal fun CardPicker(model: WalletModel, onChange: (SignerChoice.Card?) -> Unit) {
    var readers by remember { mutableStateOf<NfcReaderList?>(null) }
    var reader by remember { mutableStateOf<NfcReaderOption?>(null) }
    var pin by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    LaunchedEffect(Unit) {
        readers = runCatching { model.platform.nfcReaders() }.getOrElse { NfcReaderList(emptyList(), model.describe(it)) }
        reader = readers?.readers?.firstOrNull()
    }
    fun update() = onChange(reader?.takeIf { pin.length in GpkiCard.PIN_MIN..GpkiCard.PIN_MAX }?.let { SignerChoice.Card(it, pin) })
    val list = readers
    when {
        list == null -> CircularProgressIndicator(Modifier.size(20.dp))
        list.readers.isEmpty() -> {
            Text(list.problem ?: stringResource(Res.string.files_no_reader), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            OutlinedButton(onClick = { scope.launch { readers = runCatching { model.platform.nfcReaders() }.getOrNull(); reader = readers?.readers?.firstOrNull(); update() } }) { Text(stringResource(Res.string.action_find_again)) }
        }
        else -> WrapRow() {
            list.readers.forEach { r -> FilterChip(selected = r === reader, onClick = { reader = r; update() }, label = { Text(r.name) }) }
        }
    }
    OutlinedTextField(
        value = pin,
        onValueChange = { v -> pin = v.filter { it.isDigit() }.take(GpkiCard.PIN_MAX); update() },
        label = { Text(stringResource(Res.string.files_card_pin, GpkiCard.PIN_MIN, GpkiCard.PIN_MAX)) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth(),
    )
    Text(stringResource(Res.string.files_card_pin_text),
        style = MaterialTheme.typography.bodySmall)
}

/**
 * Picks a PIV card (NIST SP 800-73-4: YubiKey, PIVKey, US PIV/CAC and the like) on a reader, takes its PIN, and
 * optionally reads the card once to list every certificate on it so the user can choose which slot signs instead of
 * the wallet choosing the first usable one. Slots are not restricted: all four primary slots and the twenty retired
 * key-management slots are listed when they hold a usable certificate.
 */
@Composable
private fun PivKeyPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    var readers by remember { mutableStateOf<NfcReaderList?>(null) }
    var reader by remember { mutableStateOf<NfcReaderOption?>(null) }
    var pin by remember { mutableStateOf("") }
    var slot by remember { mutableStateOf<Int?>(null) }
    var certs by remember { mutableStateOf<List<PivCard.KeyInfo>?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(Unit) {
        readers = runCatching { model.platform.nfcReaders() }.getOrElse { NfcReaderList(emptyList(), model.describe(it)) }
        reader = readers?.readers?.firstOrNull()
    }
    fun update() = onChange(reader?.takeIf { pin.length in PivCard.PIN_MIN..PivCard.PIN_MAX }?.let { SignerChoice.Piv(it, pin, slot) })
    val list = readers
    when {
        list == null -> CircularProgressIndicator(Modifier.size(20.dp))
        list.readers.isEmpty() -> {
            Text(list.problem ?: stringResource(Res.string.files_no_reader), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            OutlinedButton(onClick = { scope.launch { readers = runCatching { model.platform.nfcReaders() }.getOrNull(); reader = readers?.readers?.firstOrNull(); certs = null; slot = null; update() } }) { Text(stringResource(Res.string.action_find_again)) }
        }
        else -> WrapRow() {
            list.readers.forEach { r -> FilterChip(selected = r === reader, onClick = { reader = r; certs = null; slot = null; update() }, label = { Text(r.name) }) }
        }
    }
    OutlinedTextField(
        value = pin,
        onValueChange = { v -> pin = v.filter { it.code in 0x21..0x7E }.take(PivCard.PIN_MAX); update() },
        label = { Text(stringResource(Res.string.files_piv_pin, PivCard.PIN_MIN, PivCard.PIN_MAX)) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth(),
    )
    reader?.let { r ->
        OutlinedButton(onClick = {
            busy = true
            scope.launch {
                problem = null
                certs = runCatching { model.files.pivCertificates(r) }.getOrElse { problem = model.describe(it); null }
                busy = false
            }
        }, enabled = !busy) { Text(if (busy) stringResource(Res.string.state_reading) else if (certs == null) stringResource(Res.string.files_piv_read) else stringResource(Res.string.files_piv_read_again)) }
    }
    problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    val found = certs
    if (found != null) {
        if (found.isEmpty()) {
            Text(stringResource(Res.string.files_piv_none), style = MaterialTheme.typography.bodySmall)
        } else {
            Row(Modifier.fillMaxWidth().clickable { slot = null; update() }, verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(selected = slot == null, onClick = { slot = null; update() })
                Text(stringResource(Res.string.files_piv_auto), style = MaterialTheme.typography.bodyMedium)
            }
            found.forEach { k ->
                val name = runCatching { DocumentSigning.certificateSummary(k.certificate)?.first }.getOrNull()
                Row(Modifier.fillMaxWidth().clickable { slot = k.slot; update() }, verticalAlignment = Alignment.CenterVertically) {
                    androidx.compose.material3.RadioButton(selected = slot == k.slot, onClick = { slot = k.slot; update() })
                    Column {
                        Text(k.slotName, style = MaterialTheme.typography.bodyMedium)
                        Text((name?.let { "$it · " } ?: "") + (if (k.keyType == diw.wallet.core.document.sign.SignerKeyType.RSA) "RSA" else "EC P-256"),
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
    Text(stringResource(Res.string.files_piv_text),
        style = MaterialTheme.typography.bodySmall)
}

@Composable
internal fun SignerPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    var kind by remember { mutableStateOf(SignerKind.HARDWARE) }
    var hardware by remember { mutableStateOf(HardwareKind.SMART_CARD) }
    var p12 by remember { mutableStateOf<PickedFile?>(null) }
    var password by remember { mutableStateOf("") }
    var walletName by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    var other by remember { mutableStateOf<SignerChoice?>(null) }
    fun update() = onChange(
        when (kind) {
            SignerKind.PKCS12 -> p12?.takeIf { password.isNotEmpty() }?.let { SignerChoice.Pkcs12(it.bytes, password) }
            SignerKind.WALLET -> SignerChoice.Wallet(walletName)
            SignerKind.HARDWARE, SignerKind.SYSTEM, SignerKind.MOBILE, SignerKind.CSC -> other
        }
    )
    WrapRow() {
        SignerKind.entries.forEach { k -> FilterChip(selected = k == kind, onClick = { kind = k; other = null; update() }, label = { Text(stringResource(k.title)) }) }
    }
    when (kind) {
        SignerKind.HARDWARE -> {
            WrapRow() {
                HardwareKind.entries.forEach { h -> FilterChip(selected = h == hardware, onClick = { hardware = h; other = null; update() }, label = { Text(stringResource(h.title)) }) }
            }
            when (hardware) {
                HardwareKind.SMART_CARD -> CardPicker(model) { other = it; update() }
                HardwareKind.PIV -> PivKeyPicker(model) { other = it; update() }
                HardwareKind.OPENPGP -> OpenPgpKeyPicker(model, x509 = true) { other = it; update() }
                HardwareKind.PKCS11 -> TokenKeyPicker(model) { other = it; update() }
            }
        }
        SignerKind.SYSTEM -> SystemKeyPicker(model) { other = it; update() }
        SignerKind.MOBILE -> if (model.legal.enabled(diw.wallet.app.legal.Integration.MOBILE_MOICA)) MobileMoicaPicker(model) { other = it; update() }
            else IntegrationOffRow(model, diw.wallet.app.legal.Integration.MOBILE_MOICA)
        SignerKind.CSC -> CscPicker(model) { other = it; update() }
        SignerKind.PKCS12 -> {
            OutlinedButton(onClick = { scope.launch { model.platform.pickFile()?.let { p12 = it; update() } } }) { Text(p12?.name ?: stringResource(Res.string.files_choose_p12)) }
            OutlinedTextField(
                value = password, onValueChange = { password = it; update() }, label = { Text(stringResource(Res.string.files_p12_password)) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
            )
            Text(stringResource(Res.string.files_p12_note), style = MaterialTheme.typography.bodySmall)
        }
        SignerKind.WALLET -> {
            OutlinedTextField(value = walletName, onValueChange = { walletName = it.take(64); update() }, label = { Text(stringResource(Res.string.files_cert_name)) }, singleLine = true,
                modifier = Modifier.fillMaxWidth())
            Text(stringResource(Res.string.files_wallet_key_text), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** A key in the operating system's store: Android shows its own picker, desktops list the store here. */
@Composable
private fun SystemKeyPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    val keys = model.platform.externalKeys
    val reason = keys.systemUnavailableReason
    if (reason != null) {
        Text(reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        return
    }
    if (keys.systemPicker) {
        LaunchedEffect(Unit) { onChange(SignerChoice.System(null)) }
        Text(stringResource(Res.string.files_android_keychain),
            style = MaterialTheme.typography.bodySmall)
        return
    }
    var list by remember { mutableStateOf<List<ExternalKeyOption>?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    var chosen by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    fun load() = scope.launch {
        problem = null
        list = runCatching { keys.systemKeys() }.getOrElse { problem = model.describe(it); emptyList() }
    }
    LaunchedEffect(Unit) { load() }
    KeyList(list, chosen, problem, stringResource(Res.string.files_system_none)) { chosen = it; onChange(SignerChoice.System(it)) }
    OutlinedButton(onClick = { load() }) { Text(stringResource(Res.string.action_reload)) }
    Text(stringResource(Res.string.files_system_text),
        style = MaterialTheme.typography.bodySmall)
}

/** A PKCS#11 module and PIN, then a key on the token. */
@Composable
private fun TokenKeyPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    val keys = model.platform.externalKeys
    keys.tokenUnavailableReason?.let {
        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        return
    }
    val found = remember { keys.tokenLibraries() }
    var library by remember { mutableStateOf(found.firstOrNull().orEmpty()) }
    var pin by remember { mutableStateOf("") }
    var list by remember { mutableStateOf<List<ExternalKeyOption>?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    var chosen by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    if (found.isNotEmpty()) {
        WrapRow() {
            found.forEach { path -> FilterChip(selected = path == library, onClick = { library = path; list = null; onChange(null) },
                label = { Text(path.substringAfterLast('/').substringAfterLast('\\')) }) }
        }
    }
    OutlinedTextField(value = library, onValueChange = { library = it.trim(); list = null; onChange(null) }, label = { Text(stringResource(Res.string.files_pkcs11_path)) },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(
        value = pin, onValueChange = { pin = it.take(32); list = null; onChange(null) }, label = { Text(stringResource(Res.string.files_pin)) }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
    )
    OutlinedButton(onClick = {
        busy = true
        scope.launch {
            problem = null
            list = runCatching { keys.tokenKeys(library, pin) }.getOrElse { problem = model.describe(it); emptyList() }
            busy = false
        }
    }, enabled = library.isNotBlank() && pin.isNotEmpty() && !busy) { Text(if (busy) stringResource(Res.string.state_reading) else stringResource(Res.string.files_pkcs11_read)) }
    if (list != null || problem != null) {
        KeyList(list, chosen, problem, stringResource(Res.string.files_pkcs11_none)) { chosen = it; onChange(SignerChoice.Token(library, pin, it)) }
    }
    Text(stringResource(Res.string.files_pkcs11_text),
        style = MaterialTheme.typography.bodySmall)
}

@Composable
private fun KeyList(list: List<ExternalKeyOption>?, chosen: String?, problem: String?, empty: String, onPick: (String) -> Unit) {
    when {
        problem != null -> Text(problem, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        list == null -> CircularProgressIndicator(Modifier.size(20.dp))
        list.isEmpty() -> Text(empty, style = MaterialTheme.typography.bodySmall)
        else -> list.forEach { k ->
            Row(Modifier.fillMaxWidth().clickable { onPick(k.id) }, verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(selected = k.id == chosen, onClick = { onPick(k.id) })
                Column {
                    Text(k.label, style = MaterialTheme.typography.bodyMedium)
                    Text(k.detail, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

/** Whose SP account of the Ministry of the Interior a mobile citizen certificate signature goes through. */
private enum class MobileMoicaSource(val title: org.jetbrains.compose.resources.StringResource) {
    SERVER(Res.string.moica_source_server),
    BUILT_IN(Res.string.moica_source_builtin),
    MANUAL(Res.string.moica_source_manual),
}

/**
 * The mobile citizen certificate through an SP account of the Ministry of the Interior: the production server's (no
 * key in the app), the account built into this build, or, with the developer setting on, one typed in here for this
 * run only (kept in memory, never stored).
 */
@Composable
internal fun MobileMoicaPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    val settings by model.settingsFlow.collectAsState()
    val manual = settings.manualMobileMoicaSp
    val builtIn = model.files.builtInMobileMoicaSp
    val configured = remember(settings.zkVerifierUrl) { model.server.base() }
    // The server is offered only after its /info says it holds an SP account; null while asking.
    val serverSp by produceState<Result<MobileMoicaEnvironment?>?>(null, configured) {
        value = configured?.let { url -> runCatching { model.server.mobileMoica(url) } } ?: Result.success(null)
    }
    val serverEnvironment = serverSp?.getOrNull()
    // The server answered: its SP account makes the statement due if no other source did (LegalModel.usable).
    LaunchedEffect(serverSp) { serverSp?.onSuccess { model.legal.noteServerMobileMoica(it != null) } }
    val server = configured?.takeIf { serverEnvironment != null }
    val serverNote = when {
        configured == null -> null
        serverSp == null -> stringResource(Res.string.moica_checking_server)
        serverSp?.exceptionOrNull() != null -> stringResource(Res.string.moica_server_unknown) + serverSp?.exceptionOrNull()?.let(model::describe)
        serverEnvironment == null -> stringResource(Res.string.moica_server_none, configured.substringAfter("://"))
        else -> null
    }
    val sources = listOfNotNull(
        MobileMoicaSource.SERVER.takeIf { server != null },
        MobileMoicaSource.BUILT_IN.takeIf { builtIn != null },
        MobileMoicaSource.MANUAL.takeIf { manual },
    )
    var source by remember(sources) { mutableStateOf(if (manual) MobileMoicaSource.MANUAL else sources.firstOrNull()) }
    val last = model.files.mobileMoicaSp
    var env by remember { mutableStateOf(last?.environment ?: MobileMoicaEnvironment.UAT) }
    var serviceId by remember { mutableStateOf(last?.serviceId.orEmpty()) }
    var aesKey by remember { mutableStateOf(last?.aesKeyBase64.orEmpty()) }
    var idNumber by remember { mutableStateOf(settings.myDataIdNumber.orEmpty()) }
    val canOpenApp = model.platform.mobileMoicaReturnUrl != null
    var mode by remember { mutableStateOf(if (canOpenApp) MobileMoicaMode.APP_TO_APP else MobileMoicaMode.PUSH) }
    fun update() {
        val id = idNumber.trim().uppercase()
        val choice = when (source) {
            MobileMoicaSource.SERVER -> server?.let { SignerChoice.MobileMoica(null, id, mode, server = it) }
            MobileMoicaSource.BUILT_IN -> builtIn?.let { SignerChoice.MobileMoica(it, id, mode) }
            MobileMoicaSource.MANUAL -> MobileMoicaSp(env, serviceId.trim(), aesKey.trim())
                .takeIf { serviceId.isNotBlank() && aesKey.isNotBlank() }?.let { SignerChoice.MobileMoica(it, id, mode) }
            null -> null
        }
        onChange(choice?.takeIf { MyDataProfile.isValidId(id) })
    }
    LaunchedEffect(source) { update() }
    serverNote?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    if (source == null) {
        if (configured != null && serverSp == null) return
        Text(LegalStrings.MOICA_SP_NOT_CONFIGURED + stringResource(Res.string.moica_server_hint),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        return
    }
    if (sources.size > 1) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            sources.forEach { o -> FilterChip(selected = o == source, onClick = { source = o }, label = { Text(stringResource(o.title)) }) }
        }
    }
    when (source) {
        MobileMoicaSource.SERVER -> Text(
            stringResource(Res.string.moica_via_server, (server?.substringAfter("://")).toString(), (serverEnvironment?.title).toString()) +
                stringResource(Res.string.moica_via_server_confirm) + (if (serverEnvironment == MobileMoicaEnvironment.PRODUCTION) stringResource(Res.string.moica_via_server_production) else stringResource(Res.string.moica_via_server_test)) +
                stringResource(Res.string.moica_via_server_verify),
            style = MaterialTheme.typography.bodySmall,
        )
        MobileMoicaSource.BUILT_IN -> builtIn?.let { Text(stringResource(Res.string.moica_builtin, it.environment.title), style = MaterialTheme.typography.bodySmall) }
        MobileMoicaSource.MANUAL -> {
            Text(stringResource(Res.string.moica_manual_text) +
                LegalStrings.MOICA_SP_PROVIDER_UNKNOWN, style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                MobileMoicaEnvironment.entries.forEach { e -> FilterChip(selected = e == env, onClick = { env = e; update() }, label = { Text(e.title) }) }
            }
            OutlinedTextField(value = serviceId, onValueChange = { serviceId = it.take(64); update() }, label = { Text(stringResource(Res.string.moica_sp_service_id)) },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(
                value = aesKey, onValueChange = { aesKey = it.take(64); update() }, label = { Text(stringResource(Res.string.moica_sp_key)) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
            )
        }
        null -> Unit
    }
    val environment = when (source) {
        MobileMoicaSource.SERVER -> serverEnvironment
        MobileMoicaSource.BUILT_IN -> builtIn?.environment
        MobileMoicaSource.MANUAL -> env
        null -> null
    }
    if (environment == MobileMoicaEnvironment.UAT) {
        Text(LegalStrings.MOICA_SP_ENV_TEST, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }
    OutlinedTextField(value = idNumber, onValueChange = { idNumber = it.take(10); update() }, label = { Text(stringResource(Res.string.national_id_number)) },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        MobileMoicaMode.entries.forEach { m ->
            FilterChip(selected = m == mode, enabled = m != MobileMoicaMode.APP_TO_APP || canOpenApp, onClick = { mode = m; update() }, label = { Text(m.title) })
        }
    }
    Text(
        stringResource(Res.string.moica_confirm_twice) +
            if (canOpenApp) "" else stringResource(Res.string.moica_desktop_push),
        style = MaterialTheme.typography.bodySmall,
    )
}

/** The remote signing services, test ones apart from production ones, and a form to add one. */
@Composable
private fun CscPicker(model: WalletModel, onChange: (SignerChoice?) -> Unit) {
    val settings by model.settingsFlow.collectAsState()
    val services = remember(settings.cscServices) { model.csc.services }
    var chosen by remember { mutableStateOf<String?>(null) }
    var adding by remember { mutableStateOf(false) }
    LaunchedEffect(services) {
        if (services.none { it.id == chosen }) {
            chosen = null
            onChange(null)
        }
    }
    CscEnvironment.entries.reversed().forEach { env ->
        Text(env.title, style = MaterialTheme.typography.titleSmall)
        val list = services.filter { it.environment == env }
        if (list.isEmpty()) {
            Text(if (env == CscEnvironment.PRODUCTION) stringResource(Res.string.csc_no_production) else stringResource(Res.string.csc_no_test),
                style = MaterialTheme.typography.bodySmall)
        }
        list.forEach { svc ->
            Row(Modifier.fillMaxWidth().clickable { chosen = svc.id; onChange(SignerChoice.Csc(svc)) }, verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(selected = svc.id == chosen, onClick = { chosen = svc.id; onChange(SignerChoice.Csc(svc)) })
                Column(Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(svc.name, style = MaterialTheme.typography.bodyMedium)
                        if (svc.environment == CscEnvironment.TEST) VerdictPill(Verdict.CAUTION, stringResource(Res.string.csc_test))
                    }
                    Text(svc.baseUrl.substringAfter("://").substringBefore('/') + if (svc.builtIn) stringResource(Res.string.csc_builtin) else stringResource(Res.string.csc_user),
                        style = MaterialTheme.typography.bodySmall)
                    svc.note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
                if (!svc.builtIn) TextButton(onClick = { model.csc.remove(svc.id) }) { Text(stringResource(Res.string.action_remove)) }
            }
        }
    }
    if (chosen?.let { model.csc.service(it)?.environment } == CscEnvironment.TEST) {
        Text(stringResource(Res.string.csc_test_note), style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error)
    }
    Text(stringResource(Res.string.csc_flow_text) +
        stringResource(Res.string.csc_timestamp_text),
        style = MaterialTheme.typography.bodySmall)
    if (!adding) {
        OutlinedButton(onClick = { adding = true }) { Text(stringResource(Res.string.csc_add)) }
    } else {
        CscServiceForm(model) { adding = false }
    }
}

@Composable
private fun CscServiceForm(model: WalletModel, onDone: () -> Unit) {
    var byProfile by remember { mutableStateOf(false) }
    WrapRow() {
        FilterChip(selected = !byProfile, onClick = { byProfile = false }, label = { Text(stringResource(Res.string.csc_add_fields)) })
        FilterChip(selected = byProfile, onClick = { byProfile = true }, label = { Text(stringResource(Res.string.csc_import_profile)) })
    }
    if (byProfile) {
        CscProfileForm(model, onDone)
        return
    }
    var name by remember { mutableStateOf("") }
    var baseUrl by remember { mutableStateOf("https://") }
    var clientId by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var redirect by remember { mutableStateOf(CscServices.WALLET_REDIRECT) }
    var env by remember { mutableStateOf(CscEnvironment.PRODUCTION) }
    val problem = model.csc.problem(name, baseUrl, clientId, redirect)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        CscEnvironment.entries.forEach { e -> FilterChip(selected = e == env, onClick = { env = e }, label = { Text(e.title) }) }
    }
    OutlinedTextField(value = name, onValueChange = { name = it.take(60) }, label = { Text(stringResource(Res.string.csc_name)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = baseUrl, onValueChange = { baseUrl = it.trim().take(300) }, label = { Text(stringResource(Res.string.csc_url)) },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = clientId, onValueChange = { clientId = it.trim().take(200) }, label = { Text("client_id") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = secret, onValueChange = { secret = it.trim().take(200) }, label = { Text(stringResource(Res.string.csc_secret)) }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
    OutlinedTextField(value = redirect, onValueChange = { redirect = it.trim().take(300) }, label = { Text(stringResource(Res.string.csc_redirect)) },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    Text(stringResource(Res.string.csc_redirect_text, CscServices.WALLET_REDIRECT),
        style = MaterialTheme.typography.bodySmall)
    problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    WrapRow() {
        Button(onClick = { model.csc.add(name, baseUrl, clientId, secret, redirect, env); onDone() }, enabled = problem == null) { Text(stringResource(Res.string.action_add)) }
        OutlinedButton(onClick = onDone) { Text(stringResource(Res.string.action_cancel)) }
    }
}

/**
 * Adds services from a CSC profile, pasted or read from a file: JSON with name, baseUrl, clientId and environment,
 * optionally clientSecret, redirectUri and note (CscServices.fromProfile).
 */
@Composable
private fun CscProfileForm(model: WalletModel, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }
    val addedPattern = stringResource(Res.string.csc_added, "{n}")
    OutlinedTextField(value = text, onValueChange = { text = it.take(20_000); problem = null }, label = { Text(stringResource(Res.string.csc_profile_json)) },
        minLines = 4, modifier = Modifier.fillMaxWidth())
    Text(stringResource(Res.string.csc_profile_text, CscServices.WALLET_REDIRECT),
        style = MaterialTheme.typography.bodySmall)
    problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    WrapRow() {
        Button(onClick = {
            runCatching { model.csc.addProfile(text) }
                .onSuccess { model.message.value = addedPattern.replace("{n}", it.toString()); onDone() }
                .onFailure { problem = it.message }
        }, enabled = text.isNotBlank()) { Text(stringResource(Res.string.action_add)) }
        OutlinedButton(onClick = {
            scope.launch { model.platform.pickFile()?.let { text = it.bytes.decodeToString().take(20_000); problem = null } }
        }) { Text(stringResource(Res.string.csc_from_file)) }
        OutlinedButton(onClick = onDone) { Text(stringResource(Res.string.action_cancel)) }
    }
}

/** A PIN or OTP the service asks for, or the address to paste when the browser does not come back by itself. */
@Composable
internal fun CscPromptPanel(model: WalletModel) {
    val p by model.csc.prompt.collectAsState()
    when (val prompt = p) {
        null -> {}
        is CscPrompt.Secret -> {
            var value by remember(prompt) { mutableStateOf("") }
            OutlinedTextField(
                value = value, onValueChange = { value = it.take(64) }, label = { Text(prompt.label) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = if (prompt.numeric) KeyboardType.NumberPassword else KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            WrapRow() {
                Button(onClick = { prompt.answer.complete(value) }, enabled = value.isNotEmpty()) { Text(stringResource(Res.string.action_send)) }
                OutlinedButton(onClick = { prompt.answer.complete(null) }) { Text(stringResource(Res.string.action_cancel)) }
            }
        }
        is CscPrompt.Browser -> {
            var pasted by remember(prompt) { mutableStateOf("") }
            Text(stringResource(Res.string.csc_browser_opened, prompt.purpose, prompt.redirectUri),
                style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(value = pasted, onValueChange = { pasted = it.trim() }, label = { Text(stringResource(Res.string.csc_last_url)) }, singleLine = true,
                modifier = Modifier.fillMaxWidth())
            WrapRow() {
                Button(onClick = { prompt.answer.complete(pasted) }, enabled = pasted.startsWith(prompt.redirectUri)) { Text(stringResource(Res.string.action_continue)) }
                OutlinedButton(onClick = { prompt.answer.complete(null) }) { Text(stringResource(Res.string.action_cancel)) }
            }
        }
    }
}
