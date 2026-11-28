package diw.wallet.app.ui

import diw.wallet.core.trust.TrustRole
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
import diw.wallet.app.C2paChoice
import diw.wallet.app.IcaCandidate
import diw.wallet.core.document.c2pa.CawgAggregation
import diw.wallet.app.SealPicture
import diw.wallet.core.document.ofd.OfdShading
import diw.wallet.core.document.c2pa.C2paInfo
import diw.wallet.core.document.c2pa.DigitalSourceTypes
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
import kotlin.time.Clock
import kotlin.time.Instant

/** A script the source site runs on its pages at [host] only (MyData sign-in values), and what to do when it fills inputs. */
class PortalAutofill(val host: String, val script: String, val onFilled: (Int) -> Unit)

/** A site page shown inside the app; downloads come back as [onFile], links for other apps go to [onExternal]. */
@Composable
expect fun PortalWebView(url: String, modifier: Modifier, onFile: (PickedFile) -> Unit, onExternal: (String) -> Unit, onError: (String) -> Unit, autofill: PortalAutofill? = null)

/**
 * The host page of an OpenCerts renderer ([html], see OpenCertRenderer), or an [offline] page (OpenCertOffline:
 * no scripts, nothing loaded from the network): inside the app where a web view exists, otherwise opened in the
 * system browser on request. Links the renderer opens go to [onExternal].
 */
@Composable
expect fun OpenCertRendererView(html: String, modifier: Modifier, offline: Boolean = false, onExternal: (String) -> Unit)

internal fun localTime(epochSeconds: Long): String {
    val t = Instant.fromEpochSeconds(epochSeconds).toLocalDateTime(TimeZone.currentSystemDefault())
    fun two(n: Int) = n.toString().padStart(2, '0')
    return "${t.year}-${two(t.month.ordinal + 1)}-${two(t.day)} ${two(t.hour)}:${two(t.minute)}"
}

internal fun sizeText(size: Long): String = when {
    size < 1024 -> "$size B"
    size < 1024 * 1024 -> "${size / 1024} KB"
    else -> "${size / 1024 / 1024}.${(size % (1024 * 1024)) * 10 / (1024 * 1024)} MB"
}

@Composable
private fun verdictOf(v: DocumentVerdict): Pair<Verdict, String> = when (v) {
    DocumentVerdict.VALID -> Verdict.PASS to stringResource(Res.string.doc_verdict_valid)
    DocumentVerdict.PARTIAL -> Verdict.CAUTION to stringResource(Res.string.doc_verdict_partial)
    DocumentVerdict.INVALID -> Verdict.FAIL to stringResource(Res.string.doc_verdict_invalid)
    DocumentVerdict.UNSIGNED -> Verdict.CAUTION to stringResource(Res.string.doc_verdict_unsigned)
}

private fun checkVerdict(c: Check): Verdict = when (c) {
    Check.PASS -> Verdict.PASS
    Check.FAIL -> Verdict.FAIL
    else -> Verdict.CAUTION
}

@Composable
private fun checkText(c: Check): String = when (c) {
    Check.PASS -> stringResource(Res.string.check_pass)
    Check.WARN -> stringResource(Res.string.check_warn)
    Check.FAIL -> stringResource(Res.string.check_fail)
    Check.NOT_CHECKED -> stringResource(Res.string.check_not_checked)
}

@Composable
private fun formatTitle(f: DocumentFormat): String = when (f) {
    DocumentFormat.PDF -> "PDF"
    DocumentFormat.CMS_SIGNED -> stringResource(Res.string.format_cms_signed)
    DocumentFormat.CMS_ENVELOPED -> stringResource(Res.string.format_cms_enveloped)
    DocumentFormat.TIMESTAMP -> stringResource(Res.string.format_timestamp)
    DocumentFormat.XML -> "XML"
    DocumentFormat.OFD -> "OFD"
    DocumentFormat.ASIC_E -> stringResource(Res.string.format_asic)
    DocumentFormat.ZIP -> stringResource(Res.string.format_zip)
    DocumentFormat.OPENCERTS -> stringResource(Res.string.format_opencerts)
    DocumentFormat.JSON -> "JSON"
    DocumentFormat.OFFICE -> stringResource(Res.string.format_office)
    DocumentFormat.IMAGE -> stringResource(Res.string.format_image)
    DocumentFormat.TEXT -> stringResource(Res.string.format_text)
    DocumentFormat.OPENPGP -> "OpenPGP"
    DocumentFormat.EMRTD -> stringResource(Res.string.format_emrtd)
    DocumentFormat.OTHER -> stringResource(Res.string.format_other)
}

// ---------------------------------------------------------------- files tab

/**
 * Files and official documents, as Bonds keeps its MyData vault and official document inbox beside the cards: the
 * stored files with their signature checks first; the sites that issue documents are one row away.
 */
@Composable
fun FilesTab(model: WalletModel) {
    val files by model.files.files.collectAsState()
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    ScreenColumn(spacing = 12.dp) {
        WrapRow() {
            Button(onClick = { model.files.pickAndImport() }, enabled = busy == null) {
                Icon(WalletIcons.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(stringResource(Res.string.files_import))
            }
            OutlinedButton(onClick = { model.screen.value = Screen.DocumentSources }) {
                Icon(WalletIcons.Government, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(stringResource(Res.string.files_from_web))
            }
        }
        OutlinedButton(onClick = { model.screen.value = Screen.PassportRead }, enabled = busy == null) {
            Icon(WalletIcons.Person, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(stringResource(Res.string.files_read_passport))
        }
        FilesBusyLine(model, busy, error)
        if (files.isEmpty()) {
            EmptyState(
                WalletIcons.Document, stringResource(Res.string.files_empty_title),
                stringResource(Res.string.files_empty_text),
                stringResource(Res.string.files_from_mydata),
            ) { model.screen.value = Screen.DocumentSources }
        } else FileList(model, files)
    }
}

/** The sites that issue documents: in the app where a web view exists (downloads are saved directly), else the browser. */
@Composable
fun DocumentSourcesScreen(model: WalletModel) {
    fun open(src: diw.wallet.app.DocumentSource) {
        if (model.platform.embeddedBrowser) model.screen.value = Screen.Portal(src.id) else model.platform.openBrowser(src.url)
    }
    ScreenColumn(spacing = 12.dp) {
        Text(
            if (model.platform.embeddedBrowser) stringResource(Res.string.files_web_inapp)
            else stringResource(Res.string.files_web_browser),
            style = MaterialTheme.typography.bodySmall,
        )
        SectionTitle("MyData")
        if (!model.legal.enabled(diw.wallet.app.legal.Integration.MYDATA)) IntegrationOffRow(model, diw.wallet.app.legal.Integration.MYDATA)
        else DocumentSources.myData.forEach { src ->
            ActionRow(if (src.nationalId) WalletIcons.Person else WalletIcons.Government, src.name, src.detail) { open(src) }
        }
        SectionTitle(stringResource(Res.string.files_other_sources))
        DocumentSources.others.forEach { src -> ActionRow(WalletIcons.Government, src.name, src.detail) { open(src) } }
        SectionTitle(stringResource(Res.string.files_official_exchange))
        ActionRow(WalletIcons.Send, stringResource(Res.string.files_exchange), stringResource(Res.string.files_exchange_text), enabled = false) {}
    }
}

@Composable
internal fun BusyLine(busy: String?, error: String?, onCancel: (() -> Unit)? = null) {
    busy?.let {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            CircularProgressIndicator(Modifier.size(18.dp))
            Text(it, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            onCancel?.let { cancel -> TextButton(onClick = cancel) { Text(stringResource(Res.string.action_cancel)) } }
        }
    }
    error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
}

/** [BusyLine] for vault actions, with Cancel while one runs. */
@Composable
internal fun FilesBusyLine(model: WalletModel, busy: String?, error: String?) {
    val cancellable by model.files.cancellable.collectAsState()
    BusyLine(busy, error, if (cancellable) model.files::cancel else null)
}

/** How the files list is laid out: newest first, or grouped by what the files are (MyData item, official documents). */
private enum class FileOrder(val title: org.jetbrains.compose.resources.StringResource) { RECENT(Res.string.files_by_time), ITEM(Res.string.files_by_item) }

/** The files outside containers; a container's own files show on its document's screen. */
@Composable
private fun FileList(model: WalletModel, files: List<StoredFile>) {
    var order by remember { mutableStateOf(FileOrder.RECENT) }
    var query by remember { mutableStateOf("") }
    val outside = files.filter { it.bundleOf == null }
    val counts = files.mapNotNull { it.bundleOf }.groupingBy { it }.eachCount()
    val q = query.trim()
    // A search also finds a container by the names of the files inside it.
    val shown = if (q.isEmpty()) outside else outside.filter { f ->
        listOfNotNull(f.name, f.report?.title, f.source, f.period).any { it.contains(q, ignoreCase = true) } ||
            files.any { it.bundleOf == f.id && it.name.contains(q, ignoreCase = true) }
    }
    if (outside.size > 5) {
        OutlinedTextField(value = query, onValueChange = { query = it.take(60) }, label = { Text(stringResource(Res.string.files_search)) }, singleLine = true,
            modifier = Modifier.fillMaxWidth())
    }
    if (outside.size > 1) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(Res.string.files_count, outside.size), style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            FileOrder.entries.forEach { o -> FilterChip(selected = o == order, onClick = { order = o }, label = { Text(stringResource(o.title)) }) }
        }
    }
    if (q.isNotEmpty() && shown.isEmpty()) Text(stringResource(Res.string.files_no_match, q), style = MaterialTheme.typography.bodySmall)
    when (order) {
        FileOrder.RECENT -> shown.forEach { f -> FileRow(f, counts[f.id] ?: 0) { model.screen.value = Screen.FileDetail(f.id) } }
        FileOrder.ITEM -> shown.groupBy { groupOf(it, counts[it.id] ?: 0) }.toSortedMap().forEach { (group, list) ->
            Text(stringResource(Res.string.files_group_count, group, list.size), style = MaterialTheme.typography.titleSmall)
            list.sortedWith(compareByDescending<StoredFile> { periodKey(it.period) }.thenByDescending { it.addedAt }).forEach { f ->
                FileRow(f, counts[f.id] ?: 0) { model.screen.value = Screen.FileDetail(f.id) }
            }
        }
    }
}

/** The group a file is listed under: its MyData item, official documents, else its format. */
@Composable
private fun groupOf(f: StoredFile, members: Int): String {
    val source = f.source.orEmpty()
    if (source.startsWith("MyData")) return source.substringAfter("・", "MyData").substringBefore(stringResource(Res.string.paren_open)).ifBlank { "MyData" }
    val ext = f.name.substringAfterLast('.', "").lowercase()
    if (members > 0 || ext in setOf("di", "sw", "si", "dm", "co", "en", "esw")) return stringResource(Res.string.files_group_official)
    return f.report?.format?.let { formatTitle(it) } ?: stringResource(Res.string.format_other)
}

/** "113 年度" as a number for sorting, newest first; files without a period sort last. */
private fun periodKey(period: String?): Int = period?.let { Regex("\\d+").find(it)?.value?.toIntOrNull() } ?: -1

@Composable
private fun FileRow(f: StoredFile, members: Int = 0, onClick: () -> Unit) {
    val (verdict, text) = f.report?.let { verdictOf(it.verdict) } ?: (Verdict.CAUTION to stringResource(Res.string.files_unchecked))
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(WalletIcons.Document, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(f.report?.title ?: f.name, style = MaterialTheme.typography.titleSmall)
                Text(listOfNotNull(f.period, f.report?.format?.let { formatTitle(it) }, sizeText(f.size), localTime(f.addedAt)).joinToString("・"),
                    style = MaterialTheme.typography.bodySmall)
                WrapRow(spacing = 6.dp) {
                    VerdictPill(verdict, text)
                    if (f.timestamps.isNotEmpty()) VerdictPill(if (f.timestamps.any { it.trusted }) Verdict.PASS else Verdict.CAUTION, stringResource(Res.string.files_tag_timestamp))
                    if (f.derivedDocumentId != null) InfoPill(stringResource(Res.string.files_tag_derived))
                    if (f.nationalId != null) InfoPill(stringResource(Res.string.files_tag_national_id))
                    if (members > 0) InfoPill(stringResource(Res.string.files_tag_container, members))
                }
            }
        }
    }
}

// ---------------------------------------------------------------- official document containers

/** The container of an official document (its exchange form, approval file, attachments), or the one a file is in. */
@Composable
private fun OfficialContainerSection(model: WalletModel, f: StoredFile, files: List<StoredFile>) {
    val owner = f.bundleOf?.let { id -> files.firstOrNull { it.id == id } }
    if (owner != null) {
        SectionTitle(stringResource(Res.string.files_container))
        LabelValue(stringResource(Res.string.files_belongs_to), owner.name, onClick = { model.screen.value = Screen.FileDetail(owner.id) })
        OutlinedButton(onClick = { model.files.leaveBundle(f) }) { Text(stringResource(Res.string.files_move_out)) }
        return
    }
    var main by remember(f.id) { mutableStateOf(false) }
    LaunchedEffect(f.id) { main = model.files.isOfficialMain(f) }
    if (!main) return
    val own = files.filter { it.bundleOf == f.id }.sortedBy { it.name }
    val inherited = remember(f.id, files) { model.files.inherited(f) }.sortedBy { it.name }
    val members = own + inherited
    // With an online approval in the container, its files are shown under the signing point that signed them.
    val layout by produceState<FilesModel.ContainerLayout?>(null, f.id, files) { value = model.files.containerLayout(f) }
    SectionTitle(stringResource(Res.string.files_container))
    if (members.isEmpty()) {
        Text(stringResource(Res.string.files_container_empty), style = MaterialTheme.typography.bodySmall)
    }
    val open = { m: StoredFile -> model.screen.value = Screen.FileDetail(m.id) }
    val l = layout
    if (l != null) {
        ContainerHealth(l, listOf(f) + members)
        Text(stringResource(Res.string.files_container_by_point), style = MaterialTheme.typography.bodySmall)
        FileRow(l.approval) { open(l.approval) }
        l.points.forEach { p -> ContainerPointView(p, f, open) }
        if (l.others.isNotEmpty()) {
            Text(stringResource(Res.string.files_container_unlisted), style = MaterialTheme.typography.titleSmall)
            l.others.forEach { m -> FileRow(m) { open(m) } }
        }
    } else {
        own.forEach { m -> FileRow(m) { open(m) } }
        if (inherited.isNotEmpty()) {
            Text(stringResource(Res.string.files_container_inherited), style = MaterialTheme.typography.bodySmall)
            inherited.forEach { m -> FileRow(m) { open(m) } }
        }
    }
    WrapRow() {
        OutlinedButton(onClick = { model.files.importIntoBundle(f) }) { Text(stringResource(Res.string.files_import_related)) }
        OutlinedButton(onClick = { model.screen.value = Screen.OfficialBundle(f.id, null) }) { Text(stringResource(Res.string.files_add_saved)) }
    }
    if (members.isNotEmpty()) {
        ActionRow(WalletIcons.Shield, stringResource(Res.string.files_container_revocation), stringResource(Res.string.files_container_revocation_text)) {
            model.files.collectContainerValidation(f)
        }
        ActionRow(WalletIcons.Send, stringResource(Res.string.files_container_export), stringResource(Res.string.files_container_export_text)) { model.files.exportContainer(f) }
        if (model.platform.canShareFiles) {
            ActionRow(WalletIcons.Share, stringResource(Res.string.files_container_share), stringResource(Res.string.files_container_share_text)) { model.files.exportContainer(f, share = true) }
        }
    }
}

/**
 * The health of a container in the categories the archives' check uses: files missing or changed since they were
 * signed, the signatures of the signing points, and the revocation data kept for signed files.
 */
@Composable
private fun ContainerHealth(l: FilesModel.ContainerLayout, all: List<StoredFile>) {
    val signatures = l.points.mapNotNull { it.signature }
    val failed = signatures.count { it.verdict == DocumentVerdict.INVALID }
    val unsigned = l.points.size - signatures.size
    val signed = all.filter { it.report?.signatures?.isNotEmpty() == true }
    val withRevocation = signed.count { it.signatureValidation != null }
    WrapRow(spacing = 6.dp) {
        VerdictPill(if (l.missing == 0) Verdict.PASS else Verdict.CAUTION, if (l.missing == 0) stringResource(Res.string.files_container_complete) else stringResource(Res.string.files_container_missing, l.missing))
        if (l.changed > 0) VerdictPill(Verdict.CAUTION, stringResource(Res.string.files_container_changed, l.changed))
        VerdictPill(
            when { failed > 0 -> Verdict.FAIL; unsigned == 0 && signatures.all { it.verdict == DocumentVerdict.VALID } -> Verdict.PASS; else -> Verdict.CAUTION },
            stringResource(Res.string.files_points, l.points.size) + (if (failed > 0) stringResource(Res.string.files_points_failed, failed) else "") + (if (unsigned > 0) stringResource(Res.string.files_points_unsigned, unsigned) else ""),
        )
        if (signed.isNotEmpty()) VerdictPill(if (withRevocation == signed.size) Verdict.PASS else Verdict.CAUTION, stringResource(Res.string.files_revocation_count, withRevocation, signed.size))
    }
}

/** One signing point: who signed and when, its signature check, and the files it signed first. */
@Composable
private fun ContainerPointView(p: FilesModel.ContainerPoint, main: StoredFile, open: (StoredFile) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(top = 4.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(p.title, style = MaterialTheme.typography.titleSmall)
        WrapRow(spacing = 6.dp) {
            p.signature?.let { s -> val (v, t) = verdictOf(s.verdict); VerdictPill(v, t) } ?: VerdictPill(Verdict.CAUTION, stringResource(Res.string.files_no_cert_signature))
            p.time?.let { Text(localTime(it), style = MaterialTheme.typography.bodySmall) }
        }
        Column(Modifier.padding(start = 12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            p.files.forEach { m ->
                if (m.id == main.id) Text(stringResource(Res.string.files_main_document, m.name), style = MaterialTheme.typography.bodySmall)
                else FileRow(m) { open(m) }
            }
            if (p.repeated.isNotEmpty()) Text(stringResource(Res.string.files_point_repeated, p.repeated.size), style = MaterialTheme.typography.bodySmall)
            p.changed.forEach { VerdictPill(Verdict.CAUTION, stringResource(Res.string.files_point_changed, it)) }
            p.missing.forEach { VerdictPill(Verdict.CAUTION, stringResource(Res.string.files_point_absent, it)) }
        }
    }
}

/** Confirms which files go into an official document's container, showing why each one may belong to it. */
@Composable
fun OfficialBundleScreen(model: WalletModel, screen: Screen.OfficialBundle) {
    val files by model.files.files.collectAsState()
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val main = files.firstOrNull { it.id == screen.mainId }
    if (main == null) {
        EmptyState(WalletIcons.Document, stringResource(Res.string.files_official_missing), stringResource(Res.string.files_official_missing_text), stringResource(Res.string.files_back_to_list)) { model.showTab(HomeTab.FILES) }
        return
    }
    var candidates by remember(screen) { mutableStateOf<List<FilesModel.BundleCandidate>?>(null) }
    val chosen = remember(screen) { androidx.compose.runtime.mutableStateMapOf<String, Boolean>() }
    LaunchedEffect(screen) {
        val list = model.files.bundleCandidates(main, screen.only)
        list.forEach { chosen[it.file.id] = it.match.suggested }
        candidates = list
    }
    ScreenColumn(spacing = 10.dp) {
        Text(main.report?.title ?: main.name, style = MaterialTheme.typography.titleMedium)
        Text(stringResource(Res.string.files_pick_related_text),
            style = MaterialTheme.typography.bodySmall)
        FilesBusyLine(model, busy, error)
        val list = candidates
        when {
            list == null -> CircularProgressIndicator(Modifier.size(20.dp))
            list.isEmpty() -> Text(stringResource(Res.string.files_pick_none), style = MaterialTheme.typography.bodySmall)
            else -> list.forEach { c ->
                Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                        Checkbox(checked = chosen[c.file.id] == true, onCheckedChange = { chosen[c.file.id] = it })
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(c.file.name, style = MaterialTheme.typography.titleSmall)
                            Text(listOfNotNull(c.file.report?.title, c.file.report?.format?.let { formatTitle(it) }, localTime(c.file.addedAt)).joinToString(stringResource(Res.string.sep_space)),
                                style = MaterialTheme.typography.bodySmall)
                            if (c.match.evidence.isEmpty()) Text(stringResource(Res.string.files_pick_no_clue), style = MaterialTheme.typography.bodySmall)
                            c.match.evidence.forEach { e -> VerdictPill(if (e.supports) Verdict.PASS else Verdict.CAUTION, e.text) }
                        }
                    }
                }
            }
        }
        val ids = chosen.filterValues { it }.keys.toList()
        WrapRow() {
            Button(onClick = { model.files.confirmBundle(main, ids, screen.only, screen.next) }, enabled = ids.isNotEmpty() && busy == null) {
                Text(stringResource(Res.string.files_put_in, ids.size))
            }
            OutlinedButton(onClick = { model.files.confirmBundle(main, emptyList(), screen.only, screen.next) }, enabled = busy == null) {
                Text(if (screen.next.isEmpty()) stringResource(Res.string.files_put_none) else stringResource(Res.string.files_skip_document))
            }
        }
    }
}

// ---------------------------------------------------------------- file detail

@Composable
fun FileDetailScreen(model: WalletModel, screen: Screen.FileDetail) {
    val files by model.files.files.collectAsState()
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val previews by model.files.previews.collectAsState()
    val docs by model.documents.collectAsState()
    val f = files.firstOrNull { it.id == screen.fileId }
    // Every open checks the signatures again with the current time and trust anchors.
    LaunchedEffect(screen.fileId) { model.files.refresh(screen.fileId) }
    if (f == null) {
        EmptyState(WalletIcons.Document, stringResource(Res.string.files_file_missing), stringResource(Res.string.files_document_missing_text), stringResource(Res.string.files_back_to_list)) { model.showTab(HomeTab.FILES) }
        return
    }
    val report = f.report
    var confirmDelete by remember { mutableStateOf(false) }
    var withMembers by remember { mutableStateOf(false) }
    var removeStamp by remember { mutableStateOf<Int?>(null) }
    var pickContent by remember { mutableStateOf(false) }
    var encrypting by remember { mutableStateOf(false) }
    val derived = f.derivedDocumentId?.let { id -> docs.firstOrNull { it.identifier == id } }
    ScreenColumn(spacing = 10.dp) {
        // What it is and whether it holds, then what can be done with it.
        Text(report?.title ?: f.name, style = MaterialTheme.typography.titleLarge)
        Text(listOfNotNull(if (report?.title != null && report.title != f.name) f.name else null, f.period,
            report?.format?.let { formatTitle(it) } ?: f.mediaType, sizeText(f.size), f.source ?: f.origin.title).joinToString("・"),
            style = MaterialTheme.typography.bodySmall)
        FilesBusyLine(model, busy, error)
        if (report != null) ReportVerdict(report)
        WrapRow() {
            Button(onClick = { model.screen.value = Screen.FileSign(f.id) }) { Text(stringResource(Res.string.files_sign)) }
            OutlinedButton(onClick = { model.files.addTimestamp(f) }, enabled = busy == null) { Text(stringResource(Res.string.files_add_timestamp)) }
            OutlinedButton(onClick = { model.screen.value = Screen.FileDerive(f.id) }) { Text(if (derived != null) stringResource(Res.string.files_rederive) else stringResource(Res.string.files_derive)) }
            OutlinedButton(onClick = { model.files.export(f) }) { Text(stringResource(Res.string.action_export)) }
            if (model.platform.canShareFiles) OutlinedButton(onClick = { model.files.export(f, share = true) }) { Text(stringResource(Res.string.action_share)) }
        }
        f.contentId?.let { id -> files.firstOrNull { it.id == id } }?.let { c ->
            LabelValue(stringResource(Res.string.files_signed_file), c.name, onClick = { model.screen.value = Screen.FileDetail(c.id) })
        }
        OfficialContainerSection(model, f, files)
        // An OpenCerts certificate is shown field by field below rather than as JSON text.
        if (report?.format != DocumentFormat.OPENCERTS) FilePreviewSection(model, f)

        if (report != null) {
            SectionTitle(if (report.signatures.isEmpty()) stringResource(Res.string.files_check_result) else stringResource(Res.string.files_signatures, report.signatures.size))
            report.signatures.forEachIndexed { i, s -> SignatureCard(model, s, i, report.signatures.size) }
            if (report.signatures.isNotEmpty()) {
                val v = f.signatureValidation
                if (v != null) LabelValue(stringResource(Res.string.files_signature_revocation), v.summary() + stringResource(Res.string.files_got_at, localTime(v.collectedAt)), small = true)
                TextButton(onClick = { model.files.collectSignatureValidation(f) }, enabled = busy == null) {
                    Text(if (v == null) stringResource(Res.string.files_get_revocation) else stringResource(Res.string.files_get_revocation_again))
                }
                if (model.files.canExtend(f)) {
                    TextButton(onClick = { model.files.extendPdf(f) }, enabled = busy == null) { Text(stringResource(Res.string.files_extend)) }
                }
            }
            report.envelope?.let { e ->
                Text(stringResource(Res.string.files_envelope), style = MaterialTheme.typography.titleSmall)
                Text(stringResource(Res.string.files_envelope_text), style = MaterialTheme.typography.bodySmall)
                e.recipients.forEach { LabelValue(stringResource(Res.string.files_recipients), it, small = true) }
                e.contentEncryption?.let { LabelValue(stringResource(Res.string.files_content_encryption), it, small = true) }
            }
            report.openCert?.let { oc -> OpenCertSection(model, f, oc, busy) }
            report.openPgp?.let { pgp -> OpenPgpFileSection(model, f, report, pgp, busy) }
            report.c2pa?.let { C2paSection(model, f, it) }
            if (report.format == DocumentFormat.IMAGE || report.aiProvenance != null) AiProvenanceSection(model, report.aiProvenance)
            report.travelDocument?.let { TravelDocumentSection(it) }
            if (report.entries.isNotEmpty()) {
                val zip = report.format == DocumentFormat.ASIC_E || report.format == DocumentFormat.ZIP
                CollapsibleSection(stringResource(Res.string.files_container_files), report.entries.size, initiallyExpanded = report.entries.size <= 10, key = "entries-${f.id}") {
                    if (zip) Text(stringResource(Res.string.files_container_files_text), style = MaterialTheme.typography.bodySmall)
                    report.entries.take(50).forEach { entry ->
                        if (zip) LabelValue(stringResource(Res.string.label_file), OfficialBundles.decodeZipName(entry), small = true, onClick = { model.files.openEntry(f, entry) })
                        else Text(entry, style = MaterialTheme.typography.bodySmall)
                    }
                    if (report.entries.size > 50) Text(stringResource(Res.string.files_more, report.entries.size - 50), style = MaterialTheme.typography.bodySmall)
                }
            }
            report.notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            // The stored check runs without the open password; once this session's password has opened the PDF, the
            // locked-PDF problem no longer holds for the holder.
            val opened = previews[f.id] is FilePreview.Pages
            report.problems.forEach { p ->
                if (opened && ENCRYPTED_PDF_PROBLEMS.any { p.startsWith(it) }) {
                    Text(stringResource(Res.string.files_pdf_encrypted), style = MaterialTheme.typography.bodySmall)
                } else Text(p, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(Res.string.files_checked_at, localTime(report.checkedAt)), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                TextButton(onClick = { model.files.reinspect(f) }, enabled = busy == null) { Text(stringResource(Res.string.zk_check_again)) }
            }
        }

        SectionTitle(stringResource(Res.string.files_timestamps, f.timestamps.size))
        if (f.timestamps.isEmpty()) Text(stringResource(Res.string.files_no_timestamp, TsaServices.byId(model.settings.tsaId).name),
            style = MaterialTheme.typography.bodySmall)
        f.timestamps.forEachIndexed { i, t ->
            VerdictPill(if (t.trusted) Verdict.PASS else Verdict.CAUTION, stringResource(Res.string.files_timestamp_line, t.tsa ?: stringResource(Res.string.tsa_fallback), localTime(t.time)) + if (t.trusted) "" else stringResource(Res.string.files_tsa_untrusted))
            val v = t.validation
            if (v != null) Text(v.summary() + stringResource(Res.string.files_got_at, localTime(v.collectedAt)), style = MaterialTheme.typography.bodySmall)
            WrapRow() {
                if (v == null) TextButton(onClick = { model.files.refreshTimestampValidation(f, i) }, enabled = busy == null) { Text(stringResource(Res.string.files_get_tsa_revocation)) }
                TextButton(onClick = { removeStamp = i }, enabled = busy == null) { Text(stringResource(Res.string.files_remove_timestamp), color = MaterialTheme.colorScheme.error) }
            }
        }

        SectionTitle(stringResource(Res.string.files_credentials_proofs))
        if (derived != null) {
            ActionRow(WalletIcons.Card, derived.displayName ?: stringResource(Res.string.files_derived), stringResource(Res.string.files_derived_exists)) {
                model.screen.value = Screen.DocumentDetail(derived.identifier, Screen.FileDetail(f.id))
            }
        } else {
            Text(stringResource(Res.string.files_derived_text), style = MaterialTheme.typography.bodySmall)
        }
        if (report?.format == DocumentFormat.EMRTD) {
            val photoId = f.photoIdDocumentId?.let { id -> docs.firstOrNull { it.identifier == id } }
            if (photoId != null) {
                ActionRow(WalletIcons.Card, photoId.displayName ?: stringResource(Res.string.files_photo_id), stringResource(Res.string.files_photo_id_exists)) {
                    model.screen.value = Screen.DocumentDetail(photoId.identifier, Screen.FileDetail(f.id))
                }
            } else {
                Text(stringResource(Res.string.files_photo_id_text), style = MaterialTheme.typography.bodySmall)
            }
            OutlinedButton(onClick = { model.files.issuePhotoId(f) }, enabled = busy == null) {
                Text(if (photoId != null) stringResource(Res.string.files_photo_id_remake) else stringResource(Res.string.files_photo_id_make))
            }
        }
        if (report?.format == DocumentFormat.EMRTD) {
            val links by produceState<List<FilesModel.TravelDocumentLink>?>(null, f.id, files.size) { value = model.files.travelDocumentLinks(f) }
            SectionTitle(stringResource(Res.string.files_passport_links))
            when {
                links == null -> Text(stringResource(Res.string.files_passport_links_reading), style = MaterialTheme.typography.bodySmall)
                links!!.isEmpty() -> Text(stringResource(Res.string.files_passport_links_none), style = MaterialTheme.typography.bodySmall)
                else -> links!!.forEach { link ->
                    val text = if (link.sameName) stringResource(Res.string.files_passport_link_name, link.number) else stringResource(Res.string.files_passport_link, link.number)
                    ActionRow(WalletIcons.Document, link.file.report?.title ?: link.file.name, text) { model.screen.value = Screen.FileDetail(link.file.id) }
                }
            }
            Text(stringResource(Res.string.files_passport_links_text), style = MaterialTheme.typography.bodySmall)
        }
        f.zkPdfPending?.let { pending ->
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius)) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(stringResource(Res.string.files_zkpdf_pending), style = MaterialTheme.typography.titleSmall)
                    Text(
                        stringResource(Res.string.files_zkpdf_pending_text_1, localTime(pending.createdAt)) +
                            stringResource(Res.string.files_zkpdf_pending_text_2),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    WrapRow() {
                        Button(onClick = { model.files.importZkPdfProof(f) }, enabled = busy == null) { Text(stringResource(Res.string.files_import_proof)) }
                        TextButton(onClick = { model.files.cancelZkPdfRequest(f) }, enabled = busy == null) { Text(stringResource(Res.string.files_cancel_request)) }
                    }
                }
            }
        }
        if (f.nationalId != null) {
            ActionRow(WalletIcons.Person, stringResource(Res.string.national_id_bonds), stringResource(Res.string.files_national_id_made)) {
                model.screen.value = Screen.NationalId(f.id, Screen.FileDetail(f.id))
            }
        } else if (report?.format == DocumentFormat.PDF) {
            ActionRow(WalletIcons.Person, stringResource(Res.string.files_make_national_id), stringResource(Res.string.files_make_national_id_text)) {
                model.screen.value = Screen.NationalIdCreate(f.id)
            }
        }
        if (report?.format == DocumentFormat.PDF) {
            ActionRow(WalletIcons.Shield, stringResource(Res.string.files_make_zkpdf), stringResource(Res.string.files_make_zkpdf_text)) {
                model.screen.value = Screen.FileDerive(f.id)
            }
        }
        f.webProofIds.mapNotNull { id -> docs.firstOrNull { it.identifier == id } }.forEach { proof ->
            ActionRow(WalletIcons.Link, proof.displayName ?: stringResource(Res.string.files_web_result), stringResource(Res.string.files_web_result_text)) {
                model.screen.value = Screen.DocumentDetail(proof.identifier, Screen.FileDetail(f.id))
            }
        }
        ActionRow(WalletIcons.Link, stringResource(Res.string.files_make_zktls),
            stringResource(Res.string.files_make_zktls_text)) {
            model.taiwan.zkTls.openSelf(f.id)
        }

        CollapsibleSection(stringResource(Res.string.files_info), key = "file-info-${f.id}") {
            LabelValue(stringResource(Res.string.files_name), f.name)
            report?.title?.let { LabelValue(stringResource(Res.string.files_title), it) }
            LabelValue(stringResource(Res.string.credential_format), report?.format?.let { formatTitle(it) } ?: f.mediaType)
            LabelValue(stringResource(Res.string.files_size), sizeText(f.size))
            report?.pages?.let { LabelValue(stringResource(Res.string.files_pages), "$it") }
            f.period?.let { LabelValue(stringResource(Res.string.files_period), it) }
            LabelValue(stringResource(Res.string.files_saved_at), localTime(f.addedAt))
            LabelValue(stringResource(Res.string.files_source), f.source ?: f.origin.title)
            if (f.source != null || f.archive != null) LabelValue(stringResource(Res.string.files_obtained_by), f.origin.title + (f.archive?.let { stringResource(Res.string.parenthesized, it) } ?: ""))
            LabelValue("SHA-256", f.sha256, small = true)
        }
        SectionTitle(stringResource(Res.string.files_other_actions))
        if (report?.format == DocumentFormat.ZIP) ActionRow(WalletIcons.Document, stringResource(Res.string.files_extract), stringResource(Res.string.files_extract_text)) { model.files.extract(f) }
        if ((report?.format == DocumentFormat.CMS_SIGNED || report?.openPgp?.kind == OpenPgpKind.DETACHED_SIGNATURE) &&
            f.contentId == null && report.signatures.any { it.integrity == Check.NOT_CHECKED }) {
            ActionRow(WalletIcons.Link, stringResource(Res.string.files_choose_signed), stringResource(Res.string.files_choose_signed_text)) { pickContent = true }
        }
        if (report?.openPgp?.kind != OpenPgpKind.ENCRYPTED) {
            ActionRow(WalletIcons.Shield, stringResource(Res.string.pgp_encrypt_title), stringResource(Res.string.files_pgp_encrypt_text)) { encrypting = true }
        }
        if (model.files.hasEvidence(f)) {
            ActionRow(WalletIcons.Send, stringResource(Res.string.files_export_evidence), stringResource(Res.string.files_export_evidence_text)) { model.files.exportWithEvidence(f) }
            if (model.platform.canShareFiles) {
                ActionRow(WalletIcons.Share, stringResource(Res.string.files_share_evidence), stringResource(Res.string.files_container_share_text)) { model.files.exportWithEvidence(f, share = true) }
            }
        }
        OutlinedButton(onClick = { confirmDelete = true }) {
            Icon(WalletIcons.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(stringResource(Res.string.files_delete), color = MaterialTheme.colorScheme.error)
        }
    }
    if (confirmDelete) {
        val own = files.count { it.bundleOf == f.id }
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(Res.string.files_delete_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(Res.string.files_delete_text))
                    if (own > 0) {
                        Row(Modifier.clickable { withMembers = !withMembers }, verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = withMembers, onCheckedChange = { withMembers = it })
                            Text(stringResource(Res.string.files_delete_members, own))
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { confirmDelete = false; model.files.delete(f, withMembers && own > 0) }) { Text(stringResource(Res.string.action_delete), color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
    removeStamp?.let { index ->
        AlertDialog(
            onDismissRequest = { removeStamp = null },
            title = { Text(stringResource(Res.string.files_remove_timestamp_title)) },
            text = { Text(stringResource(Res.string.files_remove_timestamp_text)) },
            confirmButton = { TextButton(onClick = { removeStamp = null; model.files.removeTimestamp(f, index) }) { Text(stringResource(Res.string.action_remove), color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { removeStamp = null }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
    if (encrypting) OpenPgpEncryptDialog(model, f) { encrypting = false }
    if (pickContent) {
        AlertDialog(
            onDismissRequest = { pickContent = false },
            title = { Text(stringResource(Res.string.files_choose_signed)) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    val others = files.filter { it.id != f.id }
                    if (others.isEmpty()) Text(stringResource(Res.string.files_import_original))
                    others.forEach { c ->
                        Text(c.name, Modifier.fillMaxWidth().clickable { pickContent = false; model.files.attachContent(f, c) }.padding(vertical = 6.dp),
                            color = MaterialTheme.colorScheme.primary)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { pickContent = false }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
}

@Composable
private fun ReportVerdict(report: DocumentReport) {
    val (verdict, title) = verdictOf(report.verdict)
    val caveats = buildList {
        when (report.verdict) {
            DocumentVerdict.VALID -> report.bestTier?.let { add(stringResource(Res.string.files_signer_tier) + WalletModel.tierTitle(it)) }
            DocumentVerdict.PARTIAL -> add(stringResource(Res.string.files_partial_text))
            DocumentVerdict.INVALID -> add(stringResource(Res.string.files_invalid_text))
            DocumentVerdict.UNSIGNED -> add(if (report.envelope != null) stringResource(Res.string.files_envelope_not_signed) else stringResource(Res.string.files_unsigned_text))
        }
        if (report.encrypted) add(stringResource(Res.string.files_encrypted_ok))
    }
    VerdictCard(verdict, title, caveats)
}

private fun certOf(c: CertInfo): X509Cert? = runCatching { X509Cert(ByteString(c.der.fromBase64())) }.getOrNull()

@Composable
private fun SignatureCard(model: WalletModel, s: SignatureInfo, index: Int, count: Int) {
    val (verdict, text) = verdictOf(s.verdict)
    val role = signatureRole(s.format)
    val at = signatureTime(s)
    // The signature is intact but its chain leads to no enabled anchor (T3): the chain and its root can be reviewed,
    // and the root trusted, on the certificate screen.
    val reviewRoot = s.integrity == Check.PASS && s.format != SignatureFormat.OPENPGP &&
        s.trust.let { t -> t == null || t.anchorName == null || "UNKNOWN_ANCHOR" in t.labels }
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (count > 1) stringResource(Res.string.files_signature_n, index + 1) else stringResource(Res.string.label_signature_noun), style = MaterialTheme.typography.titleSmall)
                VerdictPill(verdict, text)
            }
            Text(s.format.title, style = MaterialTheme.typography.bodySmall)
            s.signer?.let { signer ->
                // An OpenPGP signer is a key, not an X.509 certificate (its der is empty), so there is no certificate
                // screen to open: only make the row tappable when the chain actually holds DER-encoded X.509 certs,
                // otherwise the X.509 certificate screen would be opened on empty bytes and crash.
                val chain = s.chain.filter { it.der.isNotBlank() }.mapNotNull { certOf(it) }
                LabelValue(stringResource(Res.string.files_signer), signer.commonName ?: signer.subject,
                    onClick = if (chain.isEmpty()) null else ({ model.screen.value = Screen.Certificate(chain, 0, model.screen.value, role, at = at) }))
            }
            s.trust?.let { t ->
                val d = t.decision()
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TierBadge(d)
                    d.anchorName?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
                Text(signerTrustLine(d), style = MaterialTheme.typography.bodySmall)
            }
            if (reviewRoot) {
                val chain = s.chain.filter { it.der.isNotBlank() }.mapNotNull { certOf(it) }
                if (chain.isNotEmpty()) TextButton(onClick = {
                    model.screen.value = Screen.Certificate(chain, 0, model.screen.value, role, focusRoot = true, at = at)
                }) { Text(stringResource(Res.string.files_review_chain_root)) }
            }
            val openPgp = s.format == SignatureFormat.OPENPGP
            if (openPgp) s.signer?.let { LabelValue(stringResource(Res.string.files_key_fingerprint), groupedFingerprint(it.serialHex), small = true) }
            LabelValue(stringResource(Res.string.files_integrity), checkText(s.integrity), small = true)
            LabelValue(if (openPgp) stringResource(Res.string.files_key_validity) else stringResource(Res.string.files_cert_validity), checkText(s.certificateValidity), small = true)
            s.coversWholeDocument?.let { LabelValue(stringResource(Res.string.files_covers_whole), if (it) stringResource(Res.string.answer_yes) else stringResource(Res.string.answer_no), small = true) }
            s.laterChanges?.let {
                LabelValue(stringResource(Res.string.files_changes_after), when (it) {
                    LaterChanges.NONE -> stringResource(Res.string.files_changes_none)
                    LaterChanges.SIGNATURES_ONLY -> stringResource(Res.string.files_changes_later_sigs)
                    LaterChanges.OTHER -> stringResource(Res.string.files_changes_other)
                }, small = true)
            }
            s.timestamp?.let { TimestampLine(model, it) } ?: s.claimedTime?.let { LabelValue(stringResource(Res.string.files_claimed_time), localTime(it) + stringResource(Res.string.files_claimed_unproven), small = true) }
            if (!openPgp) LabelValue(stringResource(Res.string.files_revocation), if (s.revocationData) stringResource(Res.string.files_revocation_embedded) else stringResource(Res.string.files_revocation_none), small = true)
            s.reason?.let { LabelValue(stringResource(Res.string.files_reason), it, small = true) }
            s.location?.let { LabelValue(stringResource(Res.string.files_location), it, small = true) }
            s.problems.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            s.notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/** The trust role a signature's chain is evaluated for: travel documents and content credentials have their own anchors. */
private fun signatureRole(f: SignatureFormat): TrustRole = when (f) {
    SignatureFormat.ICAO_PA -> TrustRole.TRAVEL_DOCUMENT
    SignatureFormat.C2PA -> TrustRole.CONTENT
    SignatureFormat.RFC3161, SignatureFormat.PDF_DOC_TIMESTAMP -> TrustRole.TSA
    else -> TrustRole.DOCUMENT
}

/**
 * The time a signature's chain was judged at, as the inspector does: the trusted time stamp; else now while the signer
 * certificate is valid, otherwise the signing time the signer wrote. Null stands for now.
 */
private fun signatureTime(s: SignatureInfo): Instant? {
    s.timestamp?.takeIf { it.trusted }?.let { return Instant.fromEpochSeconds(it.time) }
    val signer = s.signer ?: return null
    val now = Clock.System.now().epochSeconds
    if (now in signer.notBefore..signer.notAfter) return null
    return s.claimedTime?.let { Instant.fromEpochSeconds(it) }
}

/** A signature's time stamp; its authority's chain opens on the certificate screen at its genTime, up to the root. */
@Composable
private fun TimestampLine(model: WalletModel, t: TimestampInfo) {
    val chain = t.chain.filter { it.der.isNotBlank() }.mapNotNull { certOf(it) }
    LabelValue(stringResource(Res.string.files_tag_timestamp), localTime(t.time) + stringResource(Res.string.sep_space) + (t.tsa ?: "") + if (t.trusted) "" else stringResource(Res.string.parenthesized, checkText(if (t.signature == Check.PASS) Check.WARN else t.signature)), small = true,
        onClick = if (chain.isEmpty()) null else ({ model.screen.value = Screen.Certificate(chain, 0, model.screen.value, TrustRole.TSA, at = Instant.fromEpochSeconds(t.time)) }))
}

/** Checked evidence of a derived credential, for the verifier result. */
@Composable
fun EvidenceRows(evidence: List<EvidenceResult>) {
    if (evidence.isEmpty()) return
    Text(stringResource(Res.string.files_evidence), style = MaterialTheme.typography.titleSmall)
    evidence.forEach { e ->
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            VerdictPill(checkVerdict(e.check), e.title + stringResource(Res.string.label_colon_sep) + checkText(e.check))
            Text(e.detail, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** The start of the core problem for a PDF that needs an open password, in the app language and in Chinese (older reports). */
private val ENCRYPTED_PDF_PROBLEMS: List<String>
    get() = listOf(CoreText.prefix("core_pdf_encrypted_password"), CoreText.chinese("core_pdf_encrypted_password").substringBefore("（"))

// ---------------------------------------------------------------- sign

@Composable
fun FileSignScreen(model: WalletModel, screen: Screen.FileSign) {
    val f = model.files.file(screen.fileId) ?: return
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val forms = remember(f) { model.files.formsFor(f) }
    var form by remember { mutableStateOf(forms.first()) }
    var choice by remember { mutableStateOf<SignerChoice?>(null) }
    var reason by remember { mutableStateOf("") }
    var location by remember { mutableStateOf("") }
    var timestamp by remember { mutableStateOf(true) }
    ScreenColumn(spacing = 10.dp) {
        Text(f.report?.title ?: f.name, style = MaterialTheme.typography.titleLarge)
        if (f.report?.title != null && f.report.title != f.name) Text(f.name, style = MaterialTheme.typography.bodySmall)
        SectionTitle(stringResource(Res.string.sign_step_format))
        forms.forEach { sf ->
            Row(Modifier.fillMaxWidth().clickable { form = sf }, verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(selected = sf == form, onClick = { form = sf })
                Column {
                    Text(sf.title, style = MaterialTheme.typography.bodyMedium)
                    Text(sf.detail, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        SectionTitle(stringResource(Res.string.sign_step_signer))
        val openPgpForm = form == SignForm.OPENPGP_DETACHED
        // The OpenPGP form signs only with an OpenPGP card; switching forms starts the signer choice again.
        LaunchedEffect(openPgpForm) { choice = null }
        androidx.compose.runtime.key(openPgpForm) {
            if (openPgpForm) OpenPgpKeyPicker(model, x509 = false) { choice = it } else SignerPicker(model) { choice = it }
        }
        val tsaName = TsaServices.byId(model.settings.tsaId).name
        var level by remember { mutableStateOf(SignatureLevel.of(model.settings.padesLevel)) }
        var certification by remember { mutableStateOf<Int?>(null) }
        var visible by remember { mutableStateOf<VisibleSignature?>(null) }
        var seal by remember { mutableStateOf<OfdSealChoice?>(null) }
        var c2pa by remember { mutableStateOf(C2paChoice()) }
        val firstSignature = f.report?.signatures.isNullOrEmpty()
        var action by remember { mutableStateOf(ApprovalPoint().action) }
        var organization by remember { mutableStateOf("") }
        var unit by remember { mutableStateOf("") }
        var jobTitle by remember { mutableStateOf("") }
        var account by remember { mutableStateOf("") }
        var role by remember { mutableStateOf("") }
        var returned by remember { mutableStateOf(false) }
        when (form) {
            SignForm.PADES -> {
                SectionTitle(stringResource(Res.string.sign_step_level))
                LevelPicker("PAdES", level) { level = it }
                if (level.timestamp) Text(stringResource(Res.string.sign_tsa, tsaName), style = MaterialTheme.typography.bodySmall)
                if (level.revocation) Text(stringResource(Res.string.sign_lta_strict), style = MaterialTheme.typography.bodySmall)
                SectionTitle(stringResource(Res.string.sign_step_certify))
                if (firstSignature) {
                    CERTIFICATIONS.forEach { (p, title, detail) ->
                        Row(Modifier.fillMaxWidth().clickable { certification = p }, verticalAlignment = Alignment.CenterVertically) {
                            androidx.compose.material3.RadioButton(selected = p == certification, onClick = { certification = p })
                            Column {
                                Text(stringResource(title), style = MaterialTheme.typography.bodyMedium)
                                Text(stringResource(detail), style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                } else Text(stringResource(Res.string.sign_certify_unavailable), style = MaterialTheme.typography.bodySmall)
                SectionTitle(stringResource(Res.string.sign_step_visible))
                VisibleSignaturePicker(model, f, visible) { visible = it }
                CollapsibleSection(stringResource(Res.string.sign_reason_location), key = "sign-reason-${f.id}") {
                    OutlinedTextField(value = reason, onValueChange = { reason = it.take(100) }, label = { Text(stringResource(Res.string.sign_reason)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = location, onValueChange = { location = it.take(100) }, label = { Text(stringResource(Res.string.sign_location)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }
            }
            SignForm.APPROVAL -> {
                val case by produceState<FilesModel.ApprovalCase?>(null, f.id) { value = runCatching { model.files.approvalCase(f) }.getOrNull() }
                case?.let { c ->
                    InfoCard(stringResource(Res.string.sign_approval_scope), buildList {
                        add(if (c.approval != null) stringResource(Res.string.sign_approval_after, c.approval.name) else stringResource(Res.string.sign_approval_new))
                        add(stringResource(Res.string.sign_approval_covers, c.files.size) + c.files.joinToString(stringResource(Res.string.sep_list)) { it.name })
                        if (c.missing.isNotEmpty()) add(stringResource(Res.string.sign_approval_absent) + c.missing.joinToString(stringResource(Res.string.sep_list)))
                        add(stringResource(Res.string.sign_approval_note))
                    })
                }
                if (choice is SignerChoice.Wallet) {
                    VerdictCard(Verdict.CAUTION, stringResource(Res.string.sign_approval_wallet_key), listOf(
                        stringResource(Res.string.sign_approval_rules),
                        stringResource(Res.string.sign_approval_wallet_text),
                    ))
                }
                SectionTitle(stringResource(Res.string.sign_step_approval))
                WrapRow(spacing = 6.dp) {
                    ApprovalPoint.ACTIONS.forEach { a -> FilterChip(selected = a == action, onClick = { action = a }, label = { Text(a) }) }
                }
                OutlinedTextField(value = action, onValueChange = { action = it.trim().take(ApprovalPoint.ACTION_MAX) }, label = { Text(stringResource(Res.string.sign_change_kind)) },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = returned, onCheckedChange = { returned = it })
                    Text(stringResource(Res.string.sign_return))
                }
                OutlinedTextField(value = reason, onValueChange = { reason = it.take(500) }, label = { Text(stringResource(Res.string.sign_opinion)) }, modifier = Modifier.fillMaxWidth())
                SectionTitle(stringResource(Res.string.sign_step_person))
                OutlinedTextField(value = organization, onValueChange = { organization = it.take(60) }, label = { Text(stringResource(Res.string.sign_agency)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = unit, onValueChange = { unit = it.take(60) }, label = { Text(stringResource(Res.string.sign_unit)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = jobTitle, onValueChange = { jobTitle = it.take(60) }, label = { Text(stringResource(Res.string.sign_job_title)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = account, onValueChange = { account = it.take(60) }, label = { Text(stringResource(Res.string.sign_account)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = role, onValueChange = { role = it.take(60) }, label = { Text(stringResource(Res.string.sign_role)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Text(stringResource(Res.string.sign_person_note), style = MaterialTheme.typography.bodySmall)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = timestamp, onCheckedChange = { timestamp = it })
                    Text(stringResource(Res.string.sign_approval_timestamp, tsaName))
                }
            }
            SignForm.OPENPGP_DETACHED -> {
                Text(stringResource(Res.string.sign_pgp_level),
                    style = MaterialTheme.typography.bodySmall)
            }
            SignForm.OFD -> {
                OfdSignOptions(model, timestamp, tsaName) { timestamp = it }
                OfdSealPicker(model, f, seal) { seal = it }
            }
            SignForm.C2PA -> {
                val candidates by produceState(emptyList<IcaCandidate>(), f.id) { value = runCatching { model.files.icaCandidates() }.getOrDefault(emptyList()) }
                C2paSignOptions(f, c2pa, choice, timestamp, tsaName, candidates, { c2pa = it }, { timestamp = it })
            }
            else -> {
                SectionTitle(stringResource(Res.string.sign_step_level))
                LevelPicker(if (form == SignForm.XADES) "XAdES" else if (form == SignForm.ASIC) "ASiC-E" else "CAdES", level) { level = it }
                if (level.timestamp) Text(stringResource(Res.string.sign_tsa, tsaName), style = MaterialTheme.typography.bodySmall)
                if (level.archive) Text(stringResource(Res.string.sign_lta_lt), style = MaterialTheme.typography.bodySmall)
                else if (level.revocation) Text(stringResource(Res.string.sign_lt_only), style = MaterialTheme.typography.bodySmall)
            }
        }
        var details by remember { mutableStateOf(false) }
        TextButton(onClick = { details = !details }) { Text(if (details) stringResource(Res.string.action_hide_details) else stringResource(Res.string.technical_details)) }
        if (details) InfoCard(stringResource(Res.string.technical_details), signDetails(form, level, timestamp, certification.takeIf { form == SignForm.PADES && firstSignature }, visible != null, c2pa))
        val locked = form == SignForm.PADES && f.report?.signatures?.any { it.docMdp == 1 } == true
        val breakOk = if (locked) {
            VerdictCard(Verdict.FAIL, stringResource(Res.string.sign_certified_locked), listOf(stringResource(Res.string.sign_certified_locked_text)))
            riskOverride(
                f.id, stringResource(Res.string.sign_pades_anyway), stringResource(Res.string.sign_break_certification),
                listOf(stringResource(Res.string.sign_break_text_1), stringResource(Res.string.sign_break_text_2), stringResource(Res.string.sign_break_text_3)),
            )
        } else true
        FilesBusyLine(model, busy, error)
        CscPromptPanel(model)
        Button(onClick = { choice?.let { model.files.sign(
                    f, it, form, reason, location, timestamp, allowBreakingCertification = locked,
                    point = ApprovalPoint(
                        action.ifBlank { ApprovalPoint().action }, reason.ifBlank { null }, unit.ifBlank { null }, jobTitle.ifBlank { null }, role.ifBlank { null },
                        account.ifBlank { null }, organization.ifBlank { null }, returned,
                    ),
                    level = level, certification = certification.takeIf { form == SignForm.PADES && firstSignature },
                    visible = visible.takeIf { form == SignForm.PADES },
                    seal = seal.takeIf { form == SignForm.OFD },
                    c2pa = c2pa.takeIf { form == SignForm.C2PA },
                ) } }, enabled = choice != null && busy == null && breakOk) {
            Text(stringResource(Res.string.files_sign))
        }
    }
}

/**
 * Whether the PDF signature shows on a page, and where: the page (first, last or a number), a preset position and an
 * optional picture. The box is drawn over the page preview when that page has been rendered.
 */
@Composable
private fun VisibleSignaturePicker(model: WalletModel, f: StoredFile, value: VisibleSignature?, onChange: (VisibleSignature?) -> Unit) {
    val scope = rememberCoroutineScope()
    val total = (f.report?.pages ?: 1).coerceAtLeast(1)
    var pageText by remember(f.id) { mutableStateOf(total.toString()) }
    var imageNote by remember(f.id) { mutableStateOf<String?>(null) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = value != null, onCheckedChange = { on ->
            onChange(if (on) VisibleSignature(-1, PdfSignatureAppearance.Position.BOTTOM_RIGHT) else null)
            pageText = total.toString()
        })
        Text(stringResource(Res.string.sign_visible))
    }
    if (value == null) {
        Text(stringResource(Res.string.sign_invisible_note), style = MaterialTheme.typography.bodySmall)
        return
    }
    Text(stringResource(Res.string.sign_page_count, total), style = MaterialTheme.typography.bodyMedium)
    WrapRow(spacing = 6.dp) {
        FilterChip(selected = value.page == 0, onClick = { pageText = "1"; onChange(VisibleSignature(0, value.position, value.image)) }, label = { Text(stringResource(Res.string.sign_first_page)) })
        FilterChip(selected = value.page == -1 || value.page == total - 1, onClick = { pageText = total.toString(); onChange(VisibleSignature(-1, value.position, value.image)) }, label = { Text(stringResource(Res.string.sign_last_page)) })
        OutlinedTextField(
            value = pageText,
            onValueChange = { t ->
                pageText = t.filter { it.isDigit() }.take(5)
                pageText.toIntOrNull()?.takeIf { it in 1..total }?.let { onChange(VisibleSignature(it - 1, value.position, value.image)) }
            },
            label = { Text(stringResource(Res.string.sign_page_number)) }, singleLine = true, modifier = Modifier.width(110.dp),
        )
    }
    Text(stringResource(Res.string.sign_position), style = MaterialTheme.typography.bodyMedium)
    WrapRow(spacing = 6.dp) {
        PdfSignatureAppearance.Position.entries.forEach { pos ->
            FilterChip(selected = pos == value.position, onClick = { onChange(VisibleSignature(value.page, pos, value.image)) }, label = { Text(pos.title) })
        }
    }
    WrapRow() {
        OutlinedButton(onClick = {
            scope.launch {
                val picked = runCatching { model.platform.pickImage() }.getOrNull() ?: return@launch
                val img = runCatching { model.files.signatureImage(picked.bytes) }.getOrNull()
                imageNote = if (img == null) model.text(Res.string.sign_image_bad) else model.text(Res.string.sign_image_chosen) + picked.name
                if (img != null) onChange(VisibleSignature(value.page, value.position, img))
            }
        }) { Text(if (value.image == null) stringResource(Res.string.sign_add_image) else stringResource(Res.string.sign_change_image)) }
        if (value.image != null) TextButton(onClick = { imageNote = null; onChange(VisibleSignature(value.page, value.position, null)) }) { Text(stringResource(Res.string.sign_remove_image)) }
    }
    imageNote?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    Text(stringResource(Res.string.sign_box_text), style = MaterialTheme.typography.bodySmall)
    // The box over the page preview, when that page is among the rendered ones.
    val previews by model.files.previews.collectAsState()
    val pages = (previews[f.id] as? FilePreview.Pages)?.pages.orEmpty()
    val index = if (value.page < 0) total + value.page else value.page
    val look = PdfSignatureAppearance.preset(value.position, index, listOf("x"))
    pages.getOrNull(index)?.let { image ->
        BoxWithConstraints(Modifier.fillMaxWidth(0.6f)) {
            val w = maxWidth
            val h = w * (image.height.toFloat() / image.width.coerceAtLeast(1))
            Image(image, contentDescription = stringResource(Res.string.sign_page_n, index + 1), contentScale = ContentScale.FillWidth,
                modifier = Modifier.fillMaxWidth().height(h).border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(6.dp)))
            Box(
                Modifier.offset(x = w * look.x.toFloat(), y = h * look.y.toFloat())
                    .size(width = w * look.width.toFloat(), height = h * look.height.toFloat())
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.14f))
                    .border(2.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(3.dp)),
            )
        }
    }
}

/** A plain card with a title and lines (no verdict colours). */
@Composable
private fun InfoCard(title: String, lines: List<String>) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            lines.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/** DocMDP permissions a certification signature can carry: value, title and what it allows. */
private val CERTIFICATIONS = listOf(
    Triple(null, Res.string.certify_none, Res.string.certify_none_text),
    Triple(2, Res.string.certify_p2, Res.string.certify_p2_text),
    Triple(3, Res.string.certify_p3, Res.string.certify_p3_text),
    Triple(1, Res.string.certify_p1, Res.string.certify_p1_text),
)

/** The four baseline levels for [format], each with what it adds. */
@Composable
private fun LevelPicker(format: String, level: SignatureLevel, onPick: (SignatureLevel) -> Unit) {
    SignatureLevel.entries.forEach { l ->
        Row(Modifier.fillMaxWidth().clickable { onPick(l) }, verticalAlignment = Alignment.CenterVertically) {
            androidx.compose.material3.RadioButton(selected = l == level, onClick = { onPick(l) })
            Column {
                Text(l.title(format), style = MaterialTheme.typography.bodyMedium)
                Text(l.detail, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/**
 * Options of an OFD digital signature: the time stamp, what each key type produces, and making an SM2 key with a
 * self-issued certificate (saved as a PKCS#12 file, then chosen as the PKCS#12 signer) when the holder has none.
 */
@Composable
private fun OfdSignOptions(model: WalletModel, timestamp: Boolean, tsaName: String, onTimestamp: (Boolean) -> Unit) {
    Text(stringResource(Res.string.sign_ofd_keys), style = MaterialTheme.typography.bodySmall)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = timestamp, onCheckedChange = onTimestamp)
        Text(stringResource(Res.string.sign_ofd_timestamp, tsaName))
    }
    var open by remember { mutableStateOf(false) }
    var name by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    TextButton(onClick = { open = !open }) { Text(stringResource(Res.string.sign_sm2_make)) }
    if (open) {
        Text(stringResource(Res.string.sign_sm2_make_text), style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(value = name, onValueChange = { name = it.take(60) }, label = { Text(stringResource(Res.string.sign_sm2_name)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            value = password, onValueChange = { password = it.take(64) }, label = { Text(stringResource(Res.string.files_p12_password)) }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
        )
        OutlinedButton(onClick = { model.files.createSm2Pkcs12(name, password) }, enabled = password.length >= 6) { Text(stringResource(Res.string.sign_sm2_save)) }
    }
}

/**
 * Whether an OFD signature is an electronic seal (Type "Seal"), and which: one the wallet makes for the signing key
 * (name, round organisation or square personal seal, own picture, width) or an issued seal file (.esl) with what it
 * says; and where it is stamped (page and position).
 */
@Composable
private fun OfdSealPicker(model: WalletModel, f: StoredFile, value: OfdSealChoice?, onChange: (OfdSealChoice?) -> Unit) {
    val scope = rememberCoroutineScope()
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = value != null, onCheckedChange = { onChange(if (it) OfdSealChoice() else null) })
        Text(stringResource(Res.string.sign_ofd_seal))
    }
    if (value == null) {
        Text(stringResource(Res.string.sign_ofd_seal_off), style = MaterialTheme.typography.bodySmall)
        return
    }
    Text(stringResource(Res.string.sign_ofd_seal_sm2), style = MaterialTheme.typography.bodySmall)
    var note by remember(f.id) { mutableStateOf<String?>(null) }
    var fileMode by remember(f.id) { mutableStateOf(value.file != null) }
    WrapRow(spacing = 6.dp) {
        FilterChip(selected = !fileMode, onClick = { fileMode = false; note = null; onChange(value.copy(file = null, fileName = null)) }, label = { Text(stringResource(Res.string.sign_seal_make)) })
        FilterChip(selected = fileMode, onClick = { fileMode = true }, label = { Text(stringResource(Res.string.sign_seal_file)) })
    }
    if (!fileMode) {
        OutlinedTextField(value = value.name, onValueChange = { onChange(value.copy(name = it.take(24))) }, label = { Text(stringResource(Res.string.sign_seal_name)) },
            singleLine = true, modifier = Modifier.fillMaxWidth())
        WrapRow(spacing = 6.dp) {
            FilterChip(selected = !value.personal, onClick = { onChange(value.copy(personal = false, widthMm = 40.0)) }, label = { Text(stringResource(Res.string.sign_seal_org)) })
            FilterChip(selected = value.personal, onClick = { onChange(value.copy(personal = true, widthMm = 20.0)) }, label = { Text(stringResource(Res.string.sign_seal_person)) })
        }
        var widthText by remember(f.id, value.personal) { mutableStateOf(value.widthMm.toInt().toString()) }
        OutlinedTextField(
            value = widthText,
            onValueChange = { t ->
                widthText = t.filter { it.isDigit() }.take(3)
                widthText.toIntOrNull()?.takeIf { it in 5..150 }?.let { onChange(value.copy(widthMm = it.toDouble())) }
            },
            label = { Text(stringResource(Res.string.sign_seal_size)) }, singleLine = true, modifier = Modifier.width(140.dp),
        )
        WrapRow() {
            OutlinedButton(onClick = {
                scope.launch {
                    val picked = runCatching { model.platform.pickImage() }.getOrNull() ?: return@launch
                    val img = runCatching { model.files.signatureImage(picked.bytes) }.getOrNull()
                    note = if (img == null) model.text(Res.string.sign_image_bad) else model.text(Res.string.sign_image_chosen) + picked.name
                    if (img != null) onChange(value.copy(image = img))
                }
            }) { Text(stringResource(Res.string.sign_seal_own_image)) }
            if (value.image != null) TextButton(onClick = { note = null; onChange(value.copy(image = null)) }) { Text(stringResource(Res.string.sign_remove_image)) }
        }
        note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        val resolver = androidx.compose.ui.platform.LocalFontFamilyResolver.current
        val shown = value.name.trim().ifEmpty { stringResource(Res.string.sign_seal_sample_name) }
        val preview = remember(shown, value.personal, value.image) {
            value.image?.let { img -> model.platform.decodeImage(OfdShading.png(img.width, img.height, img.argb)) } ?: SealPicture.draw(shown, value.personal, resolver, 240)
        }
        preview?.let { Image(it, contentDescription = stringResource(Res.string.sign_seal_preview), modifier = Modifier.size(96.dp)) }
        Text(stringResource(Res.string.sign_seal_made_note), style = MaterialTheme.typography.bodySmall)
    } else {
        OutlinedButton(onClick = {
            scope.launch {
                val picked = runCatching { model.platform.pickFile() }.getOrNull() ?: return@launch
                if (DocumentSigning.ofdSealInfo(picked.bytes) == null) {
                    note = model.text(Res.string.sign_seal_bad)
                    onChange(value.copy(file = null, fileName = null))
                } else {
                    note = null
                    onChange(value.copy(file = picked.bytes, fileName = picked.name))
                }
            }
        }) { Text(stringResource(Res.string.sign_seal_pick)) }
        note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        val info = remember(value.file) { value.file?.let { DocumentSigning.ofdSealInfo(it) } }
        if (info != null) {
            fun day(t: Long?) = t?.let { kotlin.time.Instant.fromEpochSeconds(it).toString().take(10) } ?: "-"
            val kind = if (info.personal) stringResource(Res.string.sign_seal_type_person) else stringResource(Res.string.sign_seal_type_org)
            InfoCard(stringResource(Res.string.sign_seal_info_title) + (value.fileName?.let { "  $it" } ?: ""), listOf(
                stringResource(Res.string.sign_seal_info_name, info.name, kind),
                stringResource(Res.string.sign_seal_info_version, info.version),
                stringResource(Res.string.sign_seal_info_valid, day(info.validFrom), day(info.validTo)),
                stringResource(Res.string.sign_seal_info_maker, info.maker ?: "-"),
                if (info.signers == 0) stringResource(Res.string.sign_seal_info_any) else stringResource(Res.string.sign_seal_info_signers, info.signers),
            ))
            val pic = remember(value.file) { model.platform.decodeImage(info.picture) }
            pic?.let { Image(it, contentDescription = stringResource(Res.string.sign_seal_preview), modifier = Modifier.size(96.dp)) }
        }
    }
    // Where it is stamped.
    val total = (f.report?.pages ?: 1).coerceAtLeast(1)
    var pageText by remember(f.id) { mutableStateOf(total.toString()) }
    Text(stringResource(Res.string.sign_page_count, total), style = MaterialTheme.typography.bodyMedium)
    WrapRow(spacing = 6.dp) {
        FilterChip(selected = value.page == 0, onClick = { pageText = "1"; onChange(value.copy(page = 0)) }, label = { Text(stringResource(Res.string.sign_first_page)) })
        FilterChip(selected = value.page == -1 || value.page == total - 1, onClick = { pageText = total.toString(); onChange(value.copy(page = -1)) }, label = { Text(stringResource(Res.string.sign_last_page)) })
        OutlinedTextField(
            value = pageText,
            onValueChange = { t ->
                pageText = t.filter { it.isDigit() }.take(5)
                pageText.toIntOrNull()?.takeIf { it in 1..total }?.let { onChange(value.copy(page = it - 1)) }
            },
            label = { Text(stringResource(Res.string.sign_page_number)) }, singleLine = true, modifier = Modifier.width(110.dp),
        )
    }
    Text(stringResource(Res.string.sign_position), style = MaterialTheme.typography.bodyMedium)
    WrapRow(spacing = 6.dp) {
        PdfSignatureAppearance.Position.entries.forEach { pos ->
            FilterChip(selected = pos == value.position, onClick = { onChange(value.copy(position = pos)) }, label = { Text(pos.title) })
        }
    }
}

/** What the chosen form and options put in the signature, for the expandable technical details. */
@Composable
private fun signDetails(form: SignForm, level: SignatureLevel, timestamp: Boolean, certification: Int?, visible: Boolean = false, c2pa: C2paChoice = C2paChoice()): List<String> = when (form) {
    SignForm.C2PA -> buildList {
        add(stringResource(Res.string.tech_c2pa_1))
        add(stringResource(Res.string.tech_c2pa_2))
        if (c2pa.update) add(stringResource(Res.string.tech_c2pa_update))
        else if (c2pa.identity) add(stringResource(if (c2pa.c2paRsOrder) Res.string.tech_c2pa_identity_rs else Res.string.tech_c2pa_identity))
        if (!c2pa.update && c2pa.aggregation.isNotEmpty()) add(stringResource(if (c2pa.aggregationEdDsa) Res.string.tech_c2pa_ica_eddsa else Res.string.tech_c2pa_ica))
        if (!c2pa.update) add(stringResource(Res.string.tech_c2pa_multi))
        if (c2pa.compress) add(stringResource(Res.string.tech_c2pa_compress))
        if (timestamp) add(stringResource(Res.string.tech_c2pa_ts))
        add(stringResource(Res.string.tech_c2pa_rsa))
        add(stringResource(Res.string.tech_verify_after))
    }
    SignForm.PADES -> buildList {
        add(stringResource(Res.string.tech_pades_1))
        add(stringResource(Res.string.tech_pades_2))
        add(if (visible) stringResource(Res.string.tech_pades_visible)
            else stringResource(Res.string.tech_pades_invisible))
        certification?.let { add(stringResource(Res.string.tech_pades_certify, it)) }
        if (level.timestamp) add(stringResource(Res.string.tech_pades_bt))
        if (level.revocation) add(stringResource(Res.string.tech_pades_lt))
        if (level.archive) add(stringResource(Res.string.tech_pades_lta))
        add(stringResource(Res.string.tech_verify_after))
    }
    SignForm.APPROVAL -> listOf(
        stringResource(Res.string.tech_approval_1),
        stringResource(Res.string.tech_approval_2),
        stringResource(Res.string.tech_approval_3),
        stringResource(Res.string.tech_approval_4),
    ) + (if (timestamp) listOf(stringResource(Res.string.tech_approval_5)) else emptyList())
    SignForm.XADES -> buildList {
        add(stringResource(Res.string.tech_xades_1))
        if (level.timestamp) add(stringResource(Res.string.tech_xades_bt))
        if (level.revocation) add(stringResource(Res.string.tech_xades_lt))
        if (level.archive) add(stringResource(Res.string.tech_xades_lta))
    }
    SignForm.OFD -> buildList {
        add(stringResource(Res.string.tech_ofd_1))
        add(stringResource(Res.string.tech_ofd_2))
        if (timestamp) add(stringResource(Res.string.tech_ofd_ts))
        add(stringResource(Res.string.tech_verify_after))
    }
    SignForm.OPENPGP_DETACHED -> listOf(
        stringResource(Res.string.tech_pgp_1),
        stringResource(Res.string.tech_pgp_2),
        stringResource(Res.string.tech_pgp_3),
        stringResource(Res.string.tech_pgp_4),
    )
    else -> buildList {
        add(stringResource(Res.string.tech_cades_1))
        if (level.timestamp) add(stringResource(Res.string.tech_cades_bt))
        if (level.revocation) add(stringResource(Res.string.tech_cades_lt))
        if (level.archive) add(stringResource(Res.string.tech_cades_lta))
        if (form == SignForm.ASIC) add(stringResource(Res.string.tech_asic))
    }
}

// ---------------------------------------------------------------- preview

/** The content of [f]: PDF pages (with the password field of an encrypted PDF), a picture, or the text. */
@Composable
private fun FilePreviewSection(model: WalletModel, f: StoredFile) {
    val previews by model.files.previews.collectAsState()
    LaunchedEffect(f.id, f.sha256) { if (previews[f.id] == null) model.files.preview(f) }
    val p = previews[f.id]
    var password by remember(f.id) { mutableStateOf("") }
    var page by remember(f.id) { mutableStateOf(0) }
    var showText by remember(f.id) { mutableStateOf(false) }
    SectionTitle(stringResource(Res.string.files_preview))
    when (p) {
        null, FilePreview.Loading -> Text(stringResource(Res.string.files_preview_making), style = MaterialTheme.typography.bodySmall)
        is FilePreview.Pages -> {
            when (val r = p.entryExit) {
                is EntryExitCertificate -> EntryExitView(r)
                is MainlandEntryExitRecord -> MainlandEntryExitView(r)
                null -> {}
            }
            p.household?.let { HouseholdView(it) }
            when (val c = p.certificate) {
                is StudentStatusProof -> StudentStatusView(c)
                is MainlandPermitLink -> PermitLinkView(c)
                is ChinaInvoice -> InvoiceView(c)
                null -> {}
            }
            if (p.pages.isNotEmpty()) {
                val i = page.coerceIn(0, p.pages.lastIndex)
                val placements = f.report?.signaturePlacements.orEmpty()
                val signatures = f.report?.signatures.orEmpty()
                PreviewImage(p.pages[i], stringResource(Res.string.sign_page_n, i + 1), placements.filter { it.page == i }, signatures)
                WrapRow() {
                    TextButton(onClick = { page = i - 1 }, enabled = i > 0) { Text(stringResource(Res.string.files_prev_page)) }
                    Text(stringResource(Res.string.preview_page_of, i + 1, p.total), style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = { page = i + 1 }, enabled = i < p.pages.lastIndex) { Text(stringResource(Res.string.files_next_page)) }
                }
                SignaturePlacementLegend(placements, signatures, i, p.pages.size)
                if (p.systemFonts) Text(stringResource(Res.string.preview_system_fonts), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                if (p.total > p.pages.size) Text(stringResource(Res.string.preview_first_pages, p.pages.size), style = MaterialTheme.typography.bodySmall)
            } else {
                Text(stringResource(Res.string.preview_text_only), style = MaterialTheme.typography.bodySmall)
            }
            p.text?.let { t ->
                TextButton(onClick = { showText = !showText }) { Text(if (showText) stringResource(Res.string.preview_hide_text) else stringResource(Res.string.preview_show_text)) }
                if (showText || p.pages.isEmpty()) SelectableText(t)
            }
        }
        is FilePreview.Picture -> PreviewImage(p.image, f.name)
        is FilePreview.Passport -> PassportDataView(p.view) { pic, n, original -> model.files.exportPicture(pic, n, original) }
        is FilePreview.Text -> {
            SelectableText(p.text)
            if (p.truncated) Text(stringResource(Res.string.preview_text_limit, FilePreview.TEXT_LIMIT), style = MaterialTheme.typography.bodySmall)
        }
        is FilePreview.Official -> {
            OfficialDocumentView(p.document)
            TextButton(onClick = { showText = !showText }) { Text(if (showText) stringResource(Res.string.preview_hide_xml) else stringResource(Res.string.preview_show_xml)) }
            if (showText) {
                SelectableText(p.source)
                if (p.truncated) Text(stringResource(Res.string.preview_text_limit, FilePreview.TEXT_LIMIT), style = MaterialTheme.typography.bodySmall)
            }
        }
        is FilePreview.NeedsPassword -> {
            Text(if (p.wrong) stringResource(Res.string.pdf_wrong_password) else stringResource(Res.string.pdf_password_text),
                style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(value = password, onValueChange = { password = it.take(64) }, label = { Text(stringResource(Res.string.pdf_password)) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.weight(1f))
                Button(onClick = { model.files.preview(f, password) }, enabled = password.isNotBlank()) { Text(stringResource(Res.string.action_open)) }
            }
        }
        is FilePreview.Unavailable -> Text(p.reason, style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * A household transcript: the household's fields, then one person at a time with a switch between people; the
 * holder (matched by the national ID card or the saved ID number) comes first and is marked.
 */
@Composable
private fun HouseholdView(h: HouseholdTranscript) {
    var selected by remember(h) { mutableStateOf(0) }
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(h.title ?: stringResource(Res.string.household_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        if (h.household.isNotEmpty()) {
            Text(stringResource(Res.string.household_registration), style = MaterialTheme.typography.titleSmall)
            h.household.forEach { (k, v) -> if (k.isEmpty()) Text(v, style = MaterialTheme.typography.bodySmall) else LabelValue(k, v, small = true) }
        }
        Text(stringResource(Res.string.household_people, h.people.size), style = MaterialTheme.typography.titleSmall)
        if (!h.holderFound) {
            Text(stringResource(Res.string.household_no_holder), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline)
        }
        if (h.people.size > 1) {
            WrapRow() {
                h.people.forEachIndexed { i, person ->
                    FilterChip(
                        selected = i == selected,
                        onClick = { selected = i },
                        label = { Text((person.member.name ?: stringResource(Res.string.household_person, i + 1)) + if (person.holder) stringResource(Res.string.household_self) else "") },
                    )
                }
            }
        }
        val person = h.people[selected.coerceIn(0, h.people.lastIndex)]
        if (person.holder) Text(stringResource(Res.string.household_holder), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        person.fields.forEach { (k, v) -> if (k.isEmpty()) Text(v, style = MaterialTheme.typography.bodySmall) else LabelValue(k, v, small = true) }
    }
}

/** An entry and exit certificate laid out as its parts: the person, the certificate and the table of trips. */
@Composable
private fun EntryExitView(c: EntryExitCertificate) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(stringResource(Res.string.entry_exit_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        Text(stringResource(Res.string.section_personal), style = MaterialTheme.typography.titleSmall)
        c.name?.let { LabelValue(stringResource(Res.string.field_name), it, small = true) }
        c.englishName?.let { LabelValue(stringResource(Res.string.field_name_en), it, small = true) }
        c.nationality?.let { LabelValue(stringResource(Res.string.field_nationality), it, small = true) }
        c.gender?.let { LabelValue(stringResource(Res.string.field_sex), it, small = true) }
        c.idNumber?.let { LabelValue(stringResource(Res.string.field_passport_or_id), it, small = true) }
        c.birthDate?.let { LabelValue(stringResource(Res.string.field_birth_date), it.toString(), small = true) }
        Text(stringResource(Res.string.section_document), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        c.issuer?.let { LabelValue(stringResource(Res.string.field_issuing_authority), it, small = true) }
        c.serialNumber?.let { LabelValue(stringResource(Res.string.field_certificate_serial), it, small = true) }
        c.issuedAt?.let { LabelValue(stringResource(Res.string.field_issued_at), it, small = true) }
        if (c.periodFrom != null && c.periodTo != null) LabelValue(stringResource(Res.string.field_query_period), stringResource(Res.string.range_from_to, c.periodFrom.toString(), c.periodTo.toString()), small = true)
        c.pages?.let { LabelValue(stringResource(Res.string.files_pages), stringResource(Res.string.page_count, it), small = true) }
        Text(stringResource(Res.string.entry_exit_summary), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        LabelValue(stringResource(Res.string.field_record_count), stringResource(Res.string.record_count, c.trips.size), small = true)
        c.latestExit?.let { LabelValue(stringResource(Res.string.field_last_exit), it.toString(), small = true) }
        c.latestEntry?.let { LabelValue(stringResource(Res.string.field_last_entry), it.toString(), small = true) }
        c.returnedFromLatestTrip?.let { LabelValue(stringResource(Res.string.field_latest_exit), if (it) stringResource(Res.string.entry_back) else stringResource(Res.string.entry_not_back), small = true) }
        c.inTaiwanAtEnd?.let { LabelValue(stringResource(Res.string.as_of, c.coveredUntil.toString()), if (it) stringResource(Res.string.entry_inside) else stringResource(Res.string.entry_outside), small = true) }
        if (c.trips.isNotEmpty()) {
            Text(stringResource(Res.string.entry_exit_records), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
            Row(Modifier.fillMaxWidth()) {
                Text(stringResource(Res.string.field_item_no), style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(0.6f))
                Text(stringResource(Res.string.field_exit_date), style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.2f))
                Text(stringResource(Res.string.field_entry_date), style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.2f))
            }
            HorizontalDivider()
            c.trips.forEach { t ->
                Row(Modifier.fillMaxWidth()) {
                    Text(t.item.toString(), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(0.6f))
                    Text(t.exit?.toString() ?: stringResource(Res.string.value_none), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1.2f))
                    Text(t.entry?.toString() ?: stringResource(Res.string.entry_not_back), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1.2f))
                }
            }
        }
    }
}

/** A proof of student status laid out as its parts: the student, the study, the issuing office and verification. */
@Composable
private fun StudentStatusView(c: StudentStatusProof) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(c.title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        c.number?.let { Text("NO. $it", style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center) }
        Text(stringResource(Res.string.section_student), style = MaterialTheme.typography.titleSmall)
        c.name?.let { LabelValue(stringResource(Res.string.field_name), it, small = true) }
        c.englishName?.let { LabelValue(stringResource(Res.string.field_name_en), it, small = true) }
        c.gender?.let { LabelValue(stringResource(Res.string.field_sex), it, small = true) }
        c.birthDate?.let { LabelValue(stringResource(Res.string.field_birth_date), it.toString(), small = true) }
        c.studentId?.let { LabelValue(stringResource(Res.string.field_student_id), it, small = true) }
        c.idNumber?.let { LabelValue(stringResource(Res.string.field_id_number), it, small = true) }
        Text(stringResource(Res.string.section_enrolment), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        c.school?.let { LabelValue(stringResource(Res.string.field_school), it, small = true) }
        LabelValue(stringResource(Res.string.field_status), stringResource(Res.string.enrolment_status), small = true)
        c.enrolled?.let { LabelValue(stringResource(Res.string.field_enrolled), it, small = true) }
        c.college?.let { LabelValue(stringResource(Res.string.field_college), it + (c.collegeEnglish?.let { e -> "\n$e" } ?: ""), small = true) }
        c.major?.let { LabelValue(stringResource(Res.string.field_major), it + (c.majorEnglish?.let { e -> "\n$e" } ?: ""), small = true) }
        c.programme?.let { LabelValue(stringResource(Res.string.field_program), it + (c.programmeEnglish?.let { e -> "\n$e" } ?: ""), small = true) }
        Text(stringResource(Res.string.section_issuer), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        c.office?.let { LabelValue(stringResource(Res.string.field_unit), it + (c.officeEnglish?.let { e -> "\n$e" } ?: ""), small = true) }
        c.printDate?.let { LabelValue(stringResource(Res.string.field_print_date), it.toString(), small = true) }
        c.address?.let { LabelValue(stringResource(Res.string.field_address), it + (c.zipCode?.let { z -> stringResource(Res.string.postal_code, z) } ?: ""), small = true) }
        c.phone?.let { LabelValue(stringResource(Res.string.field_phone), it, small = true) }
        c.contactPhone?.let { LabelValue(stringResource(Res.string.field_enquiry_phone), it, small = true) }
        c.email?.let { LabelValue(stringResource(Res.string.field_email), it, small = true) }
        c.website?.let { LabelValue(stringResource(Res.string.field_website), it, small = true) }
        if (c.verificationCode != null || c.verificationUrl != null) {
            Text(stringResource(Res.string.section_verification), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
            c.verificationCode?.let { LabelValue(stringResource(Res.string.field_verify_key), it, small = true) }
            c.verificationUrl?.let { LabelValue(stringResource(Res.string.field_verify_url), it, small = true) }
            Text(stringResource(Res.string.enrolment_verify_note),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        }
    }
}

/**
 * A mainland China permit association laid out as its parts: the person, the documents linked to them (travel
 * permit with its expiry, residence permit) and the record with the last day it is valid.
 */
@Composable
private fun PermitLinkView(c: MainlandPermitLink) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(stringResource(Res.string.permits_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        Text(stringResource(Res.string.section_personal), style = MaterialTheme.typography.titleSmall)
        c.name?.let { LabelValue(stringResource(Res.string.field_name), it, small = true) }
        c.gender?.let { LabelValue(stringResource(Res.string.field_sex), it, small = true) }
        c.birthDate?.let { LabelValue(stringResource(Res.string.field_birth_date), it.toString(), small = true) }
        c.residentOf?.let { LabelValue(stringResource(Res.string.field_identity), stringResource(Res.string.permits_resident, it), small = true) }
        Text(stringResource(Res.string.permits_held), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        if (c.permits.isEmpty()) Text(stringResource(Res.string.permits_unreadable), style = MaterialTheme.typography.bodySmall)
        c.permits.forEach { p -> LabelValue(p.name, p.number + (p.validUntil?.let { stringResource(Res.string.permits_valid_until, it) } ?: ""), small = true) }
        if (c.travelPermit != null && c.residencePermit != null) {
            Text(stringResource(Res.string.permits_same_person), style = MaterialTheme.typography.bodySmall)
        }
        Text(stringResource(Res.string.section_document), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        LabelValue(stringResource(Res.string.field_issuing_authority), c.issuer, small = true)
        c.number?.let { LabelValue(stringResource(Res.string.field_number), it, small = true) }
        c.queryDate?.let { LabelValue(stringResource(Res.string.field_query_date), it.toString(), small = true) }
        c.validUntil?.let { LabelValue(stringResource(Res.string.field_valid_until), stringResource(Res.string.permits_valid_days, it, c.validDays.toString()), small = true) }
        c.pages?.let { LabelValue(stringResource(Res.string.files_pages), stringResource(Res.string.page_count, it), small = true) }
    }
}

/**
 * A mainland China electronic invoice laid out as its parts: the invoice, the buyer, the seller and the amounts.
 * Whether it is genuine is for the tax authority's verification platform to say; the note says so.
 */
@Composable
private fun InvoiceView(c: ChinaInvoice) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(c.kind, style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        c.number?.let { LabelValue(stringResource(Res.string.invoice_number), it, small = true) }
        c.code?.let { LabelValue(stringResource(Res.string.invoice_code), it, small = true) }
        c.issueDate?.let { LabelValue(stringResource(Res.string.invoice_date), it.toString(), small = true) }
        c.checkCode?.let { LabelValue(stringResource(Res.string.invoice_check_code), it, small = true) }
        if (c.buyerName != null || c.buyerTaxId != null) {
            Text(stringResource(Res.string.invoice_buyer), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
            c.buyerName?.let { LabelValue(stringResource(Res.string.invoice_party_name), it, small = true) }
            c.buyerTaxId?.let { LabelValue(stringResource(Res.string.invoice_tax_id), it, small = true) }
        }
        if (c.sellerName != null || c.sellerTaxId != null) {
            Text(stringResource(Res.string.invoice_seller), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
            c.sellerName?.let { LabelValue(stringResource(Res.string.invoice_party_name), it, small = true) }
            c.sellerTaxId?.let { LabelValue(stringResource(Res.string.invoice_tax_id), it, small = true) }
        }
        Text(stringResource(Res.string.invoice_amounts), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        if (c.items.isNotEmpty()) LabelValue(stringResource(Res.string.invoice_items), c.items.joinToString("\n"), small = true)
        c.amount?.let { LabelValue(stringResource(Res.string.invoice_amount), it, small = true) }
        c.tax?.let { LabelValue(stringResource(Res.string.invoice_tax), it, small = true) }
        c.total?.let { LabelValue(stringResource(Res.string.invoice_total), it, small = true) }
        c.totalInWords?.let { LabelValue(stringResource(Res.string.invoice_total_words), it, small = true) }
        c.issuedBy?.let { LabelValue(stringResource(Res.string.invoice_issued_by), it, small = true) }
        Text(stringResource(Res.string.invoice_verify_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
    }
}

/**
 * A mainland China entry and exit record laid out as its parts: the person, the record and every movement of the
 * queried period, latest first (出境 leaves mainland China, 入境 arrives).
 */
@Composable
private fun MainlandEntryExitView(c: MainlandEntryExitRecord) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(stringResource(Res.string.china_movements_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        Text(stringResource(Res.string.section_personal), style = MaterialTheme.typography.titleSmall)
        c.name?.let { LabelValue(stringResource(Res.string.field_name), it, small = true) }
        c.gender?.let { LabelValue(stringResource(Res.string.field_sex), it, small = true) }
        c.birthDate?.let { LabelValue(stringResource(Res.string.field_birth_date), it.toString(), small = true) }
        c.documentNumber?.let { LabelValue((c.documentLabel ?: stringResource(Res.string.field_document)) + stringResource(Res.string.field_number_short), it, small = true) }
        Text(stringResource(Res.string.section_document), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        LabelValue(stringResource(Res.string.field_issuing_authority), c.issuer, small = true)
        c.number?.let { LabelValue(stringResource(Res.string.field_number), it, small = true) }
        c.queryDate?.let { LabelValue(stringResource(Res.string.field_query_date), it.toString(), small = true) }
        if (c.periodFrom != null && c.periodTo != null) LabelValue(stringResource(Res.string.field_query_period), stringResource(Res.string.range_from_to, c.periodFrom.toString(), c.periodTo.toString()), small = true)
        c.madeAt?.let { LabelValue(stringResource(Res.string.field_made_date), it, small = true) }
        c.pages?.let { LabelValue(stringResource(Res.string.files_pages), stringResource(Res.string.page_count, it), small = true) }
        Text(stringResource(Res.string.china_movements_summary), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        LabelValue(stringResource(Res.string.field_record_count), stringResource(Res.string.record_count, c.movements.size), small = true)
        c.latestArrival?.let { LabelValue(stringResource(Res.string.china_last_entry), it.toString(), small = true) }
        c.latestDeparture?.let { LabelValue(stringResource(Res.string.china_last_exit), it.toString(), small = true) }
        c.insideAtEnd?.let { LabelValue(stringResource(Res.string.as_of, c.coveredUntil.toString()), if (it) stringResource(Res.string.china_inside) else stringResource(Res.string.china_outside), small = true) }
        if (c.movements.isNotEmpty()) {
            Text(stringResource(Res.string.china_movements_records), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
            Row(Modifier.fillMaxWidth()) {
                Text(stringResource(Res.string.field_serial_no), style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(0.5f))
                Text(stringResource(Res.string.field_direction), style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(0.6f))
                Text(stringResource(Res.string.field_date), style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.1f))
                Text(stringResource(Res.string.field_port_flight), style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.6f))
            }
            HorizontalDivider()
            c.movements.forEach { m ->
                Row(Modifier.fillMaxWidth()) {
                    Text(m.item.toString(), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(0.5f))
                    Text(if (m.arrival) stringResource(Res.string.direction_entry) else stringResource(Res.string.direction_exit), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(0.6f))
                    Text(m.date.toString(), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1.1f))
                    Text(listOfNotNull(m.port, m.flight).joinToString(" ").ifEmpty { stringResource(Res.string.value_not_recorded) }, style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1.6f))
                }
            }
        }
    }
}

/**
 * An official document as it reads on paper: the agency and type on top, then its fields, subject and numbered
 * paragraphs, nested parts (such as each co-signing agency) and, for an online approval file, the planned flow and
 * every signing point.
 */
@Composable
private fun OfficialDocumentView(doc: OfficialDocument) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(doc.title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
        doc.sections.forEach { section ->
            section.title?.let { Text(it, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp)) }
            section.entries.forEach { e ->
                when (e) {
                    is OfficialEntry.Field -> LabelValue(e.label, e.value)
                    is OfficialEntry.Paragraph -> OfficialParagraphView(e)
                }
            }
        }
        if (doc.flow.isNotEmpty()) {
            Text(stringResource(Res.string.approval_flow), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp))
            doc.flow.forEachIndexed { i, node ->
                Text("${i + 1}. ${node.name}" + (node.action?.takeIf { it != node.name }?.let { stringResource(Res.string.parenthesized, it) } ?: ""),
                    style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = (node.depth * 16).dp))
            }
        }
        doc.steps.forEachIndexed { i, step ->
            Column(
                Modifier.fillMaxWidth().padding(top = 6.dp).background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp)).padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(stringResource(Res.string.approval_point, i + 1) + listOfNotNull(step.action, step.point?.takeIf { it != step.action }).joinToString("・"),
                    style = MaterialTheme.typography.titleSmall)
                step.signer?.let { LabelValue(stringResource(Res.string.approval_person), it + (step.role?.let { r -> stringResource(Res.string.parenthesized, r) } ?: "")) }
                step.time?.let { LabelValue(stringResource(Res.string.approval_time), it, small = true) }
                step.opinions.forEach { LabelValue(stringResource(Res.string.approval_opinion), it) }
                if (step.next.isNotEmpty()) LabelValue(stringResource(Res.string.approval_next), step.next.joinToString(stringResource(Res.string.sep_list)), small = true)
                step.certificate?.let { LabelValue(stringResource(Res.string.approval_cert), it, small = true) }
                if (step.drafts.isNotEmpty()) LabelValue(stringResource(Res.string.approval_drafts), step.drafts.joinToString(stringResource(Res.string.sep_list)), small = true)
                if (step.files.isNotEmpty()) LabelValue(stringResource(Res.string.label_file), step.files.joinToString("\n"), small = true)
            }
        }
    }
}

@Composable
private fun OfficialParagraphView(p: OfficialEntry.Paragraph) {
    Column(Modifier.fillMaxWidth().padding(top = 4.dp)) {
        val line = (p.heading?.trim().orEmpty() + p.text.orEmpty()).ifEmpty { null }
        line?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        p.items.forEach { OfficialItemView(it, 1) }
    }
}

@Composable
private fun OfficialItemView(item: OfficialItem, depth: Int) {
    Row(Modifier.fillMaxWidth().padding(start = (depth * 14).dp)) {
        item.number?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        Text(item.text ?: "", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
    }
    item.items.forEach { OfficialItemView(it, depth + 1) }
}

@Composable
private fun PreviewImage(
    image: ImageBitmap,
    description: String,
    placements: List<SignaturePlacementInfo> = emptyList(),
    signatures: List<SignatureInfo> = emptyList(),
) {
    val visible = placements.filter { it.visible }
    if (visible.isEmpty()) {
        Image(
            image, contentDescription = description, contentScale = ContentScale.FillWidth,
            modifier = Modifier.fillMaxWidth().aspectRatio(image.width.toFloat() / image.height.coerceAtLeast(1))
                .clip(RoundedCornerShape(8.dp)).border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)),
        )
        return
    }
    // Frame each visible signature over the rendered page; the frame colour follows the signature's verdict.
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val w = maxWidth
        val h = w * (image.height.toFloat() / image.width.coerceAtLeast(1))
        Image(
            image, contentDescription = description, contentScale = ContentScale.FillWidth,
            modifier = Modifier.fillMaxWidth().height(h)
                .clip(RoundedCornerShape(8.dp)).border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)),
        )
        visible.forEach { pl ->
            val verdict = signatures.firstOrNull { it.label == pl.label }?.verdict
            val color = when (verdict) {
                DocumentVerdict.VALID -> MaterialTheme.colorScheme.primary
                DocumentVerdict.INVALID -> MaterialTheme.colorScheme.error
                else -> MaterialTheme.colorScheme.tertiary
            }
            Box(
                Modifier.offset(x = w * pl.x0, y = h * pl.y0)
                    .size(width = (w * (pl.x1 - pl.x0)).coerceAtLeast(6.dp), height = (h * (pl.y1 - pl.y0)).coerceAtLeast(6.dp))
                    .border(2.dp, color, RoundedCornerShape(3.dp)),
            )
        }
    }
}

/** Which signatures sit on the page now shown, and which are invisible, so the frames above are readable. */
@Composable
private fun SignaturePlacementLegend(placements: List<SignaturePlacementInfo>, signatures: List<SignatureInfo>, page: Int, previewPages: Int) {
    if (placements.isEmpty()) return
    val onPage = placements.filter { it.page == page && it.visible }
    val invisible = placements.filter { !it.visible }
    if (onPage.isNotEmpty()) {
        Text(stringResource(Res.string.preview_visible_here) + onPage.joinToString(stringResource(Res.string.sep_list)) { it.label }, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    val otherPages = placements.filter { it.visible && it.page != page }.map { it.page }.distinct().sorted()
    if (otherPages.isNotEmpty()) {
        Text(stringResource(Res.string.preview_other_pages) + otherPages.joinToString(stringResource(Res.string.sep_list)) { (it + 1).toString() } + stringResource(Res.string.preview_pages_tail) +
            (if (otherPages.any { it >= previewPages }) stringResource(Res.string.preview_some_outside) else ""),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
    }
    if (invisible.isNotEmpty()) {
        Text(stringResource(Res.string.preview_invisible) + invisible.joinToString(stringResource(Res.string.sep_list)) { it.label },
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
    }
}

@Composable
private fun SelectableText(text: String) {
    SelectionContainer {
        Text(text, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            modifier = Modifier.fillMaxWidth().heightIn(max = 480.dp).verticalScroll(rememberScrollState())
                .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp)).padding(10.dp))
    }
}

// ---------------------------------------------------------------- OpenCerts

@Composable
private fun methodText(m: OaMethod): String = when (m) {
    OaMethod.DOCUMENT_STORE -> stringResource(Res.string.oa_document_store)
    OaMethod.TOKEN_REGISTRY -> stringResource(Res.string.oa_token_registry)
    OaMethod.DID -> stringResource(Res.string.oa_did)
    OaMethod.NONE -> stringResource(Res.string.value_not_given)
}

/**
 * An OpenCerts certificate: integrity, the online check of issuance and issuer identity (checked again when opened
 * after a while, or on request), and what the certificate shows: recipient, main fields, issuers, signatories,
 * transcript, images, attachments and the remaining fields with readable labels.
 */
/** Content credentials of a picture: what each manifest says and the checks in the C2PA specification's codes. */
@Composable
private fun C2paSection(model: WalletModel, f: StoredFile, c: C2paInfo) {
    SectionTitle(stringResource(Res.string.c2pa_title))
    Text(stringResource(Res.string.c2pa_text, c.container), style = MaterialTheme.typography.bodySmall)
    c.manifests.forEach { m ->
        val failed = m.statuses.any { !it.success && !it.informational && (it.code.endsWith("mismatch") || it.code == "assertion.missing" || it.code == "claimSignature.missing") }
        val trusted = m.statuses.any { it.code == "signingCredential.trusted" }
        CollapsibleSection(if (m.active) stringResource(Res.string.c2pa_active) else stringResource(Res.string.c2pa_ingredient_manifest), initiallyExpanded = m.active, key = "c2pa-${f.id}-${m.label}") {
            VerdictPill(
                when { failed -> Verdict.FAIL; trusted -> Verdict.PASS; else -> Verdict.CAUTION },
                when { failed -> stringResource(Res.string.c2pa_invalid); trusted -> stringResource(Res.string.c2pa_trusted); else -> stringResource(Res.string.c2pa_untrusted) },
            )
            m.title?.let { LabelValue(stringResource(Res.string.files_title), it, small = true) }
            m.signer?.let { LabelValue(stringResource(Res.string.files_signer), it, small = true) }
            m.signedAt?.let { LabelValue(stringResource(Res.string.c2pa_timestamp), localTime(it), small = true) }
            m.generator?.let { LabelValue(stringResource(Res.string.c2pa_generator), it, small = true) }
            m.format?.let { LabelValue(stringResource(Res.string.credential_format), it, small = true) }
            if (m.authors.isNotEmpty()) LabelValue(stringResource(Res.string.c2pa_author), m.authors.joinToString(stringResource(Res.string.sep_list)), small = true)
            m.actions.forEach { a ->
                LabelValue(stringResource(Res.string.c2pa_actions), listOfNotNull(a.action, a.digitalSourceType?.let { stringResource(Res.string.c2pa_source, it) }, a.softwareAgent, a.description, a.time).joinToString(stringResource(Res.string.sep_comma)), small = true)
            }
            m.ingredients.forEach { i ->
                LabelValue(stringResource(Res.string.c2pa_ingredients), listOfNotNull(i.title, i.relationship, i.format).joinToString(stringResource(Res.string.sep_comma)) + if (i.manifest != null) stringResource(Res.string.c2pa_has_manifest) else "", small = true)
            }
            m.identities.forEach { id -> CawgIdentityCard(model, f, m.label, id) }
            m.training.forEach { LabelValue(stringResource(Res.string.c2pa_training), it, small = true) }
            CollapsibleSection(stringResource(Res.string.technical_details), m.statuses.size, key = "c2pa-detail-${f.id}-${m.label}") {
                LabelValue("Manifest", m.label, small = true)
                LabelValue(stringResource(Res.string.c2pa_claim_version), "v${m.claimVersion}", small = true)
                m.instanceId?.let { LabelValue("instanceID", it, small = true) }
                LabelValue(stringResource(Res.string.c2pa_assertions), m.assertions.joinToString(stringResource(Res.string.sep_list)), small = true)
                m.statuses.forEach { StatusLine(it) }
            }
        }
    }
}

/** One C2PA or CAWG status code with its explanation: failures in the error colour, informational codes plain. */
@Composable
private fun StatusLine(s: diw.wallet.core.document.c2pa.C2paStatus) {
    Text(s.code + (s.explanation?.let { stringResource(Res.string.colon_value, it) } ?: ""), style = MaterialTheme.typography.bodySmall,
        color = if (s.success || s.informational) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error)
}

/**
 * A CAWG identity assertion: who the named actor is, the roles and the verdict in CAWG terms (trusted, well-formed
 * without a root of trust, or failed), the X.509 signature as a signature card or the identities an aggregator
 * verified, and the status codes.
 */
@Composable
private fun CawgIdentityCard(model: WalletModel, f: StoredFile, manifest: String, id: diw.wallet.core.document.c2pa.C2paIdentity) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(stringResource(Res.string.cawg_identity_title), style = MaterialTheme.typography.titleSmall)
            VerdictPill(
                checkVerdict(id.signature),
                when (id.signature) {
                    Check.PASS -> stringResource(Res.string.cawg_trusted)
                    Check.WARN -> stringResource(Res.string.cawg_well_formed)
                    else -> stringResource(Res.string.cawg_invalid)
                },
            )
            LabelValue(stringResource(Res.string.cawg_named_actor), id.names.joinToString(stringResource(Res.string.sep_list)).ifEmpty { stringResource(Res.string.c2pa_no_name) }, small = true)
            LabelValue(stringResource(Res.string.cawg_sig_type), id.sigType.ifEmpty { "-" }, small = true)
            if (id.roles.isNotEmpty()) {
                val roles = id.roles.map { cawgRole(it) }
                LabelValue(stringResource(Res.string.cawg_roles), roles.joinToString(stringResource(Res.string.sep_list)), small = true)
            }
            id.issuer?.let { LabelValue(stringResource(Res.string.cawg_issuer), it, small = true) }
            id.issuerTrust?.let { t ->
                val d = t.decision()
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TierBadge(d)
                    d.anchorName?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            }
            id.verifiedIdentities.forEach { v ->
                LabelValue(cawgIdentityType(v.type), listOfNotNull(v.name, v.username, v.address, v.uri, v.providerName?.let { stringResource(Res.string.cawg_provider, it) }, v.verifiedAt)
                    .joinToString(stringResource(Res.string.sep_comma)), small = true)
            }
            id.validFrom?.let { LabelValue(stringResource(Res.string.cawg_valid_from), it, small = true) }
            id.validUntil?.let { LabelValue(stringResource(Res.string.cawg_valid_until), it, small = true) }
            if (id.referenced.isNotEmpty()) LabelValue(stringResource(Res.string.cawg_referenced), id.referenced.joinToString(stringResource(Res.string.sep_list)), small = true)
            id.detail.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            id.x509?.let { SignatureCard(model, it, 0, 1) }
            CollapsibleSection(stringResource(Res.string.technical_details), id.statuses.size, key = "cawg-${f.id}-$manifest-${id.label}") {
                id.label?.let { LabelValue(stringResource(Res.string.cawg_label), it, small = true) }
                id.statuses.forEach { StatusLine(it) }
            }
        }
    }
}

@Composable
private fun cawgRole(role: String): String = when (role) {
    "cawg.creator" -> stringResource(Res.string.cawg_role_creator)
    "cawg.contributor" -> stringResource(Res.string.cawg_role_contributor)
    "cawg.editor" -> stringResource(Res.string.cawg_role_editor)
    "cawg.producer" -> stringResource(Res.string.cawg_role_producer)
    "cawg.publisher" -> stringResource(Res.string.cawg_role_publisher)
    "cawg.sponsor" -> stringResource(Res.string.cawg_role_sponsor)
    "cawg.translator" -> stringResource(Res.string.cawg_role_translator)
    else -> role
}

@Composable
private fun cawgIdentityType(type: String): String = when (type) {
    "cawg.document_verification" -> stringResource(Res.string.cawg_type_document)
    "cawg.web_site" -> stringResource(Res.string.cawg_type_web_site)
    "cawg.affiliation" -> stringResource(Res.string.cawg_type_affiliation)
    "cawg.social_media" -> stringResource(Res.string.cawg_type_social)
    "cawg.crypto_wallet" -> stringResource(Res.string.cawg_type_crypto)
    else -> type
}

/**
 * What the file declares about AI generation and watermarks, read offline: digital source types in its C2PA actions
 * and XMP, soft binding assertions, and SynthID mentions. Nothing is detected in the content; Google's SynthID site
 * can check the file itself after the holder uploads it there.
 */
@Composable
private fun AiProvenanceSection(model: WalletModel, ai: diw.wallet.core.document.c2pa.AiProvenance?) {
    SectionTitle(stringResource(Res.string.ai_title))
    InfoPill(stringResource(Res.string.ai_declared_only))
    if (ai == null || (ai.declarations.isEmpty() && ai.softBindings.isEmpty() && ai.synthIdHints.isEmpty())) {
        Text(stringResource(Res.string.ai_nothing), style = MaterialTheme.typography.bodySmall)
    } else {
        when {
            ai.aiDeclared -> VerdictPill(Verdict.CAUTION, stringResource(Res.string.ai_generated_declared))
            ai.syntheticDeclared -> VerdictPill(Verdict.CAUTION, stringResource(Res.string.ai_synthetic_declared))
            else -> Text(stringResource(Res.string.ai_no_ai_declared), style = MaterialTheme.typography.bodySmall)
        }
        ai.declarations.forEach { d ->
            val where = if (d.source == "xmp") stringResource(Res.string.ai_source_xmp)
                else stringResource(Res.string.ai_source_c2pa, d.manifest ?: "-") + when (d.signed) {
                    true -> stringResource(Res.string.ai_signed)
                    false -> stringResource(Res.string.ai_unsigned)
                    null -> ""
                }
            LabelValue(stringResource(Res.string.ai_source_type), listOfNotNull(d.code, d.tool, where).joinToString(stringResource(Res.string.sep_comma)), small = true)
        }
        if (ai.aiTools.isNotEmpty()) LabelValue(stringResource(Res.string.ai_tools), ai.aiTools.joinToString(stringResource(Res.string.sep_list)), small = true)
        ai.softBindings.forEach { b ->
            LabelValue(stringResource(Res.string.ai_soft_binding), listOfNotNull(b.alg, b.type, b.description, if (b.registered) null else stringResource(Res.string.ai_unregistered))
                .joinToString(stringResource(Res.string.sep_comma)), small = true)
        }
        if (ai.synthIdDeclared) Text(stringResource(Res.string.ai_synthid_named, ai.synthIdHints.joinToString(stringResource(Res.string.sep_list))), style = MaterialTheme.typography.bodySmall)
        else if (ai.googleAi) Text(stringResource(Res.string.ai_synthid_google), style = MaterialTheme.typography.bodySmall)
    }
    Text(stringResource(Res.string.ai_synthid_explain), style = MaterialTheme.typography.bodySmall)
    OutlinedButton(onClick = { model.platform.openBrowser(SYNTHID_URL) }) { Text(stringResource(Res.string.ai_synthid_check)) }
    Text(stringResource(Res.string.ai_synthid_privacy), style = MaterialTheme.typography.bodySmall)
}

/** Google's SynthID Detector, where a signed-in user uploads a file to check for a SynthID watermark. */
private const val SYNTHID_URL = "https://synthid.com/"

/**
 * Options of a C2PA manifest: how the file was made (signed as it was, or created with an IPTC digital source type),
 * the CAWG identity assertion and roles, the AI training choice, which key signs the claim, the time stamp and the
 * non-standard c2pa-rs encoding; for a file with content credentials, an update manifest instead (no hard binding,
 * how-made or identity); Brotli compression for a file that embeds the manifest; the held credentials ([candidates])
 * the wallet vouches for as identity claims aggregator; with a warning that validators expect C2PA and CAWG
 * certificate profiles.
 */
@Composable
private fun C2paSignOptions(
    f: StoredFile, value: C2paChoice, choice: SignerChoice?, timestamp: Boolean, tsaName: String, candidates: List<IcaCandidate>,
    onChange: (C2paChoice) -> Unit, onTimestamp: (Boolean) -> Unit,
) {
    val sidecar = f.name.substringAfterLast('.', "").lowercase() !in C2PA_EMBEDDABLE
    Text(if (sidecar) stringResource(Res.string.c2pa_sign_sidecar, f.name.substringBeforeLast('.') + ".c2pa") else stringResource(Res.string.c2pa_sign_embedded), style = MaterialTheme.typography.bodySmall)
    val hasManifest = f.report?.c2pa != null
    if (hasManifest) {
        Text(stringResource(Res.string.c2pa_sign_keeps), style = MaterialTheme.typography.bodySmall)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = value.update, onCheckedChange = { onChange(value.copy(update = it)) })
            Column {
                Text(stringResource(Res.string.c2pa_sign_update))
                Text(stringResource(Res.string.c2pa_sign_update_text), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    val update = value.update && hasManifest
    if (!update) {
        C2paMadeAndIdentity(value, onChange)
        C2paAggregation(value, candidates, onChange)
    }
    SectionTitle(stringResource(Res.string.c2pa_sign_training))
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        FilterChip(selected = value.allowTraining == null, onClick = { onChange(value.copy(allowTraining = null)) }, label = { Text(stringResource(Res.string.c2pa_sign_training_none)) })
        FilterChip(selected = value.allowTraining == false, onClick = { onChange(value.copy(allowTraining = false)) }, label = { Text(stringResource(Res.string.c2pa_sign_training_no)) })
        FilterChip(selected = value.allowTraining == true, onClick = { onChange(value.copy(allowTraining = true)) }, label = { Text(stringResource(Res.string.c2pa_sign_training_yes)) })
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = timestamp, onCheckedChange = onTimestamp)
        Text(stringResource(Res.string.c2pa_sign_timestamp, tsaName))
    }
    if (!sidecar) Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = value.compress, onCheckedChange = { onChange(value.copy(compress = it)) })
        Column {
            Text(stringResource(Res.string.c2pa_sign_compress))
            Text(stringResource(Res.string.c2pa_sign_compress_text), style = MaterialTheme.typography.bodySmall)
        }
    }
    if (value.identity && !update) {
        CollapsibleSection(stringResource(Res.string.c2pa_sign_interop), key = "c2pa-interop-${f.id}") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = value.c2paRsOrder, onCheckedChange = { onChange(value.copy(c2paRsOrder = it)) })
                Column {
                    Text(stringResource(Res.string.c2pa_sign_rs_order))
                    Text(stringResource(Res.string.c2pa_sign_rs_order_text), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
    VerdictCard(Verdict.CAUTION, stringResource(Res.string.c2pa_sign_profile_title), buildList {
        add(stringResource(Res.string.c2pa_sign_profile_1))
        if (!update) add(stringResource(Res.string.c2pa_sign_profile_2))
        if (choice is SignerChoice.Wallet) add(stringResource(Res.string.c2pa_sign_profile_wallet))
        if (choice is SignerChoice.Card) add(stringResource(Res.string.c2pa_sign_profile_card))
    })
}

/** How the content was made and the CAWG identity assertion: what a standard manifest declares and an update manifest does not. */
@Composable
private fun C2paMadeAndIdentity(value: C2paChoice, onChange: (C2paChoice) -> Unit) {
    SectionTitle(stringResource(Res.string.c2pa_sign_how))
    Row(Modifier.fillMaxWidth().clickable { onChange(value.copy(sourceType = null)) }, verticalAlignment = Alignment.CenterVertically) {
        androidx.compose.material3.RadioButton(selected = value.sourceType == null, onClick = { onChange(value.copy(sourceType = null)) })
        Column {
            Text(stringResource(Res.string.c2pa_sign_opened), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(Res.string.c2pa_sign_opened_text), style = MaterialTheme.typography.bodySmall)
        }
    }
    Row(Modifier.fillMaxWidth().clickable { onChange(value.copy(sourceType = value.sourceType ?: "digitalCreation")) }, verticalAlignment = Alignment.CenterVertically) {
        androidx.compose.material3.RadioButton(selected = value.sourceType != null, onClick = { onChange(value.copy(sourceType = value.sourceType ?: "digitalCreation")) })
        Column {
            Text(stringResource(Res.string.c2pa_sign_created), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(Res.string.c2pa_sign_created_text), style = MaterialTheme.typography.bodySmall)
        }
    }
    if (value.sourceType != null) {
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            DigitalSourceTypes.DECLARABLE.forEach { code ->
                FilterChip(selected = code == value.sourceType, onClick = { onChange(value.copy(sourceType = code)) }, label = { Text(code) })
            }
        }
        if (value.sourceType in DigitalSourceTypes.AI_GENERATED) Text(stringResource(Res.string.c2pa_sign_ai_note), style = MaterialTheme.typography.bodySmall)
    }
    SectionTitle(stringResource(Res.string.c2pa_sign_identity))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = value.identity, onCheckedChange = { onChange(value.copy(identity = it)) })
        Text(stringResource(Res.string.c2pa_sign_identity_add))
    }
    if (value.identity || value.aggregation.isNotEmpty()) {
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            CAWG_ROLES.forEach { r ->
                FilterChip(selected = r in value.roles, onClick = {
                    onChange(value.copy(roles = if (r in value.roles) value.roles - r else value.roles + r))
                }, label = { Text(cawgRole(r)) })
            }
        }
    }
    if (value.identity) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = value.walletClaim, onCheckedChange = { onChange(value.copy(walletClaim = it)) })
            Column {
                Text(stringResource(Res.string.c2pa_sign_wallet_claim))
                Text(stringResource(Res.string.c2pa_sign_wallet_claim_text), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/**
 * The identity claims aggregation the wallet issues itself: which held credentials of highly trusted issuers it lists,
 * as an identity document (cawg.document_verification, which needs the holder's name) or an affiliation, and the
 * EdDSA key for validators built on c2pa-rs.
 */
@Composable
private fun C2paAggregation(value: C2paChoice, candidates: List<IcaCandidate>, onChange: (C2paChoice) -> Unit) {
    SectionTitle(stringResource(Res.string.c2pa_sign_ica_title))
    Text(stringResource(Res.string.c2pa_sign_ica_text), style = MaterialTheme.typography.bodySmall)
    if (candidates.isEmpty()) {
        Text(stringResource(Res.string.c2pa_sign_ica_none), style = MaterialTheme.typography.bodySmall)
        return
    }
    candidates.forEach { k ->
        val type = value.aggregation[k.documentId]
        fun toggle(on: Boolean) = onChange(value.copy(aggregation = if (on) {
            value.aggregation + (k.documentId to if (k.name != null) CawgAggregation.DOCUMENT_VERIFICATION else CawgAggregation.AFFILIATION)
        } else value.aggregation - k.documentId))
        Row(Modifier.fillMaxWidth().clickable { toggle(type == null) }, verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = type != null, onCheckedChange = { toggle(it) })
            Column {
                Text(k.title, style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(Res.string.c2pa_sign_ica_entry, k.name ?: stringResource(Res.string.c2pa_sign_ica_no_name), k.providerName, k.tier.name), style = MaterialTheme.typography.bodySmall)
            }
        }
        if (type != null) Row(Modifier.horizontalScroll(rememberScrollState()).padding(start = 40.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            FilterChip(selected = type == CawgAggregation.DOCUMENT_VERIFICATION, enabled = k.name != null,
                onClick = { onChange(value.copy(aggregation = value.aggregation + (k.documentId to CawgAggregation.DOCUMENT_VERIFICATION))) },
                label = { Text(stringResource(Res.string.c2pa_sign_ica_document)) })
            FilterChip(selected = type == CawgAggregation.AFFILIATION,
                onClick = { onChange(value.copy(aggregation = value.aggregation + (k.documentId to CawgAggregation.AFFILIATION))) },
                label = { Text(stringResource(Res.string.c2pa_sign_ica_affiliation)) })
        }
    }
    if (value.aggregation.isNotEmpty()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = value.aggregationEdDsa, onCheckedChange = { onChange(value.copy(aggregationEdDsa = it)) })
            Column {
                Text(stringResource(Res.string.c2pa_sign_ica_eddsa))
                Text(stringResource(Res.string.c2pa_sign_ica_eddsa_text), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** File extensions of the containers a C2PA manifest is embedded in; other files get a sidecar (.c2pa). */
private val C2PA_EMBEDDABLE = setOf(
    "jpg", "jpeg", "png", "webp", "wav", "avi", "gif", "tif", "tiff", "dng", "svg", "mp3", "flac", "jxl",
    "mp4", "m4v", "m4a", "mov", "3gp", "heic", "heif", "avif", "pdf", "zip", "docx", "xlsx", "pptx", "odt", "ods",
    "odp", "epub",
)

/** CAWG named actor roles offered when signing. */
private val CAWG_ROLES = listOf("cawg.creator", "cawg.contributor", "cawg.editor", "cawg.producer", "cawg.publisher", "cawg.sponsor", "cawg.translator")

@Composable
private fun OpenCertSection(model: WalletModel, f: StoredFile, oc: OpenCertInfo, busy: String?) {
    val view by produceState<OpenCertView?>(null, f.id, f.sha256) { value = model.files.openCertView(f) }
    val v = view
    SectionTitle(stringResource(Res.string.oa_title))
    (v?.title ?: oc.name)?.let { LabelValue(stringResource(Res.string.oa_name), it) }
    LabelValue(stringResource(Res.string.oa_version), oc.version, small = true)
    VerdictPill(checkVerdict(oc.integrity), stringResource(Res.string.oa_integrity) + checkText(oc.integrity))
    if (oc.integrity == Check.FAIL) Text(stringResource(Res.string.oa_tampered), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    val online = oc.online
    if (online == null) {
        Text(stringResource(Res.string.oa_not_checked), style = MaterialTheme.typography.bodySmall)
    } else {
        VerdictPill(checkVerdict(online.issuance), stringResource(Res.string.oa_issuance) + checkText(online.issuance))
        online.issuanceDetail.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        VerdictPill(checkVerdict(online.identity), stringResource(Res.string.oa_identity) + checkText(online.identity))
        online.identityDetail.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        online.registryName?.let { LabelValue(stringResource(Res.string.oa_registry), it, small = true) }
        Text(stringResource(Res.string.oa_checked_at, localTime(online.checkedAt)), style = MaterialTheme.typography.bodySmall)
    }
    OutlinedButton(onClick = { model.files.recheckOpenCert(f) }, enabled = busy == null) { Text(if (online == null) stringResource(Res.string.oa_check) else stringResource(Res.string.action_check_again_query)) }
    if (v == null) return
    val builtIn = v.templateUrl?.let { url -> Regex("^https://([^/:]+)").find(url.trim())?.groupValues?.get(1)?.lowercase() in OpenCertOffline.BUILT_IN_HOSTS } == true
    ActionRow(WalletIcons.Document, stringResource(Res.string.oa_offline),
        if (builtIn) stringResource(Res.string.oa_offline_template) else stringResource(Res.string.oa_offline_wallet)) {
        model.screen.value = Screen.OpenCertRender(f.id, offline = true)
    }
    v.templateUrl?.let { url ->
        val origin = Regex("^https://[^/]+").find(url.trim())?.value
        if (origin != null) {
            ActionRow(WalletIcons.Document, stringResource(Res.string.oa_issuer_style), stringResource(Res.string.oa_issuer_style_text, origin)) {
                model.screen.value = Screen.OpenCertRender(f.id)
            }
        } else {
            ActionRow(WalletIcons.Document, stringResource(Res.string.oa_issuer_style), stringResource(Res.string.oa_renderer_not_https), enabled = false) {}
        }
    }
    if (v.recipient.isNotEmpty()) {
        SectionTitle(stringResource(Res.string.oa_recipient))
        v.recipient.forEach { (k, value) -> LabelValue(k, value) }
    }
    if (v.main.isNotEmpty()) {
        SectionTitle(stringResource(Res.string.oa_content))
        v.main.forEach { (k, value) -> LabelValue(k, value) }
    }
    v.issuers.forEachIndexed { i, issuer ->
        SectionTitle(if (v.issuers.size > 1) stringResource(Res.string.oa_issuer_n, i + 1) else stringResource(Res.string.oa_issuer))
        issuer.name?.let { LabelValue(stringResource(Res.string.oa_name), it) }
        issuer.url?.let { LabelValue(stringResource(Res.string.oa_url), it, small = true) }
        LabelValue(stringResource(Res.string.oa_method), methodText(issuer.method), small = true)
        issuer.value?.let { LabelValue(if (issuer.method == OaMethod.DID) "DID" else stringResource(Res.string.oa_contract), it, small = true) }
        issuer.identityType?.let { t -> LabelValue(stringResource(Res.string.oa_identity_proof), t + (issuer.identityLocation?.let { stringResource(Res.string.colon_value, it) } ?: ""), small = true) }
        issuer.revocationType?.let { t -> LabelValue(stringResource(Res.string.oa_revocation), t + (issuer.revocationLocation?.let { stringResource(Res.string.colon_value, it) } ?: ""), small = true) }
    }
    if (v.signatories.isNotEmpty()) {
        SectionTitle(stringResource(Res.string.oa_signatories))
        v.signatories.forEach { s ->
            listOfNotNull(s.name, s.position, s.organisation).takeIf { it.isNotEmpty() }?.let { Text(it.joinToString(stringResource(Res.string.sep_comma)), style = MaterialTheme.typography.bodyMedium) }
            s.image?.let { model.platform.decodeImage(it) }?.let { img ->
                Image(img, contentDescription = stringResource(Res.string.oa_signature), contentScale = ContentScale.Fit, modifier = Modifier.height(64.dp))
            }
        }
    }
    if (v.transcript.isNotEmpty()) {
        SectionTitle(stringResource(Res.string.oa_transcript))
        val tableScroll = rememberScrollState()
        Column(Modifier.fillMaxWidth().horizontalScroll(tableScroll)) {
            Row {
                v.transcriptColumns.forEach { c -> Text(c, style = MaterialTheme.typography.labelMedium, modifier = Modifier.width(120.dp).padding(4.dp)) }
            }
            v.transcript.forEach { row ->
                Row { row.forEach { cell -> Text(cell, style = MaterialTheme.typography.bodySmall, modifier = Modifier.width(120.dp).padding(4.dp)) } }
            }
        }
        HorizontalScrollIndicator(tableScroll, Modifier.fillMaxWidth())
    }
    if (v.images.isNotEmpty()) {
        SectionTitle(stringResource(Res.string.format_image))
        v.images.forEach { (name, bytes) ->
            model.platform.decodeImage(bytes)?.let { img ->
                Text(name, style = MaterialTheme.typography.bodySmall)
                Image(img, contentDescription = name, contentScale = ContentScale.Fit, modifier = Modifier.heightIn(max = 160.dp))
            }
        }
    }
    if (v.attachments.isNotEmpty()) {
        SectionTitle(stringResource(Res.string.oa_attachments))
        v.attachments.forEach { a ->
            Text(stringResource(Res.string.files_group_count, a.name, sizeText(a.bytes.size.toLong())), style = MaterialTheme.typography.bodyMedium)
            WrapRow() {
                OutlinedButton(onClick = { model.files.storeOpenCertAttachment(f, a) }, enabled = busy == null) { Text(stringResource(Res.string.oa_store)) }
                OutlinedButton(onClick = { model.files.exportOpenCertAttachment(a) }, enabled = busy == null) { Text(stringResource(Res.string.action_export)) }
                if (model.platform.canShareFiles) {
                    OutlinedButton(onClick = { model.files.exportOpenCertAttachment(a, share = true) }, enabled = busy == null) { Text(stringResource(Res.string.action_share)) }
                }
            }
        }
    }
    if (v.other.isNotEmpty()) {
        SectionTitle(stringResource(Res.string.oa_other_fields))
        v.other.forEach { (k, value) -> LabelValue(k, value, small = true) }
    }
}

/** The certificate shown by the renderer its issuer chose; the content goes to that site only when this opens. */
@Composable
fun OpenCertRenderScreen(model: WalletModel, screen: Screen.OpenCertRender) {
    val f = model.files.file(screen.fileId) ?: return
    val page by produceState<String?>(null, f.id, screen.offline) {
        value = (if (screen.offline) model.files.openCertOfflinePage(f)?.html else model.files.openCertRendererPage(f)) ?: ""
    }
    Column(Modifier.fillMaxSize()) {
        if (!screen.offline) {
            Text(stringResource(Res.string.oa_renderer_note), style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
        }
        when (val html = page) {
            null -> Text(stringResource(Res.string.state_preparing), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
            "" -> Text(if (screen.offline) stringResource(Res.string.oa_unreadable) else stringResource(Res.string.oa_no_renderer), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
            else -> OpenCertRendererView(html, Modifier.fillMaxWidth().weight(1f), offline = screen.offline) { url ->
                model.platform.openBrowser(url)
            }
        }
    }
}

// ---------------------------------------------------------------- derive

@Composable
fun FileDeriveScreen(model: WalletModel, screen: Screen.FileDerive) {
    val f = model.files.file(screen.fileId) ?: return
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    var password by remember(f) { mutableStateOf("") }
    var tried by remember(f) { mutableStateOf<String?>(null) }
    val fields by produceState<FilesModel.DeriveFields?>(null, f, tried) { value = model.files.deriveFields(f, tried) }
    val suggested = fields?.claims.orEmpty()
    var chosen by remember(f, suggested) { mutableStateOf(suggested.map { it.name }.toSet()) }
    var showNote by remember { mutableStateOf(false) }
    var noteName by remember { mutableStateOf("") }
    var noteValue by remember { mutableStateOf("") }
    var timestamp by remember { mutableStateOf(true) }
    var validDays by remember { mutableStateOf<Int?>(null) }
    var dayText by remember(f) { mutableStateOf("") }
    var dayClaims by remember(f) { mutableStateOf<List<DerivedClaim>>(emptyList()) }
    var zkForm by remember(f) { mutableStateOf(ZkPdfDeriveForm()) }
    var zkGate by remember(f) { mutableStateOf(false) }
    val composition = zkPdfComposition(model)
    ScreenColumn(spacing = 10.dp) {
        Text(stringResource(Res.string.derive_intro, f.report?.title ?: f.name),
            style = MaterialTheme.typography.bodyMedium)
        WrapRow(spacing = 6.dp) {
            f.report?.let { r -> val (v, t) = verdictOf(r.verdict); VerdictPill(v, t) }
            if (f.timestamps.any { it.trusted }) VerdictPill(Verdict.PASS, stringResource(Res.string.derive_has_timestamp))
            f.source?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        SectionTitle(stringResource(Res.string.derive_step_fields))
        if (fields == null) Text(stringResource(Res.string.derive_reading), style = MaterialTheme.typography.bodySmall)
        if (fields?.locked == true) {
            Text(if (tried != null) stringResource(Res.string.pdf_wrong_password) else stringResource(Res.string.derive_password_text),
                style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(value = password, onValueChange = { password = it.take(64) }, label = { Text(stringResource(Res.string.pdf_password)) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.weight(1f))
                Button(onClick = { tried = password }, enabled = password.isNotBlank()) { Text(stringResource(Res.string.derive_read)) }
            }
        }
        fields?.notice?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        suggested.forEach { c ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = c.name in chosen, onCheckedChange = { chosen = if (it) chosen + c.name else chosen - c.name })
                Column {
                    Text(DerivedCredentials.labelOf(c), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        if (diw.wallet.core.document.derived.TravelDocumentFields.isRaw(c.name)) stringResource(Res.string.derive_chip_file, c.value.length * 3 / 4)
                        else c.value,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
        if (fields != null && suggested.isEmpty()) Text(stringResource(Res.string.derive_no_fields), style = MaterialTheme.typography.bodySmall)
        val entryExit = fields?.entryExit
        if (entryExit != null) {
            Text(stringResource(Res.string.derive_presence, entryExit.inside), style = MaterialTheme.typography.bodyMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(value = dayText, onValueChange = { dayText = it.take(10) }, label = { Text(stringResource(Res.string.derive_date_label)) }, singleLine = true,
                    modifier = Modifier.weight(1f))
                val day = runCatching { LocalDate.parse(dayText.trim()) }.getOrNull()
                val answer = day?.let { DocumentFields.insideOn(entryExit, it) }
                Button(onClick = { answer?.let { a -> dayClaims = dayClaims.filter { it.name != a.name } + a } }, enabled = answer != null) { Text(stringResource(Res.string.action_add)) }
            }
            val day = runCatching { LocalDate.parse(dayText.trim()) }.getOrNull()
            if (dayText.isNotBlank() && (day == null || DocumentFields.insideOn(entryExit, day) == null)) {
                Text(if (day == null) stringResource(Res.string.derive_date_format) else stringResource(Res.string.derive_date_outside, entryExit.periodFrom.toString(), entryExit.coveredUntil.toString()),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            dayClaims.forEach { c ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = true, onCheckedChange = { dayClaims = dayClaims - c })
                    Column {
                        Text(DerivedCredentials.labelOf(c), style = MaterialTheme.typography.bodyMedium)
                        Text(if (c.value == "true") stringResource(Res.string.derive_was_in, entryExit.inside) else stringResource(Res.string.derive_was_not_in, entryExit.inside), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
        TextButton(onClick = { showNote = !showNote }) { Text(if (showNote) stringResource(Res.string.derive_no_note) else stringResource(Res.string.derive_add_note)) }
        if (showNote) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = noteName, onValueChange = { noteName = it.take(32) }, label = { Text(stringResource(Res.string.derive_note_name)) }, singleLine = true, modifier = Modifier.weight(1f))
                OutlinedTextField(value = noteValue, onValueChange = { noteValue = it.take(200) }, label = { Text(stringResource(Res.string.derive_note_value)) }, singleLine = true, modifier = Modifier.weight(1f))
            }
        }
        SectionTitle(stringResource(Res.string.derive_step_evidence))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = timestamp, onCheckedChange = { timestamp = it })
            Text(if (f.timestamps.any { it.trusted }) stringResource(Res.string.derive_attach_timestamp) else stringResource(Res.string.derive_get_timestamp))
        }
        if (f.report?.format == DocumentFormat.PDF) ZkPdfDeriveSection(model, f.id, fields?.zkPdf, zkForm) { zkForm = it }
        SectionTitle(stringResource(Res.string.derive_step_validity))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf<Pair<Int?, String>>(null to stringResource(Res.string.derive_unlimited), 365 to stringResource(Res.string.derive_one_year), 1825 to stringResource(Res.string.derive_five_years)).forEach { (d, t) ->
                FilterChip(selected = validDays == d, onClick = { validDays = d }, label = { Text(t) })
            }
        }
        FilesBusyLine(model, busy, error)
        val claims = suggested.filter { it.name in chosen } + dayClaims + listOfNotNull(
            if (showNote && noteName.isNotBlank() && noteValue.isNotBlank()) {
                DerivedClaim(DerivedCredentials.SELF_ASSERTED_PREFIX + noteName.trim(), noteValue.trim(), stringResource(Res.string.derive_self_asserted) + noteName.trim())
            } else null,
        )
        val zkMatch = fields?.zkPdf?.let { zkForm.match(it) }?.takeIf { zkForm.on }
        val zkProblem = zkMatch?.let { zkForm.predicates(it).second }
        Button(
            onClick = { if (zkMatch != null) zkGate = true else model.files.derive(f, claims, timestamp, validDays) },
            enabled = busy == null && (claims.isNotEmpty() || zkMatch != null) && zkProblem == null,
        ) { Text(if (zkMatch != null) stringResource(Res.string.derive_make_zk) else stringResource(Res.string.derive_make)) }
        if (zkGate && zkMatch != null) {
            val chooseOne = stringResource(Res.string.derive_choose_one)
            val notOffered = stringResource(Res.string.derive_not_offered)
            ZkProofGate(
                zk = model.zk,
                kind = ZkProofKind.PDF,
                context = ZkChoiceContext(
                    selfHostConfigured = model.settings.zkProverUrl.isNotEmpty(),
                    withoutZk = stringResource(Res.string.derive_without_zk),
                    desktopImport = composition == ZkPdfStatement.PHONE,
                ),
                assets = ZkPdfAssets.required(composition, true),
                verifyAssets = FilesModel.SELF_HOST_ASSETS,
                onDecision = { choice, extended ->
                    zkGate = false
                    when (choice) {
                        ZkChoiceKind.ON_DEVICE -> model.files.derive(f, claims, timestamp, validDays,
                            FilesModel.ZkPdfChoice(zkMatch.profile.id, zkForm.predicates(zkMatch).first, composition, extended))
                        ZkChoiceKind.DESKTOP -> model.files.exportZkPdfRequest(f, claims, timestamp, validDays,
                            FilesModel.ZkPdfChoice(zkMatch.profile.id, zkForm.predicates(zkMatch).first, ZkPdfStatement.DESKTOP, extended = true))
                        ZkChoiceKind.SELF_HOSTED -> model.files.derive(f, claims, timestamp, validDays,
                            FilesModel.ZkPdfChoice(zkMatch.profile.id, zkForm.predicates(zkMatch).first, composition, extended = true, selfHosted = true))
                        ZkChoiceKind.WITHOUT_ZK -> if (claims.isNotEmpty()) model.files.derive(f, claims, timestamp, validDays)
                            else model.message.value = chooseOne
                        else -> model.message.value = notOffered
                    }
                },
                onDismiss = { zkGate = false },
            )
        }
        CollapsibleSection(stringResource(Res.string.derive_what_title), key = "derive-about") {
            Text(stringResource(Res.string.derive_what_text),
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
fun PortalScreen(model: WalletModel, screen: Screen.Portal) {
    val src = DocumentSources.byId(screen.sourceId) ?: return
    if (src.myData && !model.legal.enabled(diw.wallet.app.legal.Integration.MYDATA)) {
        Column(Modifier.padding(16.dp)) { IntegrationOffRow(model, diw.wallet.app.legal.Integration.MYDATA) }
        return
    }
    val busy by model.files.busy.collectAsState()
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(src.name, style = MaterialTheme.typography.titleSmall)
            Text(
                when {
                    src.nationalId -> stringResource(Res.string.mydata_steps_mobile)
                    src.myData -> stringResource(Res.string.mydata_steps)
                    else -> stringResource(Res.string.portal_steps)
                },
                style = MaterialTheme.typography.bodySmall,
            )
            busy?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
        }
        val noApp = stringResource(Res.string.portal_no_app)
        PortalWebView(
            url = src.url,
            modifier = Modifier.fillMaxWidth().weight(1f),
            onFile = { model.files.importDownload(it, src) },
            onExternal = { url ->
                if (!model.platform.openExternal(url)) model.message.value = noApp
            },
            onError = { model.message.value = it },
            autofill = myDataAutofill(model).takeIf { src.myData },
        )
    }
}

/** The saved MyData ID number and birth date, filled into MyData's own pages (Bonds autofill). */
@Composable
private fun myDataAutofill(model: WalletModel): PortalAutofill? {
    val id = model.settings.myDataIdNumber ?: return null
    val birth = model.settings.myDataBirthDate ?: return null
    val filled = stringResource(Res.string.mydata_autofilled, "{n}")
    return PortalAutofill(MyDataProfile.HOST, MyDataProfile.autofillScript(id, birth)) { n -> model.message.value = filled.replace("{n}", n.toString()) }
}

