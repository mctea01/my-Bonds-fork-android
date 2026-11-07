package diw.wallet.app.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
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
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import diw.wallet.app.NfcReaderList
import diw.wallet.app.NfcReaderOption
import diw.wallet.app.PassportView
import diw.wallet.app.Passports
import diw.wallet.app.WalletModel
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.document.mrtd.AccessSecret
import diw.wallet.core.document.mrtd.ChipCheck
import diw.wallet.core.document.mrtd.Mrz
import diw.wallet.core.document.mrtd.MrzKey
import kotlinx.coroutines.launch
import org.jetbrains.compose.resources.stringResource
import kotlin.time.Clock

/**
 * Reading an electronic passport (or another ICAO 9303 travel document) by NFC: the document number, date of birth
 * and date of expiry from the data page unlock the chip (or the zone pasted as text, or the card access number of
 * a document that has one), then the chip is read while it stays on the phone.
 */
@Composable
fun PassportReadScreen(model: WalletModel) {
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    var number by remember { mutableStateOf("") }
    var birth by remember { mutableStateOf("") }
    var expiry by remember { mutableStateOf("") }
    var zone by remember { mutableStateOf("") }
    var useCan by remember { mutableStateOf(false) }
    var can by remember { mutableStateOf("") }
    var readers by remember { mutableStateOf<NfcReaderList?>(null) }
    var reader by remember { mutableStateOf<NfcReaderOption?>(null) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(Unit) {
        readers = runCatching { model.platform.nfcReaders() }.getOrElse { NfcReaderList(emptyList(), model.describe(it)) }
        reader = readers?.readers?.firstOrNull()
    }
    val parsed = remember(zone) { if (zone.isBlank()) null else Mrz.parse(zone) ?: Mrz.find(zone) }
    LaunchedEffect(parsed) {
        parsed?.let { m ->
            number = m.documentNumber
            birth = m.birthDate
            expiry = m.expiryDate
        }
    }
    val key = remember(number, birth, expiry) { runCatching { MrzKey.of(number, birth, expiry) }.getOrNull() }
    val secret: AccessSecret? = if (useCan) can.takeIf { it.length == 6 }?.let { AccessSecret.Can(it) } else key?.let { AccessSecret.MrzSecret(it) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(Res.string.mrtd_intro), style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = !useCan, onClick = { useCan = false }, label = { Text(stringResource(Res.string.mrtd_by_zone)) })
            FilterChip(selected = useCan, onClick = { useCan = true }, label = { Text(stringResource(Res.string.mrtd_by_can)) })
        }
        if (!useCan) {
            OutlinedTextField(
                value = number, onValueChange = { v -> number = Mrz.normalize(v).take(20) },
                label = { Text(stringResource(Res.string.mrtd_number)) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = birth, onValueChange = { v -> birth = v.filter { it.isDigit() }.take(8) },
                label = { Text(stringResource(Res.string.mrtd_birth)) }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = expiry, onValueChange = { v -> expiry = v.filter { it.isDigit() }.take(8) },
                label = { Text(stringResource(Res.string.mrtd_expiry)) }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth(),
            )
            Text(stringResource(Res.string.mrtd_date_hint), style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(
                value = zone, onValueChange = { zone = it.take(200) },
                label = { Text(stringResource(Res.string.mrtd_zone)) },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                minLines = 2, modifier = Modifier.fillMaxWidth(),
            )
            parsed?.let { m ->
                Text(
                    if (m.checkDigitsValid) stringResource(Res.string.mrtd_zone_ok, m.fullName)
                    else stringResource(Res.string.mrtd_zone_bad, m.failedChecks.joinToString(", ")),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (m.checkDigitsValid) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                )
            }
        } else {
            OutlinedTextField(
                value = can, onValueChange = { v -> can = v.filter { it.isDigit() }.take(6) },
                label = { Text(stringResource(Res.string.mrtd_can)) }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth(),
            )
            Text(stringResource(Res.string.mrtd_can_text), style = MaterialTheme.typography.bodySmall)
        }
        SectionTitle(stringResource(Res.string.mrtd_reader))
        val list = readers
        when {
            list == null -> CircularProgressIndicator(Modifier.size(20.dp))
            list.readers.isEmpty() -> {
                Text(list.problem ?: stringResource(Res.string.files_no_reader), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                OutlinedButton(onClick = { scope.launch { readers = runCatching { model.platform.nfcReaders() }.getOrNull(); reader = readers?.readers?.firstOrNull() } }) {
                    Text(stringResource(Res.string.action_find_again))
                }
            }
            else -> Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                list.readers.forEach { r -> FilterChip(selected = r === reader, onClick = { reader = r }, label = { Text(r.name) }) }
            }
        }
        Button(
            onClick = { val r = reader; val s = secret; if (r != null && s != null) model.files.readPassport(r, s) },
            enabled = busy == null && reader != null && secret != null,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(Res.string.mrtd_read)) }
        BusyLine(busy, error)
        Text(stringResource(Res.string.mrtd_privacy), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
    }
}

private fun check(c: ChipCheck): org.jetbrains.compose.resources.StringResource = when (c) {
    ChipCheck.PASS -> Res.string.mrtd_check_pass
    ChipCheck.FAIL -> Res.string.mrtd_check_fail
    ChipCheck.NOT_SUPPORTED -> Res.string.mrtd_check_unsupported
    ChipCheck.NOT_RUN -> Res.string.mrtd_check_not_run
}

/** A travel document laid out as its data page: portrait, holder, document and chip. Every given name is shown. */
@Composable
internal fun PassportDataView(v: PassportView) {
    val year = remember { Clock.System.now().toString().take(4).toIntOrNull() ?: 2026 }
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        val m = v.mrz
        Text(
            when {
                m?.format == diw.wallet.core.document.mrtd.Mrz.Format.CN_PERMIT -> stringResource(Res.string.mrtd_kind_cn_permit, m.documentCode)
                m?.documentCode?.startsWith("P") != false -> stringResource(Res.string.mrtd_kind_passport)
                else -> stringResource(Res.string.mrtd_kind_travel_document)
            },
            style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center,
        )
        if (v.portraits.isNotEmpty()) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                v.portraits.forEach { img ->
                    Image(img, stringResource(Res.string.mrtd_portrait), Modifier.width(120.dp).height(160.dp).padding(4.dp), contentScale = ContentScale.Fit)
                }
            }
        }
        if (v.undecodedPortraits.isNotEmpty()) {
            Text(stringResource(Res.string.mrtd_portrait_undecoded, v.undecodedPortraits.distinct().joinToString(", ")),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        }
        Text(stringResource(Res.string.section_personal), style = MaterialTheme.typography.titleSmall)
        m?.let {
            LabelValue(stringResource(Res.string.mrtd_surname), it.primaryIdentifier, small = true)
            if (it.givenNames.isNotEmpty()) LabelValue(stringResource(Res.string.mrtd_given_names), it.givenNames.joinToString(" "), small = true)
        }
        v.personal?.fullName?.let { LabelValue(stringResource(Res.string.mrtd_full_name), it, small = true) }
        v.personal?.otherNames?.takeIf { it.isNotEmpty() }?.let { LabelValue(stringResource(Res.string.mrtd_other_names), it.joinToString("; "), small = true) }
        m?.let {
            if (it.nationality.isNotEmpty()) LabelValue(stringResource(Res.string.field_nationality), it.nationality, small = true)
            LabelValue(stringResource(Res.string.field_sex), it.sex, small = true)
            LabelValue(stringResource(Res.string.field_birth_date), Passports.fullDate(v.personal?.fullBirthDate) ?: Passports.date(it.birthDate, false, year), small = true)
        }
        v.personal?.placeOfBirth?.let { LabelValue(stringResource(Res.string.mrtd_place_of_birth), it, small = true) }
        v.personal?.personalNumber?.let { LabelValue(stringResource(Res.string.mrtd_personal_number), it, small = true) }
        if (v.personal?.personalNumber == null) m?.optionalData?.takeIf { it.isNotEmpty() }?.let { LabelValue(stringResource(Res.string.mrtd_personal_number), it, small = true) }
        v.personal?.address?.let { LabelValue(stringResource(Res.string.mrtd_address), it, small = true) }
        v.personal?.profession?.let { LabelValue(stringResource(Res.string.mrtd_profession), it, small = true) }
        v.personal?.telephone?.let { LabelValue(stringResource(Res.string.mrtd_telephone), it, small = true) }

        Text(stringResource(Res.string.section_document), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        m?.let {
            LabelValue(stringResource(Res.string.mrtd_document_code), it.documentCode, small = true)
            LabelValue(stringResource(Res.string.mrtd_issuing_state), it.issuingState, small = true)
            LabelValue(stringResource(Res.string.mrtd_number), it.documentNumber, small = true)
            it.issueCount?.let { n -> LabelValue(stringResource(Res.string.mrtd_issue_count), n, small = true) }
            LabelValue(stringResource(Res.string.mrtd_expiry_date), Passports.date(it.expiryDate, true, year), small = true)
        }
        v.document?.issueDate?.let { LabelValue(stringResource(Res.string.field_issued_at), Passports.fullDate(it) ?: it, small = true) }
        v.document?.issuingAuthority?.let { LabelValue(stringResource(Res.string.field_issuing_authority), it, small = true) }
        v.document?.endorsements?.let { LabelValue(stringResource(Res.string.mrtd_endorsements), it, small = true) }
        v.document?.otherPersons?.takeIf { it.isNotEmpty() }?.let { LabelValue(stringResource(Res.string.mrtd_other_persons), it.joinToString("; "), small = true) }

        Text(stringResource(Res.string.mrtd_chip), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
        LabelValue(stringResource(Res.string.mrtd_access), v.dump.access, small = true)
        LabelValue(stringResource(Res.string.mrtd_ca), stringResource(check(v.dump.chipAuthentication)) + (v.dump.chipAuthenticationProtocol?.let { " ($it)" } ?: ""), small = true)
        LabelValue(stringResource(Res.string.mrtd_aa), stringResource(check(v.dump.activeAuthenticationResult)), small = true)
        LabelValue(stringResource(Res.string.mrtd_files), v.dump.files.keys.joinToString(", "), small = true)
        if (v.dump.unreadable.isNotEmpty()) LabelValue(stringResource(Res.string.mrtd_unread), v.dump.unreadable.joinToString(", "), small = true)
        LabelValue(stringResource(Res.string.mrtd_read_at), localTime(v.dump.readAt), small = true)
        m?.let { z ->
            Text(z.lines.joinToString("\n"), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                modifier = Modifier.padding(top = 6.dp))
        }
    }
}

/** The passive authentication of a stored chip read: which data groups match the signed security object. */
@Composable
internal fun TravelDocumentSection(t: diw.wallet.core.document.TravelDocumentCheck) {
    fun groups(l: List<Int>) = l.joinToString(", ") { "DG$it" }
    Text(stringResource(Res.string.mrtd_hashes), style = MaterialTheme.typography.titleSmall)
    t.hashAlgorithm?.let { LabelValue(stringResource(Res.string.mrtd_hash_algorithm), it, small = true) }
    if (t.matched.isNotEmpty()) LabelValue(stringResource(Res.string.mrtd_hash_matched), groups(t.matched), small = true)
    if (t.mismatched.isNotEmpty()) LabelValue(stringResource(Res.string.mrtd_hash_mismatched), groups(t.mismatched), small = true)
    if (t.notRead.isNotEmpty()) LabelValue(stringResource(Res.string.mrtd_hash_not_read), groups(t.notRead), small = true)
    if (t.notCovered.isNotEmpty()) LabelValue(stringResource(Res.string.mrtd_hash_not_covered), groups(t.notCovered), small = true)
    t.ldsVersion?.let { LabelValue(stringResource(Res.string.mrtd_lds_version), it, small = true) }
    if (t.signerCountry != null || t.issuingState != null) {
        LabelValue(stringResource(Res.string.mrtd_signer_country), (t.signerCountry ?: "-") + " / " + (t.issuingState ?: "-"), small = true)
    }
    LabelValue(stringResource(Res.string.mrtd_aa_now), stringResource(check(t.activeAuthentication)), small = true)
}
