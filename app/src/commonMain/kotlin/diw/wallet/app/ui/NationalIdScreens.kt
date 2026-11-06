package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
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
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import diw.wallet.app.CredentialDetails
import diw.wallet.app.HomeTab
import diw.wallet.app.Screen
import diw.wallet.app.SignerChoice
import diw.wallet.app.StoredFile
import diw.wallet.app.TaiwanModel
import diw.wallet.app.WalletModel
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.profile.bonds.BondsNationalId
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.profile.bonds.MoicaVerification
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.util.fromBase64
import kotlin.time.Instant

// ---------------------------------------------------------------- card art

/** The national ID card as shown in the Documents tab: holder name and what signs it. */
@Composable
fun NationalIdCardView(name: String?, issued: String?, onClick: () -> Unit) {
    Card(
        Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(WalletIcons.Person, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(40.dp))
                Column(Modifier.weight(1f)) {
                    Text(name ?: stringResource(Res.string.national_id), style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(Res.string.national_id_bonds), style = MaterialTheme.typography.bodySmall)
                }
            }
            Text(stringResource(Res.string.national_id_signed) + (issued?.let { stringResource(Res.string.national_id_made, it) } ?: ""), style = MaterialTheme.typography.bodySmall)
        }
    }
}

private fun cardholder(card: MoicaSignedCredential): String? =
    runCatching { PlatformCrypto.certificateSubjectCn(card.certificate.fromBase64()) }.getOrNull()

private fun issuedAt(card: MoicaSignedCredential): String? =
    runCatching { (card.credential()["validFrom"] as? JsonPrimitive)?.content?.let { localTime(Instant.parse(it).epochSeconds) } }.getOrNull()

/** National ID cards of the vault, for the Documents tab. */
@Composable
fun NationalIdCards(model: WalletModel) {
    val files by model.files.files.collectAsState()
    val cards = remember(files) { model.files.nationalIdCards() }
    cards.forEach { (f, card) ->
        NationalIdCardView(cardholder(card), issuedAt(card)) { model.screen.value = Screen.NationalId(f.id) }
    }
}

// ---------------------------------------------------------------- making the card

/**
 * Makes a Bonds national ID card from the MyData national ID PDF: open it with the ID number, confirm the fields,
 * then sign them with the citizen digital certificate card.
 */
@Composable
fun NationalIdCreateScreen(model: WalletModel, screen: Screen.NationalIdCreate) {
    val f = model.files.file(screen.fileId) ?: return
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val draft by model.files.nationalIdDraft.collectAsState()
    var idNumber by remember { mutableStateOf("") }
    var card by remember { mutableStateOf<SignerChoice.Card?>(null) }
    LaunchedEffect(screen.fileId) {
        if (model.files.nationalIdDraft.value?.fileId != screen.fileId) model.files.nationalIdDraft.value = null
        // An ID number the wallet already knows (a national ID card, the saved MyData details) opens it at once.
        model.files.readNationalIdIfKnown(f)
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(Res.string.national_id_intro),
            style = MaterialTheme.typography.bodyMedium)
        LabelValue(stringResource(Res.string.label_file), f.name)
        val d = draft?.takeIf { it.fileId == f.id }
        if (d == null) {
            SectionTitle(stringResource(Res.string.action_open_file))
            OutlinedTextField(
                value = idNumber,
                onValueChange = { v -> idNumber = v.filter { it.isLetterOrDigit() }.take(10) },
                label = { Text(stringResource(Res.string.national_id_number)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, keyboardType = KeyboardType.Ascii),
                modifier = Modifier.fillMaxWidth(),
            )
            Text(stringResource(Res.string.national_id_number_text), style = MaterialTheme.typography.bodySmall)
            BusyLine(busy, error)
            Button(onClick = { model.files.readNationalId(f, idNumber) }, enabled = busy == null && idNumber.isNotBlank()) { Text(stringResource(Res.string.national_id_open_read)) }
            return@Column
        }
        SectionTitle(stringResource(Res.string.national_id_confirm))
        val claims = BondsNationalId.claims(d.fields, kotlin.time.Clock.System.now()).toMap()
        BondsNationalId.claimOrder.forEach { name -> claims[name]?.let { LabelValue(BondsNationalId.claimLabels[name] ?: name, if (name == BondsNationalId.CLAIM_OVER_18) yesNo(it) else it) } }
        if (d.over18 == null) Text(stringResource(Res.string.national_id_bad_birth), style = MaterialTheme.typography.bodySmall)
        VerdictCard(
            Verdict.CAUTION,
            stringResource(Res.string.national_id_self_stated),
            listOf(
                stringResource(Res.string.national_id_self_stated_text),
                stringResource(Res.string.national_id_name_match),
            ),
        )
        SectionTitle(stringResource(Res.string.national_id_sign_moica))
        CardPicker(model) { card = it }
        ActionRow(WalletIcons.Phone, stringResource(Res.string.national_id_mobile_moica), stringResource(Res.string.national_id_mobile_moica_text), enabled = false) {}
        BusyLine(busy, error)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { card?.let { model.files.issueNationalId(d, it) } }, enabled = busy == null && card != null) { Text(stringResource(Res.string.national_id_sign_make)) }
            OutlinedButton(onClick = { model.files.nationalIdDraft.value = null }, enabled = busy == null) { Text(stringResource(Res.string.national_id_reenter)) }
        }
    }
}

@Composable
private fun yesNo(v: String): String = when (v) {
    "true" -> stringResource(Res.string.answer_yes)
    "false" -> stringResource(Res.string.answer_no)
    else -> v
}

// ---------------------------------------------------------------- the card

@Composable
fun NationalIdScreen(model: WalletModel, screen: Screen.NationalId) {
    val files by model.files.files.collectAsState()
    val busy by model.files.busy.collectAsState()
    val error by model.files.error.collectAsState()
    val f: StoredFile? = files.firstOrNull { it.id == screen.fileId }
    val card = remember(f?.nationalId) { f?.nationalId?.let { runCatching { MoicaSignedCredential.parse(it) }.getOrNull() } }
    if (f == null || card == null) {
        EmptyState(WalletIcons.Person, stringResource(Res.string.national_id_missing), stringResource(Res.string.national_id_missing_text), stringResource(Res.string.national_id_back)) { model.showTab(HomeTab.DOCUMENTS) }
        return
    }
    var confirmDelete by remember { mutableStateOf(false) }
    val name = cardholder(card)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        NationalIdCardView(name, issuedAt(card)) {}
        BusyLine(busy, error)
        SectionTitle(stringResource(Res.string.label_fields))
        TaiwanModel.nationalIdClaims(card).forEach { (k, v) ->
            LabelValue(BondsNationalId.claimLabels[k] ?: k, if (k == BondsNationalId.CLAIM_OVER_18) yesNo(v) else v)
        }
        SectionTitle(stringResource(Res.string.label_signature))
        name?.let { LabelValue(stringResource(Res.string.national_id_holder), it) }
        issuedAt(card)?.let { LabelValue(stringResource(Res.string.national_id_made_at), it) }
        LabelValue(stringResource(Res.string.credential_format), stringResource(Res.string.national_id_format))
        LabelValue(stringResource(Res.string.national_id_source), f.name, onClick = { model.screen.value = Screen.FileDetail(f.id) })
        Text(stringResource(Res.string.national_id_present_text),
            style = MaterialTheme.typography.bodySmall)
        Text(stringResource(Res.string.national_id_meaning), style = MaterialTheme.typography.bodySmall)
        var showDetails by remember { mutableStateOf(model.settings.showDetails) }
        TextButton(onClick = { showDetails = !showDetails }) { Text(if (showDetails) stringResource(Res.string.action_hide_details) else stringResource(Res.string.action_show_details)) }
        if (showDetails) {
            // Checked again as a verifier would: signature, MOICA chain, commitments and the name.
            val check by produceState<Result<MoicaVerification>?>(null, card) {
                value = runCatching { card.verify(model.didResolver()) }
            }
            DetailSections(model, CredentialDetails.moica(card, check, BondsNationalId.claimLabels))
        }
        SectionTitle(stringResource(Res.string.label_actions))
        ActionRow(WalletIcons.Scan, stringResource(Res.string.action_present), stringResource(Res.string.national_id_present_hint)) { model.showTab(HomeTab.USE) }
        ActionRow(WalletIcons.Send, stringResource(Res.string.national_id_export), stringResource(Res.string.national_id_export_text)) { model.files.exportNationalId(f) }
        if (model.platform.canShareFiles) {
            ActionRow(WalletIcons.Share, stringResource(Res.string.national_id_share), stringResource(Res.string.national_id_share_text)) { model.files.exportNationalId(f, share = true) }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { confirmDelete = true }) {
            Icon(WalletIcons.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(stringResource(Res.string.national_id_delete), color = MaterialTheme.colorScheme.error)
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(Res.string.national_id_delete_title)) },
            text = { Text(stringResource(Res.string.national_id_delete_text)) },
            confirmButton = { TextButton(onClick = { confirmDelete = false; model.files.deleteNationalId(f) }) { Text(stringResource(Res.string.action_delete), color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(Res.string.action_cancel)) } },
        )
    }
}
