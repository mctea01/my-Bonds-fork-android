package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import diw.wallet.app.FilesModel
import diw.wallet.app.WalletModel
import diw.wallet.app.ZkJobPhase
import diw.wallet.core.document.zkpdf.ZkPdfNormalize
import diw.wallet.core.document.zkpdf.ZkPdfPredicate
import diw.wallet.core.zk.ZkPdfStatement
import kotlinx.datetime.LocalDate

/** A date condition the holder adds to a zkPDF proof: [kind] is ZkPdfPredicate.DATE_LE or DATE_GE, [date] as typed. */
data class ZkPdfConditionInput(val kind: Int, val date: String)

/** What the derive screen asks about a zkPDF proof: whether to add one, which template, and the date conditions. */
data class ZkPdfDeriveForm(
    val on: Boolean = false,
    val profileId: String? = null,
    val conditions: Map<String, ZkPdfConditionInput> = emptyMap(),
) {
    /** The chosen template among [matches] (the first one unless another was picked). */
    fun match(matches: List<FilesModel.ZkPdfMatch>): FilesModel.ZkPdfMatch? =
        matches.firstOrNull { it.profile.id == profileId } ?: matches.firstOrNull()

    /**
     * The predicates for [match], or the reason they cannot be proven: a date that does not parse, more than two
     * conditions, or a condition the document's own date does not meet (the circuit would refuse it).
     */
    fun predicates(match: FilesModel.ZkPdfMatch): Pair<List<ZkPdfPredicate>, Pair<org.jetbrains.compose.resources.StringResource, String>?> {
        val list = ArrayList<ZkPdfPredicate>()
        for ((claim, c) in conditions) {
            val field = match.fields.firstOrNull { it.name == claim } ?: continue
            val label = field.label ?: claim
            val date = runCatching { LocalDate.parse(c.date.trim()) }.getOrNull()
                ?: return emptyList<ZkPdfPredicate>() to (Res.string.zkpdf_date_format to label)
            val cutoff = date.year * 10000 + (date.month.ordinal + 1) * 100 + date.day
            if (cutoff !in 10000101..99991231) return emptyList<ZkPdfPredicate>() to (Res.string.zkpdf_date_range to label)
            val value = runCatching { LocalDate.parse(field.value) }.getOrNull()
                ?.let { it.year * 10000 + (it.month.ordinal + 1) * 100 + it.day }
                ?: return emptyList<ZkPdfPredicate>() to (Res.string.zkpdf_not_date to label)
            val holds = if (c.kind == ZkPdfPredicate.DATE_LE) value <= cutoff else value >= cutoff
            if (!holds) return emptyList<ZkPdfPredicate>() to (Res.string.zkpdf_not_met to label)
            list += ZkPdfPredicate(c.kind, claim, cutoff)
        }
        if (list.size > 2) return emptyList<ZkPdfPredicate>() to (Res.string.zkpdf_max_conditions to "")
        return list to null
    }
}

/** The circuit composition for this device: the larger desktop circuits on a computer, the phone ones elsewhere. */
@Composable
fun zkPdfComposition(model: WalletModel): String {
    val info by model.zk.platformInfo.collectAsState()
    LaunchedEffect(Unit) { if (model.zk.platformInfo.value == null) model.zk.probe() }
    return if (info?.isDesktop == true) ZkPdfStatement.DESKTOP else ZkPdfStatement.PHONE
}

/**
 * The zkPDF part of the derive screen: the templates that fit the PDF, the fields each proves with their values, the
 * fields it cannot prove and why, optional date conditions, and the running proof with its cancel button.
 */
@Composable
fun ZkPdfDeriveSection(
    model: WalletModel,
    fileId: String,
    matches: List<FilesModel.ZkPdfMatch>?,
    form: ZkPdfDeriveForm,
    onChange: (ZkPdfDeriveForm) -> Unit,
) {
    val settings by model.settingsFlow.collectAsState()
    val jobs by model.zk.jobs.collectAsState()
    val job = jobs[model.files.zkJobId(fileId)]
    if (matches == null) return
    if (matches.isEmpty()) {
        Text(
            stringResource(Res.string.zkpdf_no_profile) +
                (if (settings.testEnvironment) stringResource(Res.string.zkpdf_no_profile_test) else "") + stringResource(Res.string.sentence_end),
            style = MaterialTheme.typography.bodySmall,
        )
        return
    }
    val match = form.match(matches) ?: return
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = form.on, onCheckedChange = { onChange(form.copy(on = it, profileId = match.profile.id)) })
        Text(stringResource(Res.string.zkpdf_attach))
    }
    if (!form.on) return
    if (matches.size > 1) {
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            matches.forEach { m ->
                FilterChip(selected = m.profile.id == match.profile.id, onClick = { onChange(form.copy(profileId = m.profile.id, conditions = emptyMap())) },
                    label = { Text(m.profile.title + if (m.profile.test) stringResource(Res.string.test_suffix) else "") })
            }
        }
    }
    Text(stringResource(Res.string.zkpdf_profile, match.profile.title, match.profile.id) + if (match.profile.test) stringResource(Res.string.zkpdf_test_profile) else "",
        style = MaterialTheme.typography.bodySmall)
    Text(stringResource(Res.string.zkpdf_provable), style = MaterialTheme.typography.bodyMedium)
    match.fields.forEach { field ->
        LabelValue(field.label ?: field.name, field.value)
        if (match.profile.field(field.name)?.normalize == ZkPdfNormalize.DATE) {
            val c = form.conditions[field.name]
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                FilterChip(selected = c == null, onClick = { onChange(form.copy(conditions = form.conditions - field.name)) }, label = { Text(stringResource(Res.string.zkpdf_no_condition)) })
                FilterChip(selected = c?.kind == ZkPdfPredicate.DATE_LE,
                    onClick = { onChange(form.copy(conditions = form.conditions + (field.name to ZkPdfConditionInput(ZkPdfPredicate.DATE_LE, c?.date ?: "")))) },
                    label = { Text(stringResource(Res.string.zkpdf_not_after)) })
                FilterChip(selected = c?.kind == ZkPdfPredicate.DATE_GE,
                    onClick = { onChange(form.copy(conditions = form.conditions + (field.name to ZkPdfConditionInput(ZkPdfPredicate.DATE_GE, c?.date ?: "")))) },
                    label = { Text(stringResource(Res.string.zkpdf_not_before)) })
            }
            if (c != null) {
                OutlinedTextField(
                    value = c.date,
                    onValueChange = { onChange(form.copy(conditions = form.conditions + (field.name to c.copy(date = it.take(10))))) },
                    label = { Text(stringResource(Res.string.zkpdf_date_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(stringResource(Res.string.zkpdf_condition_note, field.label ?: field.name, if (c.kind == ZkPdfPredicate.DATE_LE) stringResource(Res.string.zkpdf_not_after_inline) else stringResource(Res.string.zkpdf_not_before_inline)),
                    style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    if (match.unavailable.isNotEmpty()) {
        Text(stringResource(Res.string.zkpdf_unprovable), style = MaterialTheme.typography.bodyMedium)
        match.unavailable.forEach { (label, why) ->
            Text(stringResource(Res.string.pair_colon, label, why), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
    }
    form.predicates(match).second?.let { Text(stringResource(it.first, it.second), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    Text(stringResource(Res.string.zkpdf_background),
        style = MaterialTheme.typography.bodySmall)
    if (job != null && job.active) {
        Text(job.step ?: if (job.phase == ZkJobPhase.QUEUED) stringResource(Res.string.zkpdf_waiting) else stringResource(Res.string.zkpdf_making), style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary)
        OutlinedButton(onClick = { model.files.cancelZkPdf(fileId) }) { Text(stringResource(Res.string.zkpdf_cancel)) }
    }
}
