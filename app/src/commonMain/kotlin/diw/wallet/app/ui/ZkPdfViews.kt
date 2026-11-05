package diw.wallet.app.ui

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
    fun predicates(match: FilesModel.ZkPdfMatch): Pair<List<ZkPdfPredicate>, String?> {
        val list = ArrayList<ZkPdfPredicate>()
        for ((claim, c) in conditions) {
            val field = match.fields.firstOrNull { it.name == claim } ?: continue
            val label = field.label ?: claim
            val date = runCatching { LocalDate.parse(c.date.trim()) }.getOrNull()
                ?: return emptyList<ZkPdfPredicate>() to "「$label」的條件日期格式為 年-月-日"
            val cutoff = date.year * 10000 + (date.month.ordinal + 1) * 100 + date.day
            if (cutoff !in 10000101..99991231) return emptyList<ZkPdfPredicate>() to "「$label」的條件日期超出範圍"
            val value = runCatching { LocalDate.parse(field.value) }.getOrNull()
                ?.let { it.year * 10000 + (it.month.ordinal + 1) * 100 + it.day }
                ?: return emptyList<ZkPdfPredicate>() to "「$label」不是日期，無法加條件"
            val holds = if (c.kind == ZkPdfPredicate.DATE_LE) value <= cutoff else value >= cutoff
            if (!holds) return emptyList<ZkPdfPredicate>() to "文件中的「$label」不符合這個條件，無法證明"
            list += ZkPdfPredicate(c.kind, claim, cutoff)
        }
        if (list.size > 2) return emptyList<ZkPdfPredicate>() to "最多加兩個日期條件"
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
            "zkPDF 零知識證明：沒有符合這份 PDF 的文件版型。版型隨發布更新" +
                (if (settings.testEnvironment) "；測試環境可在設定的「零知識證明」頁匯入測試版型" else "") + "。",
            style = MaterialTheme.typography.bodySmall,
        )
        return
    }
    val match = form.match(matches) ?: return
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = form.on, onCheckedChange = { onChange(form.copy(on = it, profileId = match.profile.id)) })
        Text("附上 zkPDF 零知識證明（證明欄位出自 PDF 內的簽章，查驗方不需要原檔）")
    }
    if (!form.on) return
    if (matches.size > 1) {
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            matches.forEach { m ->
                FilterChip(selected = m.profile.id == match.profile.id, onClick = { onChange(form.copy(profileId = m.profile.id, conditions = emptyMap())) },
                    label = { Text(m.profile.title + if (m.profile.test) "（測試）" else "") })
            }
        }
    }
    Text("文件版型：${match.profile.title}（${match.profile.id}）" + if (match.profile.test) "・測試版型，只在測試環境查驗" else "",
        style = MaterialTheme.typography.bodySmall)
    Text("可證明的欄位（出示時可個別選擇是否揭露）", style = MaterialTheme.typography.bodyMedium)
    match.fields.forEach { field ->
        LabelValue(field.label ?: field.name, field.value)
        if (match.profile.field(field.name)?.normalize == ZkPdfNormalize.DATE) {
            val c = form.conditions[field.name]
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                FilterChip(selected = c == null, onClick = { onChange(form.copy(conditions = form.conditions - field.name)) }, label = { Text("不加條件") })
                FilterChip(selected = c?.kind == ZkPdfPredicate.DATE_LE,
                    onClick = { onChange(form.copy(conditions = form.conditions + (field.name to ZkPdfConditionInput(ZkPdfPredicate.DATE_LE, c?.date ?: "")))) },
                    label = { Text("不晚於") })
                FilterChip(selected = c?.kind == ZkPdfPredicate.DATE_GE,
                    onClick = { onChange(form.copy(conditions = form.conditions + (field.name to ZkPdfConditionInput(ZkPdfPredicate.DATE_GE, c?.date ?: "")))) },
                    label = { Text("不早於") })
            }
            if (c != null) {
                OutlinedTextField(
                    value = c.date,
                    onValueChange = { onChange(form.copy(conditions = form.conditions + (field.name to c.copy(date = it.take(10))))) },
                    label = { Text("日期（2008-01-01）") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text("查驗方可只看到「${field.label ?: field.name}${if (c.kind == ZkPdfPredicate.DATE_LE) "不晚於" else "不早於"}這個日期」，不必揭露實際日期。",
                    style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    if (match.unavailable.isNotEmpty()) {
        Text("無法證明的欄位", style = MaterialTheme.typography.bodyMedium)
        match.unavailable.forEach { (label, why) ->
            Text("$label：$why", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
    }
    form.predicates(match).second?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    Text("證明在這台裝置的背景產生，手機約需數分鐘、佔用約 2 GB 記憶體；可隨時取消，未完成時不會產生憑證。只支援單頁、沒有開啟密碼且只有一個文件簽章的 PDF。",
        style = MaterialTheme.typography.bodySmall)
    if (job != null && job.active) {
        Text(job.step ?: if (job.phase == ZkJobPhase.QUEUED) "等待其他證明完成" else "產生中", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary)
        OutlinedButton(onClick = { model.files.cancelZkPdf(fileId) }) { Text("取消 zkPDF 證明") }
    }
}
