package diw.wallet.app.ui

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
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import diw.wallet.app.HomeTab
import diw.wallet.app.Screen
import diw.wallet.app.SignerChoice
import diw.wallet.app.StoredFile
import diw.wallet.app.TaiwanModel
import diw.wallet.app.WalletModel
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.profile.bonds.BondsNationalId
import diw.wallet.core.profile.bonds.MoicaSignedCredential
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
                    Text(name ?: "國民身分證", style = MaterialTheme.typography.titleMedium)
                    Text("國民身分證（Bonds 自發卡）", style = MaterialTheme.typography.bodySmall)
                }
            }
            Text("自然人憑證簽署、vc+moica" + (issued?.let { "、$it 製作" } ?: ""), style = MaterialTheme.typography.bodySmall)
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
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("把 MyData 下載的「國民身分證資料」PDF 做成 Bonds 相容的身分證卡：欄位由你的自然人憑證簽署，查驗方可以只看你選的欄位（例如只看是否年滿 18 歲）。",
            style = MaterialTheme.typography.bodyMedium)
        LabelValue("檔案", f.name)
        val d = draft?.takeIf { it.fileId == f.id }
        if (d == null) {
            SectionTitle("開啟檔案")
            OutlinedTextField(
                value = idNumber,
                onValueChange = { v -> idNumber = v.filter { it.isLetterOrDigit() }.take(10) },
                label = { Text("身分證統一編號") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, keyboardType = KeyboardType.Ascii),
                modifier = Modifier.fillMaxWidth(),
            )
            Text("MyData 的身分證資料 PDF 以你的身分證統一編號加密。編號只用來開啟這份檔案，不會保存或記錄。", style = MaterialTheme.typography.bodySmall)
            BusyLine(busy, error)
            Button(onClick = { model.files.readNationalId(f, idNumber) }, enabled = busy == null && idNumber.isNotBlank()) { Text("開啟並讀取") }
            return@Column
        }
        SectionTitle("確認欄位")
        val claims = BondsNationalId.claims(d.fields, kotlin.time.Clock.System.now()).toMap()
        BondsNationalId.claimOrder.forEach { name -> claims[name]?.let { LabelValue(BondsNationalId.claimLabels[name] ?: name, if (name == BondsNationalId.CLAIM_OVER_18) yesNo(it) else it) } }
        if (d.over18 == null) Text("出生日期不是可辨識的民國日期格式，卡片不含「年滿 18 歲」欄位。", style = MaterialTheme.typography.bodySmall)
        VerdictCard(
            Verdict.CAUTION,
            "由你本人聲明，不是戶政機關簽發",
            listOf(
                "MyData 下載的檔案本身沒有政府簽章；身分證卡由你的自然人憑證簽署，表示你本人聲明這些內容。",
                "自然人憑證上的姓名必須與上面的姓名相同，查驗方會比對。",
            ),
        )
        SectionTitle("以自然人憑證簽署")
        CardPicker(model) { card = it }
        ActionRow(WalletIcons.Phone, "改用行動自然人憑證", "需要內政部核發的服務提供者（SP）帳號才能發出簽章請求，目前只能使用實體卡", enabled = false) {}
        BusyLine(busy, error)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { card?.let { model.files.issueNationalId(d, it) } }, enabled = busy == null && card != null) { Text("簽署並製作") }
            OutlinedButton(onClick = { model.files.nationalIdDraft.value = null }, enabled = busy == null) { Text("重新輸入") }
        }
    }
}

private fun yesNo(v: String): String = when (v) {
    "true" -> "是"
    "false" -> "否"
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
        EmptyState(WalletIcons.Person, "找不到這張身分證卡", "卡片或它的來源檔案可能已刪除。", "回到證件") { model.showTab(HomeTab.DOCUMENTS) }
        return
    }
    var confirmDelete by remember { mutableStateOf(false) }
    val name = cardholder(card)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        NationalIdCardView(name, issuedAt(card)) {}
        BusyLine(busy, error)
        SectionTitle("欄位")
        TaiwanModel.nationalIdClaims(card).forEach { (k, v) ->
            LabelValue(BondsNationalId.claimLabels[k] ?: k, if (k == BondsNationalId.CLAIM_OVER_18) yesNo(v) else v)
        }
        SectionTitle("簽署")
        name?.let { LabelValue("自然人憑證持有人", it) }
        issuedAt(card)?.let { LabelValue("製作時間", it) }
        LabelValue("格式", "Bonds vc+moica（W3C VC 2.0，欄位以 SD-JWT 雜湊承諾）")
        LabelValue("來源檔案", f.name, onClick = { model.screen.value = Screen.FileDetail(f.id) })
        Text("出示：查驗方產生「自然人憑證自發卡」的 Bonds 查驗挑戰後，在「使用」掃描它，選這張卡與要揭露的欄位；姓名一定會揭露，並由查驗方與自然人憑證比對。",
            style = MaterialTheme.typography.bodySmall)
        Text("這張卡證明的是「你以自然人憑證聲明了這些內容」，不是戶政機關的背書。", style = MaterialTheme.typography.bodySmall)
        SectionTitle("動作")
        ActionRow(WalletIcons.Scan, "出示", "到「使用」掃描查驗方的 QR Code") { model.showTab(HomeTab.USE) }
        ActionRow(WalletIcons.Send, "匯出 vc+moica", "Bonds 自然人憑證自發卡片的 JSON，含全部欄位") { model.files.exportNationalId(f) }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { confirmDelete = true }) {
            Icon(WalletIcons.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text("刪除身分證卡", color = MaterialTheme.colorScheme.error)
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("刪除這張身分證卡？") },
            text = { Text("卡片會從這支裝置刪除；來源 PDF 保留在「文件」，之後可以再用自然人憑證重新製作。") },
            confirmButton = { TextButton(onClick = { confirmDelete = false; model.files.deleteNationalId(f) }) { Text("刪除", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("取消") } },
        )
    }
}
