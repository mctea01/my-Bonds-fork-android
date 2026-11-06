package diw.wallet.app.ui

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
                TextButton(onClick = { scope.launch { find() } }) { Text("重新尋找") }
            }
            list.problem?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = if (list.readers.isEmpty()) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
    if (withPin) {
        OutlinedTextField(
            value = pin,
            onValueChange = { v -> pin = v.filter { it.code in 0x20..0x7E }.take(OpenPgpCard.PIN_MAX); onChange(reader, pin) },
            label = { Text("使用者 PIN（PW1，${OpenPgpCard.PIN_MIN} 至 ${OpenPgpCard.PIN_MAX} 字元）") },
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
    reader?.let { r -> OutlinedButton(onClick = { model.openPgp.readCard(r) }, enabled = busy == null) { Text(if (card == null) "讀取卡片查看金鑰（不需 PIN）" else "重新讀取卡片") } }
    BusyLine(busy, error)
    card?.let { info ->
        OpenPgpCardView(model, info)
        val sig = info.key(OpenPgpKeySlot.SIGNATURE)
        when {
            sig == null -> Text("這張卡沒有簽章金鑰，無法簽署。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            x509 && !OpenPgpTapSigner.x509Capable(sig) -> Text(
                "簽章金鑰是 ${sig.algorithm}，只能做 OpenPGP 簽章；PDF、XML、CAdES 與 ASiC-E 需要 RSA 或 ECDSA P-256 金鑰。請改選「OpenPGP 分離式簽章」。",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
            )
            !x509 && sig.packet == null -> Text(
                "卡上的指紋與由卡片重建的公開金鑰不符，請先在「OpenPGP 公開金鑰」匯入你的公開金鑰檔，簽章才能指名你發布的金鑰。",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
            )
        }
    }
    Text(
        (if (x509) "以 OpenPGP 卡的簽章金鑰簽 X.509 格式：卡上有持卡人憑證（DO 7F21）且與金鑰相符時使用它，否則由卡片簽發一張自簽憑證（查驗方會看到 T3），之後沿用。"
        else "簽出 OpenPGP v4 分離式簽章（ASCII armor），以卡上記錄的指紋指名你的金鑰。") +
            "支援 OpenPGP 卡 2.0 以上、YubiKey 5 系列（NFC 或 USB 直插）、Nitrokey 與 Gnuk；手機 NFC 需感應兩次，USB 直插保持接上即可。PIN 只用於這次簽署，不會保存；輸入錯誤會立即停止並顯示剩餘次數。",
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
            Text(listOfNotNull("規格 ${info.version}", info.cardholder?.let { "持卡人 $it" }, info.signatureCount?.let { "已簽 $it 次" }).joinToString("・"),
                style = MaterialTheme.typography.bodySmall)
            info.pinStatus?.let { p ->
                Text("PIN 剩餘次數：使用者 ${p.pw1Tries}、重設碼 ${p.resetTries}、管理者 ${p.adminTries}" + if (info.kdf != null) "（PIN 以 KDF 處理後送出）" else "",
                    style = MaterialTheme.typography.bodySmall, color = if (p.pw1Tries == 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            }
            info.url?.let { Text("公開金鑰網址：$it", style = MaterialTheme.typography.bodySmall) }
            info.keys.forEach { k ->
                HorizontalDivider()
                Text(k.slot.title + if (k.present) "　${k.algorithm}" else "　（沒有金鑰）", style = MaterialTheme.typography.bodyMedium)
                if (k.present) {
                    k.fingerprintText?.let { SelectionContainer { Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) } }
                    val fpr = k.fingerprint?.let { f -> f.joinToString("") { b -> (b.toInt() and 0xFF).toString(16).padStart(2, '0') }.uppercase() }
                    val listed = fpr?.let { f -> keys.firstOrNull { it.info.has(f) } }
                    Text(buildList {
                        if (k.created > 0) add("建立於 " + localTime(k.created).substringBefore(' '))
                        add(if (k.packet != null) "公開金鑰已由卡片重建" else "指紋不符，需匯入公開金鑰檔")
                        if (k.certificate != null) add("有持卡人憑證")
                        add(listed?.let { "清單：" + it.trust.title } ?: "不在清單")
                    }.joinToString("・"), style = MaterialTheme.typography.bodySmall)
                }
            }
            TextButton(onClick = { model.openPgp.addReadCard() }) { Text("加入公開金鑰清單（標示為自己的卡）") }
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
        Text("OpenPGP 沒有憑證機構，金鑰可不可信由你決定。簽章與加密都以這份清單為準：", style = MaterialTheme.typography.bodyMedium)
        OpenPgpTrust.entries.forEach { t -> Text("・${t.title}：${t.detail}", style = MaterialTheme.typography.bodySmall) }
        Text("介紹人：把已核對指紋（或自己的卡）的金鑰設為介紹人後，它認證過的「未核對」金鑰會升為 T2；只算一層，不會再往下傳遞。", style = MaterialTheme.typography.bodySmall)
        BusyLine(busy, error)

        SectionTitle("加入金鑰")
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { model.openPgp.pickAndImport() }, enabled = busy == null) { Text("匯入公開金鑰檔") }
        }
        Text("可一次選多個 .asc、.gpg、.pub 檔；含私鑰的檔案只保留公開部分。匯入的金鑰為「未核對」。", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(value = query, onValueChange = { query = it.take(200) }, label = { Text("指紋、金鑰 ID 或電子郵件") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedButton(onClick = { model.openPgp.lookup(query) }, enabled = busy == null && query.isNotBlank()) { Text("查詢") }
        Text("電子郵件先查該網域的 Web Key Directory，再查 keys.openpgp.org；指紋與金鑰 ID 查 keys.openpgp.org。查到的金鑰需你確認後才加入，且為「未核對」。",
            style = MaterialTheme.typography.bodySmall)
        found?.let { fd ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("查詢「${fd.query}」：${fd.source}", style = MaterialTheme.typography.titleSmall)
                    if (fd.keys.isEmpty()) Text("沒有找到相符的公開金鑰。", style = MaterialTheme.typography.bodySmall)
                    fd.keys.forEach { (info, _) -> KeySummary(info) }
                    Row {
                        if (fd.keys.isNotEmpty()) TextButton(onClick = { confirmFound = true }) { Text("加入清單") }
                        TextButton(onClick = { model.openPgp.dismissFound() }) { Text("關閉") }
                    }
                }
            }
            if (confirmFound) RiskConfirmDialog(
                title = "加入查到的公開金鑰",
                lines = listOf(
                    "這把金鑰來自 ${fd.source}，" + if (fd.source.startsWith("Web Key Directory")) "由該網域發布，只代表網域管理者的說法。" else "該服務只確認過電子郵件的收信權，不代表持有人的身分。",
                    "加入後為「未核對」（T3）：簽章可確認屬於這把金鑰，但不能確認是誰。",
                    "請向持有人以當面、電話或官方網站核對完整指紋，再改為「已核對指紋」。",
                ),
                confirm = "加入",
                onConfirm = { confirmFound = false; model.openPgp.acceptFound() },
                onDismiss = { confirmFound = false },
            )
        }

        SectionTitle("自己的 OpenPGP 卡")
        OpenPgpReaderPin(model, withPin = false) { r, _ -> reader = r }
        reader?.let { r -> OutlinedButton(onClick = { model.openPgp.readCard(r) }, enabled = busy == null) { Text("讀取卡片（不需 PIN）") } }
        card?.let { OpenPgpCardView(model, it) }
        Text("讀取 OpenPGP 卡、YubiKey 或 Nitrokey 上的金鑰並標示為自己的卡（T2）。清單中已有含這些金鑰的完整公開金鑰時，直接把它標示為自己的卡；否則由卡片的金鑰建立一份不含使用者 ID 的公開金鑰。",
            style = MaterialTheme.typography.bodySmall)

        HorizontalDivider()
        SectionTitle("清單（${keys.size}）")
        if (keys.isEmpty()) Text("還沒有公開金鑰。", style = MaterialTheme.typography.bodySmall)
        keys.forEach { e -> KeyEntryCard(model, e, busy == null) }
    }
}

@Composable
private fun KeySummary(info: OpenPgpKeyInfo) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(info.name, style = MaterialTheme.typography.bodyMedium)
        info.userIds.drop(1).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        SelectionContainer { Text(groupedFingerprint(info.fingerprint), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
        (listOf(info.primary) + info.subkeys).forEachIndexed { i, k -> Text((if (i == 0) "主金鑰" else "子金鑰") + "　" + subkeyLine(k), style = MaterialTheme.typography.bodySmall) }
    }
}

private fun subkeyLine(k: OpenPgpSubkeyInfo): String = buildList {
    add(k.algorithm)
    val uses = listOfNotNull("簽章".takeIf { k.canSign }, "加密".takeIf { k.canEncrypt })
    if (uses.isNotEmpty()) add(uses.joinToString("、"))
    if (k.created > 0) add("建立 " + localTime(k.created).substringBefore(' '))
    k.expires?.let { add("到期 " + localTime(it).substringBefore(' ')) }
    if (k.revoked) add("已撤銷")
}.joinToString("・")

@Composable
private fun KeyEntryCard(model: WalletModel, e: OpenPgpKeyEntry, enabled: Boolean) {
    var confirmVerify by remember(e.fingerprint) { mutableStateOf(false) }
    var confirmRemove by remember(e.fingerprint) { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            KeySummary(e.info)
            if (e.info.revoked) Text("主金鑰已撤銷：它的簽章一律不可信", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            Text("來源：" + e.source + "・加入於 " + localTime(e.addedAt) + if (e.cardOnly) "・只含卡片上的金鑰" else "", style = MaterialTheme.typography.bodySmall)
            Text("信任：" + e.trust.title + "（" + e.trust.detail + "）", style = MaterialTheme.typography.bodySmall)
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
                Text(if (canIntroduce) "設為介紹人：信任它對其他金鑰的認證" else "設為介紹人（需先核對這把金鑰的指紋）", style = MaterialTheme.typography.bodySmall)
            }
            Row(Modifier.horizontalScroll(rememberScrollState())) {
                TextButton(onClick = { model.openPgp.export(e.fingerprint, share = false) }) { Text("匯出") }
                if (model.platform.canShareFiles) TextButton(onClick = { model.openPgp.export(e.fingerprint, share = true) }) { Text("分享") }
                TextButton(onClick = { confirmRemove = true }, enabled = enabled) { Text("移除", color = MaterialTheme.colorScheme.error) }
            }
        }
    }
    if (confirmVerify) AlertDialog(
        onDismissRequest = { confirmVerify = false },
        title = { Text("已核對指紋？") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("請確認你已透過可靠管道（當面、電話或對方的官方網站）取得對方的完整指紋，並與下列每一組逐一比對相同：")
                SelectionContainer { Text(groupedFingerprint(e.fingerprint), fontFamily = FontFamily.Monospace) }
                Text("只比對最後幾碼或金鑰 ID 不夠，攻擊者可以造出相同的短 ID。核對後它的簽章判定為 T2。", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = { confirmVerify = false; model.openPgp.setTrust(e.fingerprint, OpenPgpTrust.VERIFIED) }) { Text("已核對") } },
        dismissButton = { TextButton(onClick = { confirmVerify = false }) { Text("取消") } },
    )
    if (confirmRemove) AlertDialog(
        onDismissRequest = { confirmRemove = false },
        title = { Text("移除這把公開金鑰？") },
        text = { Text("移除後，它的簽章會顯示為找不到簽署者金鑰；之後可以再匯入。設為「不信任」則會保留並一律判定為不可信。") },
        confirmButton = { TextButton(onClick = { confirmRemove = false; model.openPgp.remove(e.fingerprint) }) { Text("移除", color = MaterialTheme.colorScheme.error) } },
        dismissButton = { TextButton(onClick = { confirmRemove = false }) { Text("取消") } },
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
        if (pgp.kind == OpenPgpKind.SECRET_KEYS) Text("這個檔案含私鑰。錢包不使用私鑰，加入清單時只保留公開部分；建議不要把私鑰檔留在手機上。",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        val missing = pgp.keys.count { k -> keys.none { it.fingerprint == k.fingerprint } }
        if (missing > 0) OutlinedButton(onClick = { model.openPgp.importFromFile(f) }) { Text("加入公開金鑰清單（$missing 把，未核對）") }
        else Text("這些金鑰都已在 OpenPGP 公開金鑰清單。", style = MaterialTheme.typography.bodySmall)
    }
    if (pgp.kind == OpenPgpKind.ENCRYPTED) {
        pgp.encryption?.let { LabelValue("加密方式", it, small = true) }
        pgp.recipients.forEach { r ->
            val hidden = r.key.all { it == '0' }
            val who = if (hidden || r.key == "密碼") null else keys.firstOrNull { it.info.has(r.key) }
            LabelValue("收件人", when {
                r.key == "密碼" -> "以密碼加密（錢包不支援）"
                hidden -> "隱藏的收件人（${r.algorithm}）"
                else -> (who?.info?.name ?: "不在清單") + "　" + r.key + "（${r.algorithm}）"
            }, small = true)
        }
        Text("以收件人的 OpenPGP 卡解密：卡片解出會話金鑰，錢包再解開內容並檢查完整性，解出的檔案另存一份；內含的簽章另存為 .asc。", style = MaterialTheme.typography.bodySmall)
        OpenPgpReaderPin(model) { r, p -> reader = r; pin = p }
        Button(onClick = { reader?.let { model.files.decryptOpenPgp(f, it, pin) } },
            enabled = busy == null && reader != null && pin.length in OpenPgpCard.PIN_MIN..OpenPgpCard.PIN_MAX) { Text("以 OpenPGP 卡解密") }
    }
    if (pgp.kind == OpenPgpKind.SIGNED_MESSAGE || pgp.kind == OpenPgpKind.LITERAL) {
        pgp.literalName?.let { LabelValue("內容檔名", it, small = true) }
        pgp.literalSize?.let { LabelValue("內容大小", sizeText(it), small = true) }
        OutlinedButton(onClick = { model.files.unwrapOpenPgp(f) }, enabled = busy == null) { Text("取出內容另存") }
    }
    pgp.signers.filter { s -> keys.none { it.info.has(s) } }.distinct().forEach { s ->
        ActionRow(WalletIcons.Search, "查詢簽署者的公開金鑰", "$s 不在清單；查到後需你確認才加入") {
            model.screen.value = Screen.OpenPgpKeys(s, Screen.FileDetail(f.id))
        }
    }
    if (report.signatures.any { it.signer != null }) {
        Text("OpenPGP 簽章的信任等級來自 OpenPGP 公開金鑰清單中你對簽署金鑰的設定。", style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = { model.screen.value = Screen.OpenPgpKeys(null, Screen.FileDetail(f.id)) }) { Text("管理 OpenPGP 公開金鑰") }
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
        title = { Text("以 OpenPGP 加密") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("加密給選取的收件人（AES-256，含完整性保護），另存為新檔；原檔不變。勾選自己的卡，之後才能自己解開。", style = MaterialTheme.typography.bodySmall)
                if (usable.isEmpty()) Text("清單中沒有可加密的公開金鑰。請先在「OpenPGP 公開金鑰」匯入或讀取卡片。", style = MaterialTheme.typography.bodySmall)
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
                    Text("有收件人尚未核對指紋：若金鑰不是對方的，內容會被別人解開。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Row(Modifier.clickable { armor = !armor }, verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = armor, onCheckedChange = { armor = it })
                    Text("ASCII armor（.asc，可貼進郵件）；不勾選為二進位 .gpg", style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onDismiss(); model.files.encryptOpenPgp(f, chosen.toList(), armor) }, enabled = chosen.isNotEmpty()) { Text("加密") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}
