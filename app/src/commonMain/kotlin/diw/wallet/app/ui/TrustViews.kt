package diw.wallet.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import diw.wallet.app.WalletModel
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.oid4vp.AttestationVerdict
import diw.wallet.core.oid4vp.VerifierAttestation
import diw.wallet.core.oid4vp.VerifierInfoChecker

fun tierColor(t: TrustTier): Color = when (t) {
    TrustTier.T1 -> Color(0xFF1B7F3B)
    TrustTier.T2 -> Color(0xFF1565C0)
    TrustTier.T3 -> Color(0xFFB26A00)
    TrustTier.T4 -> Color(0xFFB3261E)
}

fun labelText(l: TrustLabel): String = when (l) {
    TrustLabel.TEST_ANCHOR -> "測試錨點"
    TrustLabel.USER_ANCHOR -> "使用者自行匯入的錨點"
    TrustLabel.UNKNOWN_ANCHOR -> "憑證鏈不在信任清單"
    TrustLabel.UNSIGNED_REQUEST -> "請求未簽章"
    TrustLabel.VIA_INTERMEDIARY -> "經由中介服務"
    TrustLabel.RETAINS_DATA -> "對方會保存資料"
    TrustLabel.HAS_TRANSACTION_DATA -> "含交易資料"
    TrustLabel.SOFTWARE_KEY -> "軟體金鑰"
    TrustLabel.TIME_NOT_VERIFIED -> "時間未驗證"
    TrustLabel.UNSIGNED_METADATA -> "發行端資訊未簽章"
    TrustLabel.KEY_NOT_ATTESTED -> "金鑰未經證明"
    TrustLabel.LINKED_DOMAIN -> "網域已驗證（Microsoft Verified ID 規範）"
    TrustLabel.SYSTEM_ANCHOR -> "系統憑證庫（公開憑證機構）"
    TrustLabel.IDENTITY_VERIFIED -> "身分由政府憑證（GPKI）證明"
    TrustLabel.MAINLAND_CHINA_CA -> "中國大陸憑證機構（公開憑證機構）"
    TrustLabel.SELF_ISSUED -> "本錢包簽發"
    TrustLabel.AATL -> "Adobe 核可信任清單（AATL）"
    TrustLabel.EUTL -> "歐盟信任清單（EUTL）"
    TrustLabel.EU_QUALIFIED -> "歐盟合格信任服務"
}

/** The clause added for an EU trusted list service the list names as qualified. */
private fun qualified(t: TrustDecision): String = if (TrustLabel.EU_QUALIFIED in t.labels) "，為合格信任服務" else ""

private const val SELF_ISSUED_TEXT =
    "由這個錢包依你保存的文件產生並簽發（發行端是錢包自己的 DID），只表示內容取自該文件，不代表文件的發行機關背書。文件本身的簽章與時戳見「文件證據」。"

/** A TWDIW-listed party whose on-chain registration or role could not be confirmed (T2 from the national list). */
private fun twdiwListed(t: TrustDecision): Boolean = t.reasons.any { "TWDIW trust list" in it }

/** One-line advice per tier; official or anchored parties get the short form. */
fun tierAdvice(t: TrustDecision): String = when {
    t.environment == TrustEnvironment.TEST -> "對方的憑證來自測試錨點，結果不具任何正式效力。"
    t.tier == TrustTier.T1 -> "官方信任清單內的對象，並經過額外驗證。"
    TrustLabel.SELF_ISSUED in t.labels -> SELF_ISSUED_TEXT
    t.tier == TrustTier.T4 -> "無法驗證對方身分。除非你確定來源，否則不要分享或接受。"
    t.tier == TrustTier.T3 -> "簽章有效，但沒有連到任何信任根，無法確認對方是誰。請確認你認識這個對象再繼續。"
    TrustLabel.IDENTITY_VERIFIED in t.labels -> "憑證鏈連到政府憑證（GPKI）：${t.anchorName ?: ""}，可確認對方是哪個機關、組織或公司；不代表它列於數位憑證皮夾的清單。"
    twdiwListed(t) -> "列於數位憑證皮夾信任清單，但鏈上註冊暫時無法確認，或列名的角色不符。"
    TrustLabel.LINKED_DOMAIN in t.labels -> "已確認對方擁有網域 ${t.anchorName ?: ""}（DIF Well-Known DID Configuration，與 Microsoft Authenticator 相同的驗證方式）。"
    TrustLabel.MAINLAND_CHINA_CA in t.labels -> "憑證鏈連到中國大陸的公開憑證機構（${t.anchorName ?: ""}），可確認網域或組織名稱。"
    TrustLabel.AATL in t.labels -> "憑證鏈連到 Adobe 核可信任清單（AATL）的憑證機構（${t.anchorName ?: ""}），可確認簽署者的組織或姓名。"
    TrustLabel.EUTL in t.labels -> "憑證鏈連到歐盟信任清單（EUTL）的憑證機構（${t.anchorName ?: ""}）${qualified(t)}，可確認簽署者的組織或姓名。"
    TrustLabel.SYSTEM_ANCHOR in t.labels -> "憑證鏈連到系統憑證庫的公開憑證機構（${t.anchorName ?: ""}），可確認網域或組織名稱。"
    t.environment == TrustEnvironment.USER -> "由你自行匯入的根憑證、mdoc 簽署清單或自行信任的 DID 確認。"
    t.anchorName != null -> "憑證鏈連到內建的發行端憑證（${t.anchorName}，與 Multipaz Wallet 相同的信任清單），可確認發行者。"
    else -> "連到信任根，可確認對方身分。"
}

/**
 * Who a document signer or time-stamp authority is, by the trust of its certificate chain. It says nothing about the
 * signature itself, whose integrity and validity are shown beside it (an invalid signature must not read as valid).
 */
fun signerTrustLine(t: TrustDecision): String = when {
    t.environment == TrustEnvironment.TEST -> "簽署者的憑證來自測試錨點，不具正式效力。"
    t.tier == TrustTier.T1 -> "簽署者列於官方信任清單。"
    t.tier == TrustTier.T4 -> "簽署者的憑證鏈驗證失敗。"
    t.tier == TrustTier.T3 -> "憑證鏈沒有連到任何信任根，無法確認簽署者是誰。"
    TrustLabel.IDENTITY_VERIFIED in t.labels -> "簽署者身分由政府憑證（GPKI）證明：${t.anchorName ?: ""}。"
    TrustLabel.MAINLAND_CHINA_CA in t.labels -> "簽署者憑證連到中國大陸的公開憑證機構（${t.anchorName ?: ""}），可確認組織名稱。"
    TrustLabel.AATL in t.labels -> "簽署者憑證連到 Adobe 核可信任清單（AATL）：${t.anchorName ?: ""}。"
    TrustLabel.EUTL in t.labels -> "簽署者憑證連到歐盟信任清單（EUTL）：${t.anchorName ?: ""}${qualified(t)}。"
    TrustLabel.SYSTEM_ANCHOR in t.labels -> "簽署者憑證連到公開憑證機構（${t.anchorName ?: ""}），可確認網域或組織名稱。"
    t.environment == TrustEnvironment.USER -> "簽署者由你自行匯入的根憑證確認（${t.anchorName ?: ""}）。"
    else -> "簽署者憑證連到信任根（${t.anchorName ?: ""}）。"
}

/** What the trust says about the issuer of a document being verified, one sentence for a verdict card. */
fun issuerTrustLine(t: TrustDecision?): String = when {
    t == null -> "發行端不在任何信任來源，無法確認這張證件由誰簽發。"
    t.environment == TrustEnvironment.TEST -> "發行端的憑證來自測試錨點，結果不具效力。"
    t.tier == TrustTier.T1 -> "發行端列於官方信任清單。"
    TrustLabel.SELF_ISSUED in t.labels -> SELF_ISSUED_TEXT
    t.tier == TrustTier.T4 -> "發行端驗證失敗，無法確認這張證件由誰簽發。"
    t.tier == TrustTier.T3 -> "簽章可驗證，但發行端沒有連到任何信任根，無法確認這張證件由誰簽發。"
    TrustLabel.IDENTITY_VERIFIED in t.labels -> "發行端身分由政府憑證（GPKI）證明：${t.anchorName ?: ""}，但不代表它列於發行端清單。"
    twdiwListed(t) -> "發行端列於數位憑證皮夾信任清單，但鏈上註冊暫時無法確認，或列名的角色不是發行端。"
    TrustLabel.LINKED_DOMAIN in t.labels -> "發行端的 DID 已連結網域 ${t.anchorName ?: ""}。"
    TrustLabel.MAINLAND_CHINA_CA in t.labels -> "發行端憑證連到中國大陸憑證機構（${t.anchorName ?: ""}），可確認網域或組織名稱。"
    t.environment == TrustEnvironment.SYSTEM -> "發行端憑證連到公開憑證機構（${t.anchorName ?: ""}），可確認網域或組織名稱。"
    t.environment == TrustEnvironment.USER -> "發行端由你自行匯入的根憑證、mdoc 簽署清單（VICAL）或自行信任的 DID 確認。"
    else -> "發行端憑證連到內建的發行端憑證（${t.anchorName ?: ""}），可確認發行者。"
}

/** The four trust tiers as the wallet assigns them, each with the sources that lead to it. */
@Composable
fun TierLegend() {
    val rows = listOf(
        TrustTier.T1 to "官方清單並經額外驗證：數位憑證皮夾（TWDIW）信任清單內、DID 文件自簽有效且與 Arbitrum One 註冊相符的組織，以及標為官方的正式信任錨點。",
        TrustTier.T2 to "連到信任根，視為高可信：政府憑證（GPKI：GCA、XCA、MOEACA，查驗方與文件簽章另含 MOICA 自然人憑證）、系統憑證庫與內建公開憑證機構（含中國大陸與國密 SM2 憑證機構）、文件簽章與時戳的 Adobe 核可信任清單（AATL）與歐盟信任清單（EUTL）、內建的發行端憑證（如 Google、Apple 的身分證件）、Microsoft Verified ID 的 Linked Domains、你匯入的根憑證、mdoc 簽署清單（VICAL、RICAL）與自行信任的 DID，以及列於 TWDIW 信任清單但鏈上註冊暫時無法確認或角色不符的組織。",
        TrustTier.T3 to "簽章可驗證，但沒有連到任何信任根：不在任何清單的 DID 或憑證鏈，以及測試環境的所有錨點。出示或領卡前需要勾選確認。",
        TrustTier.T4 to "驗證失敗：簽章或憑證鏈不成立、要求未簽章、信任清單內容與鏈上註冊不符，或網域連結失效。仍可在警告確認後繼續，風險由你自行承擔。",
    )
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        // The badge sits above its text, so the text keeps the full width on a narrow phone.
        rows.forEach { (tier, text) ->
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Box(
                    Modifier.background(tierColor(tier), RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(WalletModel.tierTitle(tier), color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                }
                Text(text, style = MaterialTheme.typography.bodySmall)
            }
        }
        Text("中繼憑證（內建或匯入）只用來補足憑證鏈，等級由最後連到的根憑證決定。測試錨點最高為 T3 並標示為測試，結果永遠不是官方。", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
fun TierBadge(trust: TrustDecision, modifier: Modifier = Modifier) {
    Box(
        modifier
            .background(tierColor(trust.tier), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(WalletModel.tierTitle(trust.tier), color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun TrustCard(title: String, subject: String, trust: TrustDecision, extra: List<String> = emptyList(), onClick: (() -> Unit)? = null) {
    Card(
        modifier = Modifier.fillMaxWidth().then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
        colors = CardDefaults.cardColors(containerColor = tierColor(trust.tier).copy(alpha = 0.08f)),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(title, style = MaterialTheme.typography.labelLarge)
                TierBadge(trust)
            }
            Text(subject, style = MaterialTheme.typography.titleMedium)
            trust.anchorName?.let { Text("信任錨點：$it", style = MaterialTheme.typography.bodySmall) }
            Text(tierAdvice(trust), style = MaterialTheme.typography.bodyMedium)
            if (trust.labels.isNotEmpty()) {
                Text(trust.labels.joinToString("、") { labelText(it) }, style = MaterialTheme.typography.bodySmall, color = tierColor(trust.tier))
            }
            extra.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/**
 * One verifier_info entry as checked: who registered the verifier, for what purpose, which signer vouches for it,
 * and every failed check. A test registrar never reads as official.
 */
@Composable
fun VerifierAttestationCard(a: VerifierAttestation) {
    val (verdict, title) = when (a.verdict) {
        AttestationVerdict.VALID -> Verdict.PASS to "登錄證明有效"
        AttestationVerdict.PARTIAL -> Verdict.CAUTION to "登錄證明部分確認"
        AttestationVerdict.INVALID -> Verdict.FAIL to "登錄證明不成立"
        AttestationVerdict.UNSUPPORTED -> Verdict.CAUTION to "無法驗證的證明"
    }
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = verdict.color.copy(alpha = 0.10f))) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (a.type == VerifierInfoChecker.RC_TYP) "查驗方登錄證明" else "查驗方附上的證明", style = MaterialTheme.typography.labelLarge)
                VerdictPill(verdict, title)
            }
            a.name?.let { Text(it, style = MaterialTheme.typography.titleSmall) }
            a.purposes.takeIf { it.isNotEmpty() }?.let { Text("登錄用途：" + it.joinToString("；"), style = MaterialTheme.typography.bodyMedium) }
            a.serviceDescription?.let { Text("服務：$it", style = MaterialTheme.typography.bodySmall) }
            a.subject?.let { Text("登錄對象：$it" + when (a.boundToVerifier) {
                true -> "（與查驗方憑證相符）"
                false -> "（與查驗方不符）"
                null -> ""
            }, style = MaterialTheme.typography.bodySmall) }
            a.outsideRegistration?.let { if (it.isEmpty()) Text("要求的資料都在登錄範圍內", style = MaterialTheme.typography.bodySmall) }
            if (a.entitlements.isNotEmpty()) Text("登錄身分：" + a.entitlements.joinToString("、") { it.substringAfterLast('/').replace('_', ' ') }, style = MaterialTheme.typography.bodySmall)
            a.publicBody?.let { if (it) Text("公部門機關", style = MaterialTheme.typography.bodySmall) }
            a.country?.let { Text("登錄國家或地區：$it", style = MaterialTheme.typography.bodySmall) }
            a.signer?.let { signer ->
                val t = a.trust
                Text("簽發者：$signer" + (t?.let { "　" + WalletModel.tierTitle(it.tier) + (it.anchorName?.let { n -> "（$n）" } ?: "") } ?: ""),
                    style = MaterialTheme.typography.bodySmall)
                if (t?.environment == TrustEnvironment.TEST) Text("簽發者來自測試錨點，結果不具正式效力。", style = MaterialTheme.typography.bodySmall, color = tierColor(TrustTier.T3))
            }
            a.statusFinding?.let { Text("登錄狀態：" + diw.wallet.app.StatusTexts.finding(it), style = MaterialTheme.typography.bodySmall) }
            a.expiresAt?.let { Text("有效至 " + localTime(it), style = MaterialTheme.typography.bodySmall) }
            a.registryUri?.let { Text("登錄機關：$it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
            a.privacyPolicy?.let { Text("隱私政策：$it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
            a.supervisoryAuthority?.let { Text("監理機關：$it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
            if (a.credentialIds.isNotEmpty()) Text("適用於：" + a.credentialIds.joinToString("、"), style = MaterialTheme.typography.bodySmall)
            a.problems.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            a.notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/** Banner shown on every screen while a custom test server is in use. */
@Composable
fun TestEnvironmentBanner() {
    Box(
        Modifier.fillMaxWidth().background(Color(0xFFB3261E)).padding(vertical = 4.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text("正在使用自訂測試伺服器：測試憑證與驗證結果不具效力", color = Color.White, fontSize = 12.sp)
    }
}

/** Diagonal watermark text for documents issued in the TEST environment. */
@Composable
fun TestWatermark(modifier: Modifier = Modifier) {
    Text(
        "TEST 測試",
        modifier = modifier,
        color = Color(0x55B3261E),
        fontSize = 28.sp,
        fontWeight = FontWeight.Bold,
    )
}
