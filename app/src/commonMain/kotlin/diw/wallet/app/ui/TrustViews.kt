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

fun tierColor(t: TrustTier): Color = when (t) {
    TrustTier.T1 -> Color(0xFF1B7F3B)
    TrustTier.T2 -> Color(0xFF1565C0)
    TrustTier.T3 -> Color(0xFFB26A00)
    TrustTier.T4 -> Color(0xFFB3261E)
}

fun labelText(l: TrustLabel): String = when (l) {
    TrustLabel.TEST_ANCHOR -> "測試環境錨點"
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
}

/** One-line advice per tier; official or compliant parties get the short form. */
fun tierAdvice(t: TrustDecision): String = when {
    t.environment == TrustEnvironment.TEST -> "這是測試環境，結果不具任何正式效力。"
    t.tier == TrustTier.T1 -> "官方信任清單內的對象。"
    TrustLabel.IDENTITY_VERIFIED in t.labels -> "身分由政府憑證（GPKI）證明：${t.anchorName ?: ""}。證明對方是誰，不代表它列於數位憑證皮夾的發行端或查驗方清單。"
    t.tier == TrustTier.T2 -> "列於官方信任清單，但無法完全驗證（例如鏈上註冊暫時無法確認，或列名的角色不符）。"
    TrustLabel.LINKED_DOMAIN in t.labels -> "已確認對方擁有網域 ${t.anchorName ?: ""}（DIF Well-Known DID Configuration，與 Microsoft Authenticator 相同的驗證方式）。這證明網域擁有權，不代表組織列於官方清單。"
    TrustLabel.MAINLAND_CHINA_CA in t.labels -> "憑證鏈連到中國大陸的公開憑證機構（${t.anchorName ?: ""}），可確認網域或組織名稱，但不在台灣的官方清單。"
    TrustLabel.SYSTEM_ANCHOR in t.labels -> "憑證鏈連到系統憑證庫的公開憑證機構（${t.anchorName ?: ""}），可確認網域或組織名稱，但不在官方清單。"
    t.environment == TrustEnvironment.USER -> "由你自行匯入的根憑證或自行信任的 DID 確認（非官方）。"
    t.tier == TrustTier.T3 -> "簽章有效，但無法確認對方是誰。請確認你認識這個對象再繼續。"
    else -> "無法驗證對方身分。除非你確定來源，否則不要分享或接受。"
}

/** What the trust says about the issuer of a document being verified, one sentence for a verdict card. */
fun issuerTrustLine(t: TrustDecision?): String = when {
    t == null -> "發行端不在任何信任來源，無法確認這張證件由誰簽發。"
    t.environment == TrustEnvironment.TEST -> "發行端只在測試環境受信任，結果不具效力。"
    t.tier == TrustTier.T1 -> "發行端列於官方信任清單。"
    TrustLabel.IDENTITY_VERIFIED in t.labels -> "發行端身分由政府憑證（GPKI）證明：${t.anchorName ?: ""}，但不代表它列於發行端清單。"
    t.tier == TrustTier.T2 -> "發行端列於官方信任清單，但無法完全驗證（例如鏈上註冊暫時無法確認，或列名的角色不是發行端）。"
    t.tier == TrustTier.T4 -> "發行端驗證失敗，無法確認這張證件由誰簽發。"
    TrustLabel.LINKED_DOMAIN in t.labels -> "發行端的 DID 已連結網域 ${t.anchorName ?: ""}，只確認網域擁有權，不是官方身分。"
    TrustLabel.MAINLAND_CHINA_CA in t.labels -> "發行端憑證連到中國大陸憑證機構（${t.anchorName ?: ""}），只確認網域或組織名稱，不是官方身分。"
    t.environment == TrustEnvironment.SYSTEM -> "發行端憑證連到公開憑證機構（${t.anchorName ?: ""}），只確認網域或組織名稱，不是官方身分。"
    t.environment == TrustEnvironment.USER -> "發行端由你自行匯入的根憑證或自行信任的 DID 確認（非官方）。"
    else -> "簽章可驗證，但發行端不在任何信任來源，無法確認這張證件由誰簽發。"
}

/** The four trust tiers as the wallet assigns them, each with the sources that lead to it. */
@Composable
fun TierLegend() {
    val rows = listOf(
        TrustTier.T1 to "列於官方信任清單，並可完整驗證：數位憑證皮夾（TWDIW）信任清單內、DID 文件自簽有效且與 Arbitrum One 註冊相符的組織，以及標為官方的正式信任錨點。",
        TrustTier.T2 to "身分已確認，但不是完整驗證的官方清單成員：列於 TWDIW 信任清單但鏈上註冊暫時無法確認或角色不符；或憑證鏈連到內建的政府憑證（GPKI：GCA、XCA、MOEACA，查驗方與文件簽章另含 MOICA 自然人憑證），證明是哪個機關、組織或公司，但不代表列於發行端或查驗方清單。",
        TrustTier.T3 to "簽章可驗證，但沒有官方背書：系統憑證庫與內建公開憑證機構（含中國大陸憑證機構、常用服務的根憑證，只確認網域或組織名稱）、Microsoft Verified ID 的 Linked Domains（確認網域擁有權）、自行匯入的根憑證與自行信任的 DID、不在任何清單的 DID，以及測試環境的所有錨點。除了 Linked Domains，出示或領卡前都需要勾選確認。",
        TrustTier.T4 to "驗證失敗：簽章或憑證鏈不成立、要求未簽章、信任清單內容與鏈上註冊不符，或網域連結失效。除非確定來源，否則不要分享或接受。",
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
        Text("測試環境的錨點最高為 T3，結果永遠不是官方。", style = MaterialTheme.typography.bodySmall)
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

/** Banner shown on every screen while the TEST environment is enabled. */
@Composable
fun TestEnvironmentBanner() {
    Box(
        Modifier.fillMaxWidth().background(Color(0xFFB3261E)).padding(vertical = 4.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text("測試環境已開啟：測試憑證與驗證結果不具效力", color = Color.White, fontSize = 12.sp)
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
