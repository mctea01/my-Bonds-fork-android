package diw.wallet.app.ui

import androidx.compose.foundation.background
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
    TrustLabel.NON_STANDARD -> "非標準格式（相容模式）"
}

/** One-line advice per tier; official or compliant parties get the short form. */
fun tierAdvice(t: TrustDecision): String = when {
    t.environment == TrustEnvironment.TEST -> "這是測試環境，結果不具任何正式效力。"
    t.tier == TrustTier.T1 -> "官方信任清單內的對象。"
    t.tier == TrustTier.T2 -> "身分已由其憑證證明，但不在官方清單。"
    t.tier == TrustTier.T3 -> "簽章有效，但無法確認對方是誰。請確認你認識這個對象再繼續。"
    else -> "無法驗證對方身分。除非你確定來源，否則不要分享或接受。"
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
fun TrustCard(title: String, subject: String, trust: TrustDecision, extra: List<String> = emptyList()) {
    Card(
        modifier = Modifier.fillMaxWidth(),
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
