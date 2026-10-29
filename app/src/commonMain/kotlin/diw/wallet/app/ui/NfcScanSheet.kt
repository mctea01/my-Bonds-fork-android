package diw.wallet.app.ui

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import diw.wallet.app.WalletModel

/**
 * The NFC scan sheet, shown while the phone's own NFC is in reader mode waiting for a card tap (reading or signing
 * with a citizen certificate or PIV card). It appears only during that window, like the system's FIDO2 security-key
 * prompt, so the user knows exactly when to tap and taps outside the window are not left for the system to report as
 * an unhandled NFC tag. Platforms that read cards only through an external reader keep the prompt null and show
 * nothing.
 */
@Composable
fun NfcScanSheet(model: WalletModel) {
    val prompt by model.platform.nfcScanPrompt.collectAsState()
    val message = prompt ?: return
    Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.45f)), contentAlignment = Alignment.BottomCenter) {
        Surface(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 6.dp,
        ) {
            Column(
                Modifier.fillMaxWidth().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text("準備感應", style = MaterialTheme.typography.titleLarge)
                val transition = rememberInfiniteTransition(label = "nfc")
                val alpha by transition.animateFloat(
                    initialValue = 0.3f,
                    targetValue = 1f,
                    animationSpec = infiniteRepeatable(tween(900), RepeatMode.Reverse),
                    label = "pulse",
                )
                Icon(
                    WalletIcons.Nfc,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary.copy(alpha = alpha),
                    modifier = Modifier.size(72.dp),
                )
                Text(message, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
            }
        }
    }
}
