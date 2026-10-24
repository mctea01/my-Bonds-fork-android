package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Ways to read a QR Code: the camera where the platform has one (its dialog can also read a picture), and a picture
 * the user picks, such as a screenshot of an issuer page. Every entry takes the same path; the code decides the flow.
 */
class ScanActions(val camera: (() -> Unit)?, val image: () -> Unit) {
    /** The camera, or reading a picture where there is none. */
    val primary: () -> Unit get() = camera ?: image
    val primaryLabel: String get() = if (camera != null) "掃描 QR Code" else "從圖片讀取 QR Code"
}

/** The camera button with "from a picture" beside it; only the picture button where there is no camera. */
@Composable
fun ScanButtons(scan: ScanActions, enabled: Boolean = true) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        Button(onClick = scan.primary, enabled = enabled) {
            Icon(if (scan.camera != null) WalletIcons.Scan else WalletIcons.Image, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(scan.primaryLabel)
        }
        if (scan.camera != null) {
            OutlinedButton(onClick = scan.image, enabled = enabled) {
                Icon(WalletIcons.Image, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text("從圖片讀取")
            }
        }
    }
}
