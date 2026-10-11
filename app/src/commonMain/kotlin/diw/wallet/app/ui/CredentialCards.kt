package diw.wallet.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import diw.wallet.app.CredentialDetails
import diw.wallet.app.TaiwanModel
import diw.wallet.app.WalletModel
import diw.wallet.core.oid4vci.IssuanceRecord
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.util.QrEncoder
import org.multipaz.document.Document

/** "#RRGGBB" or "#AARRGGBB" from issuer display metadata; null for anything else. */
fun parseColor(hex: String?): Color? {
    val h = hex?.trim()?.removePrefix("#") ?: return null
    val v = h.toLongOrNull(16) ?: return null
    return when (h.length) {
        6 -> Color(0xFF000000 or v)
        8 -> Color(v)
        else -> null
    }
}

/** Category icon of a credential when the issuer gives no logo. */
fun categoryIcon(record: IssuanceRecord?): ImageVector = when {
    record == null -> WalletIcons.Card
    record.profile == TaiwanModel.TWDIW -> WalletIcons.Government
    record.profile == TaiwanModel.MSVID -> WalletIcons.Organization
    record.docType?.contains("mDL") == true || record.docType?.contains("pid", ignoreCase = true) == true ||
        record.vct?.contains("pid", ignoreCase = true) == true -> WalletIcons.Person
    else -> WalletIcons.Card
}

/** The issuer's logo when it can be shown, otherwise [fallback] drawn in [tint]. */
@Composable
fun CardLogo(model: WalletModel, logoUri: String?, fallback: ImageVector, tint: Color, size: Int = 40) {
    val art by model.cardArt.collectAsState()
    LaunchedEffect(logoUri) { logoUri?.let { model.loadCardArt(it) } }
    val image = logoUri?.let { art[it] }
    if (image != null) {
        Image(image, contentDescription = null, modifier = Modifier.size(size.dp).clip(RoundedCornerShape(6.dp)))
    } else {
        Icon(fallback, contentDescription = null, tint = tint, modifier = Modifier.size(size.dp))
    }
}

/** A stored credential as a card: issuer colours and logo, name, issuer, trust and format. */
@Composable
fun CredentialCard(model: WalletModel, doc: Document, onClick: () -> Unit) {
    val record = doc.issuanceRecord
    val background = parseColor(record?.backgroundColor)
    val text = parseColor(record?.textColor) ?: if (background != null) contrastOn(background) else MaterialTheme.colorScheme.onSurface
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Box {
            Column(Modifier.fillMaxWidth().then(if (background != null) Modifier.background(background) else Modifier).padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CardLogo(model, record?.logoUri, categoryIcon(record), if (background != null) text else MaterialTheme.colorScheme.primary)
                    Column(Modifier.weight(1f)) {
                        Text(doc.displayName ?: "憑證", style = MaterialTheme.typography.titleMedium, color = text)
                        Text(doc.typeDisplayName ?: record?.credentialIssuer ?: "", style = MaterialTheme.typography.bodySmall, color = text)
                    }
                }
                storedTrust(doc)?.let { TierBadge(it) }
                record?.let {
                    Text((listOf(CredentialDetails.formatLabel(it)) + CredentialDetails.specs(it)).joinToString("、"),
                        style = MaterialTheme.typography.bodySmall, color = text)
                }
                if (record?.pendingTransactionId != null) Text("等待發行端完成（延遲發證）", style = MaterialTheme.typography.bodySmall, color = text)
            }
            if (record?.isTestEnvironment == true) TestWatermark(Modifier.align(Alignment.CenterEnd).padding(end = 12.dp))
        }
    }
}

private fun contrastOn(c: Color): Color = if (0.299 * c.red + 0.587 * c.green + 0.114 * c.blue > 0.6) Color.Black else Color.White

/** A QR Code drawn from the encoder's modules with a four-module quiet zone. */
@Composable
fun QrImage(text: String, modifier: Modifier = Modifier, ecc: QrEncoder.Ecc = QrEncoder.Ecc.M) {
    val matrix = androidx.compose.runtime.remember(text, ecc) { runCatching { QrEncoder.encode(text, ecc) }.getOrNull() }
    if (matrix == null) {
        Text("內容過長，無法產生 QR Code", modifier = modifier)
        return
    }
    Canvas(modifier.aspectRatio(1f).background(Color.White)) {
        val total = matrix.size + 8
        val cell = size.width / total
        for (y in 0 until matrix.size) for (x in 0 until matrix.size) {
            if (matrix[x, y]) drawRect(Color.Black, Offset((x + 4) * cell, (y + 4) * cell), Size(cell + 0.5f, cell + 0.5f))
        }
    }
}
