package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Strong confirmation for an operation the wallet advises against but leaves to the user (a special environment of
 * their own may need it): the risks are listed, and the confirm button only works after the user ticks that they
 * take the consequences.
 */
@Composable
fun RiskConfirmDialog(title: String, lines: List<String>, confirm: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    var ack by remember(title) { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(WalletIcons.Caution, contentDescription = null, tint = Tokens.Fail, modifier = Modifier.size(32.dp)) },
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                lines.forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = ack, onCheckedChange = { ack = it })
                    Text("我了解風險，並自行承擔後果", style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm, enabled = ack) { Text(confirm, color = if (ack) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}

/**
 * An inline override for a blocked step: a red outlined button opens [RiskConfirmDialog]. Returns true once the user
 * confirmed for [key]; the confirmation is then stated in place of the button, so it stays visible.
 */
@Composable
fun riskOverride(key: Any?, button: String, title: String, lines: List<String>): Boolean {
    var confirmed by remember(key) { mutableStateOf(false) }
    var asking by remember(key) { mutableStateOf(false) }
    if (confirmed) {
        Text("你已確認自行承擔風險：$title", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        return true
    }
    OutlinedButton(onClick = { asking = true }, colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) {
        Text(button)
    }
    if (asking) RiskConfirmDialog(title, lines, "仍要繼續", onConfirm = { confirmed = true; asking = false }, onDismiss = { asking = false })
    return false
}
