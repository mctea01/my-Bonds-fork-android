package diw.wallet.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.awt.Desktop
import java.io.File

/**
 * The desktop has no embedded web view: the host page is written to a temporary file (removed when the app exits)
 * and opened in the system browser.
 */
@Composable
actual fun OpenCertRendererView(html: String, modifier: Modifier, onExternal: (String) -> Unit) {
    var failure by remember { mutableStateOf<String?>(null) }
    Column(modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("電腦版以系統瀏覽器顯示。頁面暫存在電腦上，關閉 App 時刪除。", style = MaterialTheme.typography.bodySmall)
        Button(onClick = {
            failure = runCatching {
                val file = File.createTempFile("opencert-", ".html").apply {
                    deleteOnExit()
                    writeText(html, Charsets.UTF_8)
                }
                if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) Desktop.getDesktop().browse(file.toURI())
                else ProcessBuilder("xdg-open", file.absolutePath).start()
            }.exceptionOrNull()?.let { "無法開啟瀏覽器：${it.message ?: it::class.simpleName}" }
        }) { Text("在瀏覽器開啟") }
        failure?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
    }
}
