package diw.wallet.app.desktop

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import diw.wallet.app.WalletModel
import diw.wallet.app.ui.WalletApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.security.Security

private fun dataDir(): File {
    val override = System.getenv("DIW_WALLET_HOME")
    if (!override.isNullOrBlank()) return File(override)
    val os = System.getProperty("os.name").lowercase()
    val home = System.getProperty("user.home")
    return when {
        "win" in os -> File(System.getenv("APPDATA") ?: home, "DIW-MY-WALLET")
        "mac" in os -> File(home, "Library/Application Support/DIW-MY-WALLET")
        else -> File(System.getenv("XDG_DATA_HOME") ?: "$home/.local/share", "diw-my-wallet")
    }
}

fun main(args: Array<String>) {
    Security.addProvider(BouncyCastleProvider())
    val dir = dataDir()
    val startUri = args.firstOrNull()
    application {
        var model by remember { mutableStateOf<WalletModel?>(null) }
        Window(onCloseRequest = ::exitApplication, title = "DIW MY WALLET", state = rememberWindowState(width = 480.dp, height = 860.dp)) {
            val m = model
            if (m == null) {
                UnlockScreen(firstRun = !PinValueCipher.isInitialized(dir)) { pin ->
                    val cipher = withContext(Dispatchers.Default) { PinValueCipher.unlock(dir, pin) } ?: return@UnlockScreen false
                    lateinit var created: WalletModel
                    val platform = DesktopPlatform(dir, cipher) { uri -> created.handleUri(uri) }
                    created = WalletModel(platform)
                    created.init()
                    startUri?.let { created.handleUri(it) }
                    model = created
                    true
                }
            } else {
                // Losing focus to the browser and getting it back without a redirect ends the login wait.
                androidx.compose.runtime.DisposableEffect(m) {
                    val listener = object : java.awt.event.WindowFocusListener {
                        override fun windowLostFocus(e: java.awt.event.WindowEvent?) = m.onAppPaused()
                        override fun windowGainedFocus(e: java.awt.event.WindowEvent?) = m.onAppResumed()
                    }
                    window.addWindowFocusListener(listener)
                    onDispose { window.removeWindowFocusListener(listener) }
                }
                WalletApp(m)
            }
        }
    }
}

/** Startup PIN: creates the App PIN on first run, then unlocks the encrypted storage. */
@Composable
private fun UnlockScreen(firstRun: Boolean, onUnlock: suspend (String) -> Boolean) {
    var pin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val valid = pin.length >= 6 && (!firstRun || pin == confirm)
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("DIW MY WALLET", style = MaterialTheme.typography.headlineSmall)
                Text(if (firstRun) "請設定 App PIN（至少 6 位數字），用於加密資料與保護軟體金鑰" else "請輸入 App PIN")
                val field = @Composable { value: String, label: String, onChange: (String) -> Unit ->
                    OutlinedTextField(
                        value = value,
                        onValueChange = { v -> onChange(v.filter { it.isDigit() }.take(12)) },
                        label = { Text(label) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.width(280.dp),
                    )
                }
                field(pin, "App PIN") { pin = it }
                if (firstRun) field(confirm, "再次輸入") { confirm = it }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(enabled = valid && !busy, onClick = {
                    busy = true
                    scope.launch {
                        error = try {
                            if (onUnlock(pin)) null else "PIN 錯誤"
                        } catch (e: Exception) {
                            "無法開啟錢包：${e.message}"
                        }
                        busy = false
                    }
                }) { Text(if (busy) "處理中" else if (firstRun) "建立錢包" else "解鎖") }
            }
        }
    }
}
