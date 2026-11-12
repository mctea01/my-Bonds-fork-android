package diw.wallet.app.desktop

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.app.text
import org.jetbrains.compose.resources.stringResource
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import diw.wallet.app.WalletModel
import diw.wallet.app.decodeImageBytes
import diw.wallet.app.ui.WalletApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.security.Security
import kotlin.system.exitProcess

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

/** Window and taskbar icon, rendered by app/icons/generate_icons.py. */
private fun appIcon(): BitmapPainter? =
    Thread.currentThread().contextClassLoader?.getResourceAsStream("app-icon.png")
        ?.use { decodeImageBytes(it.readBytes()) }
        ?.let { BitmapPainter(it) }

/** Set once the first screen has been composed; the timed exit of DIW_EXIT_AFTER_SECONDS reports it. */
@Volatile private var composed = false
@Volatile private var uncaught: Throwable? = null

/**
 * DIW_EXIT_AFTER_SECONDS (tests and the native build only): ends the app after that many seconds, through a normal
 * exit so the tracing agent writes what it recorded. Exit code 0 when the first screen was composed and nothing was
 * thrown, 1 after an uncaught exception, 2 when nothing was composed.
 */
private fun exitAfter(seconds: Long) {
    Thread.setDefaultUncaughtExceptionHandler { _, e -> uncaught = e; e.printStackTrace() }
    Thread({
        Thread.sleep(seconds * 1000)
        val problem = uncaught
        println("timed exit: composed=$composed uncaught=${problem?.let { it::class.java.name + ": " + it.message }}")
        exitProcess(if (problem != null) 1 else if (!composed) 2 else 0)
    }, "timed-exit").apply { isDaemon = true; start() }
}

/**
 * A native executable has no Java home of its own. Skiko loads the JAWT library from java.home (lib/ on Linux and
 * macOS, bin/ on Windows), and tools/desktop-native.sh puts it next to the executable.
 */
private fun nativeJavaHome() {
    if (!SelfCheck.nativeImage) return
    val current = System.getProperty("java.home")
    if (!current.isNullOrEmpty() && File(current).isDirectory) return
    val exe = ProcessHandle.current().info().command().orElse(null)?.let(::File) ?: return
    exe.absoluteFile.parentFile?.let { System.setProperty("java.home", it.path) }
}

fun main(args: Array<String>) {
    nativeJavaHome()
    if (args.firstOrNull() == "--self-check") exitProcess(SelfCheck.run(args.getOrNull(1)?.let(::File)))
    System.getenv("DIW_EXIT_AFTER_SECONDS")?.toLongOrNull()?.takeIf { it > 0 }?.let(::exitAfter)
    Security.addProvider(BouncyCastleProvider())
    val dir = dataDir()
    val startUri = args.firstOrNull()
    val language = DesktopLanguageStore()
    application {
        var model by remember { mutableStateOf<WalletModel?>(null) }
        val icon = remember { appIcon() }
        Window(onCloseRequest = ::exitApplication, title = "DIW MY WALLET", icon = icon, state = rememberWindowState(width = 480.dp, height = 860.dp)) {
            diw.wallet.app.ui.AppLocaleScope(language) {
                val m = model
                if (m == null) {
                    UnlockScreen(language, firstRun = !PinValueCipher.isInitialized(dir)) { pin ->
                        val cipher = withContext(Dispatchers.Default) { PinValueCipher.unlock(dir, pin) } ?: return@UnlockScreen false
                        lateinit var created: WalletModel
                        val platform = DesktopPlatform(dir, cipher, language) { uri -> created.handleUri(uri) }
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
}

/** Startup PIN: creates the App PIN on first run, then unlocks the encrypted storage. */
@Composable
private fun UnlockScreen(language: DesktopLanguageStore, firstRun: Boolean, onUnlock: suspend (String) -> Boolean) {
    var pin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val valid = pin.length >= 6 && (!firstRun || pin == confirm)
    LaunchedEffect(Unit) { composed = true }
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("DIW MY WALLET", style = MaterialTheme.typography.headlineSmall)
                Text(if (firstRun) stringResource(Res.string.unlock_set_pin) else stringResource(Res.string.unlock_enter_pin))
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
                if (firstRun) field(confirm, stringResource(Res.string.unlock_repeat)) { confirm = it }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(enabled = valid && !busy, onClick = {
                    busy = true
                    scope.launch {
                        error = try {
                            if (onUnlock(pin)) null else language.text(Res.string.unlock_wrong_pin)
                        } catch (e: Exception) {
                            language.text(Res.string.unlock_failed, e.message.toString())
                        }
                        busy = false
                    }
                }) { Text(if (busy) stringResource(Res.string.state_working) else if (firstRun) stringResource(Res.string.unlock_create) else stringResource(Res.string.unlock_unlock)) }
            }
        }
    }
}
