package diw.wallet.app.desktop

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.app.text
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.isBackPressed
import androidx.compose.ui.input.pointer.onPointerEvent
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.LocalWindowExceptionHandlerFactory
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.WindowExceptionHandler
import androidx.compose.ui.window.WindowExceptionHandlerFactory
import androidx.compose.ui.window.application
import diw.wallet.app.WalletModel
import diw.wallet.app.decodeImageBytes
import diw.wallet.app.ui.WalletApp
import diw.wallet.app.ui.onEnterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.awt.event.WindowEvent
import java.security.Security
import javax.swing.JOptionPane
import javax.swing.SwingUtilities
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

/** Records and logs every uncaught exception; the timed exit reports it. */
private fun handleUncaught() {
    Thread.setDefaultUncaughtExceptionHandler { thread, e ->
        uncaught = e
        e.printStackTrace()
        ErrorLog.write(e, thread.name)
    }
}

/**
 * DIW_EXIT_AFTER_SECONDS (tests and the native build only): ends the app after that many seconds, through a normal
 * exit so the tracing agent writes what it recorded. With DIW_EXERCISE_INPUT=1 it waits up to as long again for the
 * input exercise to finish. Exit code 0 when the first screen was composed and nothing was thrown, 1 after an uncaught
 * exception, 2 when nothing was composed, 3 when the input exercise failed.
 */
private fun exitAfter(seconds: Long) {
    Thread({
        Thread.sleep(seconds * 1000)
        if (InputExercise.enabled) {
            val end = System.nanoTime() + seconds * 1_000_000_000L
            while (InputExercise.result == null && uncaught == null && System.nanoTime() < end) Thread.sleep(200)
        }
        val problem = uncaught
        val exercise = if (InputExercise.enabled) InputExercise.result ?: "did not finish" else "ok"
        println("timed exit: composed=$composed uncaught=${problem?.let { it::class.java.name + ": " + it.message }} input=$exercise")
        exitProcess(if (problem != null) 1 else if (!composed) 2 else if (exercise != "ok") 3 else 0)
    }, "timed-exit").apply { isDaemon = true; start() }
}

/**
 * Replaces Compose's default handler, which shows only "Error" and the exception's message (often empty): the error
 * is saved under the data folder, the dialog names the file, and the window closes as before. The strings are read
 * from the resources directly, since an error on the unlock screen comes before the wallet loads [tr]'s strings.
 */
@OptIn(ExperimentalComposeUiApi::class)
private fun windowErrors(language: DesktopLanguageStore) = WindowExceptionHandlerFactory { window ->
    WindowExceptionHandler { e ->
        uncaught = e
        e.printStackTrace()
        val file = ErrorLog.write(e)
        SwingUtilities.invokeLater {
            val error = "${e::class.java.name}: ${e.message.orEmpty()}"
            val path = file?.path ?: "-"
            val (title, message) = runCatching {
                runBlocking { language.text(Res.string.desktop_error_title) to language.text(Res.string.desktop_error_log, error, path) }
            }.getOrElse { "DIW MY WALLET" to "$error\n\n$path" }
            JOptionPane.showMessageDialog(window, message, title, JOptionPane.ERROR_MESSAGE)
            window.dispatchEvent(WindowEvent(window, WindowEvent.WINDOW_CLOSING))
        }
    }
}

/**
 * A native executable has no Java home of its own. Skiko loads the JAWT library from java.home (lib/ on Linux, bin/
 * on Windows), and tools/desktop-native.sh puts it next to the executable.
 */
private fun nativeJavaHome() {
    if (!SelfCheck.nativeImage) return
    val current = System.getProperty("java.home")
    if (!current.isNullOrEmpty() && File(current).isDirectory) return
    val exe = ProcessHandle.current().info().command().orElse(null)?.let(::File) ?: return
    exe.absoluteFile.parentFile?.let { System.setProperty("java.home", it.path) }
}

@OptIn(ExperimentalComposeUiApi::class, FlowPreview::class)
fun main(args: Array<String>) {
    nativeJavaHome()
    if (args.firstOrNull() == "--self-check") exitProcess(SelfCheck.run(args.getOrNull(1)?.let(::File)))
    val dir = dataDir()
    ErrorLog.dir = dir
    handleUncaught()
    System.getenv("DIW_EXIT_AFTER_SECONDS")?.toLongOrNull()?.takeIf { it > 0 }?.let(::exitAfter)
    InputExercise.start()
    Security.addProvider(BouncyCastleProvider())
    val startUri = args.firstOrNull()
    val language = DesktopLanguageStore()
    application {
        var model by remember { mutableStateOf<WalletModel?>(null) }
        val icon = remember { appIcon() }
        val windowState = remember { WindowMemory.restore() }
        CompositionLocalProvider(LocalWindowExceptionHandlerFactory provides windowErrors(language)) {
            Window(
                onCloseRequest = { WindowMemory.save(windowState); exitApplication() },
                title = "DIW MY WALLET",
                icon = icon,
                state = windowState,
                onKeyEvent = { DesktopShortcuts.handle(it, model) },
            ) {
                LaunchedEffect(Unit) {
                    val min = WindowMemory.minimum
                    window.minimumSize = java.awt.Dimension(min.width.value.toInt(), min.height.value.toInt())
                }
                LaunchedEffect(windowState) {
                    snapshotFlow { Triple(windowState.size, windowState.position, windowState.placement) }
                        .debounce(1000).collect { WindowMemory.save(windowState) }
                }
                if (InputExercise.enabled) {
                    val density = LocalDensity.current.density
                    LaunchedEffect(density) { InputExercise.density = density; InputExercise.window = window }
                }
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
                        if (InputExercise.enabled) LaunchedEffect(m) { InputExercise.mainScreen = true }
                        // The mouse's back button goes back, as Alt+Left and Esc do (DesktopShortcuts).
                        Box(Modifier.fillMaxSize().onPointerEvent(PointerEventType.Press, PointerEventPass.Initial) { e ->
                            if (e.buttons.isBackPressed) m.back()
                        }) { WalletApp(m) }
                    }
                }
            }
        }
    }
}

/** Reports where a target is to the input exercise; does nothing otherwise. */
private fun Modifier.exerciseTarget(name: String): Modifier =
    if (InputExercise.enabled) onGloballyPositioned { InputExercise.place(name, it.boundsInWindow()) } else this

/** Startup PIN: creates the App PIN on first run, then unlocks the encrypted storage. */
@Composable
private fun UnlockScreen(language: DesktopLanguageStore, firstRun: Boolean, onUnlock: suspend (String) -> Boolean) {
    var pin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val valid = pin.length >= 6 && (!firstRun || pin == confirm)
    val pinFocus = remember { FocusRequester() }
    val confirmFocus = remember { FocusRequester() }
    val submit = {
        if (valid && !busy) {
            busy = true
            scope.launch {
                error = try {
                    if (onUnlock(pin)) null else language.text(Res.string.unlock_wrong_pin)
                } catch (e: Exception) {
                    language.text(Res.string.unlock_failed, e.message.toString())
                }
                busy = false
            }
        }
    }
    LaunchedEffect(Unit) {
        composed = true
        // The PIN field has the focus from the start, so the PIN can be typed straight away.
        runCatching { pinFocus.requestFocus() }
    }
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("DIW MY WALLET", style = MaterialTheme.typography.headlineSmall)
                Text(if (firstRun) stringResource(Res.string.unlock_set_pin) else stringResource(Res.string.unlock_enter_pin))
                val field = @Composable { value: String, label: String, target: String, focus: FocusRequester, onEnter: () -> Unit, onChange: (String) -> Unit ->
                    OutlinedTextField(
                        value = value,
                        onValueChange = { v -> onChange(v.filter { it.isDigit() }.take(12)) },
                        label = { Text(label) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.width(280.dp).focusRequester(focus).onEnterKey(onEnter).exerciseTarget(target),
                    )
                }
                // Enter in the first field moves to the second on first run, and unlocks otherwise.
                field(pin, "App PIN", "pin", pinFocus, { if (firstRun) runCatching { confirmFocus.requestFocus() } else submit() }) {
                    pin = it
                    if (InputExercise.enabled) InputExercise.pin = it
                }
                if (firstRun) field(confirm, stringResource(Res.string.unlock_repeat), "confirm", confirmFocus, { submit() }) {
                    confirm = it
                    if (InputExercise.enabled) InputExercise.confirm = it
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(enabled = valid && !busy, modifier = Modifier.exerciseTarget("unlock"), onClick = { submit() }) { Text(if (busy) stringResource(Res.string.state_working) else if (firstRun) stringResource(Res.string.unlock_create) else stringResource(Res.string.unlock_unlock)) }
            }
        }
    }
}
