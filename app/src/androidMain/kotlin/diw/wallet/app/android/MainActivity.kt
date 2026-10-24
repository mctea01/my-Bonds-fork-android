package diw.wallet.app.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.fragment.app.FragmentActivity
import diw.wallet.app.FileOrigin
import diw.wallet.app.HomeTab
import diw.wallet.app.QrScanStep
import diw.wallet.app.Screen
import diw.wallet.app.ui.WalletApp
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.multipaz.compose.camera.CameraCaptureResolution
import org.multipaz.compose.camera.CameraSelection
import org.multipaz.compose.permissions.rememberCameraPermissionState
import org.multipaz.compose.prompt.PromptDialogs
import org.multipaz.compose.qrcode.QrCodeScanner
import org.multipaz.prompt.AndroidPromptModel

/** Main wallet screen; also receives credential offers, presentation requests and the OID4VCI redirect as deep links. */
class MainActivity : FragmentActivity() {
    private val app get() = application as WalletApplication
    private val promptModel = AndroidPromptModel.Builder().apply { addCommonDialogs() }.build()
    private val scanRequest = MutableStateFlow<ScanRequest?>(null)
    private val fileAccess = AndroidFileAccess(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        app.platform.fileAccess = fileAccess
        enableEdgeToEdge()
        setContent {
            // The system Back gesture follows the in-app Back button; on the documents tab it leaves the app.
            val screen by app.model.screen.collectAsState()
            val tab by app.model.tab.collectAsState()
            BackHandler(enabled = screen != Screen.Home || tab != HomeTab.DOCUMENTS) { app.model.back() }
            PromptDialogs(promptModel)
            WalletApp(app.model, scanQr = { scan(ScanRequest(null)) }, scanQrStream = { onCode -> scan(ScanRequest(onCode)) })
            val scan by scanRequest.collectAsState()
            scan?.let { QrScanDialog(it) { app.model.qrFromImage() } }
        }
        handle(intent)
    }

    private suspend fun scan(request: ScanRequest): String? {
        scanRequest.value = request
        return try { request.result.await() } finally { scanRequest.value = null }
    }

    override fun onResume() {
        super.onResume()
        app.platform.promptModel = promptModel
        app.platform.activity = this
        // Card emulation preference only holds while this activity is in the foreground.
        app.platform.applyNfcPreference(this)
        app.model.onAppResumed()
    }

    override fun onPause() {
        app.platform.releaseNfcPreference(this)
        if (app.platform.promptModel === promptModel) app.platform.promptModel = null
        if (app.platform.activity === this) app.platform.activity = null
        app.model.onAppPaused()
        super.onPause()
    }

    override fun onDestroy() {
        if (app.platform.fileAccess === fileAccess) app.platform.fileAccess = null
        promptModel.cancel()
        super.onDestroy()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent?) {
        // An NFC reader completed the engagement: show the proximity screen, where the request will appear.
        if (intent?.action == ACTION_PROXIMITY) {
            app.model.screen.value = Screen.Proximity
            return
        }
        // A file shared to the wallet or opened with it goes to the document vault.
        val stream = if (intent?.action == Intent.ACTION_SEND) intentStream(intent) else null
        val viewed = intent?.data?.takeIf { intent.action == Intent.ACTION_VIEW && (it.scheme == "content" || it.scheme == "file") }
        (stream ?: viewed)?.let { uri ->
            app.model.scope.launch {
                app.awaitReady()
                val picked = runCatching { AndroidFileAccess.read(this@MainActivity, uri) }.getOrNull()
                if (picked == null) app.model.message.value = "無法讀取這個檔案"
                else app.model.files.import(picked, FileOrigin.IMPORTED, "其他 App")
            }
            return
        }
        val data = intent?.dataString ?: return
        if (intent.action != Intent.ACTION_VIEW) return
        app.model.scope.launch {
            app.awaitReady()
            app.model.handleUri(data)
        }
    }

    @Suppress("DEPRECATION")
    private fun intentStream(intent: Intent): android.net.Uri? =
        if (android.os.Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, android.net.Uri::class.java)
        else intent.getParcelableExtra(Intent.EXTRA_STREAM)

    companion object {
        /** Sent by the NFC service once a reader completed the ISO/IEC 18013-5 engagement. */
        const val ACTION_PROXIMITY = "diw.wallet.action.PROXIMITY"
    }
}

/** A camera scan: one code completes [result]; with [stream], every new code goes to it until it says done. */
private class ScanRequest(val stream: ((String) -> QrScanStep)?) {
    val result = CompletableDeferred<String?>()
}

@Composable
private fun QrScanDialog(request: ScanRequest, readImage: suspend () -> String?) {
    val result = request.result
    val permission = rememberCameraPermissionState()
    val scope = rememberCoroutineScope()
    var last by remember(request) { mutableStateOf<String?>(null) }
    var progress by remember(request) { mutableStateOf<String?>(null) }
    LaunchedEffect(permission.isGranted) {
        if (!permission.isGranted) permission.launchPermissionRequest()
    }
    Dialog(onDismissRequest = { result.complete(null) }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (permission.isGranted) {
                    QrCodeScanner(
                        modifier = Modifier.fillMaxWidth().weight(1f),
                        cameraSelection = CameraSelection.DEFAULT_BACK_CAMERA,
                        captureResolution = CameraCaptureResolution.MEDIUM,
                        showCameraPreview = true,
                        onCodeScanned = { code ->
                            val stream = request.stream
                            when {
                                code == null || code == last -> {}
                                stream == null -> result.complete(code)
                                else -> {
                                    // The camera sees each frame many times; only a new one is handed on.
                                    last = code
                                    val step = stream(code)
                                    progress = step.progress
                                    if (step.done) result.complete(null)
                                }
                            }
                        },
                    )
                } else {
                    Text("需要相機權限才能掃描 QR Code")
                    Button(onClick = { scope.launch { permission.launchPermissionRequest() } }) { Text("允許相機") }
                }
                progress?.let { Text(it) }
                // A code on this phone's own screen (an issuer page, a screenshot) cannot be scanned with its camera.
                if (request.stream == null) {
                    OutlinedButton(onClick = { scope.launch { readImage()?.let { result.complete(it) } } }, modifier = Modifier.fillMaxWidth()) {
                        Text("從圖片讀取 QR Code")
                    }
                }
                OutlinedButton(onClick = { result.complete(null) }, modifier = Modifier.fillMaxWidth()) {
                    Text(if (request.stream == null) "取消" else "停止掃描")
                }
            }
        }
    }
}
