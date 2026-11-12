package diw.wallet.app.android

import android.graphics.Bitmap
import android.graphics.Matrix
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import diw.wallet.app.QrScanStep
import diw.wallet.app.res.Res
import diw.wallet.app.res.action_cancel
import diw.wallet.app.res.scan_allow_camera
import diw.wallet.app.res.scan_camera_needed
import diw.wallet.app.res.scan_camera_needed_mrz
import diw.wallet.app.res.scan_from_image
import diw.wallet.app.res.scan_mrz_hint
import diw.wallet.app.res.scan_mrz_reading
import diw.wallet.app.res.scan_mrz_title
import diw.wallet.app.res.scan_qr_hint
import diw.wallet.app.res.scan_qr_title
import diw.wallet.app.res.scan_stop
import diw.wallet.core.document.mrtd.Mrz
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import org.jetbrains.compose.resources.stringResource
import org.multipaz.compose.camera.Camera
import org.multipaz.compose.camera.CameraCaptureResolution
import org.multipaz.compose.camera.CameraFrame
import org.multipaz.compose.camera.CameraSelection
import org.multipaz.compose.permissions.rememberCameraPermissionState
import org.multipaz.compose.qrcode.QrCodeScanner

/** A camera scan: one code completes [result]; with [stream], every new code goes to it until it says done. */
internal class ScanRequest(val stream: ((String) -> QrScanStep)?) {
    val result = CompletableDeferred<String?>()
}

/** A camera scan of a travel document's machine readable zone; [result] is the zone's lines, or null when cancelled. */
internal class MrzScanRequest {
    val result = CompletableDeferred<String?>()
}

/** Text in a camera image; implemented by the OCR engine the build ships. */
internal interface MrzTextReader {
    /** The text lines of [bitmap], top to bottom. */
    suspend fun read(bitmap: Bitmap): String

    fun close()
}

/** The shape of the window the camera looks through: square for QR Codes, a wide band for a zone. */
private enum class Window(val widthFraction: Float, val aspect: Float) { QR(0.72f, 1f), MRZ(0.92f, 0.32f) }

/** Dims everything but the window and marks its corners, so the code or the zone is put where it is read. */
@Composable
private fun ScanWindow(window: Window, modifier: Modifier = Modifier) {
    Canvas(modifier.graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen }) {
        val w = size.width * window.widthFraction
        val h = w * window.aspect
        val rect = Rect(Offset((size.width - w) / 2, (size.height - h) / 2), Size(w, h))
        drawRect(Color.Black.copy(alpha = 0.55f))
        drawRoundRect(Color.Transparent, rect.topLeft, rect.size, CornerRadius(16.dp.toPx()), blendMode = BlendMode.Clear)
        val corner = minOf(w, h) * 0.18f
        val stroke = Stroke(4.dp.toPx())
        val lines = listOf(
            rect.topLeft to Offset(corner, 0f), rect.topLeft to Offset(0f, corner),
            rect.topRight to Offset(-corner, 0f), rect.topRight to Offset(0f, corner),
            rect.bottomLeft to Offset(corner, 0f), rect.bottomLeft to Offset(0f, -corner),
            rect.bottomRight to Offset(-corner, 0f), rect.bottomRight to Offset(0f, -corner),
        )
        for ((start, delta) in lines) drawLine(Color.White, start, start + delta, stroke.width)
    }
}

/** Title over the camera, a hint under the window and the actions at the bottom. */
@Composable
private fun ScanLayout(
    title: String,
    hint: String,
    status: String?,
    window: Window,
    granted: Boolean,
    onAllow: () -> Unit,
    cameraNeeded: String,
    camera: @Composable (Modifier) -> Unit,
    actions: @Composable () -> Unit,
) {
    Surface(Modifier.fillMaxSize(), color = Color.Black) {
        Column(Modifier.fillMaxSize()) {
            Box(Modifier.fillMaxWidth().weight(1f)) {
                if (granted) {
                    camera(Modifier.fillMaxSize())
                    ScanWindow(window, Modifier.fillMaxSize())
                } else {
                    Column(
                        Modifier.align(Alignment.Center).padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(cameraNeeded, color = Color.White, textAlign = TextAlign.Center)
                        Button(onClick = onAllow) { Text(stringResource(Res.string.scan_allow_camera)) }
                    }
                }
                Text(
                    title, color = Color.White, style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.align(Alignment.TopCenter).padding(top = 32.dp, start = 16.dp, end = 16.dp),
                )
                Column(
                    Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(hint, color = Color.White, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyMedium)
                    status?.let {
                        Text(
                            it, color = Color.White, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.background(Color.Black.copy(alpha = 0.5f), MaterialTheme.shapes.small).padding(horizontal = 8.dp, vertical = 4.dp),
                        )
                    }
                }
            }
            Surface(Modifier.fillMaxWidth(), color = MaterialTheme.colorScheme.surface) {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { actions() }
            }
        }
    }
}

@Composable
internal fun QrScanDialog(request: ScanRequest, readImage: suspend () -> String?) {
    val result = request.result
    val permission = rememberCameraPermissionState()
    val scope = rememberCoroutineScope()
    var last by remember(request) { mutableStateOf<String?>(null) }
    var progress by remember(request) { mutableStateOf<String?>(null) }
    LaunchedEffect(permission.isGranted) {
        if (!permission.isGranted) permission.launchPermissionRequest()
    }
    Dialog(onDismissRequest = { result.complete(null) }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        ScanLayout(
            title = stringResource(Res.string.scan_qr_title),
            hint = stringResource(Res.string.scan_qr_hint),
            status = progress,
            window = Window.QR,
            granted = permission.isGranted,
            onAllow = { scope.launch { permission.launchPermissionRequest() } },
            cameraNeeded = stringResource(Res.string.scan_camera_needed),
            camera = { modifier ->
                QrCodeScanner(
                    modifier = modifier,
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
            },
        ) {
            // A code on this phone's own screen (an issuer page, a screenshot) cannot be scanned with its camera.
            if (request.stream == null) {
                OutlinedButton(onClick = { scope.launch { readImage()?.let { result.complete(it) } } }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(Res.string.scan_from_image))
                }
            }
            OutlinedButton(onClick = { result.complete(null) }, modifier = Modifier.fillMaxWidth()) {
                Text(if (request.stream == null) stringResource(Res.string.action_cancel) else stringResource(Res.string.scan_stop))
            }
        }
    }
}

/**
 * Reads the zone through the camera: each frame's band behind the window goes to [reader] and the text to
 * [Mrz.recognize]; the scan ends at the first zone whose check digits all hold. Frames stay on this device and
 * nothing is kept.
 */
@Composable
internal fun MrzScanDialog(request: MrzScanRequest, reader: () -> MrzTextReader) {
    val result = request.result
    val permission = rememberCameraPermissionState()
    val scope = rememberCoroutineScope()
    val engine = remember(request) { lazy(reader) }
    var lines by remember(request) { mutableStateOf(0) }
    LaunchedEffect(permission.isGranted) {
        if (!permission.isGranted) permission.launchPermissionRequest()
    }
    androidx.compose.runtime.DisposableEffect(request) {
        onDispose { if (engine.isInitialized()) engine.value.close() }
    }
    Dialog(onDismissRequest = { result.complete(null) }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        ScanLayout(
            title = stringResource(Res.string.scan_mrz_title),
            hint = stringResource(Res.string.scan_mrz_hint),
            status = if (lines > 0) stringResource(Res.string.scan_mrz_reading, lines) else null,
            window = Window.MRZ,
            granted = permission.isGranted,
            onAllow = { scope.launch { permission.launchPermissionRequest() } },
            cameraNeeded = stringResource(Res.string.scan_camera_needed_mrz),
            camera = { modifier ->
                Camera(
                    modifier = modifier,
                    cameraSelection = CameraSelection.DEFAULT_BACK_CAMERA,
                    captureResolution = CameraCaptureResolution.HIGH,
                    showCameraPreview = true,
                    onFrameCaptured = { frame ->
                        if (!result.isCompleted) {
                            val band = band(frame)
                            val text = try { engine.value.read(band) } finally { band.recycle() }
                            lines = text.lines().count { Mrz.normalize(it).length >= 28 }
                            Mrz.recognize(text)?.let { result.complete(it.lines.joinToString("\n")) }
                        }
                    },
                )
            },
        ) {
            OutlinedButton(onClick = { result.complete(null) }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(Res.string.action_cancel))
            }
        }
    }
}

/** The frame upright, cut to the band around the window (a little taller, as the preview is cropped to fill). */
private fun band(frame: CameraFrame): Bitmap {
    val source = frame.cameraImage.imageProxy.toBitmap()
    val upright = if (frame.rotation % 360 == 0) source else {
        Bitmap.createBitmap(source, 0, 0, source.width, source.height, Matrix().apply { postRotate(frame.rotation.toFloat()) }, true)
            .also { source.recycle() }
    }
    val h = (upright.width * Window.MRZ.aspect * 1.6f).toInt().coerceAtMost(upright.height)
    val top = ((upright.height - h) / 2).coerceAtLeast(0)
    return Bitmap.createBitmap(upright, 0, top, upright.width, h).also { if (it !== upright) upright.recycle() }
}
