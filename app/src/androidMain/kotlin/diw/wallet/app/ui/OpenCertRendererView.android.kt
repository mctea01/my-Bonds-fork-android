package diw.wallet.app.ui

import android.annotation.SuppressLint
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import diw.wallet.core.document.opencerts.OpenCertRenderer

/**
 * The renderer host page in a web view, loaded under a base URL that never resolves so the page has an https origin
 * of its own. Only the renderer's frame loads from the network; the top page never navigates away, links open in
 * the browser.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
actual fun OpenCertRendererView(html: String, modifier: Modifier, onExternal: (String) -> Unit) {
    var view by remember { mutableStateOf<WebView?>(null) }
    DisposableEffect(Unit) { onDispose { view?.destroy() } }
    AndroidView(
        modifier = modifier,
        factory = { context ->
            WebView(context).apply {
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                settings.allowFileAccess = false
                settings.allowContentAccess = false
                webViewClient = object : WebViewClient() {
                    override fun shouldOverrideUrlLoading(v: WebView, request: WebResourceRequest): Boolean {
                        if (!request.isForMainFrame) return false
                        onExternal(request.url.toString())
                        return true
                    }
                }
                loadDataWithBaseURL(OpenCertRenderer.HOST_BASE_URL, html, "text/html", "utf-8", null)
                view = this
            }
        },
    )
}
