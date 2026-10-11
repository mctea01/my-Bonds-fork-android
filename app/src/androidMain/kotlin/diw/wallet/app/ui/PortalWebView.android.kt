package diw.wallet.app.ui

import android.annotation.SuppressLint
import android.net.Uri
import android.util.Base64
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.URLUtil
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import diw.wallet.app.PickedFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

private const val MAX_DOWNLOAD = 64 * 1024 * 1024

/** Longest data: URL the script interface accepts: base64 of [MAX_DOWNLOAD] bytes plus the header. */
private const val MAX_DATA_URL = (MAX_DOWNLOAD / 3 + 1) * 4 + 256

/**
 * A source site inside the app: https pages load here, other schemes (mobilemoica:, intent:) go to their apps,
 * and downloads are fetched with the page's cookies and handed to the vault. Downloads made from a blob: URL are
 * read by the page itself and passed back through a script interface.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
actual fun PortalWebView(url: String, modifier: Modifier, onFile: (PickedFile) -> Unit, onExternal: (String) -> Unit, onError: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var view by remember { mutableStateOf<WebView?>(null) }
    var canGoBack by remember { mutableStateOf(false) }
    BackHandler(enabled = canGoBack) { view?.goBack() }
    DisposableEffect(Unit) { onDispose { view?.destroy() } }
    AndroidView(
        modifier = modifier,
        factory = { context ->
            WebView(context).apply {
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                settings.allowFileAccess = false
                settings.allowContentAccess = false
                CookieManager.getInstance().setAcceptCookie(true)
                CookieManager.getInstance().setAcceptThirdPartyCookies(this, true)
                addJavascriptInterface(object {
                    @JavascriptInterface
                    fun onTooLarge() {
                        post { onError("檔案超過 64 MB") }
                    }

                    @JavascriptInterface
                    fun onBlob(name: String, dataUrl: String) {
                        // Any page can call this interface, so the size is checked before anything is decoded.
                        if (dataUrl.length > MAX_DATA_URL) {
                            post { onError("檔案超過 64 MB") }
                            return
                        }
                        val comma = dataUrl.indexOf(',')
                        if (comma < 0) return
                        val mime = dataUrl.substring(5, comma).substringBefore(';')
                        val bytes = runCatching { Base64.decode(dataUrl.substring(comma + 1), Base64.DEFAULT) }.getOrNull() ?: return
                        post { onFile(PickedFile(name.ifBlank { "download" }, bytes, mime)) }
                    }
                }, "DiwVault")
                webViewClient = object : WebViewClient() {
                    override fun shouldOverrideUrlLoading(v: WebView, request: WebResourceRequest): Boolean {
                        val scheme = request.url.scheme?.lowercase()
                        if (scheme == "https" || scheme == "http" || scheme == "about" || scheme == "blob" || scheme == "data") return false
                        onExternal(request.url.toString())
                        return true
                    }

                    override fun doUpdateVisitedHistory(v: WebView, u: String?, isReload: Boolean) {
                        canGoBack = v.canGoBack()
                    }
                }
                setDownloadListener { link, userAgent, disposition, mime, _ ->
                    val name = URLUtil.guessFileName(link, disposition, mime)
                    if (link.startsWith("blob:")) {
                        val script = "(function(){fetch(" + quote(link) + ").then(function(r){return r.blob();}).then(function(b){" +
                            "if(b.size>$MAX_DOWNLOAD){DiwVault.onTooLarge();return;}" +
                            "var f=new FileReader();f.onload=function(){DiwVault.onBlob(" + quote(name) + ",f.result);};f.readAsDataURL(b);});})();"
                        evaluateJavascript(script, null)
                        return@setDownloadListener
                    }
                    scope.launch {
                        try {
                            val bytes = withContext(Dispatchers.IO) { download(link, userAgent) }
                            onFile(PickedFile(name, bytes, mime))
                        } catch (e: Exception) {
                            onError("無法下載文件：" + (e.message ?: e::class.simpleName))
                        }
                    }
                }
                loadUrl(url)
                view = this
            }
        },
    )
}

private fun quote(s: String): String = "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"

private fun download(link: String, userAgent: String): ByteArray {
    val uri = Uri.parse(link)
    if (uri.scheme != "https" && uri.scheme != "http") throw IllegalArgumentException("不支援的下載網址")
    val conn = URL(link).openConnection() as HttpURLConnection
    try {
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", userAgent)
        CookieManager.getInstance().getCookie(link)?.let { conn.setRequestProperty("Cookie", it) }
        conn.connectTimeout = 20_000
        conn.readTimeout = 60_000
        if (conn.responseCode !in 200..299) throw IllegalStateException("HTTP ${conn.responseCode}")
        val out = ByteArrayOutputStream()
        conn.inputStream.use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
                if (out.size() > MAX_DOWNLOAD) throw IllegalStateException("檔案超過 64 MB")
            }
        }
        return out.toByteArray()
    } finally {
        conn.disconnect()
    }
}
