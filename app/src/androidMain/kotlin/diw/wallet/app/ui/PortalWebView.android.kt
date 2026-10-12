package diw.wallet.app.ui

import android.annotation.SuppressLint
import android.net.Uri
import android.util.Base64
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.URLUtil
import android.webkit.WebChromeClient
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
 * Keeps the Blob behind every blob: URL the page creates, so a download survives the page revoking the URL right
 * after clicking it (MyData fetches the ZIP with XHR, clicks an <a download> and revokes at once, then leaves the
 * page). Clicks on such links and window.open of a blob (MyData's PDF preview) hand the Blob to the vault instead.
 */
private val BLOB_HOOK = """
(function(){
  if (window.__diwHooked) return; window.__diwHooked = true;
  var blobs = {};
  var create = URL.createObjectURL.bind(URL), revoke = URL.revokeObjectURL.bind(URL);
  URL.createObjectURL = function(o){ var u = create(o); if (o instanceof Blob) blobs[u] = o; return u; };
  URL.revokeObjectURL = function(u){ setTimeout(function(){ delete blobs[u]; revoke(u); }, 120000); };
  function send(b, name){
    if (b.size > $MAX_DOWNLOAD) { DiwVault.onTooLarge(); return; }
    var f = new FileReader(); f.onload = function(){ DiwVault.onBlob(name || '', f.result); }; f.readAsDataURL(b);
  }
  window.__diwBlob = function(u, name){
    if (blobs[u]) { send(blobs[u], name); return; }
    fetch(u).then(function(r){ return r.blob(); }).then(function(b){ send(b, name); })
      .catch(function(){ DiwVault.onFailed(); });
  };
  var click = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function(){
    if (this.href && this.href.indexOf('blob:') === 0 && blobs[this.href]) { send(blobs[this.href], this.download || ''); return; }
    return click.apply(this, arguments);
  };
  var open = window.open;
  window.open = function(u){
    if (typeof u === 'string' && u.indexOf('blob:') === 0 && blobs[u]) { send(blobs[u], ''); return null; }
    return open.apply(window, arguments);
  };
})();
"""

/**
 * A source site inside the app: https pages load here, other schemes (mobilemoica:, intent:) go to their apps,
 * and downloads are fetched with the page's cookies and handed to the vault. Downloads made from a blob: URL are
 * read by the page itself and passed back through a script interface. Script dialogs (alert, confirm) are shown,
 * since the citizen certificate steps of MyData rely on them.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
actual fun PortalWebView(url: String, modifier: Modifier, onFile: (PickedFile) -> Unit, onExternal: (String) -> Unit, onError: (String) -> Unit, autofill: PortalAutofill?) {
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
                    fun onFailed() {
                        post { onError("無法讀取下載的檔案，請在網站上重新下載") }
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
                        post { onFile(PickedFile(name.ifBlank { defaultName(mime) }, bytes, mime)) }
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

                    override fun onPageFinished(v: WebView, u: String?) {
                        v.evaluateJavascript(BLOB_HOOK, null)
                        // Saved MyData details go only to the exact host over https, never to a lookalike or a frame.
                        val page = u?.let { Uri.parse(it) }
                        if (autofill != null && page?.scheme == "https" && page.host.equals(autofill.host, ignoreCase = true)) {
                            v.evaluateJavascript(autofill.script) { result -> result?.toIntOrNull()?.takeIf { it > 0 }?.let(autofill.onFilled) }
                        }
                    }
                }
                // The default chrome client shows alert, confirm and prompt dialogs, which a bare WebView drops.
                webChromeClient = WebChromeClient()
                setDownloadListener { link, userAgent, disposition, mime, _ ->
                    val name = URLUtil.guessFileName(link, disposition, mime)
                    if (link.startsWith("blob:")) {
                        evaluateJavascript(BLOB_HOOK + "window.__diwBlob(" + quote(link) + "," + quote(name) + ");", null)
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

private fun defaultName(mime: String): String = when (mime.lowercase()) {
    "application/pdf" -> "download.pdf"
    "application/zip", "application/x-zip-compressed" -> "download.zip"
    else -> "download"
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
