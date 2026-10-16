package diw.wallet.app

import diw.wallet.core.document.sign.CscClient
import diw.wallet.core.document.sign.CscEnvironment
import diw.wallet.core.document.sign.CscService
import diw.wallet.core.document.sign.CscServices
import diw.wallet.core.document.sign.CscSigner
import diw.wallet.core.document.sign.CscToken
import diw.wallet.core.document.sign.CscUserAgent
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.jose.PlatformCrypto
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.takeFrom
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import org.multipaz.util.toHex

/** What the signing screen asks while a remote signing service waits for the holder. */
sealed class CscPrompt {
    /** A PIN or one-time password for this signature only. */
    class Secret(val label: String, val numeric: Boolean, val answer: CompletableDeferred<String?>) : CscPrompt()

    /** Authorization goes on in the browser; the address it ends at can be pasted when it does not come back by itself. */
    class Browser(val purpose: String, val redirectUri: String, val answer: CompletableDeferred<String?>) : CscPrompt()
}

/**
 * Remote signing through the CSC API: the built-in services (test ones apart from production ones) and the ones the
 * user adds, the sign-in tokens of this run (memory only), and the holder's part in authorizations. A sign-in that
 * asks for an OpenID4VP presentation (the EUDI QTSP asks for the PID) is answered on the wallet's own consent screen
 * without a browser; a sign-in page opens in the browser.
 */
class CscModel(private val model: WalletModel) {
    val prompt = MutableStateFlow<CscPrompt?>(null)
    private val tokens = mutableMapOf<String, CscToken>()

    val services: List<CscService>
        get() = CscServices.builtIn + model.settings.cscServices

    fun service(id: String): CscService? = services.firstOrNull { it.id == id }

    /** Checks a service the user is adding; null when it can be saved, else what is wrong. */
    fun problem(name: String, baseUrl: String, clientId: String, redirectUri: String): String? = when {
        name.isBlank() -> "請輸入服務名稱"
        !baseUrl.trim().startsWith("https://") && !(model.settings.allowLoopbackHttp && baseUrl.trim().startsWith("http://")) ->
            "CSC API 位址必須是 https"
        clientId.isBlank() -> "請輸入 client_id"
        ':' !in redirectUri -> "請輸入完整的 redirect_uri"
        else -> null
    }

    fun add(name: String, baseUrl: String, clientId: String, clientSecret: String, redirectUri: String, environment: CscEnvironment) {
        val s = CscService(
            id = "user-" + PlatformCrypto.randomBytes(6).toHex(),
            name = name.trim(),
            baseUrl = baseUrl.trim().trimEnd('/'),
            clientId = clientId.trim(),
            clientSecret = clientSecret.trim().ifEmpty { null },
            redirectUri = redirectUri.trim(),
            environment = environment,
        )
        model.updateSettings { it.copy(cscServices = it.cscServices + s) }
    }

    fun remove(id: String) {
        tokens.remove(id)
        model.updateSettings { st -> st.copy(cscServices = st.cscServices.filterNot { it.id == id }) }
    }

    /** A signer with its credential read; signs in first unless this run already holds a valid token. */
    suspend fun signer(service: CscService, hint: String, onStatus: (String) -> Unit): CscSigner {
        val signer = CscSigner(CscClient(model.http, service), agent, null, hint, onStatus, tokens[service.id])
        try {
            signer.load()
        } finally {
            signer.serviceToken?.let { tokens[service.id] = it }
        }
        return signer
    }

    /** Takes a redirect the browser handed back while an authorization waits for it. */
    fun handleRedirect(uri: String): Boolean {
        val p = prompt.value as? CscPrompt.Browser ?: return false
        if (!uri.startsWith(p.redirectUri)) return false
        p.answer.complete(uri)
        return true
    }

    private val agent = object : CscUserAgent {
        override suspend fun authorize(url: String, redirectUri: String, purpose: String): String =
            follow(url, redirectUri) ?: browser(url, redirectUri, purpose)

        override suspend fun askSecret(label: String, numeric: Boolean): String? {
            val answer = CompletableDeferred<String?>()
            prompt.value = CscPrompt.Secret(label, numeric, answer)
            return try {
                answer.await()
            } finally {
                prompt.value = null
            }
        }
    }

    /**
     * Follows the authorization redirects with a cookie jar of its own and answers a presentation request on the
     * way; returns the final redirect, or null when a page has to be shown in the browser.
     */
    private suspend fun follow(start: String, redirectUri: String): String? {
        val client = model.http.config {
            followRedirects = false
            install(HttpCookies)
        }
        var next = start
        repeat(MAX_HOPS) {
            when {
                next.startsWith(redirectUri) -> return next
                isPresentationRequest(next) -> next = model.presentForAuthorization(next)
                next.startsWith("https://") || (model.settings.allowLoopbackHttp && next.startsWith("http://")) -> {
                    val r = client.get(next)
                    val location = r.headers[HttpHeaders.Location]
                    when {
                        r.status.value in 300..399 && location != null -> next = resolve(next, location)
                        // A page that only offers the wallet link (the EUDI signer's same-device page) is followed too.
                        r.status.value in 200..299 -> next = presentationLink(r.bodyAsText()) ?: return null
                        else -> {
                            // The service's own words help more than the status alone (Spring answers with a JSON message).
                            val body = runCatching { r.bodyAsText() }.getOrDefault("")
                            val said = Regex("\"(?:message|error_description|error)\"\\s*:\\s*\"([^\"]{1,200})\"").find(body)?.groupValues?.get(1)
                                ?: body.replace(Regex("<[^>]*>"), " ").replace(Regex("\\s+"), " ").trim().take(160).ifEmpty { null }
                            throw SigningException("遠端簽章服務拒絕授權要求（HTTP ${r.status.value}，${next.substringBefore('?')}）" + (said?.let { "：$it" } ?: ""))
                        }
                    }
                }
                else -> return null
            }
        }
        throw SigningException("遠端簽章服務的授權轉址次數過多")
    }

    private suspend fun browser(url: String, redirectUri: String, purpose: String): String {
        val answer = CompletableDeferred<String?>()
        prompt.value = CscPrompt.Browser(purpose, redirectUri, answer)
        return try {
            model.platform.openBrowser(url)
            answer.await() ?: throw SigningException("已取消授權")
        } finally {
            prompt.value = null
        }
    }

    companion object {
        private const val MAX_HOPS = 12
        private val presentationSchemes = setOf("openid4vp", "haip-vp", "eudi-openid4vp", "mdoc-openid4vp")

        /** The one presentation request link on an HTML page, or null when there is none or more than one. */
        fun presentationLink(html: String): String? {
            val links = Regex("href\\s*=\\s*[\"']([^\"']+)[\"']", RegexOption.IGNORE_CASE).findAll(html)
                .map { it.groupValues[1].replace("&amp;", "&") }.filter { isPresentationRequest(it) }.distinct().toList()
            return links.singleOrNull()
        }

        fun isPresentationRequest(uri: String): Boolean = uri.substringBefore(':').lowercase() in presentationSchemes

        /** [location] against [base]; addresses with a scheme of their own (including app links) stay as they are. */
        fun resolve(base: String, location: String): String =
            if (Regex("^[A-Za-z][A-Za-z0-9+.-]*:").containsMatchIn(location)) location
            else URLBuilder(base).takeFrom(location).buildString()
    }
}
