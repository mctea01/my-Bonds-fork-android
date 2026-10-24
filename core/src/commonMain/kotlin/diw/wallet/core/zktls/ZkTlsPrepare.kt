package diw.wallet.core.zktls

import diw.wallet.core.util.ProtocolException
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.readRawBytes
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.http.isSuccess
import io.ktor.http.parseServerSetCookieHeader

/**
 * The step before a query that needs a session (ZkTlsProfile.Prepare): this device opens the page over ordinary
 * HTTPS, outside zkTLS and without the verifier, and fetches the picture code in that session. The session cookies
 * then go in the query's hidden Cookie header. Nothing of this reaches the verifier, and none of it is stored.
 */
object ZkTlsPrepare {
    const val MAX_IMAGE = 262_144

    /** Most of a prepared page read for its values. */
    const val MAX_PAGE = 524_288

    /** A prepared session: its cookies, the values read from its page, and the picture the user reads. Kept in memory only. */
    class Session(val cookies: Map<String, String>, val image: ByteArray, val values: Map<String, String> = emptyMap()) {
        override fun toString() = "ZkTlsPrepare.Session(${cookies.keys}, ${values.keys}, ${image.size} bytes)"
    }

    /** Whether [profile] needs a prepared session before the query. */
    fun needed(profile: ZkTlsProfile): Boolean = profile.prepare.type == "captcha"

    /**
     * Opens a session for [profile] with [client] (which must not follow redirects to other sites) and fetches its
     * picture. [previous] continues an earlier session, so a new picture replaces the old one in the same session.
     */
    suspend fun start(client: HttpClient, profile: ZkTlsProfile, previous: Session? = null): Session {
        val prepare = profile.prepare
        if (!needed(profile)) throw ProtocolException("invalid_profile", "This page needs no preparation")
        val origin = "https://" + profile.host + if (profile.port == 443) "" else ":${profile.port}"
        val cookies = linkedMapOf<String, String>()
        previous?.cookies?.let { cookies.putAll(it) }
        suspend fun fetch(path: String): HttpResponse {
            val response = client.get(origin + path) {
                profile.request.headers.forEach { (k, v) -> header(k, v) }
                header(HttpHeaders.AcceptEncoding, "identity")
                if (cookies.isNotEmpty()) header(HttpHeaders.Cookie, cookies.entries.joinToString("; ") { "${it.key}=${it.value}" })
            }
            response.headers.getAll(HttpHeaders.SetCookie).orEmpty().forEach { line ->
                runCatching { parseServerSetCookieHeader(line) }.getOrNull()?.let { c ->
                    if (c.name in prepare.cookies) cookies[c.name] = c.value
                }
            }
            return response
        }
        val values = linkedMapOf<String, String>()
        previous?.values?.let { values.putAll(it) }
        if (previous == null) prepare.page?.let { path ->
            val page = fetch(path)
            if (!page.status.isSuccess()) throw ProtocolException("prepare_failed", "網站回應 ${page.status.value}，無法開始查詢")
            if (prepare.values.isNotEmpty()) {
                val bytes = page.readRawBytes()
                if (bytes.size > MAX_PAGE) throw ProtocolException("prepare_failed", "網站頁面過大")
                val text = bytes.decodeToString()
                prepare.values.forEach { v ->
                    val value = Regex(v.pattern).find(text)?.groupValues?.getOrNull(1)
                    if (value == null || !ZkTlsProfile.VALUE_RE.matches(value)) throw ProtocolException("prepare_failed", "網站頁面沒有查詢需要的欄位，頁面可能已改版")
                    values[v.name] = value
                }
            }
        }
        val image = ZkTlsProfile.PLACEHOLDER.replace(prepare.image!!) { m ->
            (values[m.groupValues[1]] ?: throw ProtocolException("prepare_failed", "網頁工作階段已失效")).encodeURLParameter()
        }
        val picture = fetch(image)
        if (!picture.status.isSuccess()) throw ProtocolException("prepare_failed", "網站回應 ${picture.status.value}，無法取得驗證碼圖片")
        if (picture.contentType()?.contentType != "image") throw ProtocolException("prepare_failed", "網站沒有回傳驗證碼圖片")
        val bytes = picture.readRawBytes()
        if (bytes.isEmpty() || bytes.size > MAX_IMAGE) throw ProtocolException("prepare_failed", "驗證碼圖片大小不符")
        val missing = prepare.cookies.filter { it !in cookies }
        if (missing.isNotEmpty()) throw ProtocolException("prepare_failed", "網站沒有建立查詢工作階段")
        return Session(cookies.filterKeys { it in prepare.cookies }, bytes, values)
    }
}
