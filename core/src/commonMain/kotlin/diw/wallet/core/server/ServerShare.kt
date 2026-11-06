package diw.wallet.core.server

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.http.Url
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url

/**
 * A production server's settings handed from one wallet (or the server's operator) to another as a QR code or link,
 * `diw-server://v1?c=<base64url JSON>`. It carries what the receiver would otherwise type and compare by hand: the
 * address, the fingerprint of the root that signs the server's requests and receipts, its web verifier DID and, only
 * when the sender chose to, the access token. The fingerprint is a claim of whoever shared it: the receiver still
 * reads `/info` and accepts only when the server's root has exactly this fingerprint.
 */
data class ServerShare(
    val url: String,
    val name: String? = null,
    /** SHA-256 of the signing root, lower-case hex. */
    val rootSha256: String? = null,
    val verifierDid: String? = null,
    /** The server's OpenID Federation Entity Identifier, when it is in a federation. */
    val federation: String? = null,
    val features: List<String> = emptyList(),
    /** The access token, included only when the sender explicitly chose to share it. */
    val token: String? = null,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("url", url)
        name?.let { put("name", it) }
        rootSha256?.let { put("root", it) }
        verifierDid?.let { put("did", it) }
        federation?.let { put("fed", it) }
        if (features.isNotEmpty()) putJsonArray("features") { features.forEach { add(JsonPrimitive(it)) } }
        token?.let { put("token", it) }
    }

    fun link(): String = PREFIX + toJson().toString().encodeToByteArray().toBase64Url()

    /** The same settings without the token, for showing to someone who should only use the relay. */
    fun withoutToken(): ServerShare = copy(token = null)

    val host: String get() = runCatching { Url(url).host }.getOrDefault(url)

    companion object {
        const val PREFIX = "diw-server://v1?c="
        private const val MAX_LINK = 2048
        private val HEX64 = Regex("^[0-9a-f]{64}$")

        fun looksLike(text: String): Boolean = text.trim().startsWith(PREFIX)

        /** Reads a share link; [allowHttp] accepts a plain http address (the test environment only). */
        fun parse(link: String, allowHttp: Boolean = false): ServerShare {
            val t = link.trim()
            fun bad(what: String): Nothing = throw ProtocolException("invalid_request", "這不是有效的服務端分享：$what")
            if (!t.startsWith(PREFIX)) bad("格式不符")
            if (t.length > MAX_LINK) bad("內容過長")
            val o = runCatching { DiwJson.parseToJsonElement(t.removePrefix(PREFIX).fromBase64Url().decodeToString()) as JsonObject }
                .getOrElse { bad("無法解碼") }
            val url = o.str("url")?.trim()?.trimEnd('/') ?: bad("沒有網址")
            val u = runCatching { Url(url) }.getOrNull() ?: bad("網址無效")
            val scheme = u.protocol.name
            if (!(scheme == "https" || scheme == "http" && allowHttp) || u.host.isEmpty() || u.user != null || u.encodedQuery.isNotEmpty() || '#' in url) {
                bad(if (scheme == "http") "只在測試環境接受 http 網址" else "網址必須是 https")
            }
            val root = o.str("root")?.lowercase()?.also { if (!HEX64.matches(it)) bad("指紋格式錯誤") }
            val did = o.str("did")?.trim()?.also { if (!it.startsWith("did:") || it.length > 1024) bad("DID 格式錯誤") }
            val fed = o.str("fed")?.trim()?.trimEnd('/')?.also { if (!it.startsWith("https://") && !(allowHttp && it.startsWith("http://"))) bad("信任聯盟識別碼無效") }
            return ServerShare(
                url = url,
                name = o.str("name")?.filter { !it.isISOControl() }?.take(60)?.takeIf { it.isNotBlank() },
                rootSha256 = root,
                verifierDid = did,
                federation = fed,
                features = o.strList("features").filter { it.length <= 32 }.take(16),
                token = o.str("token")?.takeIf { it.isNotEmpty() && it.length <= 512 },
            )
        }
    }
}
