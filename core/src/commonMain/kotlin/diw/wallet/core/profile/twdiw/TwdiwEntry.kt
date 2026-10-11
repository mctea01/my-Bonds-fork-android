package diw.wallet.core.profile.twdiw

import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.util.queryParameters
import org.multipaz.util.fromBase64
import org.multipaz.util.fromBase64Url

/** What a scanned code or opened link of the TWDIW platform leads to. */
sealed interface TwdiwEntry {
    /** A credential offer, rewritten to the standard openid-credential-offer form. */
    data class Offer(val uri: String) : TwdiwEntry

    /** An authorization request, rewritten to the standard openid4vp form. */
    data class Presentation(val uri: String) : TwdiwEntry

    /** A static "apply for a card" (mode vc) or "show a card" (mode vp) code that must be resolved by the platform. */
    data class StaticQr(val mode: String, val uid: String) : TwdiwEntry

    companion object {
        /** Entry hint passed to the issuance and presentation flows so the TWDIW profile owns the session. */
        const val ENTRY_HINT = TwdiwDialect.ENTRY_HINT
    }
}

/**
 * Reads TWDIW entry points:
 * - modadigitalwallet://credential_offer?credential_offer_uri=... (the official deep link carries a CR/LF after '?');
 * - modadigitalwallet://authorize?client_id=...&request_uri=...;
 * - modadigitalwallet://staticqrcode?mode=vc|vp&vcUid=|vpUid=;
 * - the https relay pages on frontend(-uat).wallet.gov.tw with a base64 deeplink parameter (vcqrcode, vpqrcode);
 * - the static https code /api/moda/qrcode?mode=vc&vcUid=... (not an offer; resolved through the service catalogue).
 * Returns null for anything else, which then goes to the standard parsers unchanged.
 */
object TwdiwEntryParser {
    const val SCHEME = "modadigitalwallet"

    fun parse(scanned: String, depth: Int = 0): TwdiwEntry? {
        if (depth > 3) return null
        val text = scanned.replace("\r", "").replace("\n", "").trim()
        val scheme = text.substringBefore(':', "").lowercase()
        return when (scheme) {
            SCHEME -> parseScheme(text)
            "https" -> parseHttps(text, depth)
            else -> null
        }
    }

    private fun parseScheme(text: String): TwdiwEntry? {
        val rest = text.substringAfter("://", text.substringAfter(':'))
        val host = rest.substringBefore('?').substringBefore('/').lowercase()
        val query = rest.substringAfter('?', "").trimStart('&')
        return when (host) {
            "credential_offer" -> TwdiwEntry.Offer("openid-credential-offer://?$query")
            "authorize" -> TwdiwEntry.Presentation("openid4vp://authorize?$query")
            "staticqrcode" -> staticOf(queryParameters("x://x?$query"))
            else -> null
        }
    }

    private fun parseHttps(text: String, depth: Int): TwdiwEntry? {
        val host = TwdiwHosts.canonicalHost(text) ?: return null
        if (!TwdiwDialect.isTwdiwHost(host)) return null
        val params = queryParameters(text)
        params["deeplink"]?.let { encoded ->
            val decoded = decodeDeeplink(encoded) ?: return null
            return parse(decoded, depth + 1)
        }
        val path = text.substringAfter(host).substringBefore('?')
        if (path.endsWith("/api/moda/qrcode")) return staticOf(params)
        return null
    }

    private fun staticOf(params: io.ktor.http.Parameters): TwdiwEntry? {
        val mode = params["mode"]?.lowercase() ?: return null
        val uid = when {
            mode.startsWith("vp") -> params["vpUid"] ?: params["vpuid"]
            else -> params["vcUid"] ?: params["vcuid"]
        } ?: return null
        return TwdiwEntry.StaticQr(if (mode.startsWith("vp")) "vp" else "vc", uid)
    }

    private fun decodeDeeplink(encoded: String): String? {
        val t = encoded.trim()
        if (t.contains("://")) return t
        val bytes = runCatching { t.trimEnd('=').fromBase64Url() }.getOrNull() ?: runCatching { t.fromBase64() }.getOrNull() ?: return null
        return bytes.decodeToString().takeIf { it.contains(':') }
    }
}
