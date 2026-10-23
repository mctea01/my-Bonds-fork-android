package diw.wallet.core.profile.bonds

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Instant

/**
 * A Bonds age proof request: the JSON QR a Bonds web verifier shows,
 * {v:1, a:age, b:request id, c:nonce, d:cutoff date, p:purpose, s:g|s, t:seconds, u:response URL}. The holder answers
 * online by posting an OpenAC proof to [responseUrl]; unlike [BondsPresentationRequest] there is no offline or BLE
 * path. Everything in it is untrusted text from the verifier.
 */
data class BondsAgeRequest(
    val minimumAge: Int,
    val requestId: String,
    val nonce: String,
    /** The latest birth date that meets [minimumAge] on the verifier's day. */
    val cutoff: LocalDate,
    val purpose: String,
    val source: BondsCredentialSource,
    val createdAt: Instant,
    val responseUrl: String,
) {
    val responseHost: String get() = Url(responseUrl).host

    /** Response hosts Bonds itself allows; another host is shown to the user as unknown, not refused. */
    val knownHost: Boolean get() = responseHost in KNOWN_HOSTS

    companion object {
        const val VERSION = 1
        const val MAX_NONCE = 128
        val KNOWN_HOSTS = setOf("verifier.mashbean.net")
        private val UUID_RE = Regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")

        private fun json(text: String): JsonObject? = text.trim().takeIf { it.startsWith("{") }
            ?.let { runCatching { DiwJson.parseToJsonElement(it) as? JsonObject }.getOrNull() }

        /** True for a JSON object with a response URL and a nonce: an online age request, never an offline challenge. */
        fun looksLike(text: String): Boolean = json(text)?.let { "u" in it && "c" in it && "v" in it } == true

        fun parse(text: String): BondsAgeRequest {
            val o = json(text) ?: throw ProtocolException("invalid_request", "This request could not be read")
            val version = (o["v"] as? JsonPrimitive)?.content?.toIntOrNull()
            if (version != VERSION) throw ProtocolException("invalid_request", "Unsupported age request version $version")
            val age = (o["a"] as? JsonPrimitive)?.content?.toIntOrNull()?.takeIf { it in 1..150 }
                ?: throw ProtocolException("invalid_request", "No minimum age")
            val id = o.str("b")?.takeIf { UUID_RE.matches(it) } ?: throw ProtocolException("invalid_request", "Malformed request id")
            val nonce = o.str("c")?.takeIf { it.isNotEmpty() && it.length <= MAX_NONCE }
                ?: throw ProtocolException("invalid_request", "Malformed nonce")
            val cutoff = o.str("d")?.let { runCatching { LocalDate.parse(it) }.getOrNull() }
                ?: throw ProtocolException("invalid_request", "Malformed cutoff date")
            val source = BondsCredentialSource.fromWire(o.str("s"))?.takeIf { it != BondsCredentialSource.ANY }
                ?: throw ProtocolException("invalid_request", "Unknown credential source")
            val created = (o["t"] as? JsonPrimitive)?.content?.toLongOrNull() ?: throw ProtocolException("invalid_request", "No request time")
            val url = o.str("u")?.takeIf { u ->
                runCatching { Url(u).let { it.protocol == URLProtocol.HTTPS && it.host.isNotEmpty() && it.user == null } }.getOrDefault(false)
            } ?: throw ProtocolException("invalid_request", "The response address must be https")
            return BondsAgeRequest(age, id, nonce, cutoff, o.str("p").orEmpty().take(BondsPresentationRequest.MAX_PURPOSE),
                source, Instant.fromEpochSeconds(created), url)
        }
    }
}
