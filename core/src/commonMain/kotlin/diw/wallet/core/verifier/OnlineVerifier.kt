package diw.wallet.core.verifier

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.oid4vp.LanEndpoints
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.long
import diw.wallet.core.util.str
import diw.wallet.core.verifier.declaration.JwsSigner
import io.ktor.client.HttpClient
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.http.parseQueryString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/**
 * The server's OpenID4VP mailbox (feature oid4vp, docs/design/p5-verifier.md section 6.2): a phone verifier opens a
 * session with its access token, puts the signed request object, and fetches the encrypted response the holder posted.
 * The server keeps only the request object and the response, until fetched or [LIFETIME] passes.
 */
object Oid4vpMailbox {
    const val PATH = "/oid4vp/v1"
    const val SESSIONS = "$PATH/sessions"
    const val REQUEST = "$PATH/req"
    const val RESPONSE = "$PATH/resp"
    const val FEATURE = "oid4vp"
    val LIFETIME: Duration = 10.minutes
    const val MAX_REQUEST_BYTES = 128 * 1024
    const val MAX_RESPONSE_BYTES = 4 * 1024 * 1024
    /** How long one fetch of the response waits on the server before answering 204. */
    val POLL_WAIT: Duration = 25.seconds

    /** Session ids and secrets: 32 random bytes, base64url. */
    fun newSecret(): String = PlatformCrypto.randomBytes(32).toBase64Url()

    fun validId(id: String): Boolean = id.length == 43 && id.all { it.isLetterOrDigit() || it == '-' || it == '_' }
}

/** One mailbox session as the verifier keeps it; [secret] never leaves the verifier. */
data class MailboxSession(val id: String, val secret: String, val requestUri: String, val responseUri: String, val expiresAt: Instant)

/** The verifier's side of [Oid4vpMailbox]. */
class Oid4vpMailboxClient(private val http: HttpClient, baseUrl: String, private val token: String?) {
    private val base = baseUrl.trimEnd('/')

    suspend fun open(): MailboxSession {
        val r = http.post(base + Oid4vpMailbox.SESSIONS) {
            token?.let { header(HttpHeaders.Authorization, "Bearer $it") }
            contentType(ContentType.Application.Json)
            setBody("{}")
        }
        if (r.status != HttpStatusCode.Created && r.status != HttpStatusCode.OK) {
            throw ProtocolException("server_error", "The server refused the session (HTTP ${r.status.value}): ${r.bodyAsText().take(200)}")
        }
        val o = DiwJson.parseToJsonElement(r.bodyAsText()) as? JsonObject ?: throw ProtocolException("server_error", "Malformed session")
        return MailboxSession(
            id = o.str("id") ?: throw ProtocolException("server_error", "No session id"),
            secret = o.str("secret") ?: throw ProtocolException("server_error", "No session secret"),
            requestUri = o.str("request_uri") ?: throw ProtocolException("server_error", "No request_uri"),
            responseUri = o.str("response_uri") ?: throw ProtocolException("server_error", "No response_uri"),
            expiresAt = Clock.System.now() + ((o.long("expires_in") ?: Oid4vpMailbox.LIFETIME.inWholeSeconds)).seconds,
        )
    }

    suspend fun putRequest(s: MailboxSession, requestObject: String) {
        val r = http.put(base + Oid4vpMailbox.SESSIONS + "/" + s.id + "/request") {
            header(HttpHeaders.Authorization, "Bearer ${s.secret}")
            contentType(ContentType.parse("application/oauth-authz-req+jwt"))
            setBody(requestObject)
        }
        if (!(r.status == HttpStatusCode.NoContent || r.status == HttpStatusCode.OK)) {
            throw ProtocolException("server_error", "The server did not take the request (HTTP ${r.status.value})")
        }
    }

    /** The form parameters the holder posted, or null when none arrived before [until]. */
    suspend fun awaitResponse(s: MailboxSession, until: Instant = s.expiresAt): Map<String, String>? {
        while (Clock.System.now() < until) {
            val r = http.get(base + Oid4vpMailbox.SESSIONS + "/" + s.id + "/response") {
                header(HttpHeaders.Authorization, "Bearer ${s.secret}")
            }
            when (r.status) {
                HttpStatusCode.OK -> {
                    val o = DiwJson.parseToJsonElement(r.bodyAsText()) as? JsonObject ?: throw ProtocolException("server_error", "Malformed response")
                    return o.mapNotNull { (k, v) -> (v as? JsonPrimitive)?.takeIf { it.isString }?.let { k to it.content } }.toMap()
                }
                HttpStatusCode.NoContent -> continue
                HttpStatusCode.NotFound, HttpStatusCode.Gone -> return null
                else -> throw ProtocolException("server_error", "The server answered HTTP ${r.status.value}")
            }
        }
        return null
    }

    suspend fun close(s: MailboxSession) {
        runCatching { http.delete(base + Oid4vpMailbox.SESSIONS + "/" + s.id) { header(HttpHeaders.Authorization, "Bearer ${s.secret}") } }
    }
}

/** A request a phone verifier made: the signed object, how the holder opens it, and what the verifier keeps. */
data class OnlineRequest(val requestObject: String, val invocation: String, val session: VerifierSession)

/** Builds the signed OpenID4VP 1.0 request of a wallet acting as verifier (docs/design/p5-verifier.md section 6.1). */
object OnlineVerifierRequests {
    const val LAN_REQUEST = LanEndpoints.PATH_PREFIX + "request"
    const val LAN_RESPONSE = LanEndpoints.PATH_PREFIX + "response"

    /** A fresh nonce (32 random bytes, base64url). */
    fun nonce(): String = PlatformCrypto.randomBytes(32).toBase64Url()

    /**
     * Signs the request with [signer]. [verifierInfo] builds the verifier_info entries for the client_id and nonce
     * (registration certificate, then the declaration); the response is always direct_post.jwt with a fresh key.
     */
    suspend fun build(
        signer: JwsSigner,
        dcql: JsonObject,
        requestUri: String,
        responseUri: String,
        nonce: String = nonce(),
        verifierInfo: suspend (clientId: String, nonce: String) -> List<JsonObject> = { _, _ -> emptyList() },
    ): OnlineRequest {
        val key = Crypto.createEcPrivateKey(EcCurve.P256)
        val state = PlatformCrypto.randomBytes(16).toBase64Url()
        val info = verifierInfo(signer.clientId, nonce)
        val spec = VerifierRequestSpec(
            clientId = signer.clientId,
            responseMode = "direct_post.jwt",
            nonce = nonce,
            dcqlQuery = dcql,
            responseUri = responseUri,
            state = state,
            encryptionKey = key,
            verifierInfo = if (info.isEmpty()) null else JsonArray(info),
            extra = mapOf(
                "iat" to JsonPrimitive(Clock.System.now().epochSeconds),
                "exp" to JsonPrimitive((Clock.System.now() + Oid4vpMailbox.LIFETIME).epochSeconds),
            ),
        )
        val jws = RequestObjectBuilder.sign(spec, signer)
        val session = VerifierSession(nonce, signer.clientId, "direct_post.jwt", dcql, responseUri, state, key)
        return OnlineRequest(jws, invocation(signer.clientId, requestUri), session)
    }

    /** The QR code and link content: openid4vp://?client_id=...&request_uri=... (OpenID4VP 1.0 section 5). */
    fun invocation(clientId: String, requestUri: String): String =
        "openid4vp://?client_id=" + clientId.encodeURLParameter() + "&request_uri=" + requestUri.encodeURLParameter()

    /** The form parameters of a direct_post body. */
    fun form(body: ByteArray): Map<String, String> {
        val p = parseQueryString(body.decodeToString())
        return p.names().associateWith { p[it].orEmpty() }
    }
}
