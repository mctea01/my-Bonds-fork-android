package diw.testservers

import diw.wallet.core.did.DidResolver
import diw.wallet.core.profile.bonds.BondsAgePackage
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerdict
import diw.wallet.core.profile.bonds.BondsAgeVerifier
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.str
import diw.wallet.core.zk.OpenAcAgeVerifier
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.util.toBase64Url
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/**
 * A Bonds-compatible web age verifier (the API of verifier.mashbean.net/zkp) for interoperability tests, in two modes.
 * "server" checks the posted OpenAC proofs here with [engine]. "relay" only forwards: the session's creator (this
 * wallet acting as verifier) fetches the package with its token, verifies it on its own device and posts the verdict,
 * which is then returned to the holder still waiting on its POST. Sessions live in memory only.
 */
class BondsAgeService(
    private val baseUrl: String,
    private val engine: OpenAcAgeVerifier?,
    private val resolver: DidResolver,
    private val didTrust: DidTrust = DidTrust.NONE,
    /** Test servers know no government issuer, so an unanchored did:key (T3) is accepted and named in the verdict. */
    private val minimumTier: TrustTier = TrustTier.T3,
) {
    class Session(val id: String, val token: String, val request: BondsAgeRequest, val relay: Boolean) {
        @Volatile var pkg: String? = null
        val verdict = CompletableDeferred<BondsAgeVerdict>()
        val deadline: Instant get() = request.expiresAt + GRACE
    }

    private val sessions = ConcurrentHashMap<String, Session>()
    private val random = SecureRandom()

    val serverVerification: Boolean get() = engine != null

    fun create(source: BondsCredentialSource, minimumAge: Int, purpose: String, relay: Boolean): Session {
        val now = Clock.System.now()
        sessions.values.removeIf { now > it.deadline }
        val id = ByteArray(16).also(random::nextBytes).toBase64Url()
        val request = BondsAgeRequest.create(minimumAge, source, purpose, "${baseUrl.trimEnd('/')}/api/zkp/response/$id", now)
        return Session(id, ByteArray(32).also(random::nextBytes).toBase64Url(), request, relay).also { sessions[id] = it }
    }

    fun session(id: String, token: String?): Session? = sessions[id]?.takeIf {
        token != null && MessageDigest.isEqual(it.token.encodeToByteArray(), token.encodeToByteArray()) && Clock.System.now() <= it.deadline
    }

    /** The holder's POST: the HTTP status and verdict to answer with. */
    suspend fun respond(id: String, body: String): Pair<HttpStatusCode, BondsAgeVerdict> {
        val s = sessions[id]?.takeIf { Clock.System.now() <= it.deadline }
            ?: return HttpStatusCode.Gone to failed("查驗請求不存在或已過期")
        if (!s.request.isFresh(Clock.System.now())) return HttpStatusCode.Gone to failed("查驗請求已過期")
        if (s.pkg != null) return HttpStatusCode.Conflict to failed("這個查驗請求已收到證明")
        val pkg = runCatching { BondsAgePackage.parse(body, s.request) }.getOrNull()
            ?: return HttpStatusCode.BadRequest to failed("證明回應缺少必要欄位")
        s.pkg = body
        if (s.relay) {
            val verdict = withTimeoutOrNull(RELAY_WAIT) { s.verdict.await() }
                ?: return HttpStatusCode.GatewayTimeout to failed("查驗方沒有在時限內回覆")
            return HttpStatusCode.OK to verdict
        }
        val engine = engine ?: return HttpStatusCode.ServiceUnavailable to failed("查驗端沒有零知識驗證引擎")
        val verdict = try {
            BondsAgeVerifier.verify(pkg, engine, resolver, didTrust, minimumTier).verdict()
        } catch (_: Exception) {
            return HttpStatusCode.BadGateway to failed("驗證後端發生錯誤")
        }
        s.verdict.complete(verdict)
        return HttpStatusCode.OK to verdict
    }

    /** The verdict the relaying creator reached on its own device; false when the session has none waiting. */
    fun decide(s: Session, verdict: BondsAgeVerdict): Boolean = s.relay && s.pkg != null && s.verdict.complete(verdict)

    private fun failed(reason: String) = BondsAgeVerdict("failed", false, reason, null, null)

    companion object {
        val RELAY_WAIT = 75.seconds
        val GRACE = 60.seconds
    }
}

fun Route.bondsAgeRoutes(service: BondsAgeService) {
    get("/api/zkp/config") {
        call.respondJson(buildJsonObject {
            put("configured", true)
            put("backend", if (service.serverVerification) "native" else "relay")
            putJsonArray("modes") {
                if (service.serverVerification) add(JsonPrimitive("server"))
                add(JsonPrimitive("relay"))
            }
            put("requestLifetimeMs", BondsAgeRequest.LIFETIME.inWholeMilliseconds)
            putJsonArray("minimumAgeRange") { add(JsonPrimitive(1)); add(JsonPrimitive(120)) }
        })
    }
    post("/api/zkp/sessions") {
        val body = runCatching { call.receiveJsonObject() }.getOrNull()
            ?: return@post call.respondError(HttpStatusCode.BadRequest, "invalid_request", "JSON body required")
        val source = when (body.str("credentialSource")) {
            "selfIssued", "s" -> BondsCredentialSource.SELF_ISSUED
            "government", "g", null -> BondsCredentialSource.TWDIW
            else -> return@post call.respondError(HttpStatusCode.BadRequest, "invalid_request", "credentialSource is selfIssued or government")
        }
        val age = (body["minimumAge"] as? JsonPrimitive)?.content?.toIntOrNull() ?: 18
        if (age !in 1..120) return@post call.respondError(HttpStatusCode.BadRequest, "invalid_request", "minimumAge out of range")
        val relay = when (body.str("mode")) {
            "relay" -> true
            "server", null -> false
            else -> return@post call.respondError(HttpStatusCode.BadRequest, "invalid_request", "mode is server or relay")
        }
        if (!relay && !service.serverVerification) {
            return@post call.respondError(HttpStatusCode.ServiceUnavailable, "unavailable", "This server has no OpenAC verifier; use relay")
        }
        val s = service.create(source, age, body.str("purpose").orEmpty(), relay)
        call.respondJson(buildJsonObject {
            put("sessionId", s.id)
            put("token", s.token)
            put("request", s.request.encode())
            put("responseUrl", s.request.responseUrl)
            put("expiresAt", s.request.expiresAt.toEpochMilliseconds())
            put("mode", if (relay) "relay" else "server")
        })
    }
    post("/api/zkp/response/{id}") {
        val (status, verdict) = service.respond(call.parameters["id"]!!, call.receiveText())
        call.respondText(verdict.encode(), ContentType.Application.Json, status)
    }
    get("/api/zkp/sessions/{id}") {
        val s = service.session(call.parameters["id"]!!, call.request.queryParameters["token"])
            ?: return@get call.respondError(HttpStatusCode.NotFound, "not_found", "Unknown or expired session")
        val verdict = s.verdict.takeIf { it.isCompleted }?.getCompleted()
        call.respondText(buildJsonObject {
            put("state", if (verdict != null) "done" else if (s.pkg != null) "received" else "waiting")
            if (s.relay && verdict == null) s.pkg?.let { put("package", it) }
            verdict?.let { put("verdict", kotlinx.serialization.json.Json.parseToJsonElement(it.encode())) }
        }.toString(), ContentType.Application.Json)
    }
    post("/api/zkp/sessions/{id}/verdict") {
        val s = service.session(call.parameters["id"]!!, call.request.queryParameters["token"])
            ?: return@post call.respondError(HttpStatusCode.NotFound, "not_found", "Unknown or expired session")
        val verdict = BondsAgeVerdict.parse(call.receiveText())
            ?: return@post call.respondError(HttpStatusCode.BadRequest, "invalid_request", "Verdict JSON with status and accepted required")
        if (!service.decide(s, verdict)) return@post call.respondError(HttpStatusCode.Conflict, "conflict", "No package is waiting for a verdict")
        call.respondJson(buildJsonObject { put("ok", true) })
    }
}
