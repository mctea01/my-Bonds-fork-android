package diw.testservers.zktls

import diw.testservers.TestPki
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zktls.NativeZkTlsEngine
import diw.wallet.core.zktls.WebSocketChannel
import diw.wallet.core.zktls.ZkTlsCheck
import diw.wallet.core.zktls.ZkTlsKey
import diw.wallet.core.zktls.ZkTlsOutcome
import diw.wallet.core.zktls.ZkTlsProfile
import diw.wallet.core.zktls.ZkTlsProfiles
import diw.wallet.core.zktls.ZkTlsSessionRequest
import diw.wallet.core.zktls.ZkTlsTransport
import diw.wallet.core.zktls.ZkTlsVerification
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.CloseReason
import io.ktor.websocket.close
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.util.toBase64Url
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Clock

/**
 * The zkTLS verifier as a server (M6a): a client (the wallet's verify tab, or a test) creates a session for a
 * verification page, shows the signed request, and polls for the verdict while the holder connects to
 * `/zktls/sessions/{sid}/ws` and proves the page here. The request is signed with the test reader certificate.
 * [profiles] are the pages this server offers besides the built-in ones; their definitions travel inline in the
 * request, so only wallets in the test environment accept them. [roots] are extra server roots (test CAs).
 */
class ZkTlsVerifierService(
    private val baseUrl: String,
    private val pki: TestPki,
    private val profiles: () -> List<ZkTlsProfile>,
    private val roots: () -> List<ByteArray>,
    private val available: suspend () -> Boolean,
) {
    class Session(val id: String, val token: String, val request: ZkTlsSessionRequest, val jws: String, val profile: ZkTlsProfile, val key: ZkTlsKey) {
        @Volatile var status: String = "waiting"
        @Volatile var reason: String? = null
        @Volatile var outcome: ZkTlsOutcome? = null
    }

    private val sessions = ConcurrentHashMap<String, Session>()
    private val random = SecureRandom()

    fun profile(id: String): ZkTlsProfile? = ZkTlsProfiles.find(id) ?: profiles().firstOrNull { it.id == id }

    /** The pages sessions can be created for. */
    fun offered(): List<ZkTlsProfile> = ZkTlsProfiles.installed + profiles()

    suspend fun create(profileId: String, fields: List<String>, purpose: String, mode: String): Session {
        if (!available()) throw ProtocolException("unsupported", "這台查驗主機沒有 zkTLS（TLSNotary）原生程式庫")
        val profile = profile(profileId) ?: throw ProtocolException("invalid_request", "Unknown verification page $profileId")
        val now = Clock.System.now()
        sessions.values.removeIf { now > it.request.expiresAt }
        val id = ByteArray(16).also(random::nextBytes).toBase64Url()
        val key = ZkTlsKey()
        val base = Url(baseUrl.trimEnd('/'))
        val scheme = if (base.protocol.name == "https") "wss" else "ws"
        val port = if (base.port == base.protocol.defaultPort) "" else ":${base.port}"
        val transport = ZkTlsTransport.Wss("$scheme://${base.host}$port${base.encodedPath.trimEnd('/')}/zktls/sessions/$id/ws")
        val request = ZkTlsSessionRequest.create(
            listOf(transport), key.publicKey, profile, fields, purpose, mode, now,
            inlineProfile = ZkTlsProfiles.find(profile.id) == null, sessionId = id,
        )
        val signer = pki.readerKey(base.host)
        val jws = ZkTlsSessionRequest.sign(request, signer, chain = signer.certChain.certificates)
        return Session(id, ByteArray(32).also(random::nextBytes).toBase64Url(), request, jws, profile, key).also { sessions[id] = it }
    }

    fun session(id: String, token: String?): Session? = sessions[id]?.takeIf {
        token != null && MessageDigest.isEqual(it.token.encodeToByteArray(), token.encodeToByteArray())
    }

    /** Verifies the holder on [channel] once; a second connection to the same session is refused. */
    suspend fun run(id: String, channel: WebSocketChannel): Boolean {
        val s = sessions[id]?.takeIf { it.status == "waiting" && it.request.isFresh(Clock.System.now()) } ?: return false
        synchronized(s) {
            if (s.status != "waiting") return false
            s.status = "verifying"
        }
        val result = withContext(Dispatchers.IO) {
            try {
                ZkTlsVerification.verify(channel, s.jws, s.request, s.profile, s.key, roots())
            } catch (e: ZkException) {
                NativeZkTlsEngine.failure(e)
            }
        }
        when (result) {
            is ZkResult.Ok -> {
                s.outcome = ZkTlsCheck.check(s.request, s.profile, result.value)
                s.status = "done"
            }
            is ZkResult.Failed -> {
                s.reason = result.reason
                s.status = "failed"
            }
            ZkResult.Cancelled -> {
                s.reason = "查驗已取消"
                s.status = "failed"
            }
        }
        return true
    }

    fun state(s: Session): JsonObject = buildJsonObject {
        put("status", s.status)
        s.reason?.let { put("reason", it) }
        s.outcome?.let { put("outcome", it.toJson()) }
    }
}

fun Route.zkTlsVerifierRoutes(service: ZkTlsVerifierService) {
    get("/zktls/profiles") {
        val list = buildJsonArray { service.offered().forEach { add(DiwJson.encodeToJsonElement(ZkTlsProfile.serializer(), it)) } }
        call.respondText(buildJsonObject { put("profiles", list) }.toString(), ContentType.Application.Json)
    }
    post("/zktls/sessions") {
        val o = runCatching { DiwJson.parseToJsonElement(call.receiveText()) as JsonObject }.getOrNull()
        if (o == null) {
            call.respondText("""{"error":"invalid_request"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
            return@post
        }
        try {
            val s = service.create(o.str("profile").orEmpty(), o.strList("fields"), o.str("purpose").orEmpty(), o.str("mode") ?: "proxy")
            val body = buildJsonObject {
                put("sessionId", s.id)
                put("token", s.token)
                put("request", ZkTlsSessionRequest.link(s.jws))
                put("expiresAt", s.request.expiresAt.epochSeconds)
            }
            call.respondText(body.toString(), ContentType.Application.Json)
        } catch (e: ProtocolException) {
            call.respondText(buildJsonObject { put("error", e.code); put("error_description", e.message ?: "") }.toString(),
                ContentType.Application.Json, HttpStatusCode.BadRequest)
        }
    }
    get("/zktls/sessions/{sid}") {
        val s = service.session(call.parameters["sid"].orEmpty(), call.request.queryParameters["token"])
        if (s == null) call.respondText("""{"error":"not_found"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
        else call.respondText(service.state(s).toString(), ContentType.Application.Json)
    }
    webSocket("/zktls/sessions/{sid}/ws") {
        val channel = WebSocketChannel(this)
        if (!service.run(call.parameters["sid"].orEmpty(), channel)) close(CloseReason(CloseReason.Codes.CANNOT_ACCEPT, "No such session"))
    }
}
