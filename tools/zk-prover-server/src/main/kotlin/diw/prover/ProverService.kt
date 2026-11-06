package diw.prover

import diw.wallet.core.zk.ZkPdfEngine
import diw.wallet.core.zk.ZkPdfRemote
import diw.wallet.core.zk.ZkResult
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.utils.io.*
import kotlinx.coroutines.*
import kotlinx.io.readByteArray
import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

/**
 * The zkPDF proving service of a self-hosted prover. One proof runs at a time (a proof holds about 2 GB); finished
 * results are kept for [keep] and then dropped. Requests carry private document windows, so nothing from a request
 * or a result is ever logged, and every route needs the access token.
 */
class ProverService(
    private val engine: ZkPdfEngine,
    token: String,
    private val scope: CoroutineScope,
    private val keep: Duration = 1.hours,
    private val clock: () -> Instant = { Clock.System.now() },
) {
    private val expected = MessageDigest.getInstance("SHA-256").digest(token.encodeToByteArray())
    private val jobs = LinkedHashMap<String, Job>()
    private val random = SecureRandom()

    init {
        require(token.length >= MIN_TOKEN) { "The access token must have at least $MIN_TOKEN characters" }
    }

    private class Job(val id: String, val created: Instant) {
        @Volatile var state = "queued"
        @Volatile var kind: String? = null
        @Volatile var done = 0
        @Volatile var total = 0
        @Volatile var result: JsonObject? = null
        @Volatile var reason: String? = null
        @Volatile var retryable = false
        @Volatile var finished: Instant? = null
        var work: kotlinx.coroutines.Job? = null
    }

    fun authorized(header: String?): Boolean {
        val presented = header?.removePrefix("Bearer ")?.takeIf { header.startsWith("Bearer ") } ?: return false
        return MessageDigest.isEqual(expected, MessageDigest.getInstance("SHA-256").digest(presented.encodeToByteArray()))
    }

    /** Starts a proof of [body] (an encoded request); null when another proof is running. */
    @Synchronized
    fun start(body: ByteArray): String? {
        purge()
        if (jobs.values.any { it.state == "queued" || it.state == "running" }) return null
        val request = ZkPdfRemote.parseRequest(ZkPdfRemote.parse(body))
        val id = ByteArray(18).also(random::nextBytes).let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
        val job = Job(id, clock())
        jobs[id] = job
        job.work = scope.launch {
            job.state = "running"
            val result = try {
                engine.prove(request.statement, request.witness) { kind, done, total ->
                    job.kind = kind; job.done = done; job.total = total
                }
            } catch (_: kotlinx.coroutines.CancellationException) {
                ZkResult.Cancelled
            } catch (_: Throwable) {
                ZkResult.Failed("證明器發生錯誤", true)
            }
            when (result) {
                is ZkResult.Ok -> {
                    job.result = ZkPdfRemote.encodeResponse(ZkPdfRemote.Response(request.id, result.value))
                    job.state = "done"
                }
                is ZkResult.Failed -> { job.reason = result.reason; job.retryable = result.retryable; job.state = "failed" }
                ZkResult.Cancelled -> job.state = "cancelled"
            }
            job.finished = clock()
        }
        return id
    }

    @Synchronized
    fun status(id: String): JsonObject? {
        purge()
        val job = jobs[id] ?: return null
        return buildJsonObject {
            put("state", job.state)
            job.kind?.let { put("kind", it); put("done", job.done); put("total", job.total) }
            job.result?.let { put("result", it) }
            job.reason?.let { put("reason", it); put("retryable", job.retryable) }
        }
    }

    @Synchronized
    fun cancel(id: String): Boolean {
        val job = jobs[id] ?: return false
        job.work?.cancel()
        if (job.state == "done" || job.state == "failed" || job.state == "cancelled") jobs.remove(id)
        return true
    }

    private fun purge() {
        val now = clock()
        jobs.values.removeAll { job -> job.finished?.let { now - it > keep } ?: false }
    }

    fun ready(): List<String> = listOf("zkpdf-v1-phone", "zkpdf-v1-desktop").filter { engine.ready(it, true) }

    companion object {
        const val MIN_TOKEN = 24
    }
}

/** The HTTP routes of [service]: POST and GET/DELETE /v1/zkpdf/jobs[/{id}] and GET /v1/health. */
fun Application.prover(service: ProverService) {
    routing {
        intercept(ApplicationCallPipeline.Plugins) {
            if (!service.authorized(call.request.headers[HttpHeaders.Authorization])) {
                call.respond(HttpStatusCode.Unauthorized)
                finish()
            }
        }
        get("/v1/health") {
            call.respondText(buildJsonObject { putJsonArray("compositions") { service.ready().forEach { add(it) } } }.toString(),
                ContentType.Application.Json)
        }
        post("/v1/zkpdf/jobs") {
            val length = call.request.contentLength()
            if (length != null && length > ZkPdfRemote.MAX_BYTES) return@post call.respond(HttpStatusCode.PayloadTooLarge)
            val body = call.receiveChannel().readRemaining(ZkPdfRemote.MAX_BYTES.toLong() + 1).readByteArray()
            if (body.size > ZkPdfRemote.MAX_BYTES) return@post call.respond(HttpStatusCode.PayloadTooLarge)
            val id = try {
                service.start(body) ?: return@post call.respond(HttpStatusCode.TooManyRequests)
            } catch (_: IllegalArgumentException) {
                return@post call.respond(HttpStatusCode.BadRequest)
            }
            call.respondText(buildJsonObject { put("id", id) }.toString(), ContentType.Application.Json, HttpStatusCode.Accepted)
        }
        get("/v1/zkpdf/jobs/{id}") {
            val status = service.status(call.parameters["id"].orEmpty()) ?: return@get call.respond(HttpStatusCode.NotFound)
            call.respondText(status.toString(), ContentType.Application.Json)
        }
        delete("/v1/zkpdf/jobs/{id}") {
            call.respond(if (service.cancel(call.parameters["id"].orEmpty())) HttpStatusCode.NoContent else HttpStatusCode.NotFound)
        }
    }
}
