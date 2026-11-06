package diw.wallet.core.zk

import diw.wallet.core.document.zkpdf.ZkPdfTextRecord
import diw.wallet.core.jose.PlatformCrypto
import io.ktor.client.HttpClient
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url

/**
 * A zkPDF proof made somewhere else (p4-zkp.md section 8): on the desktop app from an exported request file, or on a
 * self-hosted prover. The request carries the public statement and the private windows only, never the whole PDF;
 * the response carries the segment proofs and their outputs. The requesting device trusts nothing in a response
 * until its own verifier accepts every segment against the statement it built itself.
 */
object ZkPdfRemote {
    const val VERSION = 1
    const val REQUEST_TYPE = "ZkPdfProveRequest"
    const val RESPONSE_TYPE = "ZkPdfProveResponse"
    /** File name extensions of an exported request and of the proof made for it. */
    const val REQUEST_EXTENSION = ".zkpdfreq"
    const val RESPONSE_EXTENSION = ".zkpdf"
    const val MEDIA_TYPE = "application/json"
    /** Upper bound of an encoded request or response; private windows stay within the phone circuit limits. */
    const val MAX_BYTES = 48 * 1024 * 1024
    private const val MAX_ITEMS = 64

    class Request(val id: String, val statement: ZkPdfStatement, val witness: ZkPdfWitness)
    class Response(val requestId: String, val output: ZkPdfProofOutput)

    fun newId(): String = PlatformCrypto.randomBytes(16).toBase64Url()

    fun encodeRequest(request: Request): JsonObject = buildJsonObject {
        put("v", VERSION)
        put("type", REQUEST_TYPE)
        put("id", request.id)
        put("statement", statement(request.statement))
        putJsonObject("witness") {
            putJsonArray("private") { request.witness.privateData.forEach { add(it.toBase64Url()) } }
            putJsonArray("salts") { request.witness.salts.forEach { add(it.toBase64Url()) } }
        }
    }

    fun encodeResponse(response: Response): JsonObject = buildJsonObject {
        put("v", VERSION)
        put("type", RESPONSE_TYPE)
        put("request", response.requestId)
        val o = response.output
        putJsonArray("segments") {
            o.segments.forEach { s ->
                addJsonObject {
                    put("kind", s.kind); put("index", s.index)
                    put("proof", s.proof.toBase64Url()); put("publicInputs", s.publicInputs.toBase64Url())
                }
            }
        }
        putJsonArray("midOuts") { o.midOuts.forEach { add(it.toBase64Url()) } }
        putJsonArray("claimRecords") { o.claimRecords.forEach { add(it.toBase64Url()) } }
        putJsonArray("claimDigests") { o.claimDigests.forEach { add(it.toBase64Url()) } }
        put("proveMs", o.proveMs)
    }

    /** Parses a request; throws IllegalArgumentException on anything missing or malformed. */
    fun parseRequest(o: JsonObject): Request {
        if (o.int("v") != VERSION || o.text("type") != REQUEST_TYPE) bad("version")
        val witness = o.obj("witness")
        return Request(
            id = o.text("id").takeIf { ID.matches(it) } ?: bad("id"),
            statement = parseStatement(o.obj("statement")),
            witness = ZkPdfWitness(witness.bytesList("private"), witness.bytesList("salts").onEach { if (it.size != 16) bad("salt") }),
        )
    }

    fun parseResponse(o: JsonObject): Response {
        if (o.int("v") != VERSION || o.text("type") != RESPONSE_TYPE) bad("version")
        val segments = o.list("segments").map {
            ZkPdfSegment(it.text("kind"), it.int("index").takeIf { i -> i >= 0 } ?: bad("index"), it.bytes("proof"), it.bytes("publicInputs"))
        }
        if (segments.isEmpty()) bad("segments")
        return Response(
            requestId = o.text("request").takeIf { ID.matches(it) } ?: bad("request"),
            output = ZkPdfProofOutput(
                segments,
                o.bytesList("midOuts").onEach { if (it.size != 32) bad("midOuts") },
                o.bytesList("claimRecords"),
                o.bytesList("claimDigests").onEach { if (it.size != 32) bad("claimDigests") },
                (o["proveMs"] as? JsonPrimitive)?.longOrNull ?: 0L,
            ),
        )
    }

    fun parse(bytes: ByteArray): JsonObject {
        if (bytes.size > MAX_BYTES) bad("size")
        return runCatching { Json.parseToJsonElement(bytes.decodeToString()) as JsonObject }.getOrElse { bad("json") }
    }

    private fun statement(s: ZkPdfStatement): JsonObject = buildJsonObject {
        put("composition", s.composition)
        put("binding", s.binding.toBase64Url())
        putJsonArray("windows") {
            s.windows.forEach { w ->
                addJsonObject {
                    put("role", w.role); put("midIn", w.midIn.toBase64Url()); put("blocks", w.blocks)
                    put("head", w.head.toBase64Url()); put("tail", w.tail.toBase64Url())
                    w.keyStream?.let { put("keyStream", it.toBase64Url()) }
                }
            }
        }
        putJsonArray("anchors") {
            s.anchors.forEach { a -> addJsonObject { put("record", a.record.encoded().toBase64Url()); put("ordinal", a.ordinal); put("total", a.total) } }
        }
        putJsonArray("slots") {
            s.slots.forEach { slot -> addJsonObject { put("slot", slot.slot); put("before", slot.beforeAnchor); put("after", slot.afterAnchor) } }
        }
        putJsonArray("digitTables") {
            s.digitTables.forEach { t ->
                addJsonObject { put("font", t.font.toBase64Url()); put("width", t.width); putJsonArray("codes") { t.codes.forEach { add(it) } } }
            }
        }
        putJsonArray("predicates") {
            s.predicates.forEach { p ->
                addJsonObject { put("kind", p.kind); put("slot", p.slot); put("format", p.format); put("cutoff", p.cutoff) }
            }
        }
    }

    private fun parseStatement(o: JsonObject): ZkPdfStatement = runCatching {
        ZkPdfStatement(
            composition = o.text("composition"),
            binding = o.bytes("binding"),
            windows = o.list("windows").map {
                ZkPdfStatement.Window(it.text("role"), it.bytes("midIn"), it.int("blocks"), it.bytes("head"), it.bytes("tail"),
                    if (it.containsKey("keyStream")) it.bytes("keyStream") else null)
            },
            anchors = o.list("anchors").map {
                val record = runCatching { ZkPdfTextRecord.parseAll(it.bytes("record")).single() }.getOrElse { bad("record") }
                ZkPdfStatement.Anchor(record, it.int("ordinal"), it.int("total"))
            },
            slots = o.list("slots").map { ZkPdfStatement.Slot(it.int("slot"), it.int("before"), it.int("after")) },
            digitTables = o.list("digitTables").map {
                val codes = (it["codes"] as? JsonArray ?: bad("codes")).map { c -> (c as? JsonPrimitive)?.intOrNull ?: bad("codes") }
                ZkPdfStatement.DigitTable(it.bytes("font"), it.int("width"), codes.toIntArray())
            },
            predicates = o.list("predicates").map { ZkPdfStatement.Predicate(it.int("kind"), it.int("slot"), it.int("format"), it.int("cutoff")) },
        )
    }.getOrElse { e -> if (e is IllegalArgumentException && e.message?.startsWith(PREFIX) == true) throw e else bad("statement") }

    private val ID = Regex("[A-Za-z0-9_-]{16,64}")
    private const val PREFIX = "Invalid zkPDF proof request"

    private fun bad(what: String): Nothing = throw IllegalArgumentException("$PREFIX: $what")
    private fun JsonObject.text(key: String) = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: bad(key)
    private fun JsonObject.int(key: String) = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull ?: bad(key)
    private fun JsonObject.obj(key: String) = this[key] as? JsonObject ?: bad(key)
    private fun JsonObject.bytes(key: String) = runCatching { text(key).fromBase64Url() }.getOrElse { bad(key) }
    private fun JsonObject.list(key: String) = (this[key] as? JsonArray ?: bad(key)).also { if (it.size > MAX_ITEMS) bad(key) }
        .map { it as? JsonObject ?: bad(key) }
    private fun JsonObject.bytesList(key: String) = (this[key] as? JsonArray ?: bad(key)).also { if (it.size > MAX_ITEMS) bad(key) }.map {
        (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content?.let { s -> runCatching { s.fromBase64Url() }.getOrNull() } ?: bad(key)
    }
}

/** A self-hosted prover the holder added in settings: its HTTPS (or private-network) address and access token. */
class ZkProverHost(val name: String, val url: String, val token: String) {
    companion object {
        /** The shortest access token the prover accepts (tools/zk-prover-server). */
        const val MIN_TOKEN = 24

        /**
         * Null when [url] is acceptable; otherwise why not. Plain HTTP is only allowed to private-network addresses, and
         * only where this build's HTTP stack permits clear text to that host ([cleartextPermitted]; Android release
         * builds refuse it, see network_security_config.xml), so a setting that cannot connect is never accepted.
         */
        fun problem(url: String, cleartextPermitted: (String) -> Boolean = { true }): String? {
            val parsed = runCatching { Url(url) }.getOrNull() ?: return "網址格式不正確"
            if (parsed.host.isBlank() || parsed.user != null || parsed.password != null || parsed.fragment.isNotEmpty()) return "網址格式不正確"
            return when (parsed.protocol) {
                URLProtocol.HTTPS -> null
                URLProtocol.HTTP -> when {
                    !privateHost(parsed.host) -> "公開網路上的主機必須使用 https"
                    !cleartextPermitted(parsed.host) -> "這個版本只能以 https 連線自架主機，請在主機前加上 TLS 反向代理後使用 https 網址"
                    else -> null
                }
                else -> "只支援 https 網址"
            }
        }

        private fun privateHost(host: String): Boolean {
            if (host == "localhost" || host.endsWith(".local")) return true
            val parts = host.split('.').mapNotNull { it.toIntOrNull() }
            if (parts.size != 4 || host.count { it == '.' } != 3 || parts.any { it !in 0..255 }) return false
            return parts[0] == 10 || parts[0] == 127 || (parts[0] == 172 && parts[1] in 16..31) || (parts[0] == 192 && parts[1] == 168)
        }
    }
}

/**
 * Proves on a self-hosted prover (tools/zk-prover-server) and checks the result here: [local] verifies every segment
 * against the statement this device built, and the attested outputs must equal the returned ones. Checks and
 * verification stay local, so only the local verification keys are needed.
 */
class RemoteZkPdfEngine(
    private val prover: ZkProverHost,
    private val local: ZkPdfEngine,
    private val http: HttpClient,
    private val pollMillis: Long = 2000,
) : ZkPdfEngine {
    override fun ready(composition: String, prover: Boolean): Boolean = local.ready(composition, false)

    override suspend fun check(statement: ZkPdfStatement, witness: ZkPdfWitness): ZkResult<ZkPdfCost> = local.check(statement, witness)

    override suspend fun verify(statement: ZkPdfStatement, segments: List<ZkPdfSegment>): ZkResult<ZkPdfVerifiedOutput?> =
        local.verify(statement, segments)

    override suspend fun prove(
        statement: ZkPdfStatement,
        witness: ZkPdfWitness,
        progress: (String, Int, Int) -> Unit,
    ): ZkResult<ZkPdfProofOutput> {
        val request = ZkPdfRemote.Request(ZkPdfRemote.newId(), statement, witness)
        val base = prover.url.trimEnd('/') + "/v1/zkpdf/jobs"
        val job = try {
            val response = http.post(base) {
                bearerAuth(prover.token)
                contentType(ContentType.Application.Json)
                setBody(ZkPdfRemote.encodeRequest(request).toString())
            }
            if (response.status == HttpStatusCode.Unauthorized) return ZkResult.Failed("自架主機拒絕存取，請檢查存取權杖", false)
            if (response.status == HttpStatusCode.TooManyRequests) return ZkResult.Failed("自架主機正在處理其他證明，請稍後重試", true)
            if (!response.status.isSuccess()) return ZkResult.Failed("自架主機無法接受這個證明（HTTP ${response.status.value}）", true)
            json(response)?.let { (it["id"] as? JsonPrimitive)?.content } ?: return INVALID
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return UNREACHABLE
        }
        val output = try {
            poll("$base/$job", progress)
        } catch (e: CancellationException) {
            withContext(NonCancellable) { runCatching { http.delete("$base/$job") { bearerAuth(prover.token) } } }
            throw e
        }
        val body = when (output) {
            is ZkResult.Ok -> output.value
            is ZkResult.Failed -> return output
            ZkResult.Cancelled -> return ZkResult.Cancelled
        }
        val response = runCatching { ZkPdfRemote.parseResponse(body) }.getOrNull() ?: return INVALID
        if (response.requestId != request.id) return INVALID
        return accept(statement, response.output, local)
    }

    /** The compositions the prover has complete assets for (GET /v1/health), or why it cannot be reached. */
    suspend fun compositions(): ZkResult<List<String>> {
        val o = try {
            val response = http.get(prover.url.trimEnd('/') + "/v1/health") { bearerAuth(prover.token) }
            if (response.status == HttpStatusCode.Unauthorized) return ZkResult.Failed("自架主機拒絕存取，請檢查存取權杖", false)
            if (!response.status.isSuccess()) return ZkResult.Failed("自架主機回應 HTTP ${response.status.value}", true)
            json(response) ?: return INVALID
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return UNREACHABLE
        }
        val list = (o["compositions"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            ?: return INVALID
        return ZkResult.Ok(list.filter { it in ZkPdfStatement.COMPOSITIONS })
    }

    private suspend fun poll(url: String, progress: (String, Int, Int) -> Unit): ZkResult<JsonObject> {
        var failures = 0
        while (true) {
            val o = try {
                val response = http.get(url) { bearerAuth(prover.token) }
                if (response.status == HttpStatusCode.NotFound) return ZkResult.Failed("自架主機已不再保留這個證明工作", true)
                if (!response.status.isSuccess()) null else json(response)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                null
            }
            if (o == null) {
                // Brief network drops are tolerated; the job keeps running on the host.
                if (++failures > 15) return UNREACHABLE
                delay(pollMillis)
                continue
            }
            failures = 0
            when ((o["state"] as? JsonPrimitive)?.content) {
                "done" -> return ZkResult.Ok(o["result"] as? JsonObject ?: return INVALID)
                "failed" -> return ZkResult.Failed("自架主機產生證明失敗：" +
                    ((o["reason"] as? JsonPrimitive)?.content?.take(80) ?: "原因不明"), (o["retryable"] as? JsonPrimitive)?.booleanOrNull ?: false)
                "cancelled" -> return ZkResult.Cancelled
                "running", "queued" -> {
                    val kind = (o["kind"] as? JsonPrimitive)?.content
                    val done = (o["done"] as? JsonPrimitive)?.intOrNull
                    val total = (o["total"] as? JsonPrimitive)?.intOrNull
                    if (kind != null && done != null && total != null) progress(kind, done, total)
                }
                else -> return INVALID
            }
            delay(pollMillis)
        }
    }

    private suspend fun json(response: HttpResponse): JsonObject? = runCatching {
        Json.parseToJsonElement(response.bodyAsText()) as JsonObject
    }.getOrNull()

    companion object {
        private val UNREACHABLE = ZkResult.Failed("無法連線到自架主機", true)
        private val INVALID = ZkResult.Failed("自架主機的回應格式不正確", false)
        private val REJECTED = ZkResult.Failed("證明未通過這台裝置的驗證，未寫入憑證", false)

        /**
         * Accepts a proof made elsewhere only when [local] verifies every segment against [statement] (built on this
         * device, with this device's credential key) and the attested window and field outputs equal the returned ones.
         */
        suspend fun accept(statement: ZkPdfStatement, output: ZkPdfProofOutput, local: ZkPdfEngine): ZkResult<ZkPdfProofOutput> {
            val verified = when (val r = local.verify(statement, output.segments)) {
                is ZkResult.Ok -> r.value ?: return REJECTED
                is ZkResult.Failed -> return r
                ZkResult.Cancelled -> return ZkResult.Cancelled
            }
            val same = verified.midOuts.size == output.midOuts.size &&
                verified.midOuts.indices.all { verified.midOuts[it].contentEquals(output.midOuts[it]) } &&
                verified.claimDigests.size == output.claimDigests.size &&
                verified.claimDigests.indices.all { verified.claimDigests[it].contentEquals(output.claimDigests[it]) } &&
                output.claimRecords.size == output.claimDigests.size
            return if (same) ZkResult.Ok(output) else REJECTED
        }
    }
}
