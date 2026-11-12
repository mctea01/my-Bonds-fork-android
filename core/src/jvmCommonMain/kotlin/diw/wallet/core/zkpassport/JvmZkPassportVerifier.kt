package diw.wallet.core.zkpassport

import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.zkpassportCertificates
import diw.wallet.core.zk.native.bindings.zkpassportCircuitRoot
import diw.wallet.core.zk.native.bindings.zkpassportInspect
import diw.wallet.core.zk.native.bindings.zkpassportVerify
import diw.wallet.core.zk.native.bindings.zkpassportVerifyLegacy
import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.close
import io.ktor.websocket.readText
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.io.File
import java.time.LocalDate
import java.time.ZoneId

/**
 * zkPassport requests over the bridge, verified by the native checker (native/zkpassport-verify) with keys from the
 * circuit registry. [crsDirectory] is the zkPDF asset folder when its full CRS is installed, so zkPDF proving keeps
 * working after a verification in the same process; [nativeReady] reports whether the library has the zkPDF backend
 * and [legacyReady] whether Barretenberg 5 is open for circuit versions before 0.22.0 (ZkEnvironment.zkPassportLegacy).
 */
class JvmZkPassportVerifier(
    http: HttpClient,
    cache: File,
    private val crsDirectory: () -> File?,
    private val nativeReady: suspend () -> Boolean,
    /** zkPassport's bridge; tests point it at a local relay. */
    private val bridgeUrl: String = ZkPassportBridgeProtocol.URL,
    private val legacyReady: suspend () -> Boolean = { false },
) : ZkPassportVerifier {
    private val client = http.config { followRedirects = true; install(WebSockets) }
    private val registry = ZkPassportRegistry(client, cache)

    override fun open(request: ZkPassportRequest, config: ZkPassportConfig, scope: CoroutineScope): ZkPassportSession {
        val session = Session(request, config)
        session.job = scope.launch(Dispatchers.IO) { session.run() }
        return session
    }

    private inner class Session(private val request: ZkPassportRequest, private val config: ZkPassportConfig) : ZkPassportSession {
        override val state = MutableStateFlow<ZkPassportState>(ZkPassportState.Connecting)
        var job: Job? = null
        private val protocol = ZkPassportBridgeProtocol()
        private val domain = ZkPassport.normalizeDomain(request.domain)
        private val url = ZkPassport.url(request, protocol.bridgeId, System.currentTimeMillis() / 1000)
        private val proofs = ArrayList<JsonObject>()
        private var total = -1
        private var failedProofs = 0
        private var queryResult: JsonElement? = null
        private var finished = false

        override fun close() {
            finished = true
            job?.cancel()
        }

        private fun finish(s: ZkPassportState) {
            finished = true
            state.value = s
        }

        suspend fun run() {
            var attempts = 0
            while (!finished && attempts <= MAX_RECONNECTS) {
                val ws = try {
                    withTimeout(CONNECT_MS) {
                        client.webSocketSession("$bridgeUrl?id=${protocol.bridgeId}&v=1") {
                            // The holder's app pins the bridge origin to the request's domain.
                            header(HttpHeaders.Origin, "https://$domain")
                        }
                    }
                } catch (_: kotlinx.coroutines.TimeoutCancellationException) {
                    null
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (_: Exception) {
                    null
                }
                if (ws == null) {
                    attempts++
                    delay(1000L shl minOf(attempts, 4))
                    continue
                }
                if (state.value == ZkPassportState.Connecting) state.value = ZkPassportState.Waiting(url)
                if (attempts > 0) protocol.replay()?.let { ws.send(Frame.Text(it)) }
                attempts = 0
                serve(ws)
                if (!finished) attempts++
            }
            if (!finished) finish(ZkPassportState.Failed("connection"))
        }

        private suspend fun serve(ws: WebSocketSession) {
            val pinger = CoroutineScope(Dispatchers.IO).launch {
                while (isActive) {
                    delay(PING_MS)
                    runCatching { ws.send(Frame.Text(protocol.ping())) }
                }
            }
            try {
                for (frame in ws.incoming) {
                    if (frame !is Frame.Text) continue
                    val (replies, events) = protocol.receive(frame.readText(), System.currentTimeMillis())
                    replies.forEach { ws.send(Frame.Text(it)) }
                    for (event in events) handle(event)
                    if (finished) break
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                // Reconnects below.
            } finally {
                pinger.cancel()
                runCatching { ws.close() }
            }
        }

        private suspend fun handle(event: ZkPassportBridgeProtocol.Event) {
            when (event) {
                ZkPassportBridgeProtocol.Event.Handshake -> state.value = ZkPassportState.Scanned(url)
                is ZkPassportBridgeProtocol.Event.Message -> when (event.method) {
                    "accept" -> state.value = ZkPassportState.Generating
                    "reject" -> finish(ZkPassportState.Rejected)
                    "proof" -> (event.params as? JsonObject)?.let { proof ->
                        if (proofs.size < MAX_PROOFS) proofs.add(proof)
                        total = (proof["total"] as? JsonPrimitive)?.intOrNull ?: total
                        state.value = ZkPassportState.Receiving(proofs.size, maxOf(total, proofs.size))
                        complete()
                    }
                    "done" -> {
                        queryResult = event.params
                        complete()
                    }
                    "error" -> {
                        val error = (event.params as? JsonObject)?.get("error")?.let { it as? JsonPrimitive }?.contentOrNull.orEmpty()
                        when {
                            error == "This ID is not supported yet" -> finish(ZkPassportState.Failed("unsupported_document"))
                            error.startsWith("Cannot generate proof") -> {
                                failedProofs++
                                complete()
                            }
                            else -> finish(ZkPassportState.Failed("holder_error", error.take(200)))
                        }
                    }
                }
            }
        }

        private suspend fun complete() {
            if (queryResult == null || total <= 0 || proofs.size + failedProofs < total) return
            if (failedProofs > 0) return finish(ZkPassportState.Failed("proof_failed"))
            state.value = ZkPassportState.Verifying
            finish(ZkPassportState.Done(verify(request, config, proofs.toList(), queryResult ?: JsonNull)))
        }
    }

    /** Checks [proofs] against [request]; never throws. */
    suspend fun verify(request: ZkPassportRequest, config: ZkPassportConfig, proofs: List<JsonObject>, queryResult: JsonElement): ZkPassportResult =
        withContext(Dispatchers.IO) {
            val dev = request.devMode
            if (!nativeReady()) return@withContext ZkPassport.failure("native_unavailable", dev)
            val chain = ZkPassport.chain(dev)
            val bundle = JsonArray(proofs).toString()
            try {
                val info = Json.parseToJsonElement(zkpassportInspect(bundle)).jsonObject
                val version = info["version"]!!.jsonPrimitive.content
                val timestamp = info["timestamp"]!!.jsonPrimitive.longOrNull!!
                val certificateRoot = info["certificateRoot"]!!.jsonPrimitive.content
                val names = info["names"]!!.jsonArray.map { it.jsonPrimitive.content }
                val manifest = registry.manifest(chain, version)
                val circuitRoot = try {
                    zkpassportCircuitRoot(manifest.toString())
                } catch (e: ZkException) {
                    registry.forget(chain, version)
                    return@withContext ZkPassport.failure("manifest_root", dev)
                }
                val rpc = if (chain == ZkPassport.MAINNET) config.mainnetRpc else config.sepoliaRpc
                val certificateValid = registry.rootValid(chain, rpc, ZkPassportRegistry.CERTIFICATE_REGISTRY, certificateRoot, timestamp)
                val circuitValid = registry.rootValid(chain, rpc, ZkPassportRegistry.CIRCUIT_REGISTRY, circuitRoot, timestamp)
                val circuits = manifest["circuits"]?.jsonObject ?: JsonObject(emptyMap())
                val hashes = names.associateWith { name ->
                    circuits[name]?.jsonObject?.get("hash")?.jsonPrimitive?.content ?: return@withContext ZkPassport.failure("vkey:$name", dev)
                }
                val vkeys = hashes.mapValues { (_, hash) -> registry.vkey(chain, hash) }
                val requestJson = buildJsonObject {
                    put("proofs", JsonArray(proofs))
                    put("query", ZkPassport.query(request))
                    put("domain", ZkPassport.normalizeDomain(request.domain))
                    request.scope?.takeIf { it.isNotEmpty() }?.let { put("scope", it) }
                    put("devMode", dev)
                    put("validity", request.validitySeconds)
                    put("today", LocalDate.now().atStartOfDay(ZoneId.systemDefault()).toEpochSecond())
                    put("manifest", manifest)
                    putJsonObject("vkeys") { vkeys.forEach { (k, v) -> put(k, v) } }
                    put("certificateRoot", certificateRoot)
                    put("certificateRootValid", certificateValid)
                    put("circuitRoot", circuitRoot)
                    put("circuitRootValid", circuitValid)
                    config.oprfKeyHash?.let { put("oprfPublicKeyHash", it) }
                }.toString()
                // Circuits before 0.22.0 were keyed by Barretenberg 5, which an optional component brings.
                val legacy = ZkPassport.legacyBackend(version) && legacyReady()
                val result = ZkPassport.result(
                    if (legacy) zkpassportVerifyLegacy(requestJson) else zkpassportVerify(requestJson, crsDirectory()?.absolutePath),
                )
                if (result.errors.none { it.startsWith("vkey:") || it.startsWith("circuit_root") || it == "manifest_root" }) {
                    registry.remember(chain, version, manifest, vkeys, hashes)
                }
                // Only a Barretenberg rejection is worth a second opinion; every other failure is final.
                val decided = (
                    if (!result.verified && config.verifierApiAllowed() && result.errors.isNotEmpty() && result.errors.all { it.startsWith("proof:") }) {
                        // Its answer is kept with the errors, so a refusal or an outage is visible, not silent.
                        when (val answer = verifierApi(request, proofs, queryResult)) {
                            "verified" -> result.copy(verified = true, errors = emptyList(), viaVerifierApi = true)
                            else -> result.copy(errors = result.errors + "verifier_api:$answer")
                        }
                    } else result
                ).let {
                    // Without Barretenberg 5 such proofs cannot verify here at all; say so rather than calling them invalid.
                    if (!it.verified && !legacy && ZkPassport.legacyBackend(version) && it.errors.isNotEmpty() && it.errors.all { e -> e.startsWith("proof:") }) {
                        it.copy(errors = listOf("backend_legacy:$version") + it.errors)
                    } else it
                }
                if (decided.verified && !dev) decided.copy(csca = csca(chain, certificateRoot, decided, config.cscaAnchors)) else decided
            } catch (e: ZkPassportRegistry.Unreachable) {
                ZkPassport.failure(e.code, dev)
            } catch (e: ZkException) {
                ZkPassport.failure("bundle", dev)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                ZkPassport.failure("bundle", dev)
            }
        }

    /**
     * The registry's CSCA keys of the issuing country against [anchors]: the disclosed issuing country, else the
     * countries the proofs limit it to; null when the proofs say nothing about it.
     */
    private suspend fun csca(chain: Long, root: String, result: ZkPassportResult, anchors: List<ByteArray>): ZkPassportCscaCheck? {
        val countries = result.disclosed?.issuingCountry?.takeIf { it.length == 3 }?.let(::listOf) ?: result.issuingCountryIn
        if (countries.isEmpty()) return null
        // The proof's own package; when it cannot be fetched, a package of another root already checked against the
        // registry still lists the country's CSCAs, which is all this comparison needs.
        val summary = try {
            registry.certificates(chain, root) { zkpassportCertificates(it) }
        } catch (e: ZkPassportRegistry.Unreachable) {
            registry.cachedCertificates(chain) ?: return ZkPassportCscaCheck(countries, 0, 0, e.code)
        }
        val entries = summary["certificates"]?.jsonArray.orEmpty().mapNotNull { it as? JsonObject }
            .filter { (it["country"] as? JsonPrimitive)?.contentOrNull in countries }
        // Expired CSCAs are left out on both sides: the anchors are the ones valid now.
        val now = System.currentTimeMillis() / 1000
        val (valid, expired) = entries.partition { e -> (e["notAfter"] as? JsonPrimitive)?.contentOrNull?.toLongOrNull()?.let { it >= now } ?: true }
        val keys = valid.mapNotNull { (it["publicKey"] as? JsonPrimitive)?.contentOrNull }
        val anchorKeys = anchors.mapNotNull { ZkPassportCsca.publicKey(it) }
        return ZkPassportCscaCheck(countries, keys.size, keys.count { k -> anchorKeys.any { ZkPassportCsca.same(it, k) } }, expired = expired.size)
    }

    /** zkPassport's verifier service: verified, rejected, or unavailable with the HTTP status (0 without an answer). */
    private suspend fun verifierApi(request: ZkPassportRequest, proofs: List<JsonObject>, queryResult: JsonElement): String = runCatching {
        val body = buildJsonObject {
            put("proofs", JsonArray(proofs))
            put("originalQuery", ZkPassport.query(request))
            put("queryResult", queryResult)
            putJsonObject("serviceConfig") {
                put("domain", ZkPassport.normalizeDomain(request.domain))
                request.scope?.takeIf { it.isNotEmpty() }?.let { put("scope", it) }
                put("validityPeriodInSeconds", request.validitySeconds)
                put("devMode", request.devMode)
            }
        }
        val response = withTimeout(60_000) {
            client.post(ZkPassportRegistry.VERIFIER_API) { contentType(ContentType.Application.Json); setBody(body.toString()) }
        }
        val verified = runCatching { (Json.parseToJsonElement(response.bodyAsText()).jsonObject["verified"] as? JsonPrimitive)?.booleanOrNull }.getOrNull()
        when {
            response.status.value in 200..299 && verified == true -> "verified"
            response.status.value in 200..499 && verified == false -> "rejected"
            else -> "unavailable:${response.status.value}"
        }
    }.getOrElse { if (it is kotlinx.coroutines.CancellationException) throw it else "unavailable:0" }

    companion object {
        private const val CONNECT_MS = 20_000L
        private const val PING_MS = 30_000L
        private const val MAX_RECONNECTS = 5
        private const val MAX_PROOFS = 32
    }
}
