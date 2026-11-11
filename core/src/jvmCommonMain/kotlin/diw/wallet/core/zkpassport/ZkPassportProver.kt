package diw.wallet.core.zkpassport

import diw.wallet.core.zk.native.bindings.ZkCancelToken
import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.ZkPassportProofSession
import diw.wallet.core.zk.native.bindings.zkpassportCertificates
import diw.wallet.core.zk.native.bindings.zkpassportCircuitRoot
import diw.wallet.core.zk.native.bindings.oprfBlind
import diw.wallet.core.zk.native.bindings.oprfFinalize
import diw.wallet.core.zk.native.bindings.zkpassportProve
import io.ktor.client.HttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64

/**
 * zkPassport proofs made on this device from a passport's chip files. zkPassport's own input generation and session
 * driver (vendored under native/vendor/zkpassport) decide which circuits run and in what order; this class
 * only fetches, checks and proves. Every fetched file is checked before use: the certificate package must hash to
 * the registry's latest root, the manifest to a circuit root the registry lists, and each circuit's key, derived
 * here, to its manifest leaf, so no circuit outside the registry runs on the chip data.
 */
class ZkPassportProver(
    http: HttpClient,
    cache: File,
    private val crsDirectory: () -> File?,
    private val nativeReady: suspend () -> Boolean,
) {
    private val registry = ZkPassportRegistry(http.config { followRedirects = true }, cache)

    class Failure(val code: String) : Exception(code)

    /** The chip files a proof is made from: SOD and DG1 always, DG2 for the face photo hash. */
    class Chip(val sod: ByteArray, val dg1: ByteArray, val dg2: ByteArray?)

    /**
     * The project's OPRF service (docs/design/zkpassport.md 5.5). [publicKey] (`{x, y}`) is the key the answer must
     * prove it used; [evaluate] sends `{"blinded_query": {x, y}}` and returns the service's JSON answer.
     */
    interface Oprf {
        val publicKey: JsonObject
        suspend fun evaluate(blindedQuery: JsonObject): JsonObject
    }

    /**
     * What to prove. [query] is the SDK query object, [domain] and [scope] the service scope the proofs bind to.
     * With [oprf] the disclosure proofs carry the salted unique identifier: the private nullifier is blinded, the
     * service's answer checked against its key, and the output becomes the circuits' `nullifier_secret`.
     */
    data class Job(
        val query: JsonObject,
        val domain: String,
        val scope: String? = null,
        val devMode: Boolean = false,
        val circuitVersion: String = CIRCUIT_VERSION,
        val rpc: String? = null,
        val nowSeconds: Long = System.currentTimeMillis() / 1000,
        val oprf: Oprf? = null,
    )

    sealed interface Progress {
        data object Registry : Progress
        data class Circuits(val count: Int) : Progress
        data class Proving(val index: Int, val total: Int, val name: String) : Progress
    }

    /** One subproof as zkPassport's bridge carries it. */
    data class Proof(
        val name: String,
        val proof: String,
        val vkey: String,
        val vkeyHash: String,
        val version: String,
        val committedInputs: JsonElement?,
    )

    /**
     * The proofs in proving order, the bridge messages in sending order (method and params, each proof carrying its
     * key hash and version as the SDK expects) and the query result the driver computed.
     */
    data class Proved(val proofs: List<Proof>, val messages: List<Pair<String, JsonElement>>, val queryResult: JsonElement)

    suspend fun prove(chip: Chip, job: Job, cancel: ZkCancelToken = ZkCancelToken(), progress: (Progress) -> Unit = {}): Proved =
        withContext(Dispatchers.IO) {
            if (!nativeReady()) throw Failure("native_unavailable")
            val crs = crsDirectory()?.absolutePath ?: throw Failure("crs_missing")
            val chain = ZkPassport.chain(job.devMode)
            progress(Progress.Registry)
            val certificateRoot = registry.latestRoot(chain, job.rpc, ZkPassportRegistry.CERTIFICATE_REGISTRY)
            val session = try {
                ZkPassportProofSession(config(chip, job, chain, certificateRoot).toString())
            } catch (e: ZkException) {
                throw Failure("session")
            }
            session.use { run(it, job, chain, certificateRoot, crs, cancel, progress) }
        }

    private suspend fun run(
        session: ZkPassportProofSession,
        job: Job,
        chain: Long,
        certificateRoot: String,
        crs: String,
        cancel: ZkCancelToken,
        progress: (Progress) -> Unit,
    ): Proved = withContext(Dispatchers.IO) {
        var hashes: Map<String, String> = emptyMap()
        var version = job.circuitVersion
        val proofs = ArrayList<Proof>()
        val messages = ArrayList<Pair<String, JsonElement>>()
        var total = 0
        var salted: Pair<String, JsonObject>? = null
        repeat(MAX_COMMANDS) {
            ensureActive()
            val command = Json.parseToJsonElement(session.next()).jsonObject
            when (command.text("action")) {
                "fetch" -> {
                    val requests = command["requests"] as? kotlinx.serialization.json.JsonArray ?: throw Failure("driver")
                    if (requests.any { (it as? JsonObject)?.text("id")?.toIntOrNull() != null }) {
                        total = requests.size
                        progress(Progress.Circuits(total))
                    }
                    for (r in requests) {
                        val o = r as? JsonObject ?: throw Failure("driver")
                        val id = o.text("id") ?: throw Failure("driver")
                        val url = o.text("url") ?: throw Failure("driver")
                        val body = when (id) {
                            "certs" -> certificates(url, certificateRoot)
                            "manifest" -> {
                                val (text, circuits, v) = manifest(url, chain, job)
                                hashes = circuits
                                version = v
                                text
                            }
                            else -> registry.file(url, "circuit_unavailable")
                        }
                        provide(session, id, body)
                    }
                }
                "prove" -> {
                    val inputs = command["inputs"] as? JsonObject ?: throw Failure("driver")
                    val oprf = job.oprf
                    val proving = if (oprf != null && "oprf_proof" in inputs) {
                        val nullifier = ((inputs["salted_private_nullifier"] as? JsonObject)?.get("value") as? JsonPrimitive)?.contentOrNull
                            ?: throw Failure("oprf_query")
                        val result = salted?.takeIf { it.first == nullifier }?.second ?: salt(oprf, nullifier).also { salted = nullifier to it }
                        JsonObject(command + ("inputs" to JsonObject(inputs + mapOf(
                            "nullifier_secret" to (result["output"] ?: throw Failure("oprf")),
                            "oprf_proof" to (result["oprf_proof"] ?: throw Failure("oprf")),
                        ))))
                    } else command
                    val index = (command["id"] as? JsonPrimitive)?.intOrNull ?: throw Failure("driver")
                    val name = command.text("name") ?: throw Failure("driver")
                    val hash = hashes[name] ?: throw Failure("vkey:$name")
                    progress(Progress.Proving(index, total, name))
                    val out = try {
                        Json.parseToJsonElement(zkpassportProve(proving.toString(), hash, crs, cancel)).jsonObject
                    } catch (e: ZkException.Cancelled) {
                        throw kotlinx.coroutines.CancellationException("cancelled")
                    } catch (e: ZkException.InvalidInput) {
                        throw Failure(if (e.reason == "circuit_vkey_mismatch") "circuit_backend:$name" else "proof:$name")
                    } catch (e: ZkException) {
                        throw Failure("proof:$name")
                    }
                    val proof = out.text("proof") ?: throw Failure("proof:$name")
                    proofs.add(Proof(name, proof, out.text("vkey").orEmpty(), hash, version, null))
                    provide(session, index.toString(), proof)
                }
                "bridge_send" -> {
                    val frame = Json.parseToJsonElement(command.text("frame") ?: throw Failure("driver")).jsonObject
                    val method = frame.text("method") ?: throw Failure("driver")
                    val params = frame["params"] ?: JsonObject(emptyMap())
                    messages.add(method to if (method == "proof") enrich(params, hashes, version, proofs) else params)
                }
                "done" -> {
                    val queryResult = command["query_result"] ?: JsonObject(emptyMap())
                    val committed = messages.filter { it.first == "proof" }.associate { (_, p) ->
                        (p as JsonObject).text("name").orEmpty() to p["committedInputs"]
                    }
                    return@withContext Proved(proofs.map { it.copy(committedInputs = committed[it.name]) }, messages, queryResult)
                }
                "error" -> throw Failure("driver:" + command.text("message").orEmpty().take(120))
                else -> throw Failure("driver")
            }
        }
        throw Failure("driver")
    }

    /**
     * The OPRF round for private nullifier [query]: blinds it here, asks the service and checks the answer's proof
     * against the configured key, so a service using another key cannot salt the identifier unnoticed.
     */
    private suspend fun salt(oprf: Oprf, query: String): JsonObject {
        val blinded = try {
            Json.parseToJsonElement(oprfBlind(query)).jsonObject
        } catch (e: ZkException) {
            throw Failure("oprf_unavailable")
        }
        val answer = try {
            oprf.evaluate(blinded["blinded_query"] as? JsonObject ?: throw Failure("oprf"))
        } catch (e: Failure) {
            throw e
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            throw Failure("oprf_unreachable")
        }
        val request = buildJsonObject {
            put("query", query)
            put("beta", blinded["beta"] ?: throw Failure("oprf"))
            put("pk", oprf.publicKey)
            for (key in listOf("response_blinded", "dlog_e", "dlog_s")) put(key, answer[key] ?: throw Failure("oprf_answer"))
        }
        return try {
            Json.parseToJsonElement(oprfFinalize(request.toString())).jsonObject
        } catch (e: ZkException) {
            throw Failure("oprf_proof")
        }
    }

    /**
     * Feeds [data] back to the driver. Input generation runs once the certificates and the manifest are in, so a
     * failure there is the passport's: its reason is kept (as `inputs:` and printable text) for the details.
     */
    private fun provide(session: ZkPassportProofSession, id: String, data: String) {
        try {
            session.provide(id, data)
        } catch (e: ZkException) {
            if (id != "manifest" && id != "certs") throw Failure("driver")
            val reason = (e as? ZkException.InvalidInput)?.reason.orEmpty().filter { it in ' '..'~' }.take(160)
            throw Failure(if (reason.isEmpty()) "inputs" else "inputs:$reason")
        }
    }

    /** The certificate package for [root]; it must hash to that root. */
    private suspend fun certificates(url: String, root: String): String {
        val text = registry.file(url, "certificates_unavailable")
        val summary = runCatching { Json.parseToJsonElement(zkpassportCertificates(text)).jsonObject }.getOrNull()
        if (summary?.text("root")?.lowercase() != root) {
            registry.forgetFile(url)
            throw Failure("certificates_root")
        }
        return text
    }

    /** The manifest text, its circuit key hashes by name and its version, once its root is valid on the registry. */
    private suspend fun manifest(url: String, chain: Long, job: Job): Triple<String, Map<String, String>, String> {
        val text = registry.file(url, "manifest_unavailable")
        val root = try {
            zkpassportCircuitRoot(text)
        } catch (e: ZkException) {
            registry.forgetFile(url)
            throw Failure("manifest_root")
        }
        if (!registry.rootValid(chain, job.rpc, ZkPassportRegistry.CIRCUIT_REGISTRY, root, job.nowSeconds)) throw Failure("circuit_root")
        val manifest = Json.parseToJsonElement(text).jsonObject
        val circuits = (manifest["circuits"] as? JsonObject ?: throw Failure("manifest_root")).mapNotNull { (name, c) ->
            (c as? JsonObject)?.text("hash")?.let { name to it }
        }.toMap()
        return Triple(text, circuits, manifest.text("version") ?: job.circuitVersion)
    }

    /** A bridge `proof` message as the SDK reads it: the driver's fields plus the key hash and version. */
    private fun enrich(params: JsonElement, hashes: Map<String, String>, version: String, proofs: List<Proof>): JsonElement {
        val o = params as? JsonObject ?: throw Failure("driver")
        val name = o.text("name") ?: throw Failure("driver")
        if (proofs.none { it.name == name }) throw Failure("driver")
        return JsonObject(o + mapOf("vkeyHash" to JsonPrimitive(hashes[name] ?: throw Failure("vkey:$name")), "version" to JsonPrimitive(version)))
    }

    private fun config(chip: Chip, job: Job, chain: Long, certificateRoot: String): JsonObject {
        val b64 = Base64.getEncoder()
        return buildJsonObject {
            put("mode", "fast")
            put("chain_id", chain)
            put("circuit_version", job.circuitVersion)
            put("certificates_root", certificateRoot)
            put("sod", b64.encodeToString(chip.sod))
            put("dg1", b64.encodeToString(chip.dg1))
            chip.dg2?.let { put("dg2", b64.encodeToString(it)) }
            put("query", job.query)
            put("service_scope", ZkPassport.normalizeDomain(job.domain))
            put("service_subscope", job.scope.orEmpty())
            put("current_date_timestamp", job.nowSeconds)
            put("salt", salt())
        }
    }

    companion object {
        /** See [ZkPassport.CIRCUIT_VERSION]. */
        const val CIRCUIT_VERSION = ZkPassport.CIRCUIT_VERSION
        private const val MAX_COMMANDS = 256
        private val random = SecureRandom()

        /** A fresh master salt below the BN254 scalar field, in decimal. */
        fun salt(): String = BigInteger(1, ByteArray(31).also(random::nextBytes)).toString()

        private fun JsonObject.text(key: String) = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
    }
}
