package diw.wallet.core.zkpassport

import diw.wallet.core.zkpassport.ZkPassportBridgeProtocol.Companion.hex
import diw.wallet.core.zkpassport.ZkPassportBridgeProtocol.Companion.text
import diw.wallet.core.zkpassport.ZkPassportBridgeProtocol.Companion.unhex
import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.close
import io.ktor.websocket.readText
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.security.SecureRandom
import java.util.Base64

/**
 * The holder (joiner) side of zkPassport's bridge. The first connection carries the handshake in `moc` and asks
 * with `ooc` for the creator connection's origin, which the bridge reports itself. As in @obsidion/bridge's joiner,
 * the origin the bridge stamps on the requester's encrypted `hello` (its answer to the handshake) counts too when
 * no `ooc` came first; once known, frames the bridge marks with another origin are dropped. Pure frame logic,
 * tested without a network.
 */
class ZkPassportHolderBridge(verifierPublicKey: String, private val random: SecureRandom = SecureRandom()) {
    sealed interface Event {
        /** The origin the bridge reports for the requester's connection. */
        data class Origin(val origin: String) : Event
        data class Message(val method: String, val params: JsonElement) : Event
    }

    val bridgeId: String = verifierPublicKey.lowercase().removePrefix("0x")
    private val channel: ZkPassportBridgeChannel
    val publicKey: ByteArray
    private val seen = LinkedHashSet<String>()

    /** The requester's origin as the bridge reported it; null until the `ooc` message arrives. */
    var origin: String? = null
        private set

    init {
        val remote = unhex(bridgeId)?.takeIf { it.size == 33 } ?: throw IllegalArgumentException("verifier key")
        val (d, pub) = ZkPassportBridgeChannel.keyPair(random)
        publicKey = pub
        channel = ZkPassportBridgeChannel(ZkPassportBridgeChannel.sharedKey(remote, d) ?: throw IllegalArgumentException("verifier key"), bridgeId, random)
    }

    /** The first connection's address: the handshake in `moc` (base64 JSON, percent-encoded) and `ooc`. */
    fun connectUrl(base: String): String = "$base?id=$bridgeId&v=1&moc=${encode(Base64.getEncoder().encodeToString(handshake().encodeToByteArray()))}&ooc"

    /** A later connection: the channel already exists, so only the origin is asked for again. */
    fun reconnectUrl(base: String): String = "$base?id=$bridgeId&v=1&ooc"

    fun handshake(): String = buildJsonObject {
        put("jsonrpc", "2.0")
        put("id", id())
        put("method", "handshake")
        putJsonObject("params") {
            put("pubkey", hex(publicKey))
            put("greeting", hex(channel.seal("hello".encodeToByteArray())))
        }
    }.toString()

    /** Handles one text frame; returns the frames to send back and the events for the session. */
    fun receive(text: String): Pair<List<String>, List<Event>> {
        val data = runCatching { Json.parseToJsonElement(text).jsonObject }.getOrNull() ?: return none
        val method = data["method"].text()
        if (method == "ping") return listOf(PONG) to emptyList()
        if (method == "ooc") {
            val reported = ((data["params"] as? JsonObject)?.get("origin")).text()?.let(::originOf) ?: return none
            if (origin != null) return none
            origin = reported
            return emptyList<String>() to listOf(Event.Origin(reported))
        }
        val id = data["id"].text() ?: return none
        if (method != "encryptedMessage" || !seen.add(id)) return none
        if (seen.size > 4096) seen.remove(seen.first())
        val pinned = origin
        val stamped = data["origin"].text()?.let(::originOf)
        if (pinned != null && stamped != pinned) return none
        val payload = ((data["params"] as? JsonObject)?.get("payload")).text() ?: return none
        val message = channel.message(payload) ?: return none
        // Only the requester holds the channel key, so a frame that decrypts is its own; the bridge stamped the origin.
        if (pinned == null && stamped != null) {
            origin = stamped
            return emptyList<String>() to listOf(Event.Origin(stamped), Event.Message(message.method, message.params))
        }
        return emptyList<String>() to listOf(Event.Message(message.method, message.params))
    }

    /** Frames carrying [method] to the requester. */
    fun frames(method: String, params: JsonElement?): List<String> = channel.frames(method, params) { seen.add(it) }

    private fun id() = hex(ByteArray(16).also { random.nextBytes(it) })

    companion object {
        private val none = emptyList<String>() to emptyList<Event>()
        private const val PONG = """{"method":"pong","params":{},"nocache":true}"""

        /** As @obsidion/bridge's parseOriginHeader: scheme and host, without port or path. */
        fun originOf(header: String): String? = runCatching {
            val u = java.net.URI(header.trim())
            if (u.scheme.isNullOrEmpty() || u.host.isNullOrEmpty()) null else "${u.scheme.lowercase()}://${u.host.lowercase()}"
        }.getOrNull()

        private fun encode(s: String): String = s.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    }
}

/**
 * Answers one zkPassport request over the bridge (Z3): [connect] opens the channel and learns the requester's
 * origin, [accept] or [reject] tell the requester the holder's choice, [send] delivers the prover's messages. The
 * connection is opened again when it drops while the proofs are made; the bridge keeps what was sent meanwhile.
 */
class ZkPassportResponder(
    http: HttpClient,
    private val incoming: ZkPassportIncoming,
    private val bridgeUrl: String = ZkPassportBridgeProtocol.URL,
    /** How long each connection waits for the origin before it is opened again. */
    private val originWaitMs: Long = ORIGIN_MS,
) {
    class Failure(val code: String) : Exception(code)

    private val client = http.config { install(WebSockets) }
    private val bridge = ZkPassportHolderBridge(incoming.verifierPublicKey)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()
    private var ws: WebSocketSession? = null
    private var reader: Job? = null
    private var originKnown = CompletableDeferred<String>()
    private val received = ArrayList<String>()

    /** The requester's origin as the bridge reports it. */
    val origin: String? get() = bridge.origin

    /** Whether the bridge's origin is the https origin of the link's domain (5.3; a relay attack otherwise). */
    val originMatches: Boolean get() = bridge.origin == incoming.expectedOrigin

    /**
     * Connects and waits for the bridge's report of the requester's origin; returns it. The bridge reports it only
     * while the request page is connected, and a page in a phone's background may have lost its connection, so the
     * connection is opened again a few times before giving up.
     */
    suspend fun connect(): String {
        repeat(ORIGIN_ATTEMPTS) {
            lock.withLock { open(bridge.connectUrl(bridgeUrl)) }
            withTimeoutOrNull(originWaitMs) { originKnown.await() }?.let { return it }
        }
        // What the bridge sent meanwhile (methods only), so the failure tells a silent bridge from a refusal.
        val methods = synchronized(received) { received.toList() }
        throw Failure("bridge_origin:${ORIGIN_ATTEMPTS}x" + methods.joinToString(",", prefix = if (methods.isEmpty()) "" else ":"))
    }

    suspend fun accept() = send(listOf("accept" to null))

    suspend fun reject() = send(listOf("reject" to null))

    /** Sends [messages] in order (method and params; null params for a bare method), reconnecting once if needed. */
    suspend fun send(messages: List<Pair<String, JsonElement?>>) = lock.withLock {
        val frames = messages.flatMap { (method, params) -> bridge.frames(method, params) }
        var attempt = 0
        var index = 0
        while (index < frames.size) {
            val socket = ws ?: run {
                if (attempt++ >= MAX_RECONNECTS) throw Failure("connection")
                delay(1000L * attempt)
                open(bridge.reconnectUrl(bridgeUrl))
                ws!!
            }
            try {
                socket.send(Frame.Text(frames[index]))
                index++
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                ws = null
            }
        }
    }

    /** The proofs of [proved] and the query result, after `accept` was sent. */
    suspend fun send(proved: ZkPassportProver.Proved) =
        send(proved.messages.filter { it.first != "accept" }.map { it.first to it.second })

    fun close() {
        reader?.cancel()
        val socket = ws
        ws = null
        scope.launch { runCatching { socket?.close() } }.invokeOnCompletion { scope.cancel() }
    }

    private suspend fun open(url: String) {
        val socket = try {
            withTimeout(CONNECT_MS) { client.webSocketSession(url) }
        } catch (_: kotlinx.coroutines.TimeoutCancellationException) {
            throw Failure("connection")
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            throw Failure("connection")
        }
        val previous = ws
        ws = socket
        reader?.cancel()
        if (previous != null) scope.launch { runCatching { previous.close() } }
        reader = scope.launch {
            val pinger = launch {
                while (isActive) {
                    delay(PING_MS)
                    runCatching { socket.send(Frame.Text(PING)) }
                }
            }
            try {
                for (frame in socket.incoming) {
                    if (frame !is Frame.Text) continue
                    val text = frame.readText()
                    if (!originKnown.isCompleted) synchronized(received) {
                        if (received.size < MAX_RECORDED) received.add(methodOf(text))
                    }
                    val (replies, events) = bridge.receive(text)
                    replies.forEach { socket.send(Frame.Text(it)) }
                    events.forEach { if (it is ZkPassportHolderBridge.Event.Origin) originKnown.complete(it.origin) }
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                // The next send reconnects.
            } finally {
                pinger.cancel()
                if (ws === socket) ws = null
            }
        }
    }

    /** A frame's JSON-RPC method, limited to a short word: the bridge's frames are not shown otherwise. */
    private fun methodOf(text: String): String =
        runCatching { (Json.parseToJsonElement(text).jsonObject["method"] as? JsonPrimitive)?.contentOrNull }.getOrNull()
            ?.takeIf { METHOD.matches(it) } ?: "?"

    companion object {
        private val METHOD = Regex("^[A-Za-z_]{1,24}$")
        private const val MAX_RECORDED = 8
        private const val CONNECT_MS = 15_000L
        private const val ORIGIN_MS = 15_000L
        private const val ORIGIN_ATTEMPTS = 3
        private const val PING_MS = 25_000L
        private const val MAX_RECONNECTS = 3
        private const val PING = """{"method":"ping","params":{},"nocache":true}"""
    }
}

/** [ZkPassportHolder] over zkPassport's bridge and [ZkPassportProver]. */
class JvmZkPassportHolder(
    private val http: HttpClient,
    private val prover: ZkPassportProver,
    private val bridgeUrl: String = ZkPassportBridgeProtocol.URL,
) : ZkPassportHolder {
    override suspend fun connect(incoming: ZkPassportIncoming, rpc: String?): ZkPassportAnswer {
        val responder = ZkPassportResponder(http, incoming, bridgeUrl)
        val origin = try {
            responder.connect()
        } catch (e: ZkPassportResponder.Failure) {
            responder.close()
            throw ZkPassportAnswerFailure(e.code)
        }
        return Answer(responder, incoming, origin, rpc)
    }

    private inner class Answer(
        private val responder: ZkPassportResponder,
        private val incoming: ZkPassportIncoming,
        override val origin: String,
        private val rpc: String?,
    ) : ZkPassportAnswer {
        override val originMatches: Boolean get() = responder.originMatches

        override suspend fun reject() = bridged { responder.reject() }

        override suspend fun answer(chip: ZkPassportChip, progress: (ZkPassportAnswerProgress) -> Unit) {
            bridged { responder.accept() }
            val job = ZkPassportProver.Job(
                query = incoming.query, domain = incoming.domain, scope = incoming.scope, devMode = incoming.devMode, rpc = rpc,
            )
            val proved = try {
                prover.prove(ZkPassportProver.Chip(chip.sod, chip.dg1, chip.dg2), job) { p ->
                    progress(
                        when (p) {
                            ZkPassportProver.Progress.Registry -> ZkPassportAnswerProgress.Registry
                            is ZkPassportProver.Progress.Circuits -> ZkPassportAnswerProgress.Circuits(p.count)
                            is ZkPassportProver.Progress.Proving -> ZkPassportAnswerProgress.Proving(p.index, p.total, p.name)
                        },
                    )
                }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                // Registry downloads fail with their own code; anything else is named by its type for the details.
                val code = when (e) {
                    is ZkPassportProver.Failure -> e.code
                    is ZkPassportRegistry.Unreachable -> e.code
                    else -> "other:" + (e::class.simpleName ?: "error")
                }
                // The requester's app reads these texts; the one for documents without inputs is the SDK's own.
                val text = if (code == "inputs" || code.startsWith("inputs:")) "This ID is not supported yet" else "Proof generation failed: $code"
                runCatching { responder.send(listOf("error" to buildJsonObject { put("error", text) })) }
                throw ZkPassportAnswerFailure(code)
            }
            progress(ZkPassportAnswerProgress.Sending)
            bridged { responder.send(proved) }
        }

        override fun close() = responder.close()

        private suspend fun bridged(block: suspend () -> Unit) = try {
            block()
        } catch (e: ZkPassportResponder.Failure) {
            throw ZkPassportAnswerFailure(e.code)
        }
    }
}
