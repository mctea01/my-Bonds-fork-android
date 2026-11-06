package diw.wallet.core.zktls

import diw.wallet.core.i18n.ct
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.zk.ZkErrors
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.bindings.ZkCancelToken
import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.ZkRange
import diw.wallet.core.zk.native.bindings.ZkTlsChannel
import diw.wallet.core.zk.native.bindings.ZkTlsRequest
import diw.wallet.core.zk.native.bindings.ZkTlsReveal
import diw.wallet.core.zk.native.bindings.ZkTlsRevealChooser
import diw.wallet.core.zk.native.bindings.ZkTlsTranscript
import diw.wallet.core.zk.native.bindings.zktlsProve
import diw.wallet.core.zk.native.bindings.zktlsVerify
import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.multipaz.util.toBase64Url
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import javax.net.SocketFactory
import kotlin.time.Clock

/**
 * [ZkTlsEngine] over the native TLSNotary library (the tlsn feature). The holder tries the request's transports in
 * order: local network addresses on its own subnet first, then the relay, then a verifier server. A verifier
 * listens on its private IPv4 addresses ([addresses]) and in a relay room at once; the first connection that sends
 * bytes that can open a Noise handshake is verified and the other listeners close.
 * [socketFactoryFor] gives sockets to a local address their network (Android, see SocketBondsLanLink).
 */
class NativeZkTlsEngine(
    http: HttpClient,
    private val addresses: () -> List<String>,
    private val preferred: (List<String>) -> List<String> = { it },
    private val socketFactoryFor: (String) -> SocketFactory? = { null },
    /** Loads the library and tells whether it has the tlsn feature. */
    private val ready: suspend () -> Boolean = { true },
) : ZkTlsEngine {
    // No maxFrameSize: the OkHttp engine (Android) refuses every session that sets it. Frame sizes are checked by
    // WebSocketChannel and firstBinary instead.
    private val ws: HttpClient by lazy { http.config { install(WebSockets) } }

    override suspend fun prove(
        session: ZkTlsSessionRequest.Verified,
        profile: ZkTlsProfile,
        request: ByteArray,
        extraRoots: List<ByteArray>,
        binding: kotlinx.serialization.json.JsonObject?,
        step: (String) -> Unit,
    ): ZkResult<ZkTlsProved> = withContext(Dispatchers.IO) {
        if (!ready()) return@withContext UNSUPPORTED
        val r = session.request
        val sentReveal = try { ZkTlsPlanner.sentReveal(profile, request) } catch (_: ProtocolException) { return@withContext ZkErrors.invalidInput }
        step(ct("core_zkn_connecting"))
        // A channel that never hears from the verifier reached something else (another device at a private
        // address, an empty relay room); nothing private has been sent yet, so the next transport is tried.
        var unanswered: ZkTlsChannelEnd? = null
        for (transport in candidates(r.transports)) {
            val channel = runCatching { channelFor(transport) }.getOrNull() ?: continue
            val attempt = proveOver(channel, transport, session, profile, request, sentReveal, extraRoots, binding, step)
            if (attempt != null) return@withContext attempt
            unanswered = unanswered ?: (channel as? EndAware)?.end
            step(ct("core_zkn_connecting"))
        }
        unanswered?.takeIf { it != ZkTlsChannelEnd.NO_REPLY }?.let { ZkResult.Failed(it.message, it.retry) } ?: unreachable(r.transports)
    }

    /** One attempt over [channel]; null when the verifier never answered there. */
    private suspend fun proveOver(
        channel: ZkTlsChannel,
        transport: ZkTlsTransport,
        session: ZkTlsSessionRequest.Verified,
        profile: ZkTlsProfile,
        request: ByteArray,
        sentReveal: List<ZkTlsRange>,
        extraRoots: List<ByteArray>,
        binding: kotlinx.serialization.json.JsonObject?,
        step: (String) -> Unit,
    ): ZkResult<ZkTlsProved>? {
        val r = session.request
        var plan: ZkTlsPlanner.Plan? = null
        val chooser = object : ZkTlsRevealChooser {
            override fun choose(transcript: ZkTlsTranscript): ZkTlsReveal {
                // A rule that fails on this page reveals nothing of the response; the verifier then reports it.
                val p = runCatching { ZkTlsPlanner.receivedReveal(profile, r.fields, transcript.received) }
                    .getOrElse { ZkTlsPlanner.Plan(emptyList(), null, emptyMap(), r.fields) }
                plan = p
                step(ct("core_zkn_disclosing"))
                return ZkTlsReveal(sentReveal.map(::range), p.received.map(::range), emptyList())
            }
        }
        step(ct("core_zkn_via", profile.host))
        return try {
            val t = cancellable(channel) { token ->
                zktlsProve(
                    channel,
                    ZkTlsRequest(
                        profile.host, profile.port.toUShort(), request, profile.limits.maxSent.toUInt(), profile.limits.maxRecv.toUInt(), r.mode,
                        binding?.let { WebProofCredentials.publicJwk(it).toString().encodeToByteArray() } ?: ByteArray(0),
                    ),
                    chooser, token, session.hash, r.verifierStatic, extraRoots,
                )
            }
            val p = plan ?: return ZkErrors.internal
            val seen = ZkTlsHolder.masked(t.serverName, t.certChainDer, t.time.toLong(), t.sent, t.received, sentReveal, p.received)
            val receipt = t.receipt.takeIf { it.isNotEmpty() }?.decodeToString()
            ZkResult.Ok(ZkTlsProved(t.serverName, t.certChainDer, t.time.toLong(), t.cipherSuite, p, ZkTlsCheck.check(r, profile, seen), transport, receipt))
        } catch (e: ZkException) {
            channel.close()
            if ((channel as? EndAware)?.answered == false && transportError(e)) null else failure(e, channel)
        }
    }

    /** Local addresses on this device's own subnet first, then the relay and verifier servers. */
    private fun candidates(transports: List<ZkTlsTransport>): List<ZkTlsTransport> {
        val lan = transports.filterIsInstance<ZkTlsTransport.Lan>()
        val order = preferred(lan.map { "tcp://${it.host}:${it.port}" }).mapNotNull { u -> lan.firstOrNull { "tcp://${it.host}:${it.port}" == u } }
        return order + ZkTlsHolder.ordered(transports).filter { it !is ZkTlsTransport.Lan }
    }

    /** A channel to [t]; the verifier answers the first Noise message at once, so a silent peer is given up early. */
    private suspend fun channelFor(t: ZkTlsTransport): ZkTlsChannel = when (t) {
        is ZkTlsTransport.Lan -> {
            val socket = (socketFactoryFor(t.host) ?: SocketFactory.getDefault()).createSocket()
            try {
                socket.connect(InetSocketAddress(t.host, t.port), LAN_CONNECT_MS)
                socket.tcpNoDelay = true
            } catch (e: IOException) {
                socket.close()
                throw e
            }
            SocketChannel(socket, FIRST_BYTES_MS)
        }
        is ZkTlsTransport.Relay -> WebSocketChannel(open("${t.url.trimEnd('/')}/${t.room}"), FIRST_BYTES_MS.toLong())
        is ZkTlsTransport.Wss -> WebSocketChannel(open(t.url), FIRST_BYTES_MS.toLong())
    }

    private suspend fun open(url: String): WebSocketSession = withTimeout(WS_CONNECT_MS) { ws.webSocketSession(url) }

    override suspend fun open(lan: Boolean, relayUrls: List<String>): ZkTlsVerifierSession = withContext(Dispatchers.IO) {
        if (!ready()) throw ProtocolException("unsupported", UNSUPPORTED.reason)
        val key = ZkTlsKey()
        val servers = if (!lan) emptyList() else addresses().distinct().take(MAX_LAN).mapNotNull { a ->
            runCatching { a to ServerSocket(0, 4, InetAddress.getByName(a)) }.getOrNull()
        }
        // One room on every relay that answers (both parties' servers when they differ); the holder picks one.
        val relays = coroutineScope {
            relayUrls.map { relayAddress(it) }.distinct().take(MAX_RELAYS).map { url ->
                async {
                    runCatching {
                        val room = ByteArray(16).also { SecureRandom().nextBytes(it) }.toBase64Url()
                        ZkTlsTransport.Relay(url, room) to open("$url/$room")
                    }.getOrNull()
                }
            }.awaitAll().filterNotNull()
        }
        if (servers.isEmpty() && relays.isEmpty()) {
            throw ProtocolException("unavailable", if (lan) ct("core_zkn_no_lan_relay") else ct("core_zkn_no_relay"))
        }
        Session(key, servers, relays)
    }

    private inner class Session(
        private val key: ZkTlsKey,
        private val servers: List<Pair<String, ServerSocket>>,
        private val relays: List<Pair<ZkTlsTransport.Relay, WebSocketSession>>,
    ) : ZkTlsVerifierSession {
        override val transports: List<ZkTlsTransport> =
            servers.map { (a, s) -> ZkTlsTransport.Lan(a, s.localPort) } + relays.map { it.first }

        override val publicKey: ByteArray get() = key.publicKey

        override suspend fun verify(
            jws: String,
            request: ZkTlsSessionRequest,
            profile: ZkTlsProfile,
            extraRoots: List<ByteArray>,
            receipts: ZkTlsReceipts?,
            waiting: (String) -> Unit,
        ): ZkResult<ZkTlsSeen> = withContext(Dispatchers.IO) {
            try {
                val left = request.expiresAt - Clock.System.now()
                val channel = withTimeoutOrNull(left) { firstHolder() } ?: return@withContext EXPIRED
                waiting(ct("core_zkn_holder_connected"))
                try {
                    ZkTlsVerification.verify(channel, jws, request, profile, key, extraRoots, receipts)
                } catch (e: ZkException) {
                    failure(e, channel)
                }
            } catch (_: IOException) {
                ZkResult.Failed(ct("core_zkn_closed"), true)
            } finally {
                close()
            }
        }

        /** Waits on every listener; the first holder that sends a plausible handshake wins and the rest close. */
        private suspend fun firstHolder(): ZkTlsChannel {
            val winner = CompletableDeferred<ZkTlsChannel>()
            var viaRelay: WebSocketSession? = null
            try {
                coroutineScope {
                    val listeners = servers.map { (_, server) -> launch { accept(server, winner) } } + relays.map { (_, session) ->
                        launch {
                            val first = runCatching { firstBinary(session) }.getOrNull()
                            if (first != null && opensHandshake(first) && winner.complete(PrimedChannel(first, WebSocketChannel(session)))) viaRelay = session
                        }
                    }
                    // Every listener ended (the relay closed, the sockets failed) with no holder.
                    launch {
                        listeners.joinAll()
                        winner.completeExceptionally(IOException("No listener left"))
                    }
                    winner.await()
                    // accept() ignores cancellation: closing the sockets is what ends the other loops.
                    servers.forEach { runCatching { it.second.close() } }
                    coroutineContext.cancelChildren()
                }
            } finally {
                servers.forEach { runCatching { it.second.close() } }
                // Leave the rooms the holder did not take.
                relays.forEach { (_, session) -> if (session !== viaRelay) runCatching { session.cancel() } }
            }
            return winner.getCompleted()
        }

        private fun accept(server: ServerSocket, winner: CompletableDeferred<ZkTlsChannel>) {
            while (!winner.isCompleted) {
                val socket = try { server.accept() } catch (_: IOException) { return }
                val first = runCatching {
                    socket.soTimeout = FIRST_BYTES_MS
                    val buffer = ByteArray(ZkTlsChannels.CHUNK)
                    val n = socket.getInputStream().read(buffer)
                    buffer.copyOf(maxOf(n, 0)).takeIf { opensHandshake(it) }
                }.getOrNull()
                if (first == null) {
                    runCatching { socket.close() }
                    continue
                }
                socket.tcpNoDelay = true
                socket.soTimeout = READ_TIMEOUT_MS
                if (!winner.complete(PrimedChannel(first, SocketChannel(socket)))) socket.close()
            }
        }

        /** Also leaves the relay room, so a verifier screen closed before any holder came frees it at once. */
        override fun close() {
            servers.forEach { runCatching { it.second.close() } }
            relays.forEach { (_, session) -> runCatching { session.cancel() } }
        }
    }

    private suspend fun firstBinary(session: WebSocketSession): ByteArray {
        while (true) {
            val frame = session.incoming.receive()
            if (frame is Frame.Binary && frame.data.size > ZkTlsChannels.MAX_FRAME) throw IOException("Frame too large")
            if (frame is Frame.Binary && frame.data.isNotEmpty()) return frame.data
            if (frame is Frame.Close) throw IOException("Relay closed")
        }
    }

    companion object {
        const val MAX_LAN = 4
        /** Relays a verifier joins at once: its own server and the holder's. */
        const val MAX_RELAYS = 3
        private const val LAN_CONNECT_MS = 4_000
        private const val WS_CONNECT_MS = 15_000L
        private const val FIRST_BYTES_MS = 30_000
        private const val READ_TIMEOUT_MS = 300_000
        private val UNREACHABLE get() = ZkResult.Failed(ct("core_zkn_unreachable"), true)
        private val UNSUPPORTED get() = ZkResult.Failed(ct("core_zkn_missing"), false)
        private val EXPIRED get() = ZkResult.Failed(ct("core_zkn_expired"), false)

        /**
         * Why no transport reached the verifier. A request that names only verifier hosts has no second device or
         * shared network involved, so the message names the host instead.
         */
        fun unreachable(transports: List<ZkTlsTransport>): ZkResult.Failed {
            val hosts = transports.map { if (it is ZkTlsTransport.Wss) runCatching { Url(it.url).host }.getOrDefault(it.url) else null }
            if (hosts.isEmpty() || hosts.any { it == null }) return UNREACHABLE
            return ZkResult.Failed(ct("core_zkn_host_unreachable", hosts.distinct().joinToString(ct("core_sep_list"))), true)
        }

        /** ws or wss address of the relay on an age host given as http(s) or ws(s). */
        fun relayAddress(base: String): String = ZkTlsTransport.relayAddress(base)

        /** The first Noise message from the prover starts with its 16-bit length: the ephemeral key and a tag. */
        fun opensHandshake(first: ByteArray): Boolean {
            if (first.size < 2) return false
            val length = ((first[0].toInt() and 0xff) shl 8) or (first[1].toInt() and 0xff)
            return length in 32..1024
        }

        private fun range(r: ZkTlsRange) = ZkRange(r.start.toUInt(), r.end.toUInt())

        /** Error codes only: native details may carry private input. A transport error says how [channel] ended when it knows. */
        fun failure(e: ZkException, channel: ZkTlsChannel): ZkResult<Nothing> {
            val end = (channel as? EndAware)?.end
            return if (end != null && transportError(e)) ZkResult.Failed(end.message, end.retry) else failure(e)
        }

        private fun transportError(e: ZkException) =
            e is ZkException.Internal && e.code in setOf(502u, ZkTlsChannels.ENDED, ZkTlsChannels.SEND_FAILED, ZkTlsChannels.RECEIVE_FAILED)

        /** Error codes only: native details may carry private input. */
        fun failure(e: ZkException): ZkResult<Nothing> = when (e) {
            is ZkException.Cancelled -> ZkResult.Cancelled
            is ZkException.Unsupported -> UNSUPPORTED
            is ZkException.InvalidInput -> ZkResult.Failed(ct("core_zkn_limits"), false)
            is ZkException.ResourceExhausted -> ZkResult.Failed(ct("core_zkn_too_large"), false)
            is ZkException.Internal -> when (e.code) {
                501u -> ZkResult.Failed(ct("core_zkn_protocol"), true)
                502u, ZkTlsChannels.ENDED, ZkTlsChannels.SEND_FAILED, ZkTlsChannels.RECEIVE_FAILED ->
                    ZkResult.Failed(ct("core_zkn_link_lost"), true)
                else -> ZkErrors.internal
            }
        }
    }
}
