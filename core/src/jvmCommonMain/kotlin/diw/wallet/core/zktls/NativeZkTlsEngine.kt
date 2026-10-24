package diw.wallet.core.zktls

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
    private val ws: HttpClient by lazy { http.config { install(WebSockets) { maxFrameSize = MAX_FRAME } } }

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
        step("連線到查驗方")
        val (channel, transport) = connect(r.transports) ?: return@withContext UNREACHABLE
        var plan: ZkTlsPlanner.Plan? = null
        val chooser = object : ZkTlsRevealChooser {
            override fun choose(transcript: ZkTlsTranscript): ZkTlsReveal {
                // A rule that fails on this page reveals nothing of the response; the verifier then reports it.
                val p = runCatching { ZkTlsPlanner.receivedReveal(profile, r.fields, transcript.received) }
                    .getOrElse { ZkTlsPlanner.Plan(emptyList(), null, emptyMap(), r.fields) }
                plan = p
                step("揭露查驗方要求的欄位")
                return ZkTlsReveal(sentReveal.map(::range), p.received.map(::range), emptyList())
            }
        }
        step("經由查驗方連線到 ${profile.host}")
        try {
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
            val p = plan ?: return@withContext ZkErrors.internal
            val seen = ZkTlsHolder.masked(t.serverName, t.certChainDer, t.time.toLong(), t.sent, t.received, sentReveal, p.received)
            val receipt = t.receipt.takeIf { it.isNotEmpty() }?.decodeToString()
            ZkResult.Ok(ZkTlsProved(t.serverName, t.certChainDer, t.time.toLong(), t.cipherSuite, p, ZkTlsCheck.check(r, profile, seen), transport, receipt))
        } catch (e: ZkException) {
            failure(e)
        }
    }

    /** The first transport that connects, with the channel over it. */
    private suspend fun connect(transports: List<ZkTlsTransport>): Pair<ZkTlsChannel, ZkTlsTransport>? {
        val lan = transports.filterIsInstance<ZkTlsTransport.Lan>()
        val order = preferred(lan.map { "tcp://${it.host}:${it.port}" }).mapNotNull { u -> lan.firstOrNull { "tcp://${it.host}:${it.port}" == u } }
        for (t in order + ZkTlsHolder.ordered(transports).filter { it !is ZkTlsTransport.Lan }) {
            val channel = runCatching {
                when (t) {
                    is ZkTlsTransport.Lan -> {
                        val socket = (socketFactoryFor(t.host) ?: SocketFactory.getDefault()).createSocket()
                        try {
                            socket.connect(InetSocketAddress(t.host, t.port), LAN_CONNECT_MS)
                            socket.tcpNoDelay = true
                            socket.soTimeout = READ_TIMEOUT_MS
                        } catch (e: IOException) {
                            socket.close()
                            throw e
                        }
                        SocketChannel(socket)
                    }
                    is ZkTlsTransport.Relay -> WebSocketChannel(open("${t.url.trimEnd('/')}/${t.room}"))
                    is ZkTlsTransport.Wss -> WebSocketChannel(open(t.url))
                }
            }.getOrNull()
            if (channel != null) return channel to t
        }
        return null
    }

    private suspend fun open(url: String): WebSocketSession = withTimeout(WS_CONNECT_MS) { ws.webSocketSession(url) }

    override suspend fun open(lan: Boolean, relayUrl: String?): ZkTlsVerifierSession = withContext(Dispatchers.IO) {
        if (!ready()) throw ProtocolException("unsupported", UNSUPPORTED.reason)
        val key = ZkTlsKey()
        val servers = if (!lan) emptyList() else addresses().distinct().take(MAX_LAN).mapNotNull { a ->
            runCatching { a to ServerSocket(0, 4, InetAddress.getByName(a)) }.getOrNull()
        }
        val relay = relayUrl?.let { base ->
            runCatching {
                val url = relayAddress(base)
                val room = ByteArray(16).also { SecureRandom().nextBytes(it) }.toBase64Url()
                ZkTlsTransport.Relay(url, room) to open("$url/$room")
            }.getOrNull()
        }
        if (servers.isEmpty() && relay == null) {
            throw ProtocolException("unavailable", if (lan) "無法在區域網路開啟連線，也無法連到中繼" else "無法連到中繼")
        }
        Session(key, servers, relay)
    }

    private inner class Session(
        private val key: ZkTlsKey,
        private val servers: List<Pair<String, ServerSocket>>,
        private val relay: Pair<ZkTlsTransport.Relay, WebSocketSession>?,
    ) : ZkTlsVerifierSession {
        override val transports: List<ZkTlsTransport> =
            servers.map { (a, s) -> ZkTlsTransport.Lan(a, s.localPort) } + listOfNotNull(relay?.first)

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
                waiting("出示者已連線，正在查驗")
                try {
                    ZkTlsVerification.verify(channel, jws, request, profile, key, extraRoots, receipts)
                } catch (e: ZkException) {
                    failure(e)
                }
            } catch (_: IOException) {
                ZkResult.Failed("查驗方的連線已關閉，沒有出示者連線", true)
            } finally {
                close()
            }
        }

        /** Waits on every listener; the first holder that sends a plausible handshake wins and the rest close. */
        private suspend fun firstHolder(): ZkTlsChannel {
            val winner = CompletableDeferred<ZkTlsChannel>()
            var viaRelay = false
            try {
                coroutineScope {
                    val listeners = servers.map { (_, server) -> launch { accept(server, winner) } } + listOfNotNull(relay?.let { (_, session) ->
                        launch {
                            val first = runCatching { firstBinary(session) }.getOrNull()
                            if (first != null && opensHandshake(first) && winner.complete(PrimedChannel(first, WebSocketChannel(session)))) viaRelay = true
                        }
                    })
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
                if (!viaRelay) relay?.second?.let { runCatching { it.cancel() } }
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

        override fun close() {
            servers.forEach { runCatching { it.second.close() } }
        }
    }

    private suspend fun firstBinary(session: WebSocketSession): ByteArray {
        while (true) {
            val frame = session.incoming.receive()
            if (frame is Frame.Binary && frame.data.isNotEmpty()) return frame.data
            if (frame is Frame.Close) throw IOException("Relay closed")
        }
    }

    companion object {
        const val MAX_LAN = 4
        private const val MAX_FRAME = 1L shl 20
        private const val LAN_CONNECT_MS = 4_000
        private const val WS_CONNECT_MS = 15_000L
        private const val FIRST_BYTES_MS = 30_000
        private const val READ_TIMEOUT_MS = 300_000
        private val UNREACHABLE = ZkResult.Failed("無法連到查驗方：請確認兩台裝置在同一個網路，或查驗方的中繼可以連線", true)
        private val UNSUPPORTED = ZkResult.Failed("這個版本沒有包含 zkTLS（TLSNotary）", false)
        private val EXPIRED = ZkResult.Failed("查驗請求已過期，沒有出示者連線", false)

        /** ws or wss address of the relay on an age host given as http(s) or ws(s). */
        fun relayAddress(base: String): String {
            val u = Url(base.trim().trimEnd('/'))
            val scheme = when (u.protocol) {
                URLProtocol.HTTPS, URLProtocol.WSS -> "wss"
                URLProtocol.HTTP, URLProtocol.WS -> "ws"
                else -> throw ProtocolException("invalid_request", "The relay must be a web address")
            }
            val port = if (u.port == u.protocol.defaultPort) "" else ":${u.port}"
            return "$scheme://${u.host}$port${u.encodedPath.trimEnd('/')}/zktls/relay"
        }

        /** The first Noise message from the prover starts with its 16-bit length: the ephemeral key and a tag. */
        fun opensHandshake(first: ByteArray): Boolean {
            if (first.size < 2) return false
            val length = ((first[0].toInt() and 0xff) shl 8) or (first[1].toInt() and 0xff)
            return length in 32..1024
        }

        private fun range(r: ZkTlsRange) = ZkRange(r.start.toUInt(), r.end.toUInt())

        /** Error codes only: native details may carry private input. */
        fun failure(e: ZkException): ZkResult<Nothing> = when (e) {
            is ZkException.Cancelled -> ZkResult.Cancelled
            is ZkException.Unsupported -> UNSUPPORTED
            is ZkException.InvalidInput -> ZkResult.Failed("查驗頁的請求不符合 zkTLS 的限制", false)
            is ZkException.ResourceExhausted -> ZkResult.Failed("網站回應超過上限，或查驗超過 10 分鐘", false)
            is ZkException.Internal -> when (e.code) {
                501u -> ZkResult.Failed("zkTLS 協定失敗：網站憑證不受信任、網站不支援 TLS 1.2，或雙方的請求不一致", true)
                502u, ZkTlsChannels.ENDED, ZkTlsChannels.SEND_FAILED, ZkTlsChannels.RECEIVE_FAILED ->
                    ZkResult.Failed("與對方的連線中斷", true)
                else -> ZkErrors.internal
            }
        }
    }
}
