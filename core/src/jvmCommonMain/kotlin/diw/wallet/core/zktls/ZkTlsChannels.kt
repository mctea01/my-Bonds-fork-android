package diw.wallet.core.zktls

import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.ZkTlsChannel
import io.ktor.websocket.DefaultWebSocketSession
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.close
import io.ktor.websocket.readReason
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Byte channels for the native TLSNotary code. The Noise layer frames its own records, so a channel only carries
 * chunks of one byte stream in order; an empty read or a closed connection ends the stream. Every call blocks (the
 * native side calls from its own threads), and [close] unblocks a pending send or receive. Errors carry codes only.
 */
internal object ZkTlsChannels {
    const val CHUNK = 16384
    const val SEND_FAILED = 910u
    const val RECEIVE_FAILED = 911u
    const val ENDED = 912u
}

/** How a relay or the peer ended a WebSocket channel, from the relay's close reason (diw-wallet-server Relay). */
enum class ZkTlsChannelEnd(val reason: String?, val message: String, val retry: Boolean) {
    PEER_LEFT("Peer left", "對方已離開連線，原因請看對方的畫面", true),
    LIMIT("Room limit", "中繼中止了連線：超過中繼的傳輸量上限", false),
    EXPIRED("Room expired", "中繼中止了連線：超過中繼房間的 15 分鐘上限，請查驗方重新產生 QR code", false),
    REFUSED("Room unavailable", "中繼拒絕加入：這個查驗的房間已有兩方或已關閉，請查驗方重新產生 QR code", false),
    BUSY("Too many connections", "中繼拒絕加入：同一個網路位址的連線太多，請稍後再試", true),
    NO_REPLY(null, "查驗方沒有回應：對方可能已離開查驗畫面或關閉螢幕，請查驗方重新產生 QR code", false),
    ;

    companion object {
        fun of(reason: String?): ZkTlsChannelEnd? = entries.firstOrNull { it.reason != null && it.reason == reason }
    }
}

/** A channel that can tell how it ended, for a clearer message than a bare disconnect. */
interface EndAware {
    val end: ZkTlsChannelEnd?

    /** Whether any bytes came back: a channel that ended unanswered never reached the verifier. */
    val answered: Boolean
}

/**
 * A TCP connection on the local network, carrying the stream as is. With [firstReplyMs] the first read waits only
 * that long (another device can hold the same private address); later reads wait [READ_TIMEOUT_MS].
 */
class SocketChannel(private val socket: Socket, private val firstReplyMs: Int? = null) : ZkTlsChannel, EndAware {
    private val closed = AtomicBoolean(false)
    private val received = AtomicBoolean(false)

    @Volatile
    override var end: ZkTlsChannelEnd? = null
        private set

    override val answered: Boolean get() = received.get()

    init {
        socket.soTimeout = firstReplyMs ?: READ_TIMEOUT_MS
    }

    override fun send(data: ByteArray) {
        try {
            socket.getOutputStream().apply { write(data); flush() }
        } catch (_: IOException) {
            throw ZkException.Internal(ZkTlsChannels.SEND_FAILED)
        }
    }

    override fun receive(): ByteArray {
        val buffer = ByteArray(ZkTlsChannels.CHUNK)
        val n = try {
            socket.getInputStream().read(buffer)
        } catch (_: java.net.SocketTimeoutException) {
            if (!received.get()) end = ZkTlsChannelEnd.NO_REPLY
            -1
        } catch (_: IOException) {
            -1
        }
        if (n <= 0) throw ZkException.Internal(ZkTlsChannels.ENDED)
        if (received.compareAndSet(false, true) && firstReplyMs != null) socket.soTimeout = READ_TIMEOUT_MS
        return buffer.copyOf(n)
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) runCatching { socket.close() }
    }

    companion object {
        const val READ_TIMEOUT_MS = 300_000
    }
}

/**
 * A WebSocket (client or server side): each binary frame is one chunk; text and control frames are ignored. With
 * [firstReplyMs] the first chunk must arrive within that time: a holder alone in a relay room the verifier already
 * left would otherwise wait for the room's lifetime.
 */
class WebSocketChannel(private val session: WebSocketSession, private val firstReplyMs: Long? = null) : ZkTlsChannel, EndAware {
    private val closed = AtomicBoolean(false)
    private val received = AtomicBoolean(false)

    @Volatile
    override var end: ZkTlsChannelEnd? = null
        private set

    override val answered: Boolean get() = received.get()

    override fun send(data: ByteArray) {
        if (closed.get()) throw ZkException.Internal(ZkTlsChannels.SEND_FAILED)
        try {
            runBlocking { session.send(Frame.Binary(true, data)) }
        } catch (_: Exception) {
            throw ZkException.Internal(ZkTlsChannels.SEND_FAILED)
        }
    }

    override fun receive(): ByteArray = runBlocking { next() }

    private suspend fun next(): ByteArray {
        while (true) {
            val wait = firstReplyMs?.takeIf { !received.get() }
            val frame = try {
                if (wait == null) session.incoming.receive()
                else withTimeoutOrNull(wait) { session.incoming.receive() } ?: run {
                    end = ZkTlsChannelEnd.NO_REPLY
                    throw ZkException.Internal(ZkTlsChannels.ENDED)
                }
            } catch (e: ZkException) {
                throw e
            } catch (_: Exception) {
                ended(null)
            }
            if (frame is Frame.Binary && frame.data.isNotEmpty()) {
                received.set(true)
                return frame.data
            }
            if (frame is Frame.Close) ended(frame.readReason()?.message)
        }
    }

    /** Notes the relay's close reason (a default session takes the Close frame itself) and ends the stream. */
    private suspend fun ended(reason: String?): Nothing {
        val text = reason ?: (session as? DefaultWebSocketSession)?.closeReason?.let { withTimeoutOrNull(1_000) { it.await() } }?.message
        if (end == null) end = ZkTlsChannelEnd.of(text)
        throw ZkException.Internal(ZkTlsChannels.ENDED)
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { runBlocking { withTimeoutOrNull(2_000) { session.close() } } }
        runCatching { session.cancel() }
    }
}

/** [inner] with [first] (a chunk already read to see that a holder arrived) put back in front of the stream. */
class PrimedChannel(private var first: ByteArray?, private val inner: ZkTlsChannel) : ZkTlsChannel, EndAware {
    override val end: ZkTlsChannelEnd? get() = (inner as? EndAware)?.end

    // The first chunk was the holder's, so this side has heard from its peer.
    override val answered: Boolean get() = true

    override fun send(data: ByteArray) = inner.send(data)

    @Synchronized
    private fun takeFirst(): ByteArray? = first.also { first = null }

    override fun receive(): ByteArray = takeFirst() ?: inner.receive()

    override fun close() = inner.close()
}
