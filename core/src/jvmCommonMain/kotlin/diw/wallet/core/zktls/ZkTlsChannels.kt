package diw.wallet.core.zktls

import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.ZkTlsChannel
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.close
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

/** A TCP connection on the local network, carrying the stream as is. */
class SocketChannel(private val socket: Socket) : ZkTlsChannel {
    private val closed = AtomicBoolean(false)

    override fun send(data: ByteArray) {
        try {
            socket.getOutputStream().apply { write(data); flush() }
        } catch (_: IOException) {
            throw ZkException.Internal(ZkTlsChannels.SEND_FAILED)
        }
    }

    override fun receive(): ByteArray {
        val buffer = ByteArray(ZkTlsChannels.CHUNK)
        val n = try { socket.getInputStream().read(buffer) } catch (_: IOException) { -1 }
        if (n <= 0) throw ZkException.Internal(ZkTlsChannels.ENDED)
        return buffer.copyOf(n)
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) runCatching { socket.close() }
    }
}

/** A WebSocket (client or server side): each binary frame is one chunk; text and control frames are ignored. */
class WebSocketChannel(private val session: WebSocketSession) : ZkTlsChannel {
    private val closed = AtomicBoolean(false)

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
            val frame = try { session.incoming.receive() } catch (_: Exception) { throw ZkException.Internal(ZkTlsChannels.ENDED) }
            if (frame is Frame.Binary && frame.data.isNotEmpty()) return frame.data
            if (frame is Frame.Close) throw ZkException.Internal(ZkTlsChannels.ENDED)
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { runBlocking { withTimeoutOrNull(2_000) { session.close() } } }
        runCatching { session.cancel() }
    }
}

/** [inner] with [first] (a chunk already read to see that a holder arrived) put back in front of the stream. */
class PrimedChannel(private var first: ByteArray?, private val inner: ZkTlsChannel) : ZkTlsChannel {
    override fun send(data: ByteArray) = inner.send(data)

    @Synchronized
    private fun takeFirst(): ByteArray? = first.also { first = null }

    override fun receive(): ByteArray = takeFirst() ?: inner.receive()

    override fun close() = inner.close()
}
