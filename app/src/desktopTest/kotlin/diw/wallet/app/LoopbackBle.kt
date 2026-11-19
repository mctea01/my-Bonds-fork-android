package diw.wallet.app

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.selects.select
import org.multipaz.crypto.EcPublicKey
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethod
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodBle
import org.multipaz.mdoc.role.MdocRole
import org.multipaz.mdoc.transport.MdocTransport
import org.multipaz.mdoc.transport.MdocTransportClosedException
import org.multipaz.mdoc.transport.MdocTransportFactory
import org.multipaz.mdoc.transport.MdocTransportOptions
import kotlin.time.Duration

/**
 * Bluetooth between two wallets in one process: each BLE connection method (by its UUID) is a pair of message
 * queues. The holder's transports wait in open() until the reader opens the one it chose from the engagement.
 */
class LoopbackBle : MdocTransportFactory {
    private class Link {
        val toReader = Channel<ByteArray>(Channel.UNLIMITED)
        val toHolder = Channel<ByteArray>(Channel.UNLIMITED)
        val holderOpen = CompletableDeferred<Unit>()
        val readerOpen = CompletableDeferred<Unit>()
    }

    private val links = HashMap<String, Link>()

    private fun link(method: MdocConnectionMethod): Link = synchronized(links) {
        val ble = method as MdocConnectionMethodBle
        links.getOrPut((ble.peripheralServerModeUuid ?: ble.centralClientModeUuid).toString()) { Link() }
    }

    override fun createTransport(connectionMethod: MdocConnectionMethod, role: MdocRole, options: MdocTransportOptions): MdocTransport =
        Pipe(role, connectionMethod, link(connectionMethod))

    private class Pipe(override val role: MdocRole, override val connectionMethod: MdocConnectionMethod, private val link: Link) : MdocTransport() {
        private val current = MutableStateFlow(State.IDLE)
        private val closed = CompletableDeferred<Unit>()
        override val state: StateFlow<State> = current
        override val scanningTime: Duration? = null
        private val holder get() = role == MdocRole.MDOC

        override suspend fun advertise() {
            current.value = State.ADVERTISING
        }

        override suspend fun open(eSenderKey: EcPublicKey) {
            current.value = State.CONNECTING
            (if (holder) link.holderOpen else link.readerOpen).complete(Unit)
            val peer = if (holder) link.readerOpen else link.holderOpen
            val connected = select {
                peer.onAwait { true }
                closed.onAwait { false }
            }
            if (!connected) throw MdocTransportClosedException("Closed before connecting")
            current.value = State.CONNECTED
        }

        override suspend fun sendMessage(message: ByteArray) {
            runCatching { (if (holder) link.toReader else link.toHolder).send(message) }
                .onFailure { throw MdocTransportClosedException("Peer closed") }
        }

        override suspend fun waitForMessage(): ByteArray = try {
            (if (holder) link.toHolder else link.toReader).receive()
        } catch (e: ClosedReceiveChannelException) {
            throw MdocTransportClosedException("Peer closed")
        }

        override suspend fun close() {
            if (current.value == State.CLOSED) return
            val wasConnected = current.value == State.CONNECTED
            current.value = State.CLOSED
            closed.complete(Unit)
            if (wasConnected) {
                link.toReader.close()
                link.toHolder.close()
            }
        }
    }
}
