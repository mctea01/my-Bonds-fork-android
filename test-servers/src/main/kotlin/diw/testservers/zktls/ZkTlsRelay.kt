package diw.testservers.zktls

import io.ktor.server.routing.Route
import io.ktor.server.websocket.DefaultWebSocketServerSession
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import org.multipaz.util.fromBase64Url
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * The zkTLS relay (p4-zkp.md section 5.2): the verifier and the holder each open `/zktls/relay/{room}` and the relay
 * forwards binary frames between them. It sees only Noise ciphertext and plays no part in trust. A room takes two
 * connections, lives at most [lifetime] from its first connection and carries at most [maxBytes] in both directions;
 * at most [maxRooms] rooms exist at once. Nothing is stored.
 */
class ZkTlsRelay(
    private val maxRooms: Int = 256,
    private val lifetime: Duration = 15.minutes,
    private val maxBytes: Long = 512L shl 20,
    private val maxFrame: Int = 1 shl 17,
) {
    private class Room(val first: DefaultWebSocketServerSession, val created: Instant) {
        val second = CompletableDeferred<DefaultWebSocketServerSession>()
        val bytes = AtomicLong(0)
    }

    private val rooms = HashMap<String, Room>()

    /** Rooms waiting or in use, for tests. */
    val size: Int get() = synchronized(rooms) { rooms.size }

    suspend fun join(id: String, session: DefaultWebSocketServerSession) {
        if (runCatching { id.fromBase64Url().size != 16 }.getOrDefault(true)) {
            session.close(CloseReason(CloseReason.Codes.CANNOT_ACCEPT, "Malformed room"))
            return
        }
        val now = Clock.System.now()
        val (room, first) = synchronized(rooms) {
            rooms.entries.removeIf { now - it.value.created > lifetime }
            val existing = rooms[id]
            when {
                existing == null && rooms.size >= maxRooms -> null to false
                existing == null -> Room(session, now).also { rooms[id] = it } to true
                existing.second.isCompleted -> null to false
                else -> existing.also { it.second.complete(session) } to false
            }
        }
        if (room == null) {
            session.close(CloseReason(CloseReason.Codes.TRY_AGAIN_LATER, "Room unavailable"))
            return
        }
        // Why the room ends, with the same reasons as diw-wallet-server's relay.
        var end = EXPIRED
        try {
            withTimeoutOrNull(lifetime - (now - room.created)) {
                val peer = if (first) {
                    // Wait for the other side, or for this side to leave first.
                    select {
                        room.second.onAwait { it }
                        session.closeReason.onAwait { null }
                    } ?: run { end = PEER_LEFT; return@withTimeoutOrNull }
                } else room.first
                end = forward(session, peer, room)
            }
        } finally {
            synchronized(rooms) { if (rooms[id] === room) rooms.remove(id) }
            runCatching { session.close(end) }
            if (room.second.isCompleted) {
                val other = if (first) room.second.getCompleted() else room.first
                runCatching { other.close(end) }
            } else {
                room.second.cancel()
            }
        }
    }

    /** Copies this side's binary frames to [peer] until this side ends or the room reaches its limit. */
    private suspend fun forward(from: DefaultWebSocketServerSession, peer: DefaultWebSocketServerSession, room: Room): CloseReason {
        for (frame in from.incoming) {
            if (frame !is Frame.Binary) continue
            val data = frame.data
            if (data.size > maxFrame || room.bytes.addAndGet(data.size.toLong()) > maxBytes) return LIMIT
            peer.send(Frame.Binary(true, data))
        }
        return PEER_LEFT
    }

    companion object {
        val PEER_LEFT = CloseReason(CloseReason.Codes.NORMAL, "Peer left")
        val LIMIT = CloseReason(CloseReason.Codes.VIOLATED_POLICY, "Room limit")
        val EXPIRED = CloseReason(CloseReason.Codes.GOING_AWAY, "Room expired")
    }
}

fun Route.zkTlsRelayRoutes(relay: ZkTlsRelay) {
    webSocket("/zktls/relay/{room}") { relay.join(call.parameters["room"].orEmpty(), this) }
}
