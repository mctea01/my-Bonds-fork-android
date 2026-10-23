package diw.wallet.core.profile.bonds

import diw.wallet.core.document.sign.CleartextHttp
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InterfaceAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import javax.net.SocketFactory
import kotlin.time.Duration

/**
 * [BondsLanLink] over plain sockets, so it works the same in Android release builds (whose HTTP stacks refuse clear
 * text) and on desktops. The server reads one request per connection with a bounded body and closes it, on every
 * address it was given, until one exchange ends.
 * [socketFactoryFor] gives the sockets for a local address their network: Android sends an unbound socket over the
 * default network, which is mobile data while the shared Wi-Fi or hotspot has no Internet, so the post would never
 * reach the other phone. Null uses the default route (desktops).
 */
class SocketBondsLanLink(private val socketFactoryFor: (host: String) -> SocketFactory? = { null }) : BondsLanLink {
    override fun localAddresses(): List<String> = interfaceAddresses()
        .filter { (name, a) -> a.address.isSiteLocalAddress && rank(name) < REMOTE_RANK }
        // Wi-Fi and hotspot interfaces first. Mobile data and VPN tunnels are left out: another phone on the same
        // Wi-Fi cannot reach their private addresses, and listening there would only expose the socket to the carrier.
        .sortedBy { (name, _) -> rank(name) }
        .map { it.second.address.hostAddress!! }
        .distinct()

    override fun preferred(urls: List<String>): List<String> {
        val own = interfaceAddresses().map { it.second }
        return urls.sortedBy { url ->
            val host = runCatching { InetAddress.getByName(URI(url).host) as? Inet4Address }.getOrNull()
            if (host != null && own.any { sameSubnet(it, host) }) 0 else 1
        }
    }

    /** IPv4 addresses of the interfaces that are up, with their interface names. */
    private fun interfaceAddresses(): List<Pair<String, InterfaceAddress>> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback && !it.isVirtual }
            .flatMap { nic -> nic.interfaceAddresses.filter { it.address is Inet4Address }.map { nic.name to it } }
    }.getOrDefault(emptyList())

    private fun sameSubnet(own: InterfaceAddress, other: Inet4Address): Boolean {
        val bits = own.networkPrefixLength.toInt()
        if (bits !in 1..32) return false
        val mask = if (bits == 32) -1 else (-1 shl (32 - bits))
        return (toInt(own.address.address) and mask) == (toInt(other.address) and mask)
    }

    private fun toInt(b: ByteArray): Int = b.fold(0) { acc, x -> (acc shl 8) or (x.toInt() and 0xff) }

    private fun rank(name: String): Int = when {
        LOCAL.any { name.startsWith(it) } -> 0
        REMOTE.any { name.startsWith(it) } -> REMOTE_RANK
        else -> 1
    }

    override suspend fun serve(
        addresses: List<String>,
        path: String,
        maxPayload: Int,
        onListening: (urls: List<String>) -> Unit,
        answer: suspend (body: ByteArray) -> Pair<ByteArray, Boolean>,
    ): ByteArray {
        val servers = withContext(Dispatchers.IO) {
            addresses.distinct().mapNotNull { a -> runCatching { a to ServerSocket(0, 8, InetAddress.getByName(a)) }.getOrNull() }
        }
        if (servers.isEmpty()) throw IOException("Cannot listen on ${addresses.joinToString()}")
        return try {
            coroutineScope {
                // accept() does not react to interruption; closing the sockets is what ends it on cancellation.
                val closer = launch { try { awaitCancellation() } finally { servers.forEach { runCatching { it.second.close() } } } }
                onListening(servers.map { (a, s) -> "http://$a:${s.localPort}$path" })
                val done = CompletableDeferred<ByteArray>()
                // One answer at a time, as with a single socket; a body arriving after the end is refused.
                val turn = Mutex()
                val ended: suspend (ByteArray) -> Pair<ByteArray, Boolean> = { body ->
                    turn.withLock { if (done.isCompleted) ERROR to false else answer(body) }
                }
                val loops = servers.map { (_, server) ->
                    launch {
                        while (!done.isCompleted) {
                            val socket = try { withContext(Dispatchers.IO) { server.accept() } } catch (_: IOException) { break }
                            socket.use { handle(it, path, maxPayload, ended) }?.let { done.complete(it) }
                        }
                    }
                }
                launch {
                    loops.joinAll()
                    done.completeExceptionally(IOException("Stopped listening"))
                }
                val body = done.await()
                coroutineContext.cancelChildren()
                body
            }
        } finally {
            withContext(Dispatchers.IO) { servers.forEach { runCatching { it.second.close() } } }
        }
    }

    /** Answers one connection; returns the body when it ended the exchange. */
    private suspend fun handle(socket: Socket, path: String, maxPayload: Int, answer: suspend (ByteArray) -> Pair<ByteArray, Boolean>): ByteArray? {
        val (method, target, body) = try {
            withContext(Dispatchers.IO) {
                socket.soTimeout = READ_TIMEOUT_MS
                read(BufferedInputStream(socket.getInputStream()), maxPayload)
            }
        } catch (e: IOException) {
            respond(socket, if (e is TooLarge) 413 else 400, ERROR)
            return null
        }
        if (method != "POST" || target != path) {
            respond(socket, 404, ERROR)
            return null
        }
        val (reply, done) = answer(body)
        respond(socket, 200, reply)
        return body.takeIf { done }
    }

    private class TooLarge : IOException("Body too large")

    private fun read(input: InputStream, maxPayload: Int): Triple<String, String, ByteArray> {
        val request = line(input) ?: throw IOException("No request")
        val parts = request.split(' ')
        if (parts.size < 3) throw IOException("Malformed request line")
        var length = -1
        while (true) {
            val h = line(input) ?: throw IOException("Connection closed in the headers")
            if (h.isEmpty()) break
            val colon = h.indexOf(':')
            if (colon > 0 && h.substring(0, colon).trim().equals("content-length", ignoreCase = true)) {
                length = h.substring(colon + 1).trim().toIntOrNull() ?: throw IOException("Bad length")
            }
        }
        if (length < 0) return Triple(parts[0], parts[1], ByteArray(0))
        if (length > maxPayload) throw TooLarge()
        val body = ByteArray(length)
        var at = 0
        while (at < length) {
            val n = input.read(body, at, length - at)
            if (n < 0) throw IOException("Connection closed in the body")
            at += n
        }
        return Triple(parts[0], parts[1], body)
    }

    private fun line(input: InputStream): String? {
        val out = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0) return if (out.isEmpty()) null else out.toString()
            if (c == '\n'.code) return out.toString().trimEnd('\r')
            if (out.length > MAX_LINE) throw IOException("Header line too long")
            out.append(c.toChar())
        }
    }

    private suspend fun respond(socket: Socket, status: Int, body: ByteArray) = withContext(Dispatchers.IO) {
        runCatching {
            val reason = when (status) { 200 -> "OK"; 404 -> "Not Found"; 413 -> "Payload Too Large"; else -> "Bad Request" }
            val out = socket.getOutputStream()
            out.write(
                ("HTTP/1.1 $status $reason\r\nContent-Type: application/json\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n")
                    .toByteArray(Charsets.ISO_8859_1),
            )
            out.write(body)
            out.flush()
        }
    }

    override suspend fun post(url: String, body: ByteArray, timeout: Duration): Pair<Int, String> {
        val host = URI(url).host?.removePrefix("[")?.removeSuffix("]")
        val factory = host?.let { socketFactoryFor(it) } ?: SocketFactory.getDefault()
        val reply = CleartextHttp(timeoutMillis = timeout.inWholeMilliseconds.toInt(), maxBytes = REPLY_MAX, socketFactory = factory)
            .exchange(url, body, "application/json", "application/json")
        return reply.status to reply.body.decodeToString()
    }

    private companion object {
        const val REMOTE_RANK = 2
        const val READ_TIMEOUT_MS = 30_000
        const val MAX_LINE = 8192
        const val REPLY_MAX = 64 * 1024
        val LOCAL = listOf("wlan", "swlan", "ap", "en", "eth", "wifi", "softap")
        val REMOTE = listOf("rmnet", "ccmni", "tun", "ppp", "ipsec", "wg", "utun", "clat", "v4-")
        val ERROR = """{"status":"failed","accepted":false,"reason":"查驗請求不存在或格式不符"}""".encodeToByteArray()
    }
}
