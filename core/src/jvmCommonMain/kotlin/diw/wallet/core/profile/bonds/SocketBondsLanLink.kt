package diw.wallet.core.profile.bonds

import diw.wallet.core.document.sign.CleartextHttp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import kotlin.time.Duration

/**
 * [BondsLanLink] over plain sockets, so it works the same in Android release builds (whose HTTP stacks refuse clear
 * text) and on desktops. The server reads one request per connection with a bounded body and closes it.
 */
class SocketBondsLanLink : BondsLanLink {
    override fun localAddresses(): List<String> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback && !it.isVirtual }
            .flatMap { nic -> nic.inetAddresses.toList().filterIsInstance<Inet4Address>().map { nic.name to it } }
            .filter { (_, a) -> a.isSiteLocalAddress }
            // Wi-Fi and hotspot interfaces first; mobile data rarely has a private address another phone can reach.
            .sortedBy { (name, _) -> if (name.startsWith("wlan") || name.startsWith("ap") || name.startsWith("swlan") || name.startsWith("en")) 0 else 1 }
            .map { it.second.hostAddress!! }
            .distinct()
    }.getOrDefault(emptyList())

    override suspend fun serve(
        address: String,
        path: String,
        maxPayload: Int,
        onListening: (url: String) -> Unit,
        answer: suspend (body: ByteArray) -> Pair<ByteArray, Boolean>,
    ): ByteArray {
        val server = withContext(Dispatchers.IO) { ServerSocket(0, 8, InetAddress.getByName(address)) }
        return try {
            coroutineScope {
                // accept() does not react to interruption; closing the socket is what ends it on cancellation.
                val closer = launch { try { awaitCancellation() } finally { server.close() } }
                onListening("http://$address:${server.localPort}$path")
                var done: ByteArray? = null
                while (done == null) {
                    val socket = withContext(Dispatchers.IO) { server.accept() }
                    done = socket.use { handle(it, path, maxPayload, answer) }
                }
                closer.cancel()
                done
            }
        } finally {
            withContext(Dispatchers.IO) { runCatching { server.close() } }
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
        val reply = CleartextHttp(timeoutMillis = timeout.inWholeMilliseconds.toInt(), maxBytes = REPLY_MAX)
            .exchange(url, body, "application/json", "application/json")
        return reply.status to reply.body.decodeToString()
    }

    private companion object {
        const val READ_TIMEOUT_MS = 30_000
        const val MAX_LINE = 8192
        const val REPLY_MAX = 64 * 1024
        val ERROR = """{"status":"failed","accepted":false,"reason":"查驗請求不存在或格式不符"}""".encodeToByteArray()
    }
}
