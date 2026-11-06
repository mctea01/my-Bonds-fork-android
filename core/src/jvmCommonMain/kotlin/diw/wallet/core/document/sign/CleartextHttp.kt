package diw.wallet.core.document.sign

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.URI
import javax.net.SocketFactory

/**
 * A minimal HTTP/1.1 client over a plain socket, for http:// URLs of [SignedDataHttp] only. Android release builds
 * refuse clear text in their HTTP stacks (network security configuration), while time-stamp authorities, OCSP
 * responders, CRL distribution points and AIA links are published over http; their replies are verified by signature,
 * so this route does not rely on the transport. One request per connection, no compression, replies up to [maxBytes].
 * [socketFactory] picks the network the socket uses (a local network on Android, see SocketBondsLanLink).
 */
class CleartextHttp(
    private val timeoutMillis: Int = 20_000,
    private val maxBytes: Int = 17 * 1024 * 1024,
    private val socketFactory: SocketFactory = SocketFactory.getDefault(),
) : SignedDataHttp {
    override suspend fun exchange(url: String, body: ByteArray?, contentType: String?, accept: String?): FetchReply =
        withContext(Dispatchers.IO) {
            val uri = URI(url)
            if (uri.scheme != "http") throw IllegalArgumentException("Only http URLs: $url")
            val host = uri.host ?: throw IOException("No host in $url")
            val port = if (uri.port == -1) 80 else uri.port
            val path = (uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
            socketFactory.createSocket().use { socket ->
                socket.connect(InetSocketAddress(host.removePrefix("[").removeSuffix("]"), port), timeoutMillis)
                socket.soTimeout = timeoutMillis
                val head = StringBuilder()
                    .append(if (body != null) "POST " else "GET ").append(path).append(" HTTP/1.1\r\n")
                    .append("Host: ").append(if (uri.port == -1) host else "$host:$port").append("\r\n")
                    .append("Accept: ").append(accept ?: "*/*").append("\r\n")
                    .append("Connection: close\r\n")
                if (body != null) {
                    contentType?.let { head.append("Content-Type: ").append(it).append("\r\n") }
                    head.append("Content-Length: ").append(body.size).append("\r\n")
                }
                head.append("\r\n")
                val out = socket.getOutputStream()
                out.write(head.toString().toByteArray(Charsets.ISO_8859_1))
                body?.let { out.write(it) }
                out.flush()
                read(BufferedInputStream(socket.getInputStream()))
            }
        }

    private fun read(input: InputStream): FetchReply {
        while (true) {
            val statusLine = line(input) ?: throw IOException("Connection closed before a reply")
            val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: throw IOException("Not an HTTP reply: $statusLine")
            val headers = HashMap<String, String>()
            while (true) {
                val h = line(input) ?: throw IOException("Connection closed in the headers")
                if (h.isEmpty()) break
                val colon = h.indexOf(':')
                if (colon > 0) headers[h.substring(0, colon).trim().lowercase()] = h.substring(colon + 1).trim()
            }
            // An interim 1xx reply is followed by the real one.
            if (status in 100..199) continue
            val payload = when {
                headers["transfer-encoding"]?.lowercase()?.contains("chunked") == true -> chunked(input)
                headers["content-length"] != null -> {
                    val length = headers["content-length"]!!.toLongOrNull() ?: throw IOException("Bad Content-Length")
                    if (length > maxBytes) throw IOException("Reply larger than $maxBytes bytes")
                    exactly(input, length.toInt())
                }
                else -> untilEnd(input)
            }
            return FetchReply(status, payload, headers["location"])
        }
    }

    private fun chunked(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        while (true) {
            val sizeLine = line(input) ?: throw IOException("Connection closed in a chunk")
            val size = sizeLine.substringBefore(';').trim().toIntOrNull(16) ?: throw IOException("Bad chunk size: $sizeLine")
            if (size == 0) {
                // Trailers end with an empty line.
                while (!(line(input) ?: "").isEmpty()) Unit
                return out.toByteArray()
            }
            if (out.size() + size > maxBytes) throw IOException("Reply larger than $maxBytes bytes")
            out.write(exactly(input, size))
            line(input)
        }
    }

    private fun exactly(input: InputStream, length: Int): ByteArray {
        val buffer = ByteArray(length)
        var read = 0
        while (read < length) {
            val n = input.read(buffer, read, length - read)
            if (n < 0) throw IOException("Connection closed after $read of $length bytes")
            read += n
        }
        return buffer
    }

    private fun untilEnd(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) return out.toByteArray()
            if (out.size() + n > maxBytes) throw IOException("Reply larger than $maxBytes bytes")
            out.write(buffer, 0, n)
        }
    }

    /** One header line without its CRLF, or null at the end of the stream. */
    private fun line(input: InputStream): String? {
        val out = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b < 0) return if (out.size() == 0) null else out.toString(Charsets.ISO_8859_1.name())
            if (b == '\n'.code) return out.toString(Charsets.ISO_8859_1.name()).removeSuffix("\r")
            if (out.size() > 16 * 1024) throw IOException("Header line too long")
            out.write(b)
        }
    }
}
