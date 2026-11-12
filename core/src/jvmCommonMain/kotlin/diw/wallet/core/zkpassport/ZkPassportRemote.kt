package diw.wallet.core.zkpassport

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URI
import java.net.URL
import java.net.URLDecoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * Proves a zkPassport answer on the owner's prover instead of this device (diw-wallet-server DESIGN 3.9 and 3.10):
 * the SOD and DG1 go with the request, progress is polled, and the proofs come back for this device to send through
 * zkPassport's bridge. The prover reads the registries from its own node with its own clock, as the phone would.
 */
object ZkPassportRemote {
    /** One call to the prover: status code and JSON body (null when there is none). */
    fun interface Transport {
        suspend fun call(method: String, path: String, body: JsonObject?): Pair<Int, JsonObject?>
    }

    private const val JOBS = "/zkpassport/v1/jobs"
    private const val POLL_MS = 1000L
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun prove(
        transport: Transport,
        chip: ZkPassportProver.Chip,
        job: ZkPassportProver.Job,
        progress: (ZkPassportProver.Progress) -> Unit,
    ): ZkPassportProver.Proved {
        val encoder = Base64.getEncoder()
        // DG2 stays on this device: the prover takes its hash from the SOD.
        val request = buildJsonObject {
            put("sod", encoder.encodeToString(chip.sod))
            put("dg1", encoder.encodeToString(chip.dg1))
            put("query", job.query)
            put("domain", job.domain)
            job.scope?.let { put("scope", it) }
            put("dev_mode", job.devMode)
            put("circuit_version", job.circuitVersion)
        }
        val (code, created) = transport.call("POST", JOBS, request)
        if (code != 202) throw ZkPassportProver.Failure(failure(code))
        val id = created?.text("id")?.takeIf { ID.matches(it) } ?: throw ZkPassportProver.Failure("remote_protocol")
        try {
            while (true) {
                delay(POLL_MS)
                val (status, state) = transport.call("GET", "$JOBS/$id", null)
                if (status == 404) throw ZkPassportProver.Failure("remote_lost")
                if (status != 200 || state == null) throw ZkPassportProver.Failure(failure(status))
                when (state.text("state")) {
                    "registry" -> progress(ZkPassportProver.Progress.Registry)
                    "proving" -> {
                        val total = state.int("total") ?: 0
                        val name = state.text("name")
                        progress(if (name == null) ZkPassportProver.Progress.Circuits(total) else ZkPassportProver.Progress.Proving(state.int("index") ?: 0, total, name))
                    }
                    "done" -> return proved(state["result"] as? JsonObject ?: throw ZkPassportProver.Failure("remote_protocol"))
                    "failed" -> throw ZkPassportProver.Failure(state.text("code")?.takeIf { CODE.matches(it) } ?: "remote_failed")
                }
            }
        } catch (e: CancellationException) {
            // Stops the prover and drops the chip files there at once.
            withContext(NonCancellable) { runCatching { transport.call("DELETE", "$JOBS/$id", null) } }
            throw e
        }
    }

    private fun failure(code: Int): String = when (code) {
        400 -> "remote_rejected"
        401 -> "remote_unauthorized"
        429 -> "remote_busy"
        503 -> "remote_unavailable"
        else -> "remote_http_$code"
    }

    /** The prover's result as ZkPassportHost.result writes it. */
    fun proved(o: JsonObject): ZkPassportProver.Proved {
        fun bad(): Nothing = throw ZkPassportProver.Failure("remote_protocol")
        val proofs = (o["proofs"] as? JsonArray ?: bad()).map { e ->
            val p = e as? JsonObject ?: bad()
            ZkPassportProver.Proof(
                name = p.text("name") ?: bad(), proof = p.text("proof") ?: bad(), vkey = p.text("vkey") ?: bad(),
                vkeyHash = p.text("vkey_hash") ?: bad(), version = p.text("version") ?: bad(), committedInputs = p["committed_inputs"],
            )
        }
        val messages = (o["messages"] as? JsonArray ?: bad()).map { e ->
            val m = e as? JsonObject ?: bad()
            (m.text("method") ?: bad()) to (m["params"] ?: bad())
        }
        if (proofs.isEmpty() || messages.isEmpty()) bad()
        return ZkPassportProver.Proved(proofs, messages, o["query_result"] ?: bad())
    }

    /** The owner's self-hosted prover, reached with the app's HTTP client and its access token. */
    class Host(private val http: HttpClient, url: String, private val token: String) : Transport {
        private val base = url.trimEnd('/')

        override suspend fun call(method: String, path: String, body: JsonObject?): Pair<Int, JsonObject?> = try {
            val r = http.request(base + path) {
                this.method = HttpMethod.parse(method)
                header("Authorization", "Bearer $token")
                if (body != null) {
                    contentType(ContentType.Application.Json)
                    setBody(body.toString())
                }
            }
            r.status.value to parse(r.bodyAsText())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw ZkPassportProver.Failure("remote_unreachable")
        }
    }

    internal fun parse(text: String): JsonObject? = runCatching { json.parseToJsonElement(text) as? JsonObject }.getOrNull()

    internal fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
    internal fun JsonObject.int(key: String): Int? = (this[key] as? JsonPrimitive)?.intOrNull

    private val ID = Regex("^[0-9a-f]{32}$")
    private val CODE = Regex("^[ -~]{1,160}$")
}

/**
 * A session with a temporary prover (diw-server prover, DESIGN 3.10). The pairing code's secret only keys an HMAC
 * once; the session key comes from it and both nonces. TLS is pinned to the certificate the code names, and every
 * call also carries a sealed counter, method and path with sealed bodies, so nothing on the network can read or
 * replay it. Kept in memory only.
 */
class ZkPassportPairedClient private constructor(
    override val url: String,
    private val socketFactory: SSLSocketFactory,
    private val session: String,
    private val key: SecretKeySpec,
) : ZkPassportPairedProver, ZkPassportRemote.Transport {
    private val counter = AtomicLong(0)

    override suspend fun call(method: String, path: String, body: JsonObject?): Pair<Int, JsonObject?> {
        val n = counter.incrementAndGet()
        val claims = buildJsonObject {
            put("n", n)
            put("m", method)
            put("p", path)
        }.toString().encodeToByteArray()
        val auth = "DIW-Session $session." + encrypt(key, claims, "$AUTH $session")
        val sealed = body?.let { buildJsonObject { put("sealed", encrypt(key, it.toString().encodeToByteArray(), "$session $n request")) } }
        val (code, reply) = exchange(url, socketFactory, method, path, auth, sealed)
        if (code !in 200..299 || reply == null) return code to reply
        val opened = (reply["sealed"] as? JsonPrimitive)?.contentOrNull?.let { decrypt(key, it, "$session $n response") }
            ?: throw ZkPassportProver.Failure("remote_protocol")
        return code to ZkPassportRemote.parse(opened.decodeToString())
    }

    override suspend fun end() {
        runCatching { call("DELETE", "/zkpassport/v1/pair", null) }
    }

    companion object {
        private const val AUTH = "diw-prover auth v1"
        private val PAIR = "diw-prover pair v1".encodeToByteArray()
        private val SESSION = "diw-prover session v1".encodeToByteArray()
        private val B64 = Base64.getUrlEncoder().withoutPadding()
        private val B64D = Base64.getUrlDecoder()

        /** The prover's https address, pairing secret and certificate hash from its code; null when malformed. */
        fun parse(link: String): Triple<String, ByteArray, ByteArray>? {
            val text = link.trim()
            if (!ZkPassportPairingLink.looksLike(text)) return null
            val query = text.removePrefix(ZkPassportPairingLink.PREFIX).split('&').associate {
                it.substringBefore('=') to runCatching { URLDecoder.decode(it.substringAfter('=', ""), "UTF-8") }.getOrDefault("")
            }
            val url = query["u"]?.trimEnd('/') ?: return null
            val uri = runCatching { URI(url) }.getOrNull() ?: return null
            if (uri.scheme != "https" || uri.port !in 1..65535 || uri.rawPath.orEmpty().isNotEmpty() || uri.query != null) return null
            // Passport data goes only to a private-network address the user's own computer has.
            if (!privateLiteral(uri.host ?: return null)) return null
            val secret = runCatching { B64D.decode(query["p"]) }.getOrNull()?.takeIf { it.size == 32 } ?: return null
            val pin = runCatching { B64D.decode(query["c"]) }.getOrNull()?.takeIf { it.size == 32 } ?: return null
            return Triple(url, secret, pin)
        }

        /** Pairs with the prover [link] names; the link is spent on the prover either way. */
        suspend fun pair(link: String): ZkPassportPairedClient {
            val (url, secret, pin) = parse(link) ?: throw ZkPassportProver.Failure("pairing_link")
            val factory = pinned(pin)
            val nonce = ByteArray(16).also(SecureRandom()::nextBytes)
            val body = buildJsonObject {
                put("nonce", B64.encodeToString(nonce))
                put("mac", B64.encodeToString(hmac(secret, PAIR, nonce)))
            }
            val (code, reply) = exchange(url, factory, "POST", "/zkpassport/v1/pair", null, body)
            when (code) {
                200 -> {}
                401 -> throw ZkPassportProver.Failure("pairing_refused")
                410 -> throw ZkPassportProver.Failure("pairing_used")
                else -> throw ZkPassportProver.Failure("pairing_http_$code")
            }
            val session = (reply?.get("session") as? JsonPrimitive)?.contentOrNull?.takeIf { Regex("^[0-9a-f]{32}$").matches(it) }
                ?: throw ZkPassportProver.Failure("remote_protocol")
            val serverNonce = (reply["nonce"] as? JsonPrimitive)?.contentOrNull?.let { runCatching { B64D.decode(it) }.getOrNull() }
                ?.takeIf { it.size == 16 } ?: throw ZkPassportProver.Failure("remote_protocol")
            return ZkPassportPairedClient(url, factory, session, SecretKeySpec(hmac(secret, SESSION, nonce + serverNonce), "AES"))
        }

        /** IPv4 private, loopback, link-local and 100.64/10, or IPv6 loopback, link-local and ULA; a literal only. */
        internal fun privateLiteral(host: String): Boolean {
            val bare = host.removePrefix("[").removeSuffix("]")
            if (bare.isEmpty() || !bare.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it in ".:" }) return false
            val a = runCatching { InetAddress.getByName(bare) }.getOrNull() ?: return false
            if (a.isLoopbackAddress || a.isSiteLocalAddress || a.isLinkLocalAddress) return true
            val b = a.address
            return when (b.size) {
                4 -> (b[0].toInt() and 0xff) == 100 && (b[1].toInt() and 0xc0) == 64
                16 -> (b[0].toInt() and 0xfe) == 0xfc
                else -> false
            }
        }

        /** Trusts exactly the certificate whose SHA-256 is [pin]; the pin, not a name or a CA, is the prover's identity. */
        private fun pinned(pin: ByteArray): SSLSocketFactory {
            val trust = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = throw CertificateException("no client certificates")
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                    val leaf = chain.firstOrNull() ?: throw CertificateException("no certificate")
                    if (!MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(leaf.encoded), pin)) {
                        throw CertificateException("not the paired prover's certificate")
                    }
                }
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            return SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), SecureRandom()) }.socketFactory
        }

        private suspend fun exchange(
            base: String, factory: SSLSocketFactory, method: String, path: String, authorization: String?, body: JsonObject?,
        ): Pair<Int, JsonObject?> = withContext(Dispatchers.IO) {
            try {
                val connection = URL(base + path).openConnection() as HttpsURLConnection
                try {
                    connection.sslSocketFactory = factory
                    connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                    connection.instanceFollowRedirects = false
                    connection.connectTimeout = 10_000
                    connection.readTimeout = 60_000
                    connection.requestMethod = method
                    authorization?.let { connection.setRequestProperty("Authorization", it) }
                    if (body != null) {
                        connection.doOutput = true
                        connection.setRequestProperty("Content-Type", "application/json")
                        connection.outputStream.use { it.write(body.toString().encodeToByteArray()) }
                    }
                    val code = connection.responseCode
                    val stream = if (code >= HttpURLConnection.HTTP_BAD_REQUEST) connection.errorStream else connection.inputStream
                    val text = stream?.use { it.readBytes().decodeToString() }.orEmpty()
                    code to ZkPassportRemote.parse(text)
                } finally {
                    connection.disconnect()
                }
            } catch (e: IOException) {
                throw ZkPassportProver.Failure("remote_unreachable")
            }
        }

        private fun hmac(key: ByteArray, label: ByteArray, data: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(label + data)

        private fun encrypt(key: SecretKeySpec, plain: ByteArray, aad: String): String {
            val iv = ByteArray(12).also(SecureRandom()::nextBytes)
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
                updateAAD(aad.encodeToByteArray())
            }
            return B64.encodeToString(iv + c.doFinal(plain))
        }

        private fun decrypt(key: SecretKeySpec, sealed: String, aad: String): ByteArray? = runCatching {
            val bytes = B64D.decode(sealed)
            require(bytes.size > 28)
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes, 0, 12))
                updateAAD(aad.encodeToByteArray())
            }.doFinal(bytes, 12, bytes.size - 12)
        }.getOrNull()
    }
}
