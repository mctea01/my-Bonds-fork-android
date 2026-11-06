package diw.wallet.core.zkpassport

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.bouncycastle.asn1.sec.SECNamedCurves
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.zip.Deflater
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The creator side of zkPassport's bridge (@obsidion/bridge, protocol 1): a secp256k1 key whose compressed public
 * key is the bridge id, ECDH with the holder's key, AES-GCM under the first 32 bytes of the compressed shared point
 * with one nonce per session (SHA-256 of the bridge id, 12 bytes), zlib-compressed JSON in 16 KB chunks. The fixed
 * nonce is the bridge's own design (reported to its maintainers); messages here never carry secrets of this wallet.
 * Pure frame-in, frames-out logic so it can be tested without a network.
 */
class ZkPassportBridgeProtocol(random: SecureRandom = SecureRandom()) {
    sealed interface Event {
        data object Handshake : Event
        data class Message(val method: String, val params: JsonElement) : Event
    }

    private val curve = SECNamedCurves.getByName("secp256k1")
    private val privateKey: BigInteger
    val publicKey: ByteArray
    val bridgeId: String
    private var key: ByteArray? = null
    private var remote: ByteArray? = null
    private val seen = LinkedHashSet<String>()
    private val chunks = HashMap<String, Array<String?>>()
    private val random = random
    var lastMessageMillis = 0L
        private set

    init {
        var d: BigInteger
        do {
            d = BigInteger(1, ByteArray(32).also { random.nextBytes(it) })
        } while (d.signum() == 0 || d >= curve.n)
        privateKey = d
        publicKey = curve.g.multiply(d).normalize().getEncoded(true)
        bridgeId = hex(publicKey)
    }

    val established: Boolean get() = key != null

    /** Handles one text frame; returns the frames to send back and the events for the session. */
    fun receive(text: String, nowMillis: Long): Pair<List<String>, List<Event>> {
        val data = runCatching { Json.parseToJsonElement(text).jsonObject }.getOrNull() ?: return none
        val method = data["method"].text()
        if (method == "ping") return listOf(control("pong")) to emptyList()
        val id = data["id"].text() ?: return none
        if (method == "encryptedMessage" && key == null) return none
        if (!seen.add(id)) return none
        if (seen.size > 4096) seen.remove(seen.first())
        lastMessageMillis = nowMillis
        val params = data["params"] as? JsonObject ?: return none
        return when (method) {
            "handshake" -> handshake(params)
            "encryptedMessage" -> emptyList<String>() to listOfNotNull(decrypted(params["payload"].text() ?: return none))
            else -> none
        }
    }

    private fun handshake(params: JsonObject): Pair<List<String>, List<Event>> {
        val pub = params["pubkey"].text()?.let(::unhex) ?: return none
        if (remote != null && !remote.contentEquals(pub)) return none
        val shared = runCatching { curve.curve.decodePoint(pub).multiply(privateKey).normalize().getEncoded(true).copyOf(32) }
            .getOrNull() ?: return none
        val greeting = params["greeting"].text()?.let(::unhex) ?: return none
        if (runCatching { aes(Cipher.DECRYPT_MODE, shared, greeting).decodeToString() }.getOrNull() != "hello") return none
        val first = remote == null
        remote = pub
        key = shared
        return encrypted("hello", null) to if (first) listOf(Event.Handshake) else emptyList()
    }

    private fun decrypted(payload: String): Event? {
        val k = key ?: return null
        val plain = runCatching { aes(Cipher.DECRYPT_MODE, k, Base64.getDecoder().decode(payload)).decodeToString() }.getOrNull() ?: return null
        val inner = runCatching { Json.parseToJsonElement(plain).jsonObject }.getOrNull() ?: return null
        val method = inner["method"].text() ?: return null
        val chunk = inner["chunk"] as? JsonObject
        val params = inner["params"] ?: JsonNull
        if (chunk == null) return Event.Message(method, decode(params) ?: return null)
        val id = chunk["id"].text() ?: return null
        val index = (chunk["index"] as? JsonPrimitive)?.intOrNull ?: return null
        val length = (chunk["length"] as? JsonPrimitive)?.intOrNull ?: return null
        if (length !in 1..MAX_CHUNKS || index !in 0 until length) return null
        if (chunks.size > 32 && id !in chunks) return null
        val parts = chunks.getOrPut(id) { arrayOfNulls(length) }
        if (parts.size != length) return null
        parts[index] = params.text() ?: return null
        if (parts.any { it == null }) return null
        chunks.remove(id)
        return Event.Message(method, decode(JsonPrimitive(parts.joinToString(""))) ?: return null)
    }

    /** Params arrive as base64 zlib JSON, or as JSON itself. */
    private fun decode(params: JsonElement): JsonElement? {
        val s = (params as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return params
        if (s.isEmpty()) return JsonObject(emptyMap())
        val inflated = runCatching { inflate(Base64.getDecoder().decode(s)).decodeToString() }.getOrNull()
        return runCatching { Json.parseToJsonElement(inflated ?: s) }.getOrNull()
    }

    /** Frames carrying [method]: one plain frame without params, otherwise 16 KB chunks of base64 zlib JSON. */
    fun encrypted(method: String, params: JsonElement?): List<String> {
        val k = key ?: return emptyList()
        val messages = if (params == null) {
            listOf(buildJsonObject { put("method", method); putJsonObject("params") {} })
        } else {
            val compressed = Base64.getEncoder().encodeToString(deflate(Json.encodeToString(JsonElement.serializer(), params).encodeToByteArray()))
            val pieces = compressed.chunked(CHUNK)
            val id = hex(ByteArray(16).also { random.nextBytes(it) })
            pieces.mapIndexed { i, piece ->
                buildJsonObject {
                    put("method", method)
                    put("params", piece)
                    putJsonObject("chunk") { put("id", id); put("index", i); put("length", pieces.size) }
                }
            }
        }
        return messages.map { inner ->
            val id = hex(ByteArray(16).also { random.nextBytes(it) })
            seen.add(id)
            val payload = Base64.getEncoder().encodeToString(aes(Cipher.ENCRYPT_MODE, k, inner.toString().encodeToByteArray()))
            buildJsonObject {
                put("jsonrpc", "2.0")
                put("id", id)
                put("method", "encryptedMessage")
                putJsonObject("params") { put("payload", payload) }
            }.toString()
        }
    }

    /** Asks the bridge for the messages missed while disconnected. */
    fun replay(): String? = lastMessageMillis.takeIf { it > 0 }?.let {
        buildJsonObject { put("method", "replay"); putJsonObject("params") { put("timestamp", maxOf(1L, it - 1000)) } }.toString()
    }

    fun ping(): String = control("ping")

    private fun control(method: String) =
        buildJsonObject { put("method", method); putJsonObject("params") {}; put("nocache", true) }.toString()

    private fun aes(mode: Int, key: ByteArray, input: ByteArray): ByteArray {
        val nonce = MessageDigest.getInstance("SHA-256").digest(bridgeId.encodeToByteArray()).copyOf(12)
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            doFinal(input)
        }
    }

    companion object {
        const val URL = "wss://bridge.zkpassport.id"
        private const val CHUNK = 16 * 1024
        private const val MAX_CHUNKS = 256
        private const val MAX_INFLATED = 8 * 1024 * 1024
        private val none = emptyList<String>() to emptyList<Event>()

        private fun JsonElement?.text(): String? = (this as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 255) }

        fun unhex(s: String): ByteArray? {
            val h = s.removePrefix("0x")
            if (h.length % 2 != 0 || h.any { Character.digit(it, 16) < 0 }) return null
            return ByteArray(h.length / 2) { ((Character.digit(h[2 * it], 16) shl 4) or Character.digit(h[2 * it + 1], 16)).toByte() }
        }

        fun deflate(input: ByteArray): ByteArray {
            val d = Deflater()
            d.setInput(input)
            d.finish()
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (!d.finished()) out.write(buffer, 0, d.deflate(buffer))
            d.end()
            return out.toByteArray()
        }

        fun inflate(input: ByteArray): ByteArray {
            val i = Inflater()
            i.setInput(input)
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            try {
                while (!i.finished()) {
                    val n = i.inflate(buffer)
                    if (n == 0 && (i.needsInput() || i.needsDictionary())) error("truncated")
                    out.write(buffer, 0, n)
                    if (out.size() > MAX_INFLATED) error("too_large")
                }
            } finally {
                i.end()
            }
            return out.toByteArray()
        }
    }
}
