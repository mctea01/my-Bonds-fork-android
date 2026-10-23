package diw.wallet.core.zktls

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vci.X509CertChainCheck
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.http.decodeURLQueryComponent
import io.ktor.http.encodeURLParameter
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** Where the holder reaches the verifier; the channel inside is always Noise, so none of these is trusted. */
sealed interface ZkTlsTransport {
    /** A verifier server (the test server, a desktop with a public address): binary WebSocket frames. */
    data class Wss(val url: String) : ZkTlsTransport

    /** A verifier phone on the same Wi-Fi or hotspot: TCP to a private IPv4 address with length-prefixed frames. */
    data class Lan(val host: String, val port: Int) : ZkTlsTransport

    /** Both sides join [room] on a relay that only forwards bytes. */
    data class Relay(val url: String, val room: String) : ZkTlsTransport

    fun toJson(): JsonObject = when (this) {
        is Wss -> buildJsonObject { put("type", "wss"); put("url", url) }
        is Lan -> buildJsonObject { put("type", "lan"); put("host", host); put("port", port) }
        is Relay -> buildJsonObject { put("type", "relay"); put("url", url); put("room", room) }
    }

    companion object {
        /** Null for an unknown or malformed entry, which the holder skips. */
        fun parse(o: JsonObject, insecureHosts: Set<String> = emptySet()): ZkTlsTransport? = when (o.str("type")) {
            "wss" -> o.str("url")?.takeIf { webSocketUrl(it, insecureHosts) }?.let { Wss(it) }
            "lan" -> {
                val host = o.str("host")?.takeIf { BondsAgeRequest.lanHost(it) }
                val port = (o["port"] as? JsonPrimitive)?.content?.toIntOrNull()?.takeIf { it in 1..65535 }
                if (host != null && port != null) Lan(host, port) else null
            }
            "relay" -> {
                val url = o.str("url")?.takeIf { webSocketUrl(it, insecureHosts) }
                val room = o.str("room")?.takeIf { runCatching { it.fromBase64Url().size == 16 }.getOrDefault(false) }
                if (url != null && room != null) Relay(url, room) else null
            }
            else -> null
        }

        /** wss, or ws to a test host the user allowed in the test environment. */
        fun webSocketUrl(url: String, insecureHosts: Set<String>): Boolean = runCatching {
            val u = io.ktor.http.Url(url)
            (u.protocol.name == "wss" || u.protocol.name == "ws" && "${u.host}:${u.port}" in insecureHosts) && u.host.isNotEmpty() &&
                u.user == null && u.password == null && '#' !in url && url.length <= 512
        }.getOrDefault(false)
    }
}

/**
 * The signed request a verifier shows as `diw-zktls://v1?request=<JWS>` (p4-zkp.md section 5.2). [verifierStatic] is
 * the verifier's X25519 key for this session: the Noise channel is keyed to it and its prologue is the SHA-256 of the
 * request JWS ([hash]), so the channel belongs to this one signed request. [profileDefinition] carries a profile the
 * holder does not have built in; the holder accepts it only in the test environment.
 */
data class ZkTlsSessionRequest(
    val sessionId: String,
    val transports: List<ZkTlsTransport>,
    val verifierStatic: ByteArray,
    val profileId: String,
    val fields: List<String>,
    val nonce: String,
    val purpose: String,
    val mode: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val profileDefinition: JsonObject? = null,
) {
    fun payload(): JsonObject = buildJsonObject {
        put("sid", sessionId)
        putJsonArray("transport") { transports.forEach { add(it.toJson()) } }
        put("ck", verifierStatic.toBase64Url())
        put("profile", profileId)
        profileDefinition?.let { put("profile_def", it) }
        putJsonArray("fields") { fields.forEach { add(it) } }
        put("nonce", nonce)
        put("purpose", purpose)
        put("mode", mode)
        put("iat", issuedAt.epochSeconds)
        put("exp", expiresAt.epochSeconds)
    }

    fun isFresh(now: Instant): Boolean = now >= issuedAt - CLOCK_SKEW && now <= expiresAt

    override fun equals(other: Any?): Boolean = other is ZkTlsSessionRequest && payload() == other.payload()

    override fun hashCode(): Int = payload().hashCode()

    companion object {
        const val TYP = "zktls-req+jwt"
        const val SCHEME = "diw-zktls://v1?request="
        val MAX_LIFETIME = 10.minutes
        private val CLOCK_SKEW = 60.seconds
        const val MAX_PURPOSE = 100
        val MODES = setOf("proxy", "mpc")

        fun looksLike(text: String): Boolean = text.trim().startsWith(SCHEME)

        /** The JWS out of a scanned link. */
        fun jwsOf(link: String): String {
            val t = link.trim()
            if (!t.startsWith(SCHEME)) throw ProtocolException("invalid_request", "Not a zkTLS request link")
            return t.removePrefix(SCHEME).decodeURLQueryComponent()
        }

        fun link(jws: String): String = SCHEME + jws.encodeURLParameter()

        /** SHA-256 of the request JWS: the Noise prologue, binding the channel to this request. */
        fun hash(jws: String): ByteArray = PlatformCrypto.sha256(jws.trim().encodeToByteArray())

        fun create(
            transports: List<ZkTlsTransport>,
            verifierStatic: ByteArray,
            profile: ZkTlsProfile,
            fields: List<String>,
            purpose: String,
            mode: String = "proxy",
            now: Instant = Clock.System.now(),
            lifetime: kotlin.time.Duration = MAX_LIFETIME,
            inlineProfile: Boolean = false,
            sessionId: String = PlatformCrypto.randomBytes(16).toBase64Url(),
        ): ZkTlsSessionRequest {
            if (transports.isEmpty()) throw ProtocolException("invalid_request", "No transport")
            if (verifierStatic.size != 32) throw ProtocolException("invalid_request", "The verifier key must be an X25519 public key")
            if (fields.isEmpty() || fields.any { profile.field(it) == null }) throw ProtocolException("invalid_request", "Unknown field")
            if (mode !in MODES) throw ProtocolException("invalid_request", "Unknown mode")
            val p = purpose.trim().filter { !it.isISOControl() }.take(MAX_PURPOSE)
            val issued = Instant.fromEpochSeconds(now.epochSeconds)
            return ZkTlsSessionRequest(
                sessionId, transports, verifierStatic, profile.id, fields.distinct(),
                PlatformCrypto.randomBytes(16).toBase64Url(), p, mode, issued, issued + minOf(lifetime, MAX_LIFETIME),
                if (inlineProfile) DiwJson.encodeToJsonElement(ZkTlsProfile.serializer(), profile) as JsonObject else null,
            )
        }

        /** Signs [request] as a zktls-req+jwt: with [chain] in x5c, or under [did] (its first verification method). */
        suspend fun sign(request: ZkTlsSessionRequest, key: AsymmetricKey, did: String? = null, chain: List<X509Cert>? = null): String {
            val header = buildJsonObject {
                put("alg", "ES256")
                put("typ", TYP)
                if (chain != null) putJsonArray("x5c") { chain.forEach { add(it.encoded.toByteArray().toBase64()) } }
                else put("kid", DidKeys.verificationMethod(did ?: throw ProtocolException("invalid_request", "A DID or a chain is required")))
            }
            return signJws(header, request.payload(), key)
        }

        /**
         * Verifies [jws] with the key in its x5c leaf or its kid's DID and reads it. The caller decides how far the
         * verifier is trusted from [Verified.chain] or [Verified.did].
         */
        suspend fun verify(jws: String, didResolver: DidResolver, now: Instant = Clock.System.now(), insecureHosts: Set<String> = emptySet()): Verified {
            val parsed = Jws.parse(jws)
            if (parsed.typ != TYP) throw ProtocolException("invalid_request", "Not a zkTLS request")
            if (parsed.alg != "ES256") throw ProtocolException("invalid_request", "Unsupported algorithm ${parsed.alg}")
            val chain = parsed.x5c?.certificates
            var did: String? = null
            if (chain != null && chain.isNotEmpty()) {
                X509CertChainCheck.validate(chain)
                parsed.verify(VerificationKey.fromCertificate(chain.first()))
            } else {
                val kid = parsed.kid ?: throw ProtocolException("invalid_request", "The request names no key")
                did = kid.substringBefore('#').takeIf { it.startsWith("did:") } ?: throw ProtocolException("invalid_request", "kid is not a DID URL")
                parsed.verify(didResolver.resolveKey(did, kid).key)
            }
            val request = read(parsed.payload, insecureHosts)
            if (!request.isFresh(now)) throw ProtocolException("expired_request", "The request has expired")
            return Verified(request, jws.trim(), chain, did)
        }

        fun read(o: JsonObject, insecureHosts: Set<String> = emptySet()): ZkTlsSessionRequest {
            fun bad(what: String): Nothing = throw ProtocolException("invalid_request", "Malformed $what")
            val transports = (o["transport"] as? JsonArray)?.mapNotNull { (it as? JsonObject)?.let { t -> ZkTlsTransport.parse(t, insecureHosts) } }
                ?.takeIf { it.isNotEmpty() } ?: bad("transport (none usable)")
            val ck = runCatching { o.str("ck")!!.fromBase64Url() }.getOrNull()?.takeIf { it.size == 32 } ?: bad("verifier key")
            val iat = (o["iat"] as? JsonPrimitive)?.content?.toLongOrNull() ?: bad("iat")
            val exp = (o["exp"] as? JsonPrimitive)?.content?.toLongOrNull() ?: bad("exp")
            if (exp <= iat || exp - iat > MAX_LIFETIME.inWholeSeconds) bad("lifetime")
            val nonce = o.str("nonce")?.takeIf { runCatching { it.fromBase64Url().size >= 16 }.getOrDefault(false) } ?: bad("nonce")
            val mode = o.str("mode")?.takeIf { it in MODES } ?: bad("mode")
            val fields = o.strList("fields").distinct().takeIf { it.isNotEmpty() } ?: bad("fields")
            return ZkTlsSessionRequest(
                o.str("sid")?.takeIf { it.length in 8..64 } ?: bad("sid"), transports, ck, o.str("profile") ?: bad("profile"),
                fields, nonce, o.str("purpose").orEmpty().filter { !it.isISOControl() }.take(MAX_PURPOSE), mode,
                Instant.fromEpochSeconds(iat), Instant.fromEpochSeconds(exp), o["profile_def"] as? JsonObject,
            )
        }
    }

    /** A request whose signature was checked; who signed it is in [chain] (x5c) or [did]. */
    class Verified(val request: ZkTlsSessionRequest, val jws: String, val chain: List<X509Cert>?, val did: String?) {
        val hash: ByteArray get() = hash(jws)
    }
}
