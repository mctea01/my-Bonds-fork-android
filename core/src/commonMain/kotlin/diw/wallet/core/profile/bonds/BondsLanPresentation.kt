package diw.wallet.core.profile.bonds

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.JsonWebEncryption
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url

/**
 * Bonds offline presentations over the local network, this wallet's extension (Bonds ignores the keys): the verifier
 * listens on its Wi-Fi or hotspot addresses ([BondsLanLink]) and its challenge carries those http URLs (l) and a one-time
 * P-256 key (e). The holder posts {"jwe": ...}, the presentation JWS sealed to that key (ECDH-ES, A256GCM), because
 * unlike an age proof a presentation carries claim values and anyone on the same network can read clear text. The
 * reply only says whether the verifier took it; the verdict is on the verifier's screen.
 */
object BondsLanPresentation {
    /** Upper bound of a posted body: the largest presentation the other transports carry, sealed and base64url encoded. */
    const val MAX_BODY = BondsLinkTransport.MAX_PAYLOAD * 3 / 2 + 4096
    private const val MAX_URL = 200

    /** Plain http to a private IPv4 literal, no credentials or fragment. */
    fun acceptableUrl(url: String): Boolean = url.length <= MAX_URL && '#' !in url && runCatching {
        Url(url).let { it.protocol == URLProtocol.HTTP && BondsAgeRequest.lanHost(it.host) && it.user == null && it.password == null }
    }.getOrDefault(false)

    /**
     * The URLs of an l key: absent gives an empty list, one URL or an array of up to [MAX_LAN_URLS]; null when
     * malformed. Each URL is checked by the request that carries them.
     */
    fun urlList(element: JsonElement?): List<String>? = when (element) {
        null -> emptyList()
        is JsonPrimitive -> element.takeIf { it.isString }?.let { listOf(it.content) }
        is JsonArray -> element.takeIf { it.size in 1..MAX_LAN_URLS }
            ?.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: return null }
        else -> null
    }

    fun acceptableKey(text: String): Boolean = runCatching { publicKey(text) }.isSuccess

    /** A fresh key for one challenge; it never leaves the verifier's memory. */
    suspend fun newKey(): EcPrivateKey = Crypto.createEcPrivateKey(EcCurve.P256)

    /** The public key as it goes into the challenge. */
    fun keyText(key: EcPublicKey): String =
        (key as? EcPublicKeyDoubleCoordinate ?: throw ProtocolException("invalid_request", "Unsupported key")).asUncompressedPointEncoding.toBase64Url()

    fun publicKey(text: String): EcPublicKey {
        val bytes = text.fromBase64Url()
        if (bytes.size != 65 || bytes[0] != 4.toByte()) throw ProtocolException("invalid_request", "Not an uncompressed P-256 point")
        return EcPublicKeyDoubleCoordinate.fromUncompressedPointEncoding(EcCurve.P256, bytes)
    }

    /** The body the holder posts: [presentationJws] sealed to the challenge's key. */
    suspend fun seal(presentationJws: String, request: BondsPresentationRequest): ByteArray {
        val key = publicKey(request.lanKey ?: throw ProtocolException("invalid_request", "The challenge has no local network key"))
        val jwe = JsonWebEncryption.encrypt(
            claimsSet = buildJsonObject { put("vp", presentationJws) },
            recipientPublicKey = key,
            encAlg = Algorithm.A256GCM,
            apu = ByteString(PlatformCrypto.randomBytes(16)),
            apv = ByteString(request.challenge.encodeToByteArray()),
        )
        return buildJsonObject { put("jwe", jwe) }.toString().encodeToByteArray()
    }

    /**
     * The presentation in a posted [body], opened with the verifier's [key]. Only a presentation that answers
     * [request]'s challenge is returned; the full check is [BondsOfflineVerifier]'s.
     */
    suspend fun open(body: ByteArray, key: EcPrivateKey, request: BondsPresentationRequest): String {
        val jwe = runCatching { (DiwJson.parseToJsonElement(body.decodeToString()) as JsonObject).str("jwe") }.getOrNull()
            ?: throw ProtocolException("invalid_presentation", "Not a sealed presentation")
        val claims = runCatching { JsonWebEncryption.decrypt(jwe, AsymmetricKey.AnonymousExplicit(key, Algorithm.ECDH_P256)) }.getOrNull()
            ?: throw ProtocolException("invalid_presentation", "Not sealed to this challenge")
        val jws = claims.str("vp") ?: throw ProtocolException("invalid_presentation", "No presentation")
        val vp = runCatching { Jws.parse(jws.trim()).payload }.getOrNull() ?: throw ProtocolException("invalid_presentation", "Unreadable presentation")
        if (vp.str("challenge") != request.challenge) throw ProtocolException("invalid_presentation", "Challenge mismatch")
        return jws.trim()
    }

    fun received(): ByteArray = """{"status":"received"}""".encodeToByteArray()

    fun refused(reason: String): ByteArray = buildJsonObject {
        put("status", "failed")
        put("reason", reason)
    }.toString().encodeToByteArray()

    /** Null when the verifier took the presentation, else its reason (or the HTTP status). */
    fun refusal(status: Int, text: String): String? {
        val o = runCatching { DiwJson.parseToJsonElement(text) as? JsonObject }.getOrNull()
        if (status == 200 && o?.str("status") == "received") return null
        return o?.str("reason") ?: "HTTP $status"
    }
}
