package diw.wallet.core.profile.bonds

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.Jcs
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.w3c.SdJwtDisclosures
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import kotlinx.datetime.DatePeriod
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.minus
import kotlinx.datetime.toLocalDateTime
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/**
 * A Bonds age proof request: the JSON QR a Bonds web verifier shows,
 * {v:1, a:age, b:request id, c:nonce, d:cutoff date, p:purpose, s:g|s, t:seconds, u:response URL}. With u the holder
 * posts an OpenAC proof to [responseUrl]; without it (Bonds' two-device flow) b is the one-time BLE service the
 * holder advertises, and the package goes to the verifier's phone over the Bonds link with no server in between.
 * This wallet also accepts a plain http u on a local network address ([lan]): the verifier's phone listens there
 * (BondsLanLink). Everything in it is untrusted text from the verifier.
 */
data class BondsAgeRequest(
    val minimumAge: Int,
    val requestId: String,
    /** base64url of 32 random bytes; the proof binds its UTF-8 text. */
    val nonce: String,
    /** The latest birth date that meets [minimumAge] on the verifier's day. */
    val cutoff: LocalDate,
    val purpose: String,
    val source: BondsCredentialSource,
    val createdAt: Instant,
    /** Where the package is posted; null for a nearby request answered over Bluetooth. */
    val responseUrl: String?,
) {
    val nearby: Boolean get() = responseUrl == null

    /** The one-time BLE service UUID of a nearby request (Bonds uses the request id), which the holder advertises. */
    val linkServiceId: String? get() = requestId.takeIf { nearby }

    val responseHost: String? get() = responseUrl?.let { Url(it).host }

    /** Answered over the local network: plain http to a private or loopback IPv4 address (this wallet's extension). */
    val lan: Boolean get() = responseUrl?.let { runCatching { Url(it) }.getOrNull() }?.let { it.protocol == URLProtocol.HTTP && lanHost(it.host) } == true

    /** Response hosts Bonds itself allows; another host is shown to the user as unknown, not refused. */
    val knownHost: Boolean get() = responseHost in KNOWN_HOSTS

    /** The verifier forgets the request after this. */
    val expiresAt: Instant get() = createdAt + LIFETIME

    /** Within Bonds' window: at most a minute ahead of this clock and no older than [LIFETIME]. */
    fun isFresh(now: Instant): Boolean = (now - createdAt).let { it >= -CLOCK_SKEW && it <= LIFETIME }

    /** The cutoff as the circuit's integer for [claimFormat]: YYYYMMDD (ISO) or ROC year, month and day. */
    fun cutoffValue(claimFormat: Int): Long = when (claimFormat) {
        FORMAT_ISO -> cutoff.year * 10_000L + cutoff.monthNumber * 100 + cutoff.dayOfMonth
        FORMAT_ROC -> (cutoff.year - 1911).takeIf { it > 0 }?.let { it * 10_000L + cutoff.monthNumber * 100 + cutoff.dayOfMonth }
            ?: throw ProtocolException("invalid_request", "Cutoff before the ROC calendar")
        else -> throw ProtocolException("invalid_request", "Unsupported birth date format $claimFormat")
    }

    /** The QR text, in Bonds' key order. */
    fun encode(): String = buildJsonObject {
        put("a", minimumAge)
        put("b", requestId)
        put("c", nonce)
        put("d", cutoff.toString())
        put("p", purpose)
        put("s", source.wire)
        put("t", createdAt.epochSeconds)
        responseUrl?.let { put("u", it) }
        put("v", VERSION)
    }.toString()

    companion object {
        const val VERSION = 1
        const val NONCE_BYTES = 32
        const val MAX_URL = 512
        const val FORMAT_ISO = 2
        const val FORMAT_ROC = 3
        val LIFETIME = 5.minutes
        private val CLOCK_SKEW = 60.seconds
        val KNOWN_HOSTS = setOf("verifier.mashbean.net")
        private val UUID_RE = Regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
        private val DATE_RE = Regex("^\\d{4}-\\d{2}-\\d{2}$")
        private val TAIPEI = TimeZone.of("Asia/Taipei")

        /**
         * A fresh request answered at [responseUrl], or over the link when it is null: a random id (the BLE service)
         * and nonce, and the cutoff [minimumAge] years before today in Taiwan, as Bonds computes it (29 February falls
         * back to 28 February).
         */
        fun create(minimumAge: Int, source: BondsCredentialSource, purpose: String, responseUrl: String?, now: Instant = Clock.System.now()): BondsAgeRequest {
            if (minimumAge !in 1..120) throw ProtocolException("invalid_request", "Minimum age out of range")
            if (source == BondsCredentialSource.ANY) throw ProtocolException("invalid_request", "Age requests name g or s")
            val today = now.toLocalDateTime(TAIPEI).date
            return BondsAgeRequest(
                minimumAge, BondsPresentationRequest.randomUuid(), PlatformCrypto.randomBytes(NONCE_BYTES).toBase64Url(),
                today.minus(DatePeriod(years = minimumAge)), purpose.filter { !it.isISOControl() }.take(BondsPresentationRequest.MAX_PURPOSE),
                source, Instant.fromEpochSeconds(now.epochSeconds), responseUrl,
            )
        }

        private fun json(text: String): JsonObject? = text.trim().takeIf { it.startsWith("{") }
            ?.let { runCatching { DiwJson.parseToJsonElement(it) as? JsonObject }.getOrNull() }

        /** True for a JSON object with a nonce, a minimum age and a cutoff: an age request, never a presentation challenge. */
        fun looksLike(text: String): Boolean = json(text)?.let { "c" in it && "v" in it && "a" in it && "d" in it } == true

        /**
         * Safe to post to: https, a host, no credentials or fragment, as Bonds requires. Plain http only for a host
         * and port in [insecureHosts] (the wallet's own test server in the test environment).
         */
        fun acceptableUrl(u: String, insecureHosts: Set<String> = emptySet()): Boolean = u.length <= MAX_URL && '#' !in u && runCatching {
            Url(u).let {
                (it.protocol == URLProtocol.HTTPS || it.protocol == URLProtocol.HTTP && ("${it.host}:${it.port}" in insecureHosts || lanHost(it.host))) &&
                    it.host.isNotEmpty() && it.user == null && it.password == null
            }
        }.getOrDefault(false)

        /** A dotted IPv4 literal in 10/8, 172.16/12, 192.168/16 or 127/8: a phone on the same Wi-Fi or hotspot, never a name. */
        fun lanHost(host: String): Boolean {
            val o = host.split('.').takeIf { it.size == 4 }?.map { p -> p.takeIf { it.isNotEmpty() && it.length <= 3 && it.all(Char::isDigit) }?.toInt() ?: return false }
                ?.takeIf { parts -> parts.all { it in 0..255 } } ?: return false
            return o[0] == 10 || o[0] == 127 || o[0] == 172 && o[1] in 16..31 || o[0] == 192 && o[1] == 168
        }

        fun parse(text: String, insecureHosts: Set<String> = emptySet()): BondsAgeRequest {
            val o = json(text) ?: throw ProtocolException("invalid_request", "This request could not be read")
            val version = (o["v"] as? JsonPrimitive)?.content?.toIntOrNull()
            if (version != VERSION) throw ProtocolException("invalid_request", "Unsupported age request version $version")
            val age = (o["a"] as? JsonPrimitive)?.content?.toIntOrNull()?.takeIf { it in 1..120 }
                ?: throw ProtocolException("invalid_request", "No minimum age")
            val id = o.str("b")?.takeIf { UUID_RE.matches(it) } ?: throw ProtocolException("invalid_request", "Malformed request id")
            val nonce = o.str("c")?.takeIf { runCatching { it.fromBase64Url().size == NONCE_BYTES }.getOrDefault(false) }
                ?: throw ProtocolException("invalid_request", "Malformed nonce")
            val cutoff = o.str("d")?.takeIf { DATE_RE.matches(it) }?.let { runCatching { LocalDate.parse(it) }.getOrNull() }
                ?: throw ProtocolException("invalid_request", "Malformed cutoff date")
            val source = BondsCredentialSource.fromWire(o.str("s"))?.takeIf { it != BondsCredentialSource.ANY }
                ?: throw ProtocolException("invalid_request", "Unknown credential source")
            val created = (o["t"] as? JsonPrimitive)?.content?.toDoubleOrNull()?.toLong() ?: throw ProtocolException("invalid_request", "No request time")
            val url = if ("u" !in o) null
            else o.str("u")?.takeIf { acceptableUrl(it, insecureHosts) } ?: throw ProtocolException("invalid_request", "The response address must be https")
            val purpose = o.str("p").orEmpty().filter { !it.isISOControl() }.take(BondsPresentationRequest.MAX_PURPOSE)
            return BondsAgeRequest(age, id, nonce, cutoff, purpose, source, Instant.fromEpochSeconds(created), url)
        }
    }
}

/**
 * What is posted to the verifier: the two linked OpenAC proofs and the statement they answer, never a claim. The JSON
 * mirrors Bonds' encoder (sorted keys, standard base64 proofs, createdAt in milliseconds).
 */
class BondsAgePackage(
    val request: BondsAgeRequest,
    val claimName: String,
    val claimFormat: Int,
    val issuerDid: String,
    val prepareProof: ByteArray,
    val showProof: ByteArray,
    val prepareMs: Long,
    val showMs: Long,
    val createdAt: Instant,
) {
    init {
        if (claimName !in BondsAgeCredential.BIRTH_CLAIMS || claimName.encodeToByteArray().size > 31 ||
            claimFormat !in setOf(BondsAgeRequest.FORMAT_ISO, BondsAgeRequest.FORMAT_ROC)
        ) throw ProtocolException("invalid_request", "The proof does not answer this request")
        if (!issuerDid.startsWith("did:key:") || issuerDid.encodeToByteArray().size > 300) {
            throw ProtocolException("invalid_request", "The issuer must be a did:key")
        }
        if (prepareProof.isEmpty() || showProof.isEmpty() || prepareProof.size > MAX_PROOF || showProof.size > MAX_PROOF) {
            throw ProtocolException("invalid_request", "Proof size out of range")
        }
        request.cutoffValue(claimFormat)
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun encode(): String = JsonObject(
        mapOf<String, JsonElement>(
            "claimFormat" to JsonPrimitive(claimFormat),
            "claimName" to JsonPrimitive(claimName),
            "createdAt" to JsonPrimitive(createdAt.toEpochMilliseconds()),
            "credentialSource" to JsonPrimitive(request.source.wire),
            "cutoffDate" to JsonPrimitive(request.cutoff.toString()),
            "issuerDID" to JsonPrimitive(issuerDid),
            "minimumAge" to JsonPrimitive(request.minimumAge),
            "prepareMilliseconds" to JsonPrimitive(prepareMs),
            "prepareProof" to JsonPrimitive(Base64.Default.encode(prepareProof)),
            "requestNonce" to JsonPrimitive(request.nonce),
            "showMilliseconds" to JsonPrimitive(showMs),
            "showProof" to JsonPrimitive(Base64.Default.encode(showProof)),
            "version" to JsonPrimitive(VERSION),
        ),
    ).toString()

    companion object {
        const val VERSION = 1
        const val MAX_PROOF = 2_000_000

        /**
         * A posted package, accepted only when its statement is exactly [request]'s: nonce, cutoff, minimum age and
         * source. The proofs themselves are checked by the OpenAC verifier.
         */
        @OptIn(ExperimentalEncodingApi::class)
        fun parse(text: String, request: BondsAgeRequest): BondsAgePackage {
            if (text.length > 3 * MAX_PROOF) throw ProtocolException("invalid_request", "Proof package too large")
            val o = runCatching { DiwJson.parseToJsonElement(text) as? JsonObject }.getOrNull()
                ?: throw ProtocolException("invalid_request", "The proof package could not be read")
            fun int(name: String) = (o[name] as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull
            fun long(name: String) = (o[name] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
            fun bytes(name: String) = o.str(name)?.let { runCatching { Base64.Default.decode(it) }.getOrNull() }
                ?: throw ProtocolException("invalid_request", "Malformed $name")
            if (int("version") != VERSION) throw ProtocolException("invalid_request", "Unsupported package version")
            if (o.str("requestNonce") != request.nonce || o.str("cutoffDate") != request.cutoff.toString() ||
                int("minimumAge") != request.minimumAge || o.str("credentialSource") != request.source.wire
            ) throw ProtocolException("invalid_request", "The proof answers a different request")
            return BondsAgePackage(
                request,
                o.str("claimName") ?: throw ProtocolException("invalid_request", "No claim name"),
                int("claimFormat") ?: throw ProtocolException("invalid_request", "No claim format"),
                o.str("issuerDID") ?: throw ProtocolException("invalid_request", "No issuer DID"),
                bytes("prepareProof"),
                bytes("showProof"),
                long("prepareMilliseconds")?.coerceAtLeast(0) ?: 0,
                long("showMilliseconds")?.coerceAtLeast(0) ?: 0,
                long("createdAt")?.let { Instant.fromEpochMilliseconds(it) } ?: throw ProtocolException("invalid_request", "No creation time"),
            )
        }
    }
}

/** The verifier's answer to a posted package; only [accepted] decides. */
data class BondsAgeVerdict(
    val status: String,
    val accepted: Boolean,
    val reason: String?,
    val minimumAge: Int?,
    /** The verifier's own verification time, when it reports one. */
    val verifyMs: Long?,
) {
    /** The verdict body Bonds' web verifier answers with. */
    fun encode(): String = buildJsonObject {
        put("status", status)
        put("accepted", accepted)
        reason?.let { put("reason", it) }
        minimumAge?.let { put("minimumAge", it) }
        verifyMs?.let { ms -> putJsonObject("timingMs") { put("verify", ms) } }
    }.toString()

    companion object {
        /** Null unless the body is a JSON object with a status and a boolean accepted. */
        fun parse(text: String): BondsAgeVerdict? {
            val o = runCatching { DiwJson.parseToJsonElement(text) as? JsonObject }.getOrNull() ?: return null
            val status = (o["status"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
            val accepted = (o["accepted"] as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull ?: return null
            val reason = (o["reason"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.take(200)
            val age = (o["minimumAge"] as? JsonPrimitive)?.content?.toIntOrNull()
            val verify = ((o["timingMs"] as? JsonObject)?.get("verify") as? JsonPrimitive)?.longOrNull
            return BondsAgeVerdict(status.take(40), accepted, reason, age, verify)
        }
    }
}

/** The SD-JWT the OpenAC circuit reads, with the issuer DID and key the proof is checked against. */
data class BondsAgeMaterial(
    val sdJwt: String,
    val issuerDid: String,
    /** base64url of the issuer key's 32 byte x and y coordinates. */
    val issuerKeyX: String,
    val issuerKeyY: String,
)

/**
 * Card material for an age proof, as Bonds builds it. A TWDIW card is used as stored, with the issuer key its did:key
 * names. A self-issued answer is a fresh SD-JWT the holder's per-card key signs over the national ID card's birth date:
 * self-asserted, since hiding a field adds no attestation the MyData document did not carry.
 */
object BondsAgeCredential {
    /** Birth date disclosure names the OpenAC circuit accepts. */
    val BIRTH_CLAIMS = setOf("roc_birthday", "birthdate", "birthday", "date_of_birth", "birth_date", "出生日期")

    /** The birth date disclosure an SD-JWT offers for a proof, or null. */
    fun birthClaim(compactSdJwt: String): String? = runCatching {
        SdJwtDisclosures.parse(compactSdJwt).disclosures.firstNotNullOfOrNull { d -> d.name?.takeIf { it in BIRTH_CLAIMS } }
    }.getOrNull()

    suspend fun twdiw(compactSdJwt: String, resolver: DidResolver): BondsAgeMaterial {
        val parts = SdJwtDisclosures.parse(compactSdJwt)
        val payload = parts.issuerJwt.split('.').getOrNull(1)?.let { DiwJson.parseToJsonElement(it.fromBase64Url().decodeToString()) as? JsonObject }
            ?: throw ProtocolException("invalid_credential", "Malformed issuer JWT")
        val issuer = payload.str("iss")?.takeIf { it.startsWith("did:key:") }
            ?: throw ProtocolException("invalid_credential", "The card's issuer is not a did:key")
        val key = (resolver.resolve(issuer).methods.singleOrNull()?.key as? VerificationKey.Ec)?.key as? EcPublicKeyDoubleCoordinate
        if (key == null || key.curve != EcCurve.P256) throw ProtocolException("invalid_credential", "The card's issuer key is not P-256")
        return BondsAgeMaterial(parts.withDisclosures(parts.disclosures), issuer, key.x.toBase64Url(), key.y.toBase64Url())
    }

    /** Seven digit ROC birth date (YYYMMDD) from the forms MyData writes; null rather than a guess. */
    fun normalizedBirthdate(raw: String): String? {
        val s = raw.map { c -> if (c in '０'..'９') '0' + (c - '０') else c }.joinToString("")
        val digits = s.filter { it.isDigit() }
        val roc = if (digits.length == 7) {
            RocDate(digits.take(3).toInt(), digits.substring(3, 5).toInt(), digits.takeLast(2).toInt())
        } else RocDate.parse(s) ?: return null
        if (roc.year <= 0 || roc.gregorian == null) return null
        return roc.year.toString().padStart(3, '0') + roc.month.toString().padStart(2, '0') + roc.day.toString().padStart(2, '0')
    }

    /** The birthdate SD-JWT for [card], issued by and bound to [holder], the card's own key; valid for five minutes. */
    suspend fun selfIssued(card: MoicaSignedCredential, holder: HolderKey, now: Instant): BondsAgeMaterial {
        val credential = card.credential()
        val subject = credential["credentialSubject"] as? JsonObject
        val key = holder.publicKey as? EcPublicKeyDoubleCoordinate
        val id = subject?.str("id")
        if (subject == null || id == null || key == null || key.curve != EcCurve.P256 || id !in setOf(holder.did, DidKeys.didKey(key))) {
            throw ProtocolException("credential_unavailable", "The national ID card is not bound to this key")
        }
        val raw = BondsOfflinePresentation.disclosableClaims(card).firstOrNull { it.first == "birthdate" }?.second ?: subject.str("birthdate")
        val birth = raw?.let { normalizedBirthdate(it) } ?: throw ProtocolException("credential_unavailable", "The card has no readable birth date")
        val disclosure = JsonArray(listOf(JsonPrimitive(PlatformCrypto.randomBytes(16).toBase64Url()), JsonPrimitive("birthdate"), JsonPrimitive(birth)))
            .toString().encodeToByteArray().toBase64Url()
        val did = DidKeys.didKeyJwkJcs(key)
        val x = key.x.toBase64Url()
        val y = key.y.toBase64Url()
        val issued = now.epochSeconds
        val header = buildJsonObject { put("alg", "ES256"); put("typ", "vc+sd-jwt") }
        val payload = buildJsonObject {
            put("iss", did)
            put("sub", did)
            put("iat", issued)
            put("nbf", issued)
            put("exp", issued + 300)
            putJsonObject("cnf") { putJsonObject("jwk") { put("kty", "EC"); put("crv", "P-256"); put("x", x); put("y", y) } }
            putJsonObject("vc") {
                putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/2018/credentials/v1")) }
                putJsonArray("type") { add(JsonPrimitive("VerifiableCredential")); add(JsonPrimitive("SelfIssuedMyDataAgeCredential")) }
                putJsonObject("credentialSubject") {
                    put("id", did)
                    put("_sd_alg", "sha-256")
                    putJsonArray("_sd") { add(JsonPrimitive(SdJwtDisclosures.digest(disclosure))) }
                }
            }
        }
        val input = Jcs.canonicalize(header).encodeToByteArray().toBase64Url() + "." + Jcs.canonicalize(payload).encodeToByteArray().toBase64Url()
        val signature = holder.signingKey("ES256").sign(input.encodeToByteArray()).toCoseEncoded().toBase64Url()
        return BondsAgeMaterial("$input.$signature~$disclosure~", did, x, y)
    }

    /** base64url of the r||s ES256 signature over the nonce's UTF-8 bytes, which the Show circuit checks against cnf. */
    suspend fun deviceSignature(nonce: String, holder: HolderKey): String =
        holder.signingKey("ES256").sign(nonce.encodeToByteArray()).toCoseEncoded().toBase64Url()
}
