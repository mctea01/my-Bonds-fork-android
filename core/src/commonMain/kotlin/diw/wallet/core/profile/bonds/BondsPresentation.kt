package diw.wallet.core.profile.bonds

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.DerivedEvidence
import diw.wallet.core.document.derived.EvidenceResult
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vci.X509CertChainCheck
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.Jcs
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import diw.wallet.core.w3c.SdJwtDisclosures
import diw.wallet.core.w3c.W3cVcCredential
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.X509Cert
import org.multipaz.revocation.RevocationStatus
import org.multipaz.sdjwt.SdJwt
import org.multipaz.util.fromBase64
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** Which stored card family a Bonds verifier asks for. */
enum class BondsCredentialSource(val wire: String) {
    /** A vc+moica card signed by its holder with the citizen digital certificate. */
    SELF_ISSUED("s"),
    /** A TWDIW card (SD-JWT issued by a government issuer). */
    TWDIW("g"),
    /**
     * Any key-bound card the holder chooses: IETF SD-JWT VC, W3C VC as SD-JWT or W3C JWT VC. An extension of this
     * wallet for its own verifier; Bonds verifiers ask for g or s.
     */
    ANY("a");

    companion object {
        fun fromWire(w: String?): BondsCredentialSource? = entries.firstOrNull { it.wire == w }
    }
}

/**
 * The challenge a Bonds verifier shows as a plain JSON QR: {v, c, p, t, a?, b?, k}. Everything in it is untrusted
 * text from the person in front of the holder; it does not authenticate the verifier. This wallet's verifier adds
 * keys Bonds ignores: l and e, a local network address and a one-time P-256 key ([BondsLanPresentation]), and q:1,
 * which says the presentation can also be shown as an animated fountain QR ([AnimatedQrTransport]).
 */
data class BondsPresentationRequest(
    val challenge: String,
    val purpose: String,
    val createdAt: Instant,
    val audience: String?,
    /** One-time BLE service UUID the holder advertises under; null when the verifier only offers the camera. */
    val linkServiceId: String?,
    val source: BondsCredentialSource,
    /** Plain http URL on the verifier's private IPv4 address where the sealed presentation can be posted. */
    val lanUrl: String? = null,
    /** The verifier's one-time P-256 key (base64url uncompressed point) the presentation is sealed to; set with [lanUrl]. */
    val lanKey: String? = null,
    /** The verifier also scans an animated fountain QR (DIWQ1), which survives missed frames. */
    val qr: Boolean = false,
) {
    fun encode(): String = Jcs.canonicalize(buildJsonObject {
        put("v", VERSION)
        put("c", challenge)
        put("p", purpose)
        audience?.let { put("a", it) }
        linkServiceId?.let { put("b", it) }
        put("k", source.wire)
        put("t", createdAt.epochSeconds)
        lanUrl?.let { put("l", it) }
        lanKey?.let { put("e", it) }
        if (qr) put("q", 1)
    })

    companion object {
        const val VERSION = 2
        const val LEGACY_VERSION = 1
        const val MAX_CHALLENGE = 64
        const val MAX_PURPOSE = 100
        const val MAX_AUDIENCE = 128
        private const val B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        private val UUID_RE = Regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")

        /**
         * True when [text] looks like a Bonds offline challenge (a JSON object with the version and challenge keys).
         * A response address marks a [BondsAgeRequest] instead, which shares the keys but is answered online.
         */
        fun looksLike(text: String): Boolean {
            val t = text.trim()
            return t.startsWith("{") && "\"c\"" in t && "\"v\"" in t && !BondsAgeRequest.looksLike(t)
        }

        fun parse(text: String): BondsPresentationRequest {
            val o = runCatching { DiwJson.parseToJsonElement(text.trim()) as JsonObject }.getOrNull()
                ?: throw ProtocolException("invalid_request", "This request could not be read")
            val version = (o["v"] as? JsonPrimitive)?.content?.toIntOrNull()
            if (version != VERSION && version != LEGACY_VERSION) throw ProtocolException("invalid_request", "Unsupported request version $version")
            val createdAt = (o["t"] as? JsonPrimitive)?.content?.toLongOrNull() ?: throw ProtocolException("invalid_request", "No request time")
            val source = if (version == LEGACY_VERSION) BondsCredentialSource.SELF_ISSUED
            else BondsCredentialSource.fromWire(o.str("k")) ?: throw ProtocolException("invalid_request", "Unknown credential source")
            val link = o.str("b")?.also { if (!UUID_RE.matches(it)) throw ProtocolException("invalid_request", "Malformed link service id") }
            val qr = (o["q"] as? JsonPrimitive)?.content == "1"
            return create(o.str("c") ?: "", o.str("p") ?: "", Instant.fromEpochSeconds(createdAt), o.str("a"), link, source, o.str("l"), o.str("e"), qr)
        }

        /** The validating constructor: a request that fails these checks cannot exist. */
        fun create(
            challenge: String,
            purpose: String,
            createdAt: Instant,
            audience: String? = null,
            linkServiceId: String? = null,
            source: BondsCredentialSource = BondsCredentialSource.TWDIW,
            lanUrl: String? = null,
            lanKey: String? = null,
            qr: Boolean = false,
        ): BondsPresentationRequest {
            if (challenge.isEmpty() || challenge.length > MAX_CHALLENGE || challenge.any { it !in B64URL }) {
                throw ProtocolException("invalid_request", "Malformed challenge")
            }
            val p = purpose.trim()
            if (p.isEmpty()) throw ProtocolException("invalid_request", "Empty purpose")
            if (p.codePointCount() > MAX_PURPOSE) throw ProtocolException("invalid_request", "Purpose too long")
            if (p.any { displayUnsafe(it) }) throw ProtocolException("invalid_request", "Purpose contains control characters")
            val a = audience?.trim()?.ifEmpty { null }?.also {
                if (it.codePointCount() > MAX_AUDIENCE || it.any { c -> displayUnsafe(c) }) throw ProtocolException("invalid_request", "Malformed audience")
            }
            if ((lanUrl == null) != (lanKey == null)) throw ProtocolException("invalid_request", "A local network address needs its key")
            if (lanUrl != null && !BondsLanPresentation.acceptableUrl(lanUrl)) throw ProtocolException("invalid_request", "Malformed local network address")
            if (lanKey != null && !BondsLanPresentation.acceptableKey(lanKey)) throw ProtocolException("invalid_request", "Malformed local network key")
            return BondsPresentationRequest(
                challenge, p, Instant.fromEpochSeconds(createdAt.epochSeconds), a, linkServiceId?.uppercase(), source, lanUrl, lanKey, qr,
            )
        }

        /** Control and format characters plus line and paragraph separators, which can reorder or break the text around them. */
        fun displayUnsafe(c: Char): Boolean {
            val code = c.code
            return code < 0x20 || code in 0x7f..0x9f || code == 0x200b || code == 0x200e || code == 0x200f ||
                code in 0x202a..0x202e || code in 0x2066..0x2069 || code == 0xfeff || code == 0x2028 || code == 0x2029 ||
                code == 0x061c || code == 0x00ad || code in 0x2060..0x2064 || code in 0xfff9..0xfffb
        }

        /** A fresh request with a 128 bit challenge and a one-time link service id (verifier side). */
        fun generate(
            purpose: String,
            source: BondsCredentialSource,
            audience: String? = null,
            now: Instant = Clock.System.now(),
            lanUrl: String? = null,
            lanKey: String? = null,
            qr: Boolean = false,
        ): BondsPresentationRequest =
            create(PlatformCrypto.randomBytes(16).toBase64Url(), purpose, now, audience, randomUuid(), source, lanUrl, lanKey, qr)

        internal fun randomUuid(): String {
            val b = PlatformCrypto.randomBytes(16)
            b[6] = ((b[6].toInt() and 0x0f) or 0x40).toByte()
            b[8] = ((b[8].toInt() and 0x3f) or 0x80).toByte()
            val h = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }.uppercase()
            return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
        }

        private fun String.codePointCount(): Int {
            var n = 0
            var i = 0
            while (i < length) {
                if (this[i].isHighSurrogate() && i + 1 < length && this[i + 1].isLowSurrogate()) i++
                i++; n++
            }
            return n
        }
    }
}

/**
 * The Bonds offline presentation: a vp+jwt JWS signed by the holder DID key over a VCDM 2.0 presentation with
 * one EnvelopedVerifiableCredential (data:application/dc+sd-jwt for TWDIW cards and SD-JWT VC,
 * data:application/vc+jwt for JWT VC, data:application/vc+moica for self-issued cards), the verifier's challenge,
 * purpose, optional audience and the creation time. For an SD-JWT VC bound by cnf to a plain key, the holder DID
 * is the did:jwk of that key.
 */
object BondsOfflinePresentation {
    const val CREDENTIALS_V2 = "https://www.w3.org/ns/credentials/v2"
    const val TERM_NAMESPACE = "https://bonds.tw/ns/credentials#"
    const val SD_JWT_PREFIX = "data:application/dc+sd-jwt,"
    const val VC_JWT_PREFIX = "data:application/vc+jwt,"
    const val MOICA_PREFIX = "data:application/vc+moica;base64,"
    /** Self-issued cards always disclose the cardholder name, which is checked against the certificate. */
    val CLAIMS_ALWAYS_DISCLOSED = setOf("name")

    /** Name and value of each disclosure of a TWDIW card, for the holder's consent screen. */
    fun disclosableClaims(credential: W3cVcCredential): List<Pair<String, String>> =
        SdJwtDisclosures.parse(credential.raw).disclosures.mapNotNull { d ->
            val name = d.name ?: return@mapNotNull null
            name to ((d.value as? JsonPrimitive)?.content ?: d.value.toString())
        }

    /** Name and value of each named disclosure of an SD-JWT (IETF SD-JWT VC or W3C VC as SD-JWT). */
    fun disclosableClaims(compactSdJwt: String): List<Pair<String, String>> =
        SdJwtDisclosures.parse(compactSdJwt).disclosures.mapNotNull { d ->
            val name = d.name ?: return@mapNotNull null
            name to ((d.value as? JsonPrimitive)?.content ?: d.value.toString())
        }

    /**
     * Answers [request] with a W3C VC in SD-JWT form (a TWDIW card, or for [BondsCredentialSource.ANY] any such card),
     * disclosing [disclosing] (all disclosures when null).
     */
    suspend fun present(
        request: BondsPresentationRequest,
        credential: W3cVcCredential,
        holder: HolderKey,
        didResolver: DidResolver,
        disclosing: Set<String>? = null,
        now: Instant = Clock.System.now(),
    ): String {
        if (request.source == BondsCredentialSource.SELF_ISSUED) {
            throw ProtocolException("credential_unavailable", "Self-issued citizen certificate cards are not on this device")
        }
        val parts = SdJwtDisclosures.parse(credential.raw)
        val payload = Jws.parse(parts.issuerJwt).payload
        val cnf = payload.obj("cnf")?.obj("jwk")?.let { EcPublicKey.fromJwk(it) }
        if (cnf != null && cnf != holder.publicKey) throw ProtocolException("invalid_key", "The card is bound to another key")
        val holderDid = payload.str("sub") ?: credential.holderDid ?: HolderKey.didFor(holder.publicKey, HolderKey.DID_KEY_JWK_JCS)
        val resolved = runCatching { didResolver.resolveKey(holderDid, null) }.getOrNull()
        if (resolved == null || (resolved.key as? VerificationKey.Ec)?.key != holder.publicKey) {
            throw ProtocolException("invalid_key", "The holder DID does not match the card key")
        }
        val keep = if (disclosing == null) parts.disclosures else parts.disclosures.filter { it.name != null && it.name in disclosing }
        return sign(SD_JWT_PREFIX + parts.withDisclosures(keep), request, holder.signingKey("ES256"), holderDid, now)
    }

    /**
     * Answers an [BondsCredentialSource.ANY] request with an IETF SD-JWT VC bound by cnf to [holderKey], signed with
     * [signingKey] (the same key). A disclosure is kept when its path names one of [disclosing] (all when null), with
     * the disclosures its digest is nested in.
     */
    suspend fun presentSdJwtVc(
        request: BondsPresentationRequest,
        compact: String,
        signingKey: AsymmetricKey,
        holderKey: EcPublicKey,
        disclosing: Set<String>? = null,
        now: Instant = Clock.System.now(),
    ): String {
        requireAny(request)
        val sdJwt = SdJwt.fromCompactSerialization(compact.substringBeforeLast('~') + "~")
        if (sdJwt.kbKey != holderKey) throw ProtocolException("invalid_key", "The card is bound to another key")
        val kept = if (disclosing == null) sdJwt else sdJwt.filter { path, _ ->
            path.any { (it as? JsonPrimitive)?.isString == true && it.content in disclosing }
        }
        return sign(SD_JWT_PREFIX + kept.compactSerialization, request, signingKey, DidKeys.didJwk(holderKey), now)
    }

    /**
     * Answers an [BondsCredentialSource.ANY] request with a W3C JWT VC whose subject is the holder DID ([holderDid],
     * or the card's sub or credentialSubject.id), which must resolve to [holderKey]. A JWT VC is shown whole.
     */
    suspend fun presentJwtVc(
        request: BondsPresentationRequest,
        jwt: String,
        signingKey: AsymmetricKey,
        holderKey: EcPublicKey,
        holderDid: String?,
        didResolver: DidResolver,
        now: Instant = Clock.System.now(),
    ): String {
        requireAny(request)
        val payload = Jws.parse(jwt.trim()).payload
        val did = holderDid ?: payload.str("sub") ?: payload.obj("vc")?.obj("credentialSubject")?.str("id")
            ?: throw ProtocolException("invalid_key", "The card names no holder")
        val resolved = runCatching { didResolver.resolveKey(did, null) }.getOrNull()
        if ((resolved?.key as? VerificationKey.Ec)?.key != holderKey) throw ProtocolException("invalid_key", "The holder DID does not match the card key")
        return sign(VC_JWT_PREFIX + jwt.trim(), request, signingKey, did, now)
    }

    /**
     * Answers a [BondsCredentialSource.SELF_ISSUED] request with a vc+moica card whose subject is [holder]'s DID,
     * disclosing [disclosing] (all disclosures when null) and always the cardholder name.
     */
    suspend fun presentMoica(
        request: BondsPresentationRequest,
        card: MoicaSignedCredential,
        holder: HolderKey,
        disclosing: Set<String>? = null,
        now: Instant = Clock.System.now(),
    ): String {
        if (request.source != BondsCredentialSource.SELF_ISSUED) {
            throw ProtocolException("credential_unavailable", "This verifier does not accept self-issued citizen certificate cards")
        }
        val holderDid = holder.did ?: throw ProtocolException("invalid_key", "The holder key has no DID")
        if (card.credential().obj("credentialSubject")?.str("id") != holderDid) {
            throw ProtocolException("invalid_key", "The card is about another holder")
        }
        val shown = if (disclosing == null) card else card.withDisclosures(disclosing)
        val envelope = MOICA_PREFIX + shown.serialized().encodeToByteArray().toBase64()
        return sign(envelope, request, holder.signingKey("ES256"), holderDid, now)
    }

    /** Name and value of each disclosure of a vc+moica card. */
    fun disclosableClaims(card: MoicaSignedCredential): List<Pair<String, String>> =
        card.disclosures.mapNotNull { enc ->
            val d = runCatching { SdJwtDisclosures.decode(enc) }.getOrNull() ?: return@mapNotNull null
            val name = d.name ?: return@mapNotNull null
            name to ((d.value as? JsonPrimitive)?.content ?: d.value.toString())
        }

    private fun requireAny(request: BondsPresentationRequest) {
        if (request.source != BondsCredentialSource.ANY) {
            throw ProtocolException("credential_unavailable", "This verifier accepts government wallet cards only")
        }
    }

    /** Signs a presentation enveloping [envelopeId] (one of the data: URLs above) with the holder's [key]. */
    suspend fun sign(envelopeId: String, request: BondsPresentationRequest, key: AsymmetricKey, holderDid: String, now: Instant): String {
        val created = Instant.fromEpochSeconds(now.epochSeconds).toString()
        val payload = buildJsonObject {
            putJsonArray("@context") {
                add(JsonPrimitive(CREDENTIALS_V2))
                add(buildJsonObject {
                    put("@protected", true)
                    put("audience", TERM_NAMESPACE + "audience")
                    put("challenge", TERM_NAMESPACE + "challenge")
                    put("created", TERM_NAMESPACE + "created")
                    put("purpose", TERM_NAMESPACE + "purpose")
                })
            }
            request.audience?.let { put("audience", it) }
            put("challenge", request.challenge)
            put("created", created)
            put("holder", holderDid)
            put("purpose", request.purpose)
            putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
            putJsonArray("verifiableCredential") {
                add(buildJsonObject {
                    put("@context", CREDENTIALS_V2)
                    put("id", envelopeId)
                    put("type", "EnvelopedVerifiableCredential")
                })
            }
        }
        val header = buildJsonObject {
            put("alg", "ES256")
            put("cty", "vp")
            put("kid", DidKeys.verificationMethod(holderDid))
            put("typ", "vp+jwt")
        }
        return signJws(header, payload, key)
    }

    /** QR frames for the presentation, shown in rotation. */
    fun qrFrames(presentationJws: String): List<String> = BondsQrTransport.frames(presentationJws.encodeToByteArray())

    /** BLE frames for a link with the given maximum notification size (MTU minus 3). */
    fun linkFrames(presentationJws: String, maxFrameBytes: Int): List<ByteArray> =
        BondsLinkTransport.frames(presentationJws.encodeToByteArray(), maxFrameBytes)
}

/**
 * The CA a vc+moica certificate must be issued by ([moica], DER) and that CA's issuer ([root], DER). Production is
 * MOICA G3 under GRCA G3; tests use their own pair.
 */
class MoicaCa(val moica: ByteArray, val root: ByteArray) {
    companion object {
        val PRODUCTION: MoicaCa by lazy { MoicaCa(TwPkiAnchors.moicaG3.encoded.toByteArray(), TwPkiAnchors.grcaG3.encoded.toByteArray()) }
    }
}

/** A verified vc+moica card: who signed it with their citizen certificate and what they disclosed. */
data class MoicaVerification(
    val credential: JsonObject,
    val cardholderName: String,
    val claims: Map<String, String>,
    val withheldClaims: Int,
    val nameChecked: Boolean,
    val certificateSerialHex: String,
)

/**
 * The Bonds vc+moica envelope: {payload: base64url(canonical credential JSON), proof{tbsConstruction, certificate,
 * signature}, issuerJWS?, disclosures[]}. The cardholder signs "bonds-tw-credential-v1:" + hex SHA-256 of the
 * payload with RSASSA-PKCS1-v1_5 SHA-256 through the citizen digital certificate; the certificate must chain to
 * MOICA G3 under GRCA G3, its CN must equal the disclosed name, and every disclosure must be committed in _sd.
 * It states what the cardholder asserts; it is not an endorsement by the Ministry of the Interior.
 */
class MoicaSignedCredential private constructor(
    val payload: String,
    val tbsConstruction: String,
    val certificate: String,
    val signature: String,
    val issuerJws: String?,
    val disclosures: List<String>,
) {
    fun credential(): JsonObject = DiwJson.parseToJsonElement(payload.fromBase64Url().decodeToString()) as JsonObject

    fun serialized(): String = Jcs.canonicalize(buildJsonObject {
        putJsonArray("disclosures") { disclosures.forEach { add(JsonPrimitive(it)) } }
        issuerJws?.let { put("issuerJWS", it) }
        put("payload", payload)
        putJsonObject("proof") {
            put("certificate", certificate)
            put("signature", signature)
            put("tbsConstruction", tbsConstruction)
        }
    })

    /** The card with only the disclosures of [names] (and [always], the cardholder name unless asked otherwise). */
    fun withDisclosures(names: Set<String>, always: Set<String> = BondsOfflinePresentation.CLAIMS_ALWAYS_DISCLOSED): MoicaSignedCredential {
        val chosen = names + always
        val kept = disclosures.filter { runCatching { SdJwtDisclosures.decode(it).name in chosen }.getOrDefault(false) }
        return MoicaSignedCredential(payload, tbsConstruction, certificate, signature, issuerJws, kept)
    }

    suspend fun verify(didResolver: DidResolver, now: Instant = Clock.System.now(), ca: MoicaCa = MoicaCa.PRODUCTION): MoicaVerification {
        val bytes = payload.fromBase64Url()
        val credential = credential()
        issuerJws?.let { verifyIssuerJws(it, bytes, credential.str("issuer") ?: throw ProtocolException("invalid_credential", "No issuer"), didResolver) }
        if (tbsConstruction != TBS_CONSTRUCTION) throw ProtocolException("invalid_credential", "Unsupported proof construction")
        val certDer = runCatching { certificate.fromBase64() }.getOrNull() ?: throw ProtocolException("invalid_credential", "Malformed certificate")
        val sig = runCatching { signature.fromBase64() }.getOrNull()?.takeIf { it.size == SIGNATURE_BYTES }
            ?: throw ProtocolException("invalid_credential", "Malformed signature")
        validateHolderCertificate(certDer, now, ca)
        val rsa = PlatformCrypto.rsaPublicKeyFromCertificate(certDer) ?: throw ProtocolException("invalid_credential", "Certificate key is not RSA")
        val tbs = TBS_PREFIX + hex(PlatformCrypto.sha256(bytes))
        if (!PlatformCrypto.verifyRsa("RS256", rsa, tbs.encodeToByteArray(), sig)) {
            throw ProtocolException("invalid_credential", "Cardholder signature is invalid")
        }
        val cn = PlatformCrypto.certificateSubjectCn(certDer) ?: throw ProtocolException("invalid_credential", "Certificate has no cardholder name")
        val committed = credential.strList("_sd").takeIf { credential["_sd"] != null }
        val opened: Map<String, String>
        val withheld: Int
        if (committed != null) {
            val set = committed.toSet()
            val seen = mutableSetOf<String>()
            opened = disclosures.associate { enc ->
                val d = runCatching { SdJwtDisclosures.decode(enc) }.getOrNull() ?: throw ProtocolException("invalid_credential", "Malformed disclosure")
                val name = d.name ?: throw ProtocolException("invalid_credential", "Malformed disclosure")
                val value = (d.value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw ProtocolException("invalid_credential", "Malformed disclosure")
                if (d.digest !in set) throw ProtocolException("invalid_credential", "Disclosure not committed")
                if (!seen.add(name)) throw ProtocolException("invalid_credential", "Duplicate disclosure")
                name to value
            }
            withheld = maxOf(0, committed.size - opened.size)
        } else {
            opened = (credential.obj("credentialSubject") ?: JsonObject(emptyMap())).filterKeys { it != "id" }
                .mapValues { (_, v) -> (v as? JsonPrimitive)?.content ?: v.toString() }
            withheld = 0
        }
        var nameChecked = false
        val subjectName = opened["name"]
        if (!subjectName.isNullOrEmpty()) {
            if (normalize(cn) != normalize(subjectName)) throw ProtocolException("invalid_credential", "Cardholder name differs from the credential")
            nameChecked = true
        } else if (committed == null) {
            throw ProtocolException("invalid_credential", "Credential carries no name")
        }
        return MoicaVerification(credential, cn, opened, withheld, nameChecked, certificateSerial(certDer))
    }

    private suspend fun verifyIssuerJws(compact: String, expectedPayload: ByteArray, issuerDid: String, didResolver: DidResolver) {
        val parts = compact.split('.')
        if (parts.size != 3) throw ProtocolException("invalid_credential", "Issuer JWS malformed")
        if (!parts[1].fromBase64Url().contentEquals(expectedPayload)) throw ProtocolException("invalid_credential", "Issuer JWS covers another payload")
        val jws = Jws.parse(compact)
        val h = jws.header
        if (h.str("alg") != "ES256" || h.str("typ") != "vc+jwt" || h.str("cty") != "vc" || h.str("kid") != DidKeys.verificationMethod(issuerDid)) {
            throw ProtocolException("invalid_credential", "Issuer JWS header is not the Bonds form")
        }
        val key = didResolver.resolveKey(issuerDid, null).key
        jws.verify(key)
    }

    companion object {
        const val TBS_CONSTRUCTION = "bonds-tw-credential-v1/payload-sha256-hex/RSASSA-PKCS1-v1_5-SHA256"
        const val TBS_PREFIX = "bonds-tw-credential-v1:"
        const val SIGNATURE_BYTES = 256

        fun parse(serialized: String): MoicaSignedCredential {
            val o = runCatching { DiwJson.parseToJsonElement(serialized) as JsonObject }.getOrNull()
                ?: throw ProtocolException("invalid_credential", "Not a vc+moica envelope")
            val proof = o.obj("proof") ?: throw ProtocolException("invalid_credential", "No proof")
            return MoicaSignedCredential(
                payload = o.str("payload") ?: throw ProtocolException("invalid_credential", "No payload"),
                tbsConstruction = proof.str("tbsConstruction") ?: "",
                certificate = proof.str("certificate") ?: throw ProtocolException("invalid_credential", "No certificate"),
                signature = proof.str("signature") ?: throw ProtocolException("invalid_credential", "No signature"),
                issuerJws = o.str("issuerJWS"),
                disclosures = (o["disclosures"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.content },
            )
        }

        /** The holder certificate must be within its validity, issued by MOICA G3, which is issued by the pinned GRCA G3. */
        fun validateHolderCertificate(der: ByteArray, now: Instant, ca: MoicaCa = MoicaCa.PRODUCTION) {
            val moica = ca.moica
            val grca = ca.root
            if (!PlatformCrypto.certificateSignedBy(moica, grca)) throw ProtocolException("invalid_certificate_chain", "MOICA G3 is not issued by GRCA G3")
            if (!PlatformCrypto.certificateSignedBy(der, moica)) throw ProtocolException("invalid_certificate_chain", "Certificate is not issued by MOICA G3")
            val cert = org.multipaz.crypto.X509Cert(kotlinx.io.bytestring.ByteString(der))
            if (now < cert.validityNotBefore || now > cert.validityNotAfter) {
                throw ProtocolException("invalid_certificate_chain", "Citizen certificate is outside its validity period")
            }
        }

        private fun certificateSerial(der: ByteArray): String =
            runCatching { org.multipaz.crypto.X509Cert(kotlinx.io.bytestring.ByteString(der)).serialNumber.value.let(::hex) }.getOrDefault("")

        private fun normalize(s: String): String = s.trim()

        internal fun hex(b: ByteArray): String = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
    }
}

/** A verified Bonds offline presentation. */
data class BondsVerifiedPresentation(
    val holder: String,
    val source: BondsCredentialSource,
    val claims: Map<String, String>,
    val issuer: String?,
    val created: Instant,
    val boundToAudience: Boolean,
    val moica: MoicaVerification?,
    /** The card's W3C credential (disclosures resolved), whose credentialStatus a verifier checks online when it can. */
    val credential: JsonObject? = null,
    /** The issuer's X.509 chain (x5c), when it signed with a certificate rather than a DID. */
    val issuerChain: List<X509Cert>? = null,
    /** Token Status List reference of an SD-JWT VC; a W3C card carries its own in [credential]. */
    val revocationStatus: RevocationStatus? = null,
    /** vct of an SD-JWT VC, or the most specific W3C type. */
    val credentialType: String? = null,
    /** Checked evidence of a credential derived from a document (time stamp, citizen certificate signature). */
    val evidence: List<EvidenceResult> = emptyList(),
)

/**
 * Verifier side of the Bonds offline presentation: checks the vp+jwt signature with the holder DID key, the
 * challenge and purpose this verifier issued, the audience, freshness (5 minutes, 2 minutes clock skew), and the
 * enveloped card: TWDIW SD-JWT bound to the holder key, vc+moica whose subject is the holder, and for
 * [BondsCredentialSource.ANY] an IETF SD-JWT VC whose cnf is the holder key or a JWT VC whose subject is the holder.
 * An SD-JWT VC issuer key comes from x5c, a DID iss, or [issuerMetadataKey] (JWT VC issuer metadata, online only).
 */
class BondsOfflineVerifier(
    private val didResolver: DidResolver,
    private val issuerMetadataKey: (suspend (issuer: String, kid: String?) -> EcPublicKey)? = null,
    /** Trust for the time stamps carried as evidence by derived credentials; null leaves them unchecked. */
    private val documentTrust: DocumentTrustSource? = null,
    private val moicaCa: MoicaCa = MoicaCa.PRODUCTION,
) {
    suspend fun verify(presentationJws: String, request: BondsPresentationRequest, now: Instant = Clock.System.now()): BondsVerifiedPresentation {
        val jws = Jws.parse(presentationJws.trim())
        if (jws.header.str("alg") != "ES256") throw ProtocolException("invalid_presentation", "Unsupported algorithm")
        val vp = jws.payload
        if ("VerifiablePresentation" !in vp.strList("type")) throw ProtocolException("invalid_presentation", "Not a presentation")
        val holder = vp.str("holder") ?: throw ProtocolException("invalid_presentation", "No holder")
        if (jws.header.str("kid") != DidKeys.verificationMethod(holder)) throw ProtocolException("invalid_presentation", "kid does not name the holder")
        val holderKey = didResolver.resolveKey(holder, null).key
        jws.verify(holderKey)
        if (vp.str("challenge") != request.challenge) throw ProtocolException("invalid_presentation", "Challenge mismatch")
        if (vp.str("purpose") != request.purpose) throw ProtocolException("invalid_presentation", "Purpose mismatch")
        if (request.audience != null && vp.str("audience") != request.audience) throw ProtocolException("invalid_presentation", "Audience mismatch")
        val created = runCatching { Instant.parse(vp.str("created")!!) }.getOrNull() ?: throw ProtocolException("invalid_presentation", "Unreadable timestamp")
        if (created > now + 2.minutes) throw ProtocolException("invalid_presentation", "Presentation dated in the future")
        if (now - created > 5.minutes) throw ProtocolException("invalid_presentation", "Presentation too old")
        val creds = vp["verifiableCredential"] as? JsonArray ?: throw ProtocolException("invalid_presentation", "No credential")
        if (creds.size != 1) throw ProtocolException("invalid_presentation", "Expected exactly one credential")
        val env = creds.first() as? JsonObject ?: throw ProtocolException("invalid_presentation", "Credential not enveloped")
        if (env.str("type") != "EnvelopedVerifiableCredential") throw ProtocolException("invalid_presentation", "Credential not enveloped")
        val id = env.str("id") ?: throw ProtocolException("invalid_presentation", "Credential not enveloped")
        val bound = request.audience != null && vp.str("audience") == request.audience
        return when {
            id.startsWith(BondsOfflinePresentation.SD_JWT_PREFIX) -> {
                if (request.source == BondsCredentialSource.SELF_ISSUED) throw ProtocolException("invalid_presentation", "Credential source mismatch")
                val sd = id.removePrefix(BondsOfflinePresentation.SD_JWT_PREFIX)
                val parts = SdJwtDisclosures.parse(sd)
                val cjws = Jws.parse(parts.issuerJwt)
                // An IETF SD-JWT VC names its type in vct; a W3C VC as SD-JWT (TWDIW) carries the vc claim.
                if (cjws.payload["vct"] != null && cjws.payload["vc"] == null) {
                    if (request.source != BondsCredentialSource.ANY) throw ProtocolException("invalid_presentation", "Credential source mismatch")
                    return verifySdJwtVc(sd, holder, holderKey, created, bound, now)
                }
                val iss = cjws.payload.str("iss") ?: throw ProtocolException("invalid_credential", "No issuer")
                cjws.verify(didResolver.resolveKey(iss, null).key)
                val cnf = cjws.payload.obj("cnf")?.obj("jwk")?.let { VerificationKey.fromJwk(it) }
                // A TWDIW card names its holder in sub; another W3C card may be bound by cnf alone.
                val sub = cjws.payload.str("sub")
                val subjectOk = sub == holder || (sub == null && request.source == BondsCredentialSource.ANY)
                if (cnf != holderKey || !subjectOk) throw ProtocolException("invalid_credential", "Card not bound to the presenter")
                cjws.payload["exp"]?.let { (it as? JsonPrimitive)?.content?.toLongOrNull() }?.let {
                    if (Instant.fromEpochSeconds(it) < now) throw ProtocolException("invalid_credential", "Card expired")
                }
                val resolved = SdJwtDisclosures.resolve(cjws.payload, parts.disclosures)
                val subject = resolved.obj("vc")?.obj("credentialSubject") ?: resolved.obj("credentialSubject") ?: JsonObject(emptyMap())
                val claims = subject.filterKeys { it != "id" && !it.startsWith("_") }.mapValues { (_, v) -> (v as? JsonPrimitive)?.content ?: v.toString() }
                val vc = resolved.obj("vc") ?: resolved
                BondsVerifiedPresentation(holder, request.source, claims, iss, created, bound, null, vc, credentialType = vc.strList("type").lastOrNull())
            }
            id.startsWith(BondsOfflinePresentation.VC_JWT_PREFIX) -> {
                if (request.source != BondsCredentialSource.ANY) throw ProtocolException("invalid_presentation", "Credential source mismatch")
                verifyJwtVc(id.removePrefix(BondsOfflinePresentation.VC_JWT_PREFIX), holder, created, bound, now)
            }
            id.startsWith(BondsOfflinePresentation.MOICA_PREFIX) -> {
                if (request.source != BondsCredentialSource.SELF_ISSUED) throw ProtocolException("invalid_presentation", "Credential source mismatch")
                val serialized = id.removePrefix(BondsOfflinePresentation.MOICA_PREFIX).fromBase64().decodeToString()
                val card = MoicaSignedCredential.parse(serialized)
                val result = card.verify(didResolver, now, moicaCa)
                if (result.credential.obj("credentialSubject")?.str("id") != holder) throw ProtocolException("invalid_credential", "Card subject is not the presenter")
                BondsVerifiedPresentation(
                    holder, BondsCredentialSource.SELF_ISSUED, result.claims, result.credential.str("issuer"), created, bound, result, result.credential,
                    credentialType = result.credential.strList("type").lastOrNull(),
                )
            }
            else -> throw ProtocolException("invalid_presentation", "Unsupported credential envelope")
        }
    }

    /** IETF SD-JWT VC: issuer signature, cnf bound to the presenter's key, validity; claims with disclosures applied. */
    private suspend fun verifySdJwtVc(
        compact: String,
        holder: String,
        holderKey: VerificationKey,
        created: Instant,
        bound: Boolean,
        now: Instant,
    ): BondsVerifiedPresentation {
        val sdJwt = runCatching { SdJwt.fromCompactSerialization(compact) }.getOrNull() ?: throw ProtocolException("invalid_credential", "Malformed SD-JWT VC")
        val chain = sdJwt.x5c?.certificates
        val iss = sdJwt.issuer
        val kid = sdJwt.jwtHeader.str("kid")
        val issuerKey: EcPublicKey = when {
            chain != null -> {
                X509CertChainCheck.validate(chain)
                chain.first().ecPublicKey
            }
            iss != null && iss.startsWith("did:") -> (didResolver.resolveKey(iss, kid).key as? VerificationKey.Ec)?.key
                ?: throw ProtocolException("invalid_credential", "The issuer DID has no EC key")
            iss != null && issuerMetadataKey != null -> issuerMetadataKey.invoke(iss, kid)
            else -> throw ProtocolException("invalid_credential", "The issuer key cannot be found without a connection")
        }
        val processed = try {
            sdJwt.verify(issuerKey)
        } catch (e: Exception) {
            throw ProtocolException("invalid_credential", "Issuer signature is invalid", e)
        }
        val cnf = sdJwt.kbKey ?: throw ProtocolException("invalid_credential", "Card not bound to a key")
        if ((holderKey as? VerificationKey.Ec)?.key != cnf) throw ProtocolException("invalid_credential", "Card not bound to the presenter")
        sdJwt.validUntil?.let { if (it < now) throw ProtocolException("invalid_credential", "Card expired") }
        sdJwt.validFrom?.let { if (it > now + 2.minutes) throw ProtocolException("invalid_credential", "Card not yet valid") }
        val derived = sdJwt.credentialType == DerivedCredentials.VCT
        val claims = flatten(JsonObject(processed.filterKeys { it !in SD_JWT_VC_TECHNICAL && !(derived && it == "evidence") }))
        val evidence = if (derived) {
            val signed = Jws.parse(SdJwtDisclosures.parse(compact).issuerJwt).payload
            DerivedEvidence.verify(signed, documentTrust)
        } else emptyList()
        return BondsVerifiedPresentation(
            holder, BondsCredentialSource.ANY, claims, iss, created, bound, null,
            issuerChain = chain, revocationStatus = sdJwt.revocationStatus, credentialType = sdJwt.credentialType, evidence = evidence,
        )
    }

    /** W3C JWT VC: issuer signature (x5c or DID), subject is the presenter, validity; claims of credentialSubject. */
    private suspend fun verifyJwtVc(jwt: String, holder: String, created: Instant, bound: Boolean, now: Instant): BondsVerifiedPresentation {
        val cjws = runCatching { Jws.parse(jwt) }.getOrNull() ?: throw ProtocolException("invalid_credential", "Malformed JWT VC")
        val payload = cjws.payload
        val vc = payload.obj("vc") ?: payload
        val iss = payload.str("iss") ?: vc.str("issuer") ?: vc.obj("issuer")?.str("id")
        val chain = (cjws.header["x5c"] as? JsonArray)?.let { a ->
            runCatching { org.multipaz.crypto.X509CertChain.fromX5c(a).certificates }.getOrNull()
                ?: throw ProtocolException("invalid_credential", "Malformed x5c")
        }
        val key = when {
            chain != null -> {
                X509CertChainCheck.validate(chain)
                VerificationKey.Ec(chain.first().ecPublicKey)
            }
            iss != null && iss.startsWith("did:") -> didResolver.resolveKey(iss, cjws.header.str("kid")).key
            else -> throw ProtocolException("invalid_credential", "The issuer key cannot be found")
        }
        cjws.verify(key)
        val subject = vc.obj("credentialSubject") ?: JsonObject(emptyMap())
        if (payload.str("sub") != holder && subject.str("id") != holder) throw ProtocolException("invalid_credential", "Card subject is not the presenter")
        payload["exp"]?.let { (it as? JsonPrimitive)?.content?.toLongOrNull() }?.let {
            if (Instant.fromEpochSeconds(it) < now) throw ProtocolException("invalid_credential", "Card expired")
        }
        payload["nbf"]?.let { (it as? JsonPrimitive)?.content?.toLongOrNull() }?.let {
            if (Instant.fromEpochSeconds(it) > now + 2.minutes) throw ProtocolException("invalid_credential", "Card not yet valid")
        }
        return BondsVerifiedPresentation(
            holder, BondsCredentialSource.ANY, flatten(JsonObject(subject.filterKeys { it != "id" })), iss, created, bound, null, vc,
            issuerChain = chain, credentialType = vc.strList("type").lastOrNull(),
        )
    }

    private companion object {
        /** Registered and structural SD-JWT VC claims, shown elsewhere or not at all. */
        val SD_JWT_VC_TECHNICAL = setOf("iss", "sub", "iat", "nbf", "exp", "jti", "cnf", "vct", "vct#integrity", "status", "_sd", "_sd_alg")

        /** Nested objects as dotted names ("address.locality"); arrays and other values as text. */
        fun flatten(o: JsonObject, prefix: String = ""): Map<String, String> = buildMap {
            for ((k, v) in o) {
                if (k.startsWith("_")) continue
                val name = prefix + k
                when (v) {
                    is JsonObject -> putAll(flatten(v, "$name."))
                    is JsonPrimitive -> put(name, v.content)
                    else -> put(name, text(v))
                }
            }
        }

        fun text(v: JsonElement): String = when (v) {
            is JsonPrimitive -> v.content
            is JsonArray -> v.joinToString("、") { text(it) }
            is JsonObject -> v.toString()
        }
    }
}
