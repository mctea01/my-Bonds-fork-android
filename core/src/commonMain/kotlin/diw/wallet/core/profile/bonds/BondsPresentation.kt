package diw.wallet.core.profile.bonds

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.Jcs
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import diw.wallet.core.w3c.SdJwtDisclosures
import diw.wallet.core.w3c.W3cVcCredential
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.EcPublicKey
import org.multipaz.util.fromBase64
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** Which stored card family a Bonds verifier asks for. */
enum class BondsCredentialSource(val wire: String) {
    /** A vc+moica card signed by its holder with the citizen digital certificate. */
    SELF_ISSUED("s"),
    /** A TWDIW card (SD-JWT issued by a government issuer). */
    TWDIW("g");

    companion object {
        fun fromWire(w: String?): BondsCredentialSource? = entries.firstOrNull { it.wire == w }
    }
}

/**
 * The challenge a Bonds verifier shows as a plain JSON QR: {v, c, p, t, a?, b?, k}. Everything in it is untrusted
 * text from the person in front of the holder; it does not authenticate the verifier.
 */
data class BondsPresentationRequest(
    val challenge: String,
    val purpose: String,
    val createdAt: Instant,
    val audience: String?,
    /** One-time BLE service UUID the holder advertises under; null when the verifier only offers the camera. */
    val linkServiceId: String?,
    val source: BondsCredentialSource,
) {
    fun encode(): String = Jcs.canonicalize(buildJsonObject {
        put("v", VERSION)
        put("c", challenge)
        put("p", purpose)
        audience?.let { put("a", it) }
        linkServiceId?.let { put("b", it) }
        put("k", source.wire)
        put("t", createdAt.epochSeconds)
    })

    companion object {
        const val VERSION = 2
        const val LEGACY_VERSION = 1
        const val MAX_CHALLENGE = 64
        const val MAX_PURPOSE = 100
        const val MAX_AUDIENCE = 128
        private const val B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        private val UUID_RE = Regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")

        /** True when [text] looks like a Bonds request (a JSON object with the version and challenge keys). */
        fun looksLike(text: String): Boolean {
            val t = text.trim()
            return t.startsWith("{") && "\"c\"" in t && "\"v\"" in t
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
            return create(o.str("c") ?: "", o.str("p") ?: "", Instant.fromEpochSeconds(createdAt), o.str("a"), link, source)
        }

        /** The validating constructor: a request that fails these checks cannot exist. */
        fun create(
            challenge: String,
            purpose: String,
            createdAt: Instant,
            audience: String? = null,
            linkServiceId: String? = null,
            source: BondsCredentialSource = BondsCredentialSource.TWDIW,
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
            return BondsPresentationRequest(challenge, p, Instant.fromEpochSeconds(createdAt.epochSeconds), a, linkServiceId?.uppercase(), source)
        }

        /** Control and format characters plus line and paragraph separators, which can reorder or break the text around them. */
        fun displayUnsafe(c: Char): Boolean {
            val code = c.code
            return code < 0x20 || code in 0x7f..0x9f || code == 0x200b || code == 0x200e || code == 0x200f ||
                code in 0x202a..0x202e || code in 0x2066..0x2069 || code == 0xfeff || code == 0x2028 || code == 0x2029 ||
                code == 0x061c || code == 0x00ad || code in 0x2060..0x2064 || code in 0xfff9..0xfffb
        }

        /** A fresh request with a 128 bit challenge and a one-time link service id (verifier side). */
        fun generate(purpose: String, source: BondsCredentialSource, audience: String? = null, now: Instant = Clock.System.now()): BondsPresentationRequest =
            create(PlatformCrypto.randomBytes(16).toBase64Url(), purpose, now, audience, randomUuid(), source)

        private fun randomUuid(): String {
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
 * one EnvelopedVerifiableCredential (data:application/dc+sd-jwt for TWDIW cards, data:application/vc+moica for
 * self-issued cards), the verifier's challenge, purpose, optional audience and the creation time.
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

    /** Answers [request] with a TWDIW card, disclosing [disclosing] (all disclosures when null). */
    suspend fun present(
        request: BondsPresentationRequest,
        credential: W3cVcCredential,
        holder: HolderKey,
        didResolver: DidResolver,
        disclosing: Set<String>? = null,
        now: Instant = Clock.System.now(),
    ): String {
        if (request.source != BondsCredentialSource.TWDIW) {
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
        return sign(SD_JWT_PREFIX + parts.withDisclosures(keep), request, holder, holderDid, now)
    }

    /** Signs a presentation enveloping [envelopeId] (one of the data: URLs above). */
    suspend fun sign(envelopeId: String, request: BondsPresentationRequest, holder: HolderKey, holderDid: String, now: Instant): String {
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
        return signJws(header, payload, holder.signingKey("ES256"))
    }

    /** QR frames for the presentation, shown in rotation. */
    fun qrFrames(presentationJws: String): List<String> = BondsQrTransport.frames(presentationJws.encodeToByteArray())

    /** BLE frames for a link with the given maximum notification size (MTU minus 3). */
    fun linkFrames(presentationJws: String, maxFrameBytes: Int): List<ByteArray> =
        BondsLinkTransport.frames(presentationJws.encodeToByteArray(), maxFrameBytes)
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

    fun withDisclosures(names: Set<String>): MoicaSignedCredential {
        val chosen = names + BondsOfflinePresentation.CLAIMS_ALWAYS_DISCLOSED
        val kept = disclosures.filter { runCatching { SdJwtDisclosures.decode(it).name in chosen }.getOrDefault(false) }
        return MoicaSignedCredential(payload, tbsConstruction, certificate, signature, issuerJws, kept)
    }

    suspend fun verify(didResolver: DidResolver, now: Instant = Clock.System.now()): MoicaVerification {
        val bytes = payload.fromBase64Url()
        val credential = credential()
        issuerJws?.let { verifyIssuerJws(it, bytes, credential.str("issuer") ?: throw ProtocolException("invalid_credential", "No issuer"), didResolver) }
        if (tbsConstruction != TBS_CONSTRUCTION) throw ProtocolException("invalid_credential", "Unsupported proof construction")
        val certDer = runCatching { certificate.fromBase64() }.getOrNull() ?: throw ProtocolException("invalid_credential", "Malformed certificate")
        val sig = runCatching { signature.fromBase64() }.getOrNull()?.takeIf { it.size == SIGNATURE_BYTES }
            ?: throw ProtocolException("invalid_credential", "Malformed signature")
        validateHolderCertificate(certDer, now)
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
        fun validateHolderCertificate(der: ByteArray, now: Instant) {
            val moica = TwPkiAnchors.moicaG3.encoded.toByteArray()
            val grca = TwPkiAnchors.grcaG3.encoded.toByteArray()
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
)

/**
 * Verifier side of the Bonds offline presentation: checks the vp+jwt signature with the holder DID key, the
 * challenge and purpose this verifier issued, the audience, freshness (5 minutes, 2 minutes clock skew), and the
 * enveloped card (TWDIW SD-JWT bound to the holder key, or vc+moica whose subject is the holder).
 */
class BondsOfflineVerifier(private val didResolver: DidResolver) {
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
                if (request.source != BondsCredentialSource.TWDIW) throw ProtocolException("invalid_presentation", "Credential source mismatch")
                val sd = id.removePrefix(BondsOfflinePresentation.SD_JWT_PREFIX)
                val parts = SdJwtDisclosures.parse(sd)
                val cjws = Jws.parse(parts.issuerJwt)
                val iss = cjws.payload.str("iss") ?: throw ProtocolException("invalid_credential", "No issuer")
                cjws.verify(didResolver.resolveKey(iss, null).key)
                val cnf = cjws.payload.obj("cnf")?.obj("jwk")?.let { VerificationKey.fromJwk(it) }
                if (cnf != holderKey || cjws.payload.str("sub") != holder) throw ProtocolException("invalid_credential", "Card not bound to the presenter")
                cjws.payload["exp"]?.let { (it as? JsonPrimitive)?.content?.toLongOrNull() }?.let {
                    if (Instant.fromEpochSeconds(it) < now) throw ProtocolException("invalid_credential", "Card expired")
                }
                val resolved = SdJwtDisclosures.resolve(cjws.payload, parts.disclosures)
                val subject = resolved.obj("vc")?.obj("credentialSubject") ?: resolved.obj("credentialSubject") ?: JsonObject(emptyMap())
                val claims = subject.filterKeys { it != "id" && !it.startsWith("_") }.mapValues { (_, v) -> (v as? JsonPrimitive)?.content ?: v.toString() }
                BondsVerifiedPresentation(holder, BondsCredentialSource.TWDIW, claims, iss, created, bound, null)
            }
            id.startsWith(BondsOfflinePresentation.MOICA_PREFIX) -> {
                if (request.source != BondsCredentialSource.SELF_ISSUED) throw ProtocolException("invalid_presentation", "Credential source mismatch")
                val serialized = id.removePrefix(BondsOfflinePresentation.MOICA_PREFIX).fromBase64().decodeToString()
                val card = MoicaSignedCredential.parse(serialized)
                val result = card.verify(didResolver, now)
                if (result.credential.obj("credentialSubject")?.str("id") != holder) throw ProtocolException("invalid_credential", "Card subject is not the presenter")
                BondsVerifiedPresentation(holder, BondsCredentialSource.SELF_ISSUED, result.claims, result.credential.str("issuer"), created, bound, result)
            }
            else -> throw ProtocolException("invalid_presentation", "Unsupported credential envelope")
        }
    }
}
