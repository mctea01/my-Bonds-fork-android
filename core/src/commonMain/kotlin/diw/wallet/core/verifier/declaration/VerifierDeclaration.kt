package diw.wallet.core.verifier.declaration

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.bool
import diw.wallet.core.util.long
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** Who a verifier is (docs/design/p5-verifier.md section 3): the party the data is for, and whether a person acts for it. */
enum class VerifierKind(val wire: String, val partyLegal: Boolean, val representative: Boolean) {
    NATURAL_PERSON("natural_person", false, false),
    LEGAL_PERSON("legal_person", true, false),
    FOR_LEGAL_PERSON("natural_person_for_legal_person", true, true),
    FOR_NATURAL_PERSON("natural_person_for_natural_person", false, true);

    companion object {
        fun fromWire(w: String?): VerifierKind? = entries.firstOrNull { it.wire == w }
    }
}

/** An identifier of a party: scheme TW-UBN (unified business number), EUID, LEI, TW-ID or another scheme name. */
data class PartyId(val scheme: String, val value: String) {
    fun toJson(): JsonObject = buildJsonObject { put("scheme", scheme); put("value", value) }

    companion object {
        fun fromJson(o: JsonObject?): PartyId? {
            o ?: return null
            return PartyId(o.str("scheme") ?: return null, o.str("value") ?: return null)
        }

        const val TW_UBN = "TW-UBN"
        const val EUID = "EUID"
        const val LEI = "LEI"
        const val TW_ID = "TW-ID"
    }
}

/** The party data is for: a legal or a natural person. */
data class VerifierParty(val legal: Boolean, val name: String, val id: PartyId? = null, val publicBody: Boolean? = null) {
    fun toJson(): JsonObject = buildJsonObject {
        put("type", if (legal) "legal" else "natural")
        put("name", name)
        id?.let { put("id", it.toJson()) }
        publicBody?.let { put("public_body", it) }
    }

    companion object {
        fun fromJson(o: JsonObject?): VerifierParty? {
            o ?: return null
            val name = o.str("name")?.takeIf { it.isNotBlank() } ?: return null
            val legal = when (o.str("type")) {
                "legal" -> true
                "natural" -> false
                else -> return null
            }
            return VerifierParty(legal, name, PartyId.fromJson(o.obj("id")), o.bool("public_body"))
        }
    }
}

/** The natural person acting for the party (only for representative kinds). */
data class VerifierAgent(val name: String, val role: String? = null) {
    fun toJson(): JsonObject = buildJsonObject {
        put("name", name)
        role?.let { put("role", it) }
    }

    companion object {
        fun fromJson(o: JsonObject?): VerifierAgent? {
            o ?: return null
            return VerifierAgent(o.str("name")?.takeIf { it.isNotBlank() } ?: return null, o.str("role")?.takeIf { it.isNotBlank() })
        }
    }
}

/** Why the data is requested, on what legal basis, how long it is kept and where the privacy policy is. */
data class VerifierPurpose(
    val text: String,
    val lang: String? = null,
    val legalBasis: String? = null,
    /** "none", or an ISO 8601 duration such as P30D. */
    val retention: String? = null,
    val privacyPolicy: String? = null,
) {
    fun toJson(): JsonObject = buildJsonObject {
        putJsonArray("text") {
            add(buildJsonObject {
                lang?.let { put("lang", it) }
                put("value", text)
            })
        }
        legalBasis?.let { put("legal_basis", it) }
        retention?.let { put("retention", it) }
        privacyPolicy?.let { put("privacy_policy", it) }
    }

    companion object {
        val LEGAL_BASES = listOf("consent", "contract", "legal_obligation", "public_task", "vital_interest", "legitimate_interest")

        fun fromJson(o: JsonObject?): VerifierPurpose? {
            o ?: return null
            val first = when (val t = o["text"]) {
                is JsonPrimitive -> t.takeIf { it.isString }?.content?.let { it to null }
                is JsonArray -> t.firstNotNullOfOrNull { e -> (e as? JsonObject)?.let { x -> x.str("value")?.let { it to x.str("lang") } } }
                else -> null
            } ?: return null
            return VerifierPurpose(first.first, first.second, o.str("legal_basis"), o.str("retention"), o.str("privacy_policy"))
        }
    }
}

/** One piece of evidence carried by a declaration. */
sealed class DeclarationEvidence {
    /**
     * A presentation of one of the verifier's own credentials ([vpToken] keyed by the id of [query]), bound to the
     * request's client_id and nonce. [role] says whether it proves the party or the agent.
     */
    data class Presentation(val role: String, val query: JsonObject, val vpToken: JsonObject) : DeclarationEvidence()

    /** A mandate signed by the party, naming the verifier key as agent ([VerifierMandate]). */
    data class Mandate(val jws: String) : DeclarationEvidence()

    fun toJson(): JsonObject = when (this) {
        is Presentation -> buildJsonObject {
            put("type", "presentation")
            put("role", role)
            put("query", query)
            put("vp_token", vpToken)
        }
        is Mandate -> buildJsonObject {
            put("type", "mandate")
            put("jws", jws)
        }
    }

    companion object {
        const val ROLE_PARTY = "party"
        const val ROLE_AGENT = "agent"

        fun fromJson(o: JsonObject): DeclarationEvidence? = when (o.str("type")) {
            "presentation" -> {
                val role = o.str("role")
                val query = o.obj("query")
                val token = o.obj("vp_token")
                if (role in listOf(ROLE_PARTY, ROLE_AGENT) && query != null && token != null) Presentation(role!!, query, token) else null
            }
            "mandate" -> o.str("jws")?.let { Mandate(it) }
            else -> null
        }
    }
}

/** What a verifier states about itself, signed into a declaration for one request. */
data class DeclarationContent(
    val kind: VerifierKind,
    val party: VerifierParty,
    val agent: VerifierAgent? = null,
    val purpose: VerifierPurpose? = null,
    /** Credentials and claims the verifier declares it requests (WRPRC credentials structure); null declares none. */
    val credentials: JsonArray? = null,
)

/** A parsed (not yet verified) declaration. */
data class ParsedDeclaration(
    val jws: Jws,
    val issuer: String?,
    val nonce: String?,
    val issuedAt: Instant?,
    val expiresAt: Instant?,
    val content: DeclarationContent?,
    val evidence: List<DeclarationEvidence>,
    /** Members that could not be read (reported, the rest is still shown). */
    val problems: List<String>,
)

/**
 * The verifier declaration of docs/design/p5-verifier.md section 4: a verifier_info entry (format [FORMAT]) whose JWS
 * is signed by the request's own key and bound to its client_id and nonce. A DIW extension; other wallets ignore it.
 */
object VerifierDeclaration {
    const val FORMAT = "urn:diw-wallet:verifier-declaration:1"
    const val TYP = "diw-verifier-declaration+jwt"
    /** ISO 18013-5 ItemsRequest.requestInfo key carrying the declaration JWS. */
    const val REQUEST_INFO_KEY = "diw.verifierDeclaration"
    /** ISO 18013-5 requestInfo key of an EUDI registration certificate (ETSI TS 119 472-2 section 5.3.2). */
    const val REQUEST_INFO_WRPRC = "euWrprc"
    /** The response_uri in the mdoc handover of evidence presentations, which go to no endpoint. */
    const val EVIDENCE_RESPONSE_URI = "urn:diw-wallet:verifier-evidence"
    val MAX_LIFETIME: Duration = 10.minutes

    suspend fun sign(
        content: DeclarationContent,
        clientId: String,
        nonce: String,
        evidence: List<DeclarationEvidence>,
        signer: JwsSigner,
        now: Instant = Clock.System.now(),
        lifetime: Duration = MAX_LIFETIME,
    ): String {
        require(content.kind.partyLegal == content.party.legal) { "The kind ${content.kind.wire} does not fit the party" }
        require(!content.kind.representative || content.agent != null) { "A representative declaration names its agent" }
        val payload = buildJsonObject {
            put("iss", clientId)
            put("nonce", nonce)
            put("iat", now.epochSeconds)
            put("exp", (now + lifetime.coerceAtMost(MAX_LIFETIME)).epochSeconds)
            put("kind", content.kind.wire)
            put("party", content.party.toJson())
            if (content.kind.representative) content.agent?.let { put("agent", it.toJson()) }
            content.purpose?.let { put("purpose", it.toJson()) }
            content.credentials?.let { put("credentials", it) }
            if (evidence.isNotEmpty()) putJsonArray("evidence") { evidence.forEach { add(it.toJson()) } }
        }
        return signer.signCompact(TYP, payload)
    }

    /** The verifier_info element for [jws]. */
    fun entry(jws: String): JsonObject = buildJsonObject {
        put("format", FORMAT)
        put("data", jws)
    }

    /** The declaration nonce for an ISO 18013-5 session: base64url(SHA-256(SessionTranscript)). */
    fun proximityNonce(encodedSessionTranscript: ByteArray): String = PlatformCrypto.sha256(encodedSessionTranscript).toBase64Url()

    fun parse(compact: String): ParsedDeclaration {
        val jws = Jws.parse(compact)
        if (jws.typ != TYP) throw ProtocolException("invalid_declaration", "Not a verifier declaration (typ ${jws.typ})")
        val p = jws.payload
        val problems = ArrayList<String>()
        val kind = VerifierKind.fromWire(p.str("kind"))
        val party = VerifierParty.fromJson(p.obj("party"))
        val content = if (kind != null && party != null && kind.partyLegal == party.legal) {
            val agent = VerifierAgent.fromJson(p.obj("agent"))
            if (kind.representative && agent == null) problems.add("agent")
            DeclarationContent(kind, party, if (kind.representative) agent else null, VerifierPurpose.fromJson(p.obj("purpose")), p.arr("credentials"))
        } else {
            problems.add("party")
            null
        }
        val evidence = p.arr("evidence").orEmpty().mapNotNull { e ->
            (e as? JsonObject)?.let { DeclarationEvidence.fromJson(it) }.also { if (it == null) problems.add("evidence") }
        }
        return ParsedDeclaration(
            jws = jws,
            issuer = p.str("iss"),
            nonce = p.str("nonce"),
            issuedAt = p.long("iat")?.let { Instant.fromEpochSeconds(it) },
            expiresAt = p.long("exp")?.let { Instant.fromEpochSeconds(it) },
            content = content,
            evidence = evidence,
            problems = problems.distinct(),
        )
    }

    /** The data of a verifier_info element as a compact JWS string, or null. */
    fun data(element: JsonElement): String? = (element as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()
}
