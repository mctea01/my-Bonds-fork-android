package diw.wallet.core.verifier.declaration

import diw.wallet.core.jose.Jws
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.long
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/** What a mandate grants: the principal, the agent and the verifier keys (client identifiers) the agent uses. */
data class MandateContent(
    val principal: VerifierParty,
    val agent: VerifierAgent,
    /** Client identifiers (x509_hash:... or decentralized_identifier:did:...) the agent may verify with. */
    val agentClientIds: List<String>,
    /** Purposes the mandate covers; empty covers every purpose. */
    val purposes: List<String> = emptyList(),
    /** Credentials and claims the agent may request (WRPRC credentials structure); null allows any. */
    val credentials: JsonArray? = null,
    val notBefore: Instant,
    val expiresAt: Instant,
)

data class ParsedMandate(val jws: Jws, val issuer: String?, val issuedAt: Instant?, val content: MandateContent?)

/**
 * A mandate (授權書) of docs/design/p5-verifier.md section 5: the principal, with its own X.509 certificate or DID,
 * lets a natural person verify on its behalf with the named verifier keys. A DIW format with no legal effect claimed.
 */
object VerifierMandate {
    const val TYP = "diw-verifier-mandate+jwt"
    val MAX_LIFETIME: Duration = 366.days

    suspend fun sign(content: MandateContent, signer: JwsSigner, issuer: String, now: Instant = Clock.System.now()): String {
        require(content.agentClientIds.isNotEmpty()) { "A mandate names at least one verifier key" }
        require(content.expiresAt > content.notBefore) { "The mandate ends before it starts" }
        require(content.expiresAt - content.notBefore <= MAX_LIFETIME) { "A mandate lasts at most one year" }
        val payload = buildJsonObject {
            put("iss", issuer)
            put("iat", now.epochSeconds)
            put("nbf", content.notBefore.epochSeconds)
            put("exp", content.expiresAt.epochSeconds)
            put("principal", content.principal.toJson())
            putJsonObject("agent") {
                put("name", content.agent.name)
                content.agent.role?.let { put("role", it) }
                putJsonArray("client_ids") { content.agentClientIds.forEach { add(it) } }
            }
            putJsonObject("scope") {
                if (content.purposes.isNotEmpty()) putJsonArray("purposes") { content.purposes.forEach { add(it) } }
                content.credentials?.let { put("credentials", it) }
            }
        }
        return signer.signCompact(TYP, payload)
    }

    fun parse(compact: String): ParsedMandate {
        val jws = Jws.parse(compact)
        if (jws.typ != TYP) throw ProtocolException("invalid_mandate", "Not a verifier mandate (typ ${jws.typ})")
        val p = jws.payload
        val principal = VerifierParty.fromJson(p.obj("principal"))
        val agentObj = p.obj("agent")
        val agent = VerifierAgent.fromJson(agentObj)
        val nbf = p.long("nbf")
        val exp = p.long("exp")
        val scope = p.obj("scope")
        val content = if (principal != null && agent != null && nbf != null && exp != null) MandateContent(
            principal = principal,
            agent = agent,
            agentClientIds = agentObj?.strList("client_ids").orEmpty(),
            purposes = scope?.arr("purposes").orEmpty().mapNotNull { (it as? JsonPrimitive)?.takeIf { x -> x.isString }?.content },
            credentials = scope?.arr("credentials"),
            notBefore = Instant.fromEpochSeconds(nbf),
            expiresAt = Instant.fromEpochSeconds(exp),
        ) else null
        return ParsedMandate(jws, p.str("iss"), p.long("iat")?.let { Instant.fromEpochSeconds(it) }, content)
    }

    /** Whether a mandate scope with [purposes] covers the declared [purpose] text (empty covers all). */
    fun coversPurpose(purposes: List<String>, purpose: String?): Boolean =
        purposes.isEmpty() || purpose != null && purposes.any { it.trim() == purpose.trim() }
}
