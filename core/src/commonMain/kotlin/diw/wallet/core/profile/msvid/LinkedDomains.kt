package diw.wallet.core.profile.msvid

import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.Jws
import diw.wallet.core.trust.DidTrustSource
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.request
import io.ktor.http.Url
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** Outcome of the DIF Well Known DID Configuration check. */
sealed interface LinkedDomainResult {
    data class Verified(val origin: String) : LinkedDomainResult
    data class Unverified(val origin: String, val reason: String) : LinkedDomainResult
    data object Missing : LinkedDomainResult
}

/**
 * Linked Domains (DIF Well Known DID Configuration), the root of trust Microsoft Entra Verified ID uses for issuers
 * and verifiers: the DID document names a LinkedDomains origin, and that origin's /.well-known/did-configuration.json
 * holds a DomainLinkageCredential signed by the same DID. HTTPS only and no redirects.
 *
 * It proves control of a domain, not who the organisation is, so a verified link is T3 (verifiable, not anchored in
 * an official list) with the domain as the shown name; a declared link that fails is T4.
 */
class LinkedDomains(
    private val httpClient: HttpClient,
    private val didResolver: DidResolver,
    private val cacheTtl: Duration = 10.minutes,
) : DidTrustSource {
    private val cache = mutableMapOf<String, Pair<LinkedDomainResult, Instant>>()

    override suspend fun decide(did: String, role: TrustRole): TrustDecision? = when (val r = verify(did)) {
        is LinkedDomainResult.Verified -> TrustDecision(TrustTier.T3, null, false, Url(r.origin).host, setOf(TrustLabel.UNKNOWN_ANCHOR),
            listOf("Domain ${r.origin} is linked to $did (DIF Well Known DID Configuration); the organisation itself is not verified"))
        is LinkedDomainResult.Unverified -> TrustDecision(TrustTier.T4, null, false, null, setOf(TrustLabel.UNKNOWN_ANCHOR),
            listOf("Linked domain ${r.origin} could not be verified: ${r.reason}"))
        LinkedDomainResult.Missing -> null
    }

    /** A host is bound to [did] when it serves a verified linked origin of the DID. */
    override suspend fun bindsHost(did: String, host: String): Boolean =
        (verify(did) as? LinkedDomainResult.Verified)?.let { Url(it.origin).host.equals(host, ignoreCase = true) } == true

    suspend fun verify(did: String): LinkedDomainResult {
        val now = Clock.System.now()
        cache[did]?.takeIf { it.second > now }?.let { return it.first }
        val result = check(did)
        cache[did] = result to now + cacheTtl
        return result
    }

    private suspend fun check(did: String): LinkedDomainResult {
        if (did.startsWith("did:key:") || did.startsWith("did:jwk:")) return LinkedDomainResult.Missing
        val doc = runCatching { didResolver.resolve(did) }.getOrNull() ?: return LinkedDomainResult.Missing
        val origins = doc.services.filter { it.type == "LinkedDomains" }.flatMap { it.endpoints }
        if (origins.isEmpty()) return LinkedDomainResult.Missing
        var last: LinkedDomainResult = LinkedDomainResult.Missing
        for (raw in origins) {
            val origin = normalizeOrigin(raw) ?: run { last = LinkedDomainResult.Unverified(raw, "Not an https origin"); null } ?: continue
            val r = checkOrigin(did, origin)
            if (r is LinkedDomainResult.Verified) return r
            last = r
        }
        return last
    }

    private suspend fun checkOrigin(did: String, origin: String): LinkedDomainResult {
        val url = "$origin/.well-known/did-configuration.json"
        val resp = runCatching { httpClient.get(url) }.getOrElse { return LinkedDomainResult.Unverified(origin, it.message ?: "Fetch failed") }
        if (resp.request.url.toString().trimEnd('/') != url.trimEnd('/')) return LinkedDomainResult.Unverified(origin, "The configuration redirects")
        if (!resp.status.isSuccess()) return LinkedDomainResult.Unverified(origin, "The configuration returned ${resp.status.value}")
        val body = runCatching { DiwJson.parseToJsonElement(resp.bodyAsText()) as JsonObject }.getOrNull()
            ?: return LinkedDomainResult.Unverified(origin, "The configuration is not JSON")
        val linked = body.arr("linked_dids").orEmpty().mapNotNull { (it as? JsonPrimitive)?.content }
        for (jwt in linked) {
            if (verifyLinkage(jwt, did, origin)) return LinkedDomainResult.Verified(origin)
        }
        return LinkedDomainResult.Unverified(origin, "No DomainLinkageCredential for $did")
    }

    private suspend fun verifyLinkage(jwt: String, did: String, origin: String): Boolean = runCatching {
        val jws = Jws.parse(jwt)
        val p = jws.payload
        if (p.str("iss") != did || p.str("sub") != did) return false
        val vc = p.obj("vc") ?: return false
        if ("DomainLinkageCredential" !in vc.strList("type")) return false
        val subject = vc.obj("credentialSubject") ?: return false
        if (subject.str("id") != did || normalizeOrigin(subject.str("origin") ?: return false) != origin) return false
        val kid = jws.kid ?: return false
        if (kid.substringBefore('#') != did) return false
        jws.verify(didResolver.resolveKey(did, kid).key)
        true
    }.getOrDefault(false)

    private fun normalizeOrigin(raw: String): String? {
        val u = runCatching { Url(raw.trim()) }.getOrNull() ?: return null
        if (u.protocol.name != "https" || u.host.isEmpty()) return null
        return if (u.port == 443) "https://${u.host}" else "https://${u.host}:${u.port}"
    }
}
