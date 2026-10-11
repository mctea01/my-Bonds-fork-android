package diw.wallet.core.trust

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.oid4vci.X509CertChainCheck
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.hostOf
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.X509CertChain
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** How a key fetched from a jku URL is tied to the party that signed with it; the first that applies is used. */
enum class JkuBinding {
    /** The JWK carries an x5c chain to an enabled trust anchor (any environment, not only a national list). */
    X509_ANCHOR,

    /** The jku host is the signer's own: the host of its did:web or of its https identifier. */
    SIGNER_HOST,

    /** A DID trust source ties the host to the signer (a registered service host, the registry's own platform, a linked domain). */
    TRUST_SOURCE,

    /** Nothing ties the host to the signer: the key is only as good as the TLS connection it came over. */
    TLS_ONLY,
}

/** A key taken from a jku key set, with why it may (or may not) be trusted. */
data class JkuKey(
    val key: VerificationKey,
    val binding: JkuBinding,
    /** Environment of the anchor or trust source that binds the key; null for TLS_ONLY. */
    val environment: TrustEnvironment?,
    val reason: String,
) {
    val bound: Boolean get() = binding != JkuBinding.TLS_ONLY
}

/**
 * Keys published at a jku (RFC 7515 4.1.2) for documents that have no other key source, such as status lists
 * signed with a key outside the issuer's DID. Binding to the signer is preferred; a key set the signer cannot be
 * tied to is still used, downgraded to [JkuBinding.TLS_ONLY]. Only https key sets are fetched, the kid must name
 * one key when the set holds several, and sets are cached for [cacheTtl].
 */
class JkuKeys(
    private val httpClient: HttpClient,
    private val trustRegistry: TrustRegistry,
    private val didTrust: DidTrust,
    private val cacheTtl: Duration = 10.minutes,
) {
    private val cache = mutableMapOf<String, Pair<JsonArray, Instant>>()

    /**
     * The key [kid] of the set at [jku], signed for [role] by [signer] (a DID or an https identifier). [refresh]
     * fetches the set again instead of using the cached one.
     */
    suspend fun resolve(jku: String, kid: String?, signer: String?, role: TrustRole, refresh: Boolean = false): JkuKey {
        // HTTPS without exception: the test environment's local HTTP allowance never applies to key sets.
        if (!isAcceptableEndpoint(jku, allowInsecureLoopback = false)) {
            throw ProtocolException("invalid_key", "jku $jku is not an https URL")
        }
        val jwk = select(keySet(jku, refresh), kid, jku)
        val key = VerificationKey.fromJwk(jwk)
        val host = hostOf(jku).lowercase()

        jwk.arr("x5c")?.let { x5c ->
            val chain = X509CertChain.fromX5c(x5c).certificates
            X509CertChainCheck.validate(chain)
            if (VerificationKey.fromCertificate(chain.first()) != key) throw ProtocolException("invalid_key", "jku key $kid differs from its x5c certificate")
            val match = trustRegistry.match(role, chain) ?: if (role == TrustRole.STATUS_LIST) trustRegistry.match(TrustRole.ISSUER, chain) else null
            if (match != null) return JkuKey(key, JkuBinding.X509_ANCHOR, match.environment, "jku key chains to the trust anchor ${match.metadata.displayName}")
        }
        signerHost(signer)?.let { if (it == host) return JkuKey(key, JkuBinding.SIGNER_HOST, null, "jku is on the signer's own host $host") }
        if (signer != null && signer.startsWith("did:") && didTrust.bindsHost(signer, host)) {
            val env = runCatching { didTrust.decide(signer, role)?.environment }.getOrNull()
            return JkuKey(key, JkuBinding.TRUST_SOURCE, env, "jku host $host is bound to $signer by a trust source")
        }
        return JkuKey(key, JkuBinding.TLS_ONLY, null, "jku host $host is not tied to ${signer ?: "the signer"}; the key rests on TLS only")
    }

    private suspend fun keySet(jku: String, refresh: Boolean): JsonArray {
        val now = Clock.System.now()
        if (!refresh) cache[jku]?.takeIf { it.second > now }?.let { return it.first }
        val resp = httpClient.get(jku) { header(HttpHeaders.Accept, "application/jwk-set+json, application/json") }
        if (!resp.status.isSuccess()) throw ProtocolException("invalid_key", "jku $jku returned ${resp.status.value}")
        val body = resp.bodyAsText()
        if (body.length > MAX_KEY_SET_CHARS) throw ProtocolException("invalid_key", "jku key set is too large")
        val keys = runCatching { (DiwJson.parseToJsonElement(body) as JsonObject).arr("keys") }.getOrNull()
            ?: throw ProtocolException("invalid_key", "jku $jku is not a JWK set")
        cache[jku] = keys to now + cacheTtl
        return keys
    }

    private fun select(keys: JsonArray, kid: String?, jku: String): JsonObject {
        val all = keys.filterIsInstance<JsonObject>().filter { it.str("use") == null || it.str("use") == "sig" }
        if (kid != null) {
            return all.firstOrNull { it.str("kid") == kid } ?: throw ProtocolException("invalid_key", "kid $kid is not in the key set at $jku")
        }
        return all.singleOrNull() ?: throw ProtocolException("invalid_key", "The key set at $jku has several keys and the document names none")
    }

    /** The signer's own host: of a did:web (port decoded), or of an https identifier. */
    private fun signerHost(signer: String?): String? = when {
        signer == null -> null
        signer.startsWith("did:web:") -> signer.removePrefix("did:web:").substringBefore(':').replace("%3A", ":").replace("%3a", ":")
            .substringBefore(':').lowercase()
        signer.startsWith("https://") -> runCatching { hostOf(signer).lowercase() }.getOrNull()
        else -> null
    }

    companion object {
        const val MAX_KEY_SET_CHARS = 200_000
    }
}
