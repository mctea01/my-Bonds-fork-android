package diw.wallet.core.federation

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.tierFor
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.long
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.isSuccess
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTableSpec
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** An Entity Statement (OpenID Federation 1.0 section 3): an Entity Configuration when iss equals sub. */
class EntityStatement private constructor(val jws: Jws) {
    val claims: JsonObject get() = jws.payload
    val iss: String = claims.str("iss") ?: fail("Entity Statement without iss")
    val sub: String = claims.str("sub") ?: fail("Entity Statement without sub")
    val iat: Long = claims.long("iat") ?: fail("Entity Statement without iat")
    val exp: Long = claims.long("exp") ?: fail("Entity Statement without exp")
    val jwks: List<JsonObject> = claims.obj("jwks")?.arr("keys")?.mapNotNull { it as? JsonObject } ?: fail("Entity Statement without jwks")
    val isConfiguration: Boolean get() = iss == sub
    val authorityHints: List<String> get() = claims.strList("authority_hints")
    val metadata: JsonObject get() = claims.obj("metadata") ?: JsonObject(emptyMap())
    val metadataPolicy: JsonObject? get() = claims.obj("metadata_policy")
    val constraints: JsonObject? get() = claims.obj("constraints")
    val fetchEndpoint: String? get() = metadata.obj("federation_entity")?.str("federation_fetch_endpoint")
    val trustMarkTypes: List<String> get() = trustMarks.map { it.first }

    /** The leaf's trust marks as (trust_mark_type, trust-mark JWT) pairs (OpenID Federation 1.0 section 7.1). */
    val trustMarks: List<Pair<String, String>> get() = claims.arr("trust_marks").orEmpty().mapNotNull { entry ->
        val o = entry as? JsonObject ?: return@mapNotNull null
        val type = o.str("trust_mark_type") ?: o.str("id") ?: return@mapNotNull null
        val jwt = o.str("trust_mark") ?: return@mapNotNull null
        type to jwt
    }

    /** An anchor's trust_mark_issuers claim: trust_mark_type -> allowed issuer Entity Identifiers. */
    val trustMarkIssuers: JsonObject? get() = claims.obj("trust_mark_issuers")

    /** Verifies the signature with one of [keys], chosen by kid when the header names one. */
    suspend fun verifyWith(keys: List<JsonObject>) {
        val kid = jws.kid
        val candidates = if (kid != null) keys.filter { it.str("kid") == kid } else keys
        if (candidates.isEmpty()) fail("No key ${kid ?: ""} of $iss to verify its statement about $sub")
        for (k in candidates) {
            val key = runCatching { VerificationKey.fromJwk(k) }.getOrNull() ?: continue
            if (runCatching { jws.verify(key) }.isSuccess) return
        }
        fail("Signature of $iss on its statement about $sub does not verify")
    }

    /** Rejects a statement outside its validity or with critical claims this wallet does not know. */
    fun checkTime(now: Long, skew: Long) {
        if (iat > now + skew) fail("Statement of $iss about $sub is not yet valid")
        if (exp <= now - skew) fail("Statement of $iss about $sub expired")
        val unknown = claims.strList("crit").filter { it !in KNOWN_CLAIMS }
        if (unknown.isNotEmpty()) fail("Statement of $iss uses critical claims ${unknown.joinToString()}")
    }

    companion object {
        const val TYPE = "entity-statement+jwt"
        private val KNOWN_CLAIMS = setOf(
            "iss", "sub", "iat", "exp", "jwks", "authority_hints", "metadata", "metadata_policy", "metadata_policy_crit",
            "constraints", "crit", "trust_marks", "trust_mark_issuers", "trust_mark_owners", "source_endpoint",
        )

        fun parse(compact: String): EntityStatement {
            val jws = Jws.parse(compact)
            if (jws.typ != TYPE) fail("Not an Entity Statement (typ ${jws.typ})")
            return EntityStatement(jws)
        }
    }
}

private fun fail(message: String): Nothing = throw ProtocolException("invalid_trust_chain", message)

/** A Trust Anchor the user (or a test setup) chose to trust: its Entity Identifier and keys. */
@Serializable
data class FederationAnchor(
    val entityId: String,
    /** The anchor's JWK Set as {"keys": [...]}, kept as JSON text. */
    val jwks: String,
    val name: String,
    /** [TrustEnvironment.id]: production, user or test. */
    val environment: String,
    val official: Boolean = false,
    val addedAt: Long,
) {
    val keys: List<JsonObject> get() =
        (DiwJson.parseToJsonElement(jwks) as JsonObject).arr("keys").orEmpty().mapNotNull { it as? JsonObject }
    val trustEnvironment: TrustEnvironment get() = TrustEnvironment.fromId(environment) ?: TrustEnvironment.USER
}

/** Trust Anchors kept in wallet storage. Test anchors only take part while the test environment is enabled. */
class FederationAnchors(private val storage: Storage) {
    private val serializer = ListSerializer(FederationAnchor.serializer())
    private var cached: List<FederationAnchor>? = null

    suspend fun all(): List<FederationAnchor> = cached ?: run {
        val raw = storage.getTable(table).get(KEY)
        raw?.let { runCatching { DiwJson.decodeFromString(serializer, it.decodeToString()) }.getOrNull() }.orEmpty().also { cached = it }
    }

    /** Adds or replaces the anchor for its Entity Identifier. */
    suspend fun put(anchor: FederationAnchor) {
        require(anchor.keys.isNotEmpty()) { "A Trust Anchor needs at least one key" }
        save(all().filter { it.entityId != anchor.entityId } + anchor)
    }

    suspend fun remove(entityId: String) = save(all().filter { it.entityId != entityId })

    private suspend fun save(list: List<FederationAnchor>) {
        val t = storage.getTable(table)
        val bytes = DiwJson.encodeToString(serializer, list).encodeToByteString()
        if (t.get(KEY) == null) t.insert(KEY, bytes) else t.update(KEY, bytes)
        cached = list
    }

    companion object {
        private val table = StorageTableSpec(name = "DiwFederationAnchors", supportPartitions = false, supportExpiration = false)
        private const val KEY = "anchors"
    }
}

/** A validated Trust Chain and the metadata it yields for one entity type. */
data class ResolvedEntity(
    val entityId: String,
    val entityType: String,
    val metadata: JsonObject,
    /** The leaf's federation_entity metadata after policy (organization_name, logo_uri and so on), if any. */
    val federationEntity: JsonObject?,
    val anchor: FederationAnchor,
    /** Entity Identifiers from the leaf up to the Trust Anchor. */
    val path: List<String>,
    val expiresAt: Long,
    val trustMarkTypes: List<String>,
    val chain: List<String>,
    /** The leaf Entity Configuration's own keys, to verify a signed_jwks_uri it publishes. */
    val leafKeys: List<JsonObject> = emptyList(),
    /** The leaf's trust marks as (type, JWT) pairs, to be verified against the Trust Anchor on demand. */
    val trustMarks: List<Pair<String, String>> = emptyList(),
) {
    /** A Trust Anchor is the party that vouches; its environment and official flag set the tier as for X.509 anchors. */
    val trust: TrustDecision get() = TrustDecision(
        tier = tierFor(anchor.trustEnvironment, anchor.official && anchor.trustEnvironment == TrustEnvironment.PRODUCTION, cryptographicallyVerified = true),
        environment = anchor.trustEnvironment,
        official = anchor.official && anchor.trustEnvironment == TrustEnvironment.PRODUCTION,
        anchorName = anchor.name,
        labels = buildSet {
            add(TrustLabel.OPENID_FEDERATION)
            if (anchor.trustEnvironment == TrustEnvironment.TEST) add(TrustLabel.TEST_ANCHOR)
            if (anchor.trustEnvironment == TrustEnvironment.USER) add(TrustLabel.USER_ANCHOR)
        },
        reasons = listOf("OpenID Federation trust chain " + path.joinToString(" -> ")),
    )

    /** The name to show: client_name or organization_name, else the Entity Identifier's host. */
    val displayName: String get() =
        metadata.str("client_name") ?: metadata.str("display_name") ?: federationEntity?.str("organization_name")
            ?: runCatching { Url(entityId).host }.getOrDefault(entityId)
}

/**
 * Builds and validates Trust Chains (OpenID Federation 1.0 sections 10 and 6): fetches Entity Configurations and
 * Subordinate Statements upward through authority_hints until a configured Trust Anchor, checks every signature,
 * validity and constraint, then merges the metadata policies from the anchor down and applies them to the leaf.
 */
class FederationResolver(
    private val http: HttpClient,
    private val anchors: suspend () -> List<FederationAnchor>,
    private val allowInsecureLoopback: Boolean = false,
    private val clock: Clock = Clock.System,
    private val maxDepth: Int = 10,
) {
    private val skew = 2.minutes.inWholeSeconds

    /** Resolves [entityId] for [entityType] (openid_credential_verifier, openid_credential_issuer, ...). */
    suspend fun resolve(entityId: String, entityType: String): ResolvedEntity {
        val trusted = anchors()
        if (trusted.isEmpty()) fail("No OpenID Federation Trust Anchor is configured")
        val leaf = configuration(entityId)
        val errors = ArrayList<String>()
        val chain = search(leaf, trusted, listOf(leaf), setOf(entityId), errors)
            ?: fail("No trust chain from $entityId to a configured Trust Anchor" + if (errors.isEmpty()) "" else ": " + errors.joinToString("; "))
        return validate(chain.first, chain.second, entityType)
    }

    /**
     * Validates a chain handed over by the party itself (the trust_chain JWS header): leaf Entity Configuration first,
     * then Subordinate Statements, optionally the anchor's Entity Configuration. It must end at a configured anchor.
     */
    suspend fun resolveChain(statements: List<String>, entityType: String): ResolvedEntity {
        if (statements.size < 2) fail("A trust chain needs at least the leaf configuration and one statement about it")
        val parsed = statements.map { EntityStatement.parse(it) }
        val trusted = anchors()
        val last = parsed.last()
        val anchorId = if (last.isConfiguration) last.iss else last.iss
        val anchor = trusted.firstOrNull { it.entityId == anchorId } ?: fail("Trust chain ends at $anchorId, which is not a configured Trust Anchor")
        val withoutAnchorConfig = if (last.isConfiguration && parsed.size > 2) parsed.dropLast(1) else parsed
        return validate(withoutAnchorConfig, anchor, entityType)
    }

    private suspend fun search(
        current: EntityStatement,
        trusted: List<FederationAnchor>,
        chain: List<EntityStatement>,
        visited: Set<String>,
        errors: MutableList<String>,
    ): Pair<List<EntityStatement>, FederationAnchor>? {
        if (chain.size > maxDepth) { errors += "chain longer than $maxDepth"; return null }
        for (hint in current.authorityHints) {
            if (hint in visited) continue
            val result = runCatching {
                val superior = configuration(hint)
                val endpoint = superior.fetchEndpoint ?: fail("$hint publishes no federation_fetch_endpoint")
                val statement = subordinate(endpoint, hint, current.sub)
                val extended = chain + statement
                val anchor = trusted.firstOrNull { it.entityId == hint }
                if (anchor != null) extended to anchor else search(superior, trusted, extended, visited + hint, errors)
            }
            result.onFailure { errors += it.message ?: it.toString() }
            result.getOrNull()?.let { return it }
        }
        return null
    }

    /** Section 10.2: signatures from the leaf up, times, constraints, then the merged metadata policy. */
    private suspend fun validate(chain: List<EntityStatement>, anchor: FederationAnchor, entityType: String): ResolvedEntity {
        val now = clock.now().epochSeconds
        val leaf = chain.first()
        if (!leaf.isConfiguration) fail("The trust chain does not start with an Entity Configuration")
        chain.forEach { it.checkTime(now, skew) }
        leaf.verifyWith(leaf.jwks)
        for (j in 1 until chain.size) {
            val s = chain[j]
            if (s.isConfiguration) fail("Unexpected Entity Configuration of ${s.iss} inside the trust chain")
            if (chain[j - 1].iss != s.sub) fail("Statement of ${s.iss} is about ${s.sub}, not ${chain[j - 1].iss}")
            // ES[j-1] is signed with a key ES[j] states for its subject.
            chain[j - 1].verifyWith(s.jwks)
        }
        val top = chain.last()
        if (top.iss != anchor.entityId) fail("The trust chain ends at ${top.iss}, not ${anchor.entityId}")
        top.verifyWith(anchor.keys)

        // Constraints of each Subordinate Statement apply to the entities below its issuer.
        var leafMetadata = leaf.metadata
        for (j in 1 until chain.size) {
            val c = chain[j].constraints ?: continue
            c.long("max_path_length")?.let { if (j - 1 > it) fail("${chain[j].iss} allows at most $it intermediates") }
            c.obj("naming_constraints")?.let { nc ->
                val permitted = nc.strList("permitted")
                val excluded = nc.strList("excluded")
                for (k in 0 until j) {
                    val host = runCatching { Url(chain[k].sub).host }.getOrNull() ?: fail("${chain[k].sub} is not a URL")
                    if (excluded.any { matches(host, it) }) fail("${chain[k].sub} is excluded by ${chain[j].iss}")
                    if (permitted.isNotEmpty() && permitted.none { matches(host, it) }) fail("${chain[k].sub} is outside the names ${chain[j].iss} permits")
                }
            }
            c.arr("allowed_entity_types")?.let { allowed ->
                val types = allowed.mapNotNull { (it as? JsonPrimitive)?.content }.toSet() + "federation_entity"
                leafMetadata = JsonObject(leafMetadata.filterKeys { it in types })
            }
        }

        // The immediate superior's metadata claim overrides the leaf's own values.
        chain.getOrNull(1)?.claims?.obj("metadata")?.let { override ->
            leafMetadata = JsonObject(leafMetadata + override.mapValues { (type, v) ->
                val base = leafMetadata.obj(type) ?: JsonObject(emptyMap())
                if (v is JsonObject) JsonObject(base + v) else v
            })
        }

        // Policies merge from the Trust Anchor's statement downward.
        val merged = HashMap<String, JsonObject>()
        for (j in chain.size - 1 downTo 1) {
            val s = chain[j]
            val crit = s.claims.strList("metadata_policy_crit").toSet()
            val unknownCrit = crit - MetadataPolicy.OPERATORS
            val policy = s.metadataPolicy ?: continue
            for ((type, p) in policy) {
                val obj = p as? JsonObject ?: fail("metadata_policy of ${s.iss} for $type is not an object")
                merged[type] = merged[type]?.let { MetadataPolicy.merge(it, obj, unknownCrit) } ?: MetadataPolicy.merge(JsonObject(emptyMap()), obj, unknownCrit)
            }
        }
        val raw = leafMetadata.obj(entityType) ?: fail("${leaf.sub} has no $entityType metadata")
        val metadata = merged[entityType]?.let { MetadataPolicy.apply(it, raw) } ?: raw
        val federationEntity = leafMetadata.obj("federation_entity")?.let { fe -> merged["federation_entity"]?.let { MetadataPolicy.apply(it, fe) } ?: fe }
        return ResolvedEntity(
            entityId = leaf.sub,
            entityType = entityType,
            metadata = metadata,
            federationEntity = federationEntity,
            anchor = anchor,
            path = listOf(leaf.sub) + chain.drop(1).map { it.iss },
            expiresAt = chain.minOf { it.exp },
            trustMarkTypes = leaf.trustMarkTypes,
            chain = chain.map { it.jws.compact },
            leafKeys = leaf.jwks,
            trustMarks = leaf.trustMarks,
        )
    }

    /**
     * The Verifier's signing keys: inline `jwks`, else fetched from `jwks_uri`, else from a `signed_jwks_uri` JWT
     * verified with the entity's own federation keys. The earlier version read only inline `jwks`, so verifiers that
     * publish their keys by reference could not be authenticated.
     */
    suspend fun verifierKeys(resolved: ResolvedEntity): List<JsonObject> {
        val md = resolved.metadata
        md.obj("jwks")?.arr("keys")?.mapNotNull { it as? JsonObject }?.takeIf { it.isNotEmpty() }?.let { return it }
        md.str("signed_jwks_uri")?.let { uri ->
            val signed = Jws.parse(fetchBody(uri, "application/jwk-set+jwt"))
            // A signed_jwks_uri JWT is signed with one of the entity's Federation Entity Keys.
            val kid = signed.kid
            val candidates = if (kid != null) resolved.leafKeys.filter { it.str("kid") == kid } else resolved.leafKeys
            if (candidates.none { k -> runCatching { signed.verify(VerificationKey.fromJwk(k)) }.isSuccess }) {
                fail("signed_jwks_uri of ${resolved.entityId} is not signed by a key of its Entity Configuration")
            }
            // Jws.verify checks only the signature; reject a key set whose JWT is outside its own validity, so an
            // expired signed JWK Set cannot keep rotated-out keys alive.
            val now = clock.now().epochSeconds
            signed.payload.long("iat")?.let { if (it > now + skew) fail("signed_jwks_uri of ${resolved.entityId} is not yet valid") }
            signed.payload.long("exp")?.let { if (it <= now - skew) fail("signed_jwks_uri of ${resolved.entityId} has expired") }
            return signed.payload.arr("keys")?.mapNotNull { it as? JsonObject }.orEmpty()
        }
        md.str("jwks_uri")?.let { uri ->
            val set = DiwJson.parseToJsonElement(fetchBody(uri, "application/jwk-set+json")) as? JsonObject
                ?: fail("jwks_uri of ${resolved.entityId} did not return a JWK Set")
            return set.arr("keys")?.mapNotNull { it as? JsonObject }.orEmpty()
        }
        return emptyList()
    }

    /**
     * The trust mark types the leaf presents that verify (OpenID Federation 1.0 section 7.4): a signed trust-mark+jwt
     * whose subject is the leaf, within its validity, signed by an issuer the Trust Anchor authorises for that type in
     * its trust_mark_issuers (when it declares any) and whose key comes from the issuer's Entity Configuration. Marks
     * that do not verify are dropped, never failing the request; a declared type that is not verified is not returned.
     */
    suspend fun verifiedTrustMarkTypes(resolved: ResolvedEntity): List<String> {
        if (resolved.trustMarks.isEmpty()) return emptyList()
        val now = clock.now().epochSeconds
        // trust_mark_issuers must come from an anchor configuration signed by a key the user already confirmed (the
        // saved anchor keys), not merely by a key the fetched configuration carries for itself: whoever controls the
        // anchor endpoint could otherwise self-sign a configuration authorising their own trust-mark issuer.
        val issuers = runCatching {
            val config = configuration(resolved.anchor.entityId)
            config.verifyWith(resolved.anchor.keys)
            config.checkTime(now, skew)
            config.trustMarkIssuers
        }.getOrNull()
        return resolved.trustMarks.mapNotNull { (type, jwt) ->
            runCatching {
                val mark = Jws.parse(jwt)
                if (mark.typ != TRUST_MARK_TYPE) return@runCatching null
                val claims = mark.payload
                if (claims.str("sub") != resolved.entityId) return@runCatching null
                if (claims.str("trust_mark_type") != type && claims.str("id") != type) return@runCatching null
                claims.long("iat")?.let { if (it > now + skew) return@runCatching null }
                claims.long("exp")?.let { if (it <= now - skew) return@runCatching null }
                val issuer = claims.str("iss") ?: return@runCatching null
                // When the anchor lists trust_mark_issuers, the issuer must be authorised for this type.
                issuers?.arr(type)?.let { allowed ->
                    if (allowed.none { (it as? JsonPrimitive)?.content == issuer }) return@runCatching null
                }
                val issuerKeys = configuration(issuer).jwks
                val kid = mark.kid
                val candidates = if (kid != null) issuerKeys.filter { it.str("kid") == kid } else issuerKeys
                if (candidates.none { k -> runCatching { mark.verify(VerificationKey.fromJwk(k)) }.isSuccess }) return@runCatching null
                type
            }.getOrNull()
        }.distinct()
    }

    private suspend fun fetchBody(url: String, accept: String): String {
        if (!isAcceptableEndpoint(url, allowInsecureLoopback)) fail("Federation endpoints must use HTTPS: $url")
        val r = http.get(url) { header(HttpHeaders.Accept, accept) }
        if (!r.status.isSuccess()) fail("$url answered ${r.status.value}")
        val text = r.bodyAsText()
        if (text.length > MAX_STATEMENT) fail("$url returned more than $MAX_STATEMENT characters")
        return text.trim()
    }

    /** RFC 5280 style host constraint: ".example.com" covers subdomains, "example.com" the host itself. */
    private fun matches(host: String, constraint: String): Boolean {
        val c = runCatching { Url(constraint).host.takeIf { constraint.contains("://") } }.getOrNull() ?: constraint
        return if (c.startsWith(".")) host.endsWith(c) else host.equals(c, ignoreCase = true)
    }

    /** The self-signed Entity Configuration at /.well-known/openid-federation. */
    suspend fun configuration(entityId: String): EntityStatement {
        val url = entityId.trimEnd('/') + "/.well-known/openid-federation"
        val s = EntityStatement.parse(fetch(url))
        if (!s.isConfiguration || s.sub != entityId) fail("$url is not the Entity Configuration of $entityId")
        s.verifyWith(s.jwks)
        return s
    }

    private suspend fun subordinate(endpoint: String, issuer: String, subject: String): EntityStatement {
        val url = URLBuilder(endpoint).apply { parameters.append("sub", subject) }.buildString()
        val s = EntityStatement.parse(fetch(url))
        if (s.iss != issuer || s.sub != subject) fail("$endpoint returned a statement of ${s.iss} about ${s.sub}")
        return s
    }

    private suspend fun fetch(url: String): String {
        if (!isAcceptableEndpoint(url, allowInsecureLoopback)) fail("Federation endpoints must use HTTPS: $url")
        val r = http.get(url) { header(HttpHeaders.Accept, "application/entity-statement+jwt") }
        if (!r.status.isSuccess()) fail("$url answered ${r.status.value}")
        val text = r.bodyAsText()
        if (text.length > MAX_STATEMENT) fail("$url returned more than $MAX_STATEMENT characters")
        return text.trim()
    }

    companion object {
        private const val MAX_STATEMENT = 256 * 1024
        private const val TRUST_MARK_TYPE = "trust-mark+jwt"
        const val VERIFIER = "openid_credential_verifier"
        const val ISSUER = "openid_credential_issuer"

        /** The trust_chain JWS header (OpenID Federation 1.0 section 4.3), when present. */
        fun trustChainHeader(jws: Jws): List<String>? =
            (jws.header["trust_chain"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
    }
}

/** Keys of a resolved Verifier: jwks in its metadata (signed_jwks_uri and jwks_uri are not fetched). */
fun ResolvedEntity.jwks(): List<JsonObject> = metadata.obj("jwks")?.arr("keys")?.mapNotNull { it as? JsonObject }.orEmpty()

/** Seconds left on the chain, for caching decisions. */
fun ResolvedEntity.remaining(now: Instant = Clock.System.now()): Long = expiresAt - now.epochSeconds
