package diw.wallet.core.compat

import diw.wallet.core.oid4vci.AuthServerMetadata
import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.oid4vci.CredentialOffer
import diw.wallet.core.oid4vci.IssuerMetadata
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.EcPublicKey

/** An issuer key found by a dialect, with the reason shown to the user and the specification it follows. */
/** [spec] is recorded for the session; null records the dialect's own spec, an empty string records nothing. */
data class DialectIssuerKey(val key: EcPublicKey, val reason: String, val spec: String? = null)

/** What a dialect sees when the standard SD-JWT VC key lookup (x5c, JWT VC issuer metadata) does not apply. */
data class SdJwtKeyContext(
    val header: JsonObject,
    val payload: JsonObject,
    /** credential_issuer the credential was received from over TLS. */
    val credentialIssuer: String,
)

/** How the key in a proof of possession is identified. */
enum class ProofKid {
    /** jwk header with the public key (OpenID4VCI 1.0 default). */
    JWK,
    /** kid with a DID URL of the holder DID (OpenID4VCI 1.0 for DID binding). */
    DID_URL,
    /** kid with the holder DID itself, without a fragment (TWDIW). */
    BARE_DID,
}

/** Proof JWT shape a dialect requires instead of the OpenID4VCI 1.0 default. */
data class ProofStyle(val kid: ProofKid, val iss: String?)

/**
 * A wallet-level holder identity shared by every credential of one profile, as the profile's own wallet does it.
 * [didMethod] is did:key:jwk_jcs (multicodec 0xEB51), did:key (curve multicodec) or did:jwk.
 */
data class HolderProfile(val id: String, val didMethod: String)

/** Deferred issuance announced in an older way: a draft 13 transaction_id in a 200 response, or a draft 11 acceptance_token. */
data class Deferral(val id: String, val acceptanceToken: Boolean)

/** Token request facts a dialect may need to add its own parameters. */
data class TokenContext(
    val offer: CredentialOffer?,
    val issuer: IssuerMetadata,
    val configurationIds: List<String>,
    val txCode: String?,
)

/**
 * Behaviour outside OpenID4VCI 1.0 and SD-JWT VC: earlier drafts and national profiles. All dialects are always on.
 *
 * The standard path never contains dialect logic. It calls these hooks only at the points where the standard
 * would stop (an offer or metadata in an older shape, no authorization server metadata, no nonce endpoint, a
 * rejected request shape, a response or configuration it cannot read, an issuer key it cannot find), or when a
 * dialect owns the session because the issuer is known to follow it ([claimsIssuer]). Every credential obtained
 * through a hook records the specification it followed. Each hook returns null when the dialect has nothing to add.
 */
interface IssuanceDialect {
    /** Short identifier, e.g. draft13 or twdiw. */
    val id: String

    /** Specification this dialect implements, shown with credentials obtained through it. */
    val spec: String

    // ------------------------------------------------------------ session ownership

    /** True when [credentialIssuer], reached through [entryHint] (e.g. twdiw for its custom scheme), follows this dialect. */
    fun claimsIssuer(credentialIssuer: String, entryHint: String?): Boolean = false

    /** True when the (normalized) metadata shows the issuer follows this dialect, e.g. it was in the draft 11 shape. */
    fun claimsMetadata(issuer: IssuerMetadata): Boolean = false

    /**
     * The issuer identifier an owned session uses when the metadata's credential_issuer ([inMetadata]) is not
     * identical to the one the wallet was given ([given]), which OpenID4VCI 1.0 requires; null refuses the metadata.
     */
    fun issuerIdentifier(given: String, inMetadata: String): String? = null

    /** Holder identity shared by all credentials of an owned session; null keeps one key per credential. */
    fun holderProfile(issuer: IssuerMetadata): HolderProfile? = null

    /** Token request parameters for an owned session, replacing or adding to the 1.0 form. */
    fun tokenParameters(context: TokenContext): Map<String, String>? = null

    /** Proof JWT shape for an owned session. */
    fun proofStyle(issuer: IssuerMetadata, config: CredentialConfiguration): ProofStyle? = null

    /** Credential request body for an owned session. */
    fun credentialRequest(issuer: IssuerMetadata, config: CredentialConfiguration, credentialIdentifier: String?, proofs: JsonObject?): JsonObject? = null

    // ------------------------------------------------------------ older message shapes

    /** A 1.0 shaped credential offer for an offer in an older shape. */
    fun normalizeOffer(offer: JsonObject): JsonObject? = null

    /** 1.0 shaped issuer metadata for metadata in an older shape. */
    fun normalizeIssuerMetadata(metadata: JsonObject): JsonObject? = null

    /** Authorization server metadata when the issuer publishes none (token endpoint in issuer metadata, or a fixed one). */
    fun authorizationServerFallback(issuer: IssuerMetadata): AuthServerMetadata? = null

    /** c_nonce for proofs when the issuer has no nonce endpoint; [tokenResponse] is the raw token response. */
    fun nonceWithoutEndpoint(tokenResponse: JsonObject): String? = null

    /** Fresh c_nonce carried in a credential error response. */
    fun nonceFromError(error: JsonObject): String? = null

    /** A different request body after the issuer rejected the 1.0 credential request with [status] and [error]. */
    fun alternativeCredentialRequest(
        issuer: IssuerMetadata,
        config: CredentialConfiguration,
        credentialIdentifier: String?,
        proofs: JsonObject?,
        status: HttpStatusCode,
        error: JsonObject,
    ): JsonObject? = null

    /** Batch endpoint for single-proof requests in this dialect's shape (draft 13 batch_credential_endpoint). */
    fun batchEndpoint(issuer: IssuerMetadata): String? = null

    /** The request body rewritten for issuers using older parameter names (e.g. draft 11 response encryption). */
    fun adaptRequestBody(issuer: IssuerMetadata, body: JsonObject): JsonObject? = null

    /** Credentials from a response without the 1.0 credentials array. */
    fun credentialsFromResponse(response: JsonObject): List<String>? = null

    /** Deferred issuance announced in a successful response without credentials (draft 13 transaction_id, draft 11 acceptance_token). */
    fun deferral(response: JsonObject): Deferral? = null

    /** True when a deferred endpoint error means the credential is not ready yet (draft 13 issuance_pending). */
    fun isIssuancePending(status: HttpStatusCode, error: JsonObject): Boolean = false

    /** Local type for an SD-JWT configuration that has no vct. */
    fun storageType(config: CredentialConfiguration): String? = null

    /** True when this dialect knows that [config], announced as a W3C format, is delivered as an SD-JWT. */
    fun w3cDeliveredAsSdJwt(config: CredentialConfiguration): Boolean = false

    /** Issuer key for an SD-JWT that has no x5c and no https iss with JWT VC issuer metadata. */
    suspend fun sdJwtIssuerKey(context: SdJwtKeyContext): DialectIssuerKey? = null

    /** Whether an authorization response [iss] that differs from [authServer]'s issuer (RFC 9207) still names that server. */
    fun acceptsAuthorizationResponseIssuer(authServer: AuthServerMetadata, iss: String): Boolean = false
}

/** Runs dialect hooks in order and remembers which dialects, and which specifications, one session used. */
class DialectSet(private val dialects: List<IssuanceDialect>) {
    val used = mutableSetOf<String>()
    val specs = linkedSetOf<String>()

    /** Dialect that owns the session (claimed the issuer or supplied its authorization server); null for 1.0 issuers. */
    var owner: IssuanceDialect? = null
        private set

    fun record(d: IssuanceDialect, spec: String = d.spec) {
        used += d.id
        if (spec.isNotEmpty()) specs += spec
    }

    fun claim(d: IssuanceDialect) {
        if (owner == null) owner = d
        record(d)
    }

    /** Asks the owning dialect, recording it when it answers. */
    fun <T : Any> owned(hook: (IssuanceDialect) -> T?): T? {
        val d = owner ?: return null
        return hook(d)?.also { record(d) }
    }

    fun <T : Any> first(hook: (IssuanceDialect) -> T?): T? {
        for (d in ordered()) {
            val r = hook(d)
            if (r != null) { record(d, (r as? DialectIssuerKey)?.spec ?: d.spec); return r }
        }
        return null
    }

    /** The first dialect answering yes, without recording it; the caller records it once the answer was actually used. */
    fun firstWhere(hook: (IssuanceDialect) -> Boolean): IssuanceDialect? = ordered().firstOrNull(hook)

    /** Like [first] for yes/no hooks. */
    fun any(hook: (IssuanceDialect) -> Boolean): Boolean = first { if (hook(it)) true else null } == true

    /** Like [first], but a dialect that fails does not stop the next one; the first failure is rethrown if none succeeds. */
    suspend fun <T : Any> firstSuspend(hook: suspend (IssuanceDialect) -> T?): T? {
        var failure: Exception? = null
        for (d in ordered()) {
            val r = try { hook(d) } catch (e: Exception) { if (failure == null) failure = e; null }
            if (r != null) { record(d, (r as? DialectIssuerKey)?.spec ?: d.spec); return r }
        }
        failure?.let { throw it }
        return null
    }

    /** The first dialect claiming the issuer becomes the owner. */
    fun claimFor(credentialIssuer: String, entryHint: String?) {
        if (owner == null) dialects.firstOrNull { it.claimsIssuer(credentialIssuer, entryHint) }?.let { claim(it) }
    }

    /** Ownership from the metadata, when no dialect claimed the issuer already. */
    fun claimFor(issuer: IssuerMetadata) {
        if (owner == null) dialects.firstOrNull { it.claimsMetadata(issuer) }?.let { claim(it) }
    }

    /** The owner is asked first, so its answer wins over another dialect's. */
    private fun ordered(): List<IssuanceDialect> = owner?.let { o -> listOf(o) + dialects.filter { it !== o } } ?: dialects

    val all: List<IssuanceDialect> get() = dialects
    val isEmpty: Boolean get() = dialects.isEmpty()
    val ids: List<String> get() = dialects.map { it.id }
}
