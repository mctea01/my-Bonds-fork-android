package diw.wallet.core.compat

import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.oid4vci.IssuerMetadata
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.EcPublicKey

/** An issuer key found by a dialect, with the reason shown to the user and the specification it follows. */
data class DialectIssuerKey(val key: EcPublicKey, val reason: String, val spec: String? = null)

/** What a dialect sees when the standard SD-JWT VC key lookup (x5c, JWT VC issuer metadata) does not apply. */
data class SdJwtKeyContext(
    val header: JsonObject,
    val payload: JsonObject,
    /** credential_issuer the credential was received from over TLS. */
    val credentialIssuer: String,
)

/**
 * Optional behaviour outside OpenID4VCI 1.0 and SD-JWT VC: earlier drafts and national profiles.
 *
 * The standard path never contains dialect logic. It calls these hooks only at the points where the standard
 * would stop (no nonce endpoint, a rejected request shape, a response or configuration it cannot read, an issuer
 * key it cannot find), and every credential obtained through a hook records the specification it followed. Each hook
 * returns null when the dialect has nothing to add.
 */
interface IssuanceDialect {
    /** Short identifier, e.g. draft13 or twdiw. */
    val id: String

    /** Specification this dialect implements, shown with credentials obtained through it. */
    val spec: String

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

    /** Credentials from a response without the 1.0 credentials array. */
    fun credentialsFromResponse(response: JsonObject): List<String>? = null

    /** Local type for an SD-JWT configuration that has no vct. */
    fun storageType(config: CredentialConfiguration): String? = null

    /** Issuer key for an SD-JWT that has no x5c and no https iss with JWT VC issuer metadata. */
    suspend fun sdJwtIssuerKey(context: SdJwtKeyContext): DialectIssuerKey? = null
}

/** Runs dialect hooks in order and remembers which dialects, and which specifications, one issuance used. */
class DialectSet(private val dialects: List<IssuanceDialect>) {
    val used = mutableSetOf<String>()
    val specs = linkedSetOf<String>()

    fun record(d: IssuanceDialect, spec: String = d.spec) {
        used += d.id
        specs += spec
    }

    fun <T : Any> first(hook: (IssuanceDialect) -> T?): T? {
        for (d in dialects) {
            val r = hook(d)
            if (r != null) { record(d, (r as? DialectIssuerKey)?.spec ?: d.spec); return r }
        }
        return null
    }

    /** Like [first], but a dialect that fails does not stop the next one; the first failure is rethrown if none succeeds. */
    suspend fun <T : Any> firstSuspend(hook: suspend (IssuanceDialect) -> T?): T? {
        var failure: Exception? = null
        for (d in dialects) {
            val r = try { hook(d) } catch (e: Exception) { if (failure == null) failure = e; null }
            if (r != null) { record(d, (r as? DialectIssuerKey)?.spec ?: d.spec); return r }
        }
        failure?.let { throw it }
        return null
    }

    val isEmpty: Boolean get() = dialects.isEmpty()
    val ids: List<String> get() = dialects.map { it.id }
}
