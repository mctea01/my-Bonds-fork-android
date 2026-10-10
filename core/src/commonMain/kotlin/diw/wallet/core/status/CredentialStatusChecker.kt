package diw.wallet.core.status

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.isAcceptableEndpoint
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlinx.io.bytestring.decodeToString as bsDecode
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.credential.Credential
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.multipaz.util.fromBase64Url
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.revocation.CompressedStatusList
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.revocation.RevocationStatus
import org.multipaz.sdjwt.SdJwt
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.webtoken.WebTokenCheck
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** Holder- or verifier-side status of a credential per Token Status List. */
data class CredentialStatus(
    val state: RevocationCheckState,
    /** True when the status list token was signed by a chain leading to an enabled ISSUER/STATUS_LIST anchor. */
    val trusted: Boolean,
    val environment: TrustEnvironment?,
    val checkedAt: Instant,
    val detail: String? = null,
) {
    val usable: Boolean get() = state == RevocationCheckState.VALID && trusted
}

/**
 * Token Status List checker (draft-ietf-oauth-status-list) on top of Multipaz status list parsing.
 * Adds what the Multipaz checker leaves out: the token sub must equal the referenced uri, the signer must
 * chain to an anchor in an enabled environment, and plain http is refused outside the test environment.
 * Results are cached in memory until the token ttl/exp.
 */
class CredentialStatusChecker(
    private val httpClient: HttpClient,
    private val trustRegistry: TrustRegistry,
    private val maxCacheAge: Duration = 60.minutes,
) {
    private data class Cached(val list: CompressedStatusList, val trusted: Boolean, val env: TrustEnvironment?, val until: Instant)

    private val cache = mutableMapOf<String, Cached>()

    suspend fun check(credential: Credential, bypassCache: Boolean = false): CredentialStatus {
        val (status, issuerChain) = statusOf(credential)
            ?: return result(RevocationCheckState.UNKNOWN, false, null, "Credential carries no status reference")
        return check(status, issuerChain, bypassCache)
    }

    suspend fun check(status: RevocationStatus, issuerChain: List<X509Cert>?, bypassCache: Boolean = false): CredentialStatus {
        if (status !is RevocationStatus.StatusList) {
            return result(RevocationCheckState.UNKNOWN, false, null, "Only Token Status List is supported")
        }
        val loopback = trustRegistry.policy.insecureLoopbackAllowed
        if (!isAcceptableEndpoint(status.uri, loopback)) {
            return result(RevocationCheckState.UNKNOWN, false, null, "Status list uri is not https")
        }
        val now = Clock.System.now()
        val cached = cache[status.uri]?.takeIf { !bypassCache && it.until > now } ?: try {
            fetch(status.uri, issuerChain).also { cache[status.uri] = it }
        } catch (e: Exception) {
            return result(RevocationCheckState.UNKNOWN, false, null, e.message)
        }
        val code = try {
            cached.list.decompress()[status.idx]
        } catch (e: Exception) {
            return result(RevocationCheckState.UNKNOWN, false, cached.env, "Index ${status.idx} outside the status list")
        }
        val state = when (code) {
            0 -> RevocationCheckState.VALID
            1 -> RevocationCheckState.INVALID
            2 -> RevocationCheckState.SUSPENDED
            else -> RevocationCheckState.UNKNOWN
        }
        return result(state, cached.trusted, cached.env, if (state == RevocationCheckState.UNKNOWN) "Status code $code" else null)
    }

    private suspend fun fetch(uri: String, issuerChain: List<X509Cert>?): Cached {
        val resp = httpClient.get(uri) { header(HttpHeaders.Accept, "application/statuslist+jwt") }
        if (!resp.status.isSuccess()) error("Status list fetch returned ${resp.status.value}")
        val jwt = resp.bodyAsText().trim()
        val header = jwt.substringBefore('.').fromBase64Url().decodeToString()
        val signerChain = runCatching {
            X509CertChain.fromX5c((DiwJson.parseToJsonElement(header) as JsonObject)["x5c"] as JsonArray).certificates
        }.getOrNull() ?: issuerChain ?: error("Status list token has no x5c and the issuer chain is unknown")
        val match = trustRegistry.match(TrustRole.STATUS_LIST, signerChain) ?: trustRegistry.match(TrustRole.ISSUER, signerChain)
            ?: error("Status list signer does not chain to an enabled anchor")
        val list = CompressedStatusList.fromJwt(
            jwt = jwt,
            trustedRootCert = match.anchor,
            checks = mapOf(WebTokenCheck.SUB to uri),
        )
        val until = minOf(list.expirationTime, Clock.System.now() + maxCacheAge)
        return Cached(list, true, match.environment, until)
    }

    private fun result(state: RevocationCheckState, trusted: Boolean, env: TrustEnvironment?, detail: String?) =
        CredentialStatus(state, trusted, env, Clock.System.now(), detail)

    companion object {
        /** Extracts the status reference and issuer chain from a stored credential. */
        suspend fun statusOf(credential: Credential): Pair<RevocationStatus, List<X509Cert>?>? = when (credential) {
            is MdocCredential -> {
                val chain = credential.issuerAuth.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)]?.asX509CertChain?.certificates
                credential.mso.revocationStatus?.let { it to chain }
            }
            is SdJwtVcCredential -> {
                val sdJwt = SdJwt.fromCompactSerialization(credential.issuerProvidedData.bsDecode())
                sdJwt.revocationStatus?.let { it to sdJwt.x5c?.certificates }
            }
            else -> null
        }
    }
}
