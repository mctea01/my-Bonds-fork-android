package diw.wallet.core.status

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.w3c.W3cVc
import diw.wallet.core.w3c.W3cVcCredential
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.readRawBytes
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString as bsDecode
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Tagged
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.credential.Credential
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.multipaz.util.fromBase64Url
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.revocation.CompressedStatusList
import org.multipaz.revocation.IdentifierList
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.revocation.RevocationStatus
import org.multipaz.sdjwt.SdJwt
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.webtoken.WebTokenCheck
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** How far a status result can be relied on; the order is from strongest to weakest. */
enum class StatusAssurance {
    /** The list is signed by a key tied to the issuer or to a trust anchor. */
    TRUSTED,

    /** The list's signature verifies with a key that rests on TLS only (a jku not tied to the issuer). */
    TLS_ONLY,

    /** The list's signature could not be verified, or no list was read. */
    UNVERIFIED,
}

/** Holder- or verifier-side status of a credential per Token Status List or a W3C status list. */
data class CredentialStatus(
    val state: RevocationCheckState,
    /** True when the status list token was signed by a chain leading to an enabled ISSUER/STATUS_LIST anchor. */
    val trusted: Boolean,
    val environment: TrustEnvironment?,
    val checkedAt: Instant,
    val detail: String? = null,
    /** The status value read from the list. */
    val code: Int? = null,
    /** The credential's status reference (status.status_list uri and idx). */
    val uri: String? = null,
    val index: Int? = null,
    /** The status list token the value was read from. */
    val list: StatusListToken? = null,
    /** The status in the specification's own terms when it is not a Token Status List value (W3C statusPurpose and value). */
    val label: String? = null,
    /** Per-entry results of a W3C credential with several credentialStatus entries. */
    val w3cEntries: List<W3cEntryStatus> = emptyList(),
    val assurance: StatusAssurance = if (trusted) StatusAssurance.TRUSTED else StatusAssurance.UNVERIFIED,
    /** False when the credential names no status list at all (the issuer offers no status), as opposed to a list that could not be read. */
    val referenced: Boolean = true,
    /** The revocation mechanism in the specification's own name, e.g. "Token Status List" or "Identifier List". */
    val mechanism: String? = null,
) {
    val usable: Boolean get() = state == RevocationCheckState.VALID && trusted

    /** The value's name in the Token Status List specification, or its hex value for application-specific and reserved values. */
    val specName: String? get() = label ?: code?.let { STATUS_NAMES[it] ?: ("0x" + it.toString(16).uppercase().padStart(2, '0')) }

    companion object {
        val STATUS_NAMES = mapOf(0 to "VALID", 1 to "INVALID", 2 to "SUSPENDED")
    }
}

/** Parsed status list token (draft-ietf-oauth-status-list): list parameters, lifetime and signer. */
data class StatusListToken(
    val bitsPerItem: Int,
    val issuedAt: Instant,
    val expiresAt: Instant?,
    /** Seconds the token may be cached (ttl claim). */
    val ttl: Long?,
    val signer: List<X509Cert>,
    val anchorName: String?,
)

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
    didTrust: DidTrust = DidTrust.NONE,
) {
    /** W3C credentials (Bitstring Status List, Status List 2021, Revocation List 2020) are checked here. */
    val w3c = W3cStatusChecker(httpClient, trustRegistry, didTrust, maxCacheAge)

    private data class Cached(val list: CompressedStatusList, val trusted: Boolean, val env: TrustEnvironment?, val until: Instant, val token: StatusListToken)

    private data class CachedIdentifiers(val list: IdentifierList, val env: TrustEnvironment?, val until: Instant, val anchorName: String?)

    private val cache = mutableMapOf<String, Cached>()

    private val identifierCache = mutableMapOf<String, CachedIdentifiers>()

    suspend fun check(credential: Credential, bypassCache: Boolean = false): CredentialStatus {
        if (credential is W3cVcCredential) {
            val vc = runCatching { credential.credentialJson() }.getOrNull()
                ?: return result(RevocationCheckState.UNKNOWN, false, null, "Credential cannot be parsed")
            val jwt = W3cVc.jwtPayloadOrNull(credential.raw, credential.encoding)
            return w3c.check(vc, W3cVc.issuer(vc, jwt), bypassCache)
        }
        val (status, issuerChain) = statusOf(credential)
            ?: return result(RevocationCheckState.UNKNOWN, false, null, "Credential carries no status reference").copy(referenced = false)
        return check(status, issuerChain, bypassCache)
    }

    suspend fun check(status: RevocationStatus, issuerChain: List<X509Cert>?, bypassCache: Boolean = false): CredentialStatus = when (status) {
        is RevocationStatus.StatusList -> checkStatusList(status, issuerChain, bypassCache)
        // ISO/IEC 18013-5 Section 12.3.6.4 Identifier List: a CWT whose membership set lists the revoked documents.
        is RevocationStatus.IdentifierList -> checkIdentifierList(status, issuerChain, bypassCache)
        else -> result(RevocationCheckState.UNKNOWN, false, null, "Unsupported revocation mechanism")
    }

    private suspend fun checkStatusList(status: RevocationStatus.StatusList, issuerChain: List<X509Cert>?, bypassCache: Boolean): CredentialStatus {
        val loopback = trustRegistry.policy.insecureLoopbackAllowed
        if (!isAcceptableEndpoint(status.uri, loopback)) {
            return result(RevocationCheckState.UNKNOWN, false, null, "Status list uri is not https", mechanism = TOKEN_STATUS_LIST)
        }
        val now = Clock.System.now()
        val cached = cache[status.uri]?.takeIf { !bypassCache && it.until > now } ?: try {
            fetch(status.uri, issuerChain).also { cache[status.uri] = it }
        } catch (e: Exception) {
            return result(RevocationCheckState.UNKNOWN, false, null, e.message, uri = status.uri, index = status.idx, mechanism = TOKEN_STATUS_LIST)
        }
        val code = try {
            cached.list.decompress()[status.idx]
        } catch (e: Exception) {
            return result(RevocationCheckState.UNKNOWN, false, cached.env, "Index ${status.idx} outside the status list", null, status.uri, status.idx, cached.token, mechanism = TOKEN_STATUS_LIST)
        }
        val state = when (code) {
            0 -> RevocationCheckState.VALID
            1 -> RevocationCheckState.INVALID
            2 -> RevocationCheckState.SUSPENDED
            else -> RevocationCheckState.UNKNOWN
        }
        val detail = if (state == RevocationCheckState.UNKNOWN) "Status code $code" else null
        return result(state, cached.trusted, cached.env, detail, code, status.uri, status.idx, cached.token, mechanism = TOKEN_STATUS_LIST)
    }

    /**
     * Identifier List (ISO/IEC 18013-5): the document is revoked when its [RevocationStatus.IdentifierList.id] is in
     * the signed CWT's membership set. The CWT signer must chain to an enabled STATUS_LIST or ISSUER anchor, matching
     * the trust evaluation the Token Status List path uses; an unverified list is never relied on.
     */
    private suspend fun checkIdentifierList(status: RevocationStatus.IdentifierList, issuerChain: List<X509Cert>?, bypassCache: Boolean): CredentialStatus {
        val loopback = trustRegistry.policy.insecureLoopbackAllowed
        if (!isAcceptableEndpoint(status.uri, loopback)) {
            return result(RevocationCheckState.UNKNOWN, false, null, "Identifier list uri is not https", uri = status.uri, mechanism = IDENTIFIER_LIST)
        }
        val now = Clock.System.now()
        val cached = identifierCache[status.uri]?.takeIf { !bypassCache && it.until > now } ?: try {
            fetchIdentifiers(status, issuerChain).also { identifierCache[status.uri] = it }
        } catch (e: Exception) {
            return result(RevocationCheckState.UNKNOWN, false, null, e.message, uri = status.uri, mechanism = IDENTIFIER_LIST)
        }
        val state = if (cached.list.contains(status.id)) RevocationCheckState.INVALID else RevocationCheckState.VALID
        return result(state, true, cached.env, "ISO/IEC 18013-5 Identifier List（${cached.anchorName ?: "signed"}）", uri = status.uri, mechanism = IDENTIFIER_LIST)
    }

    private suspend fun fetchIdentifiers(status: RevocationStatus.IdentifierList, issuerChain: List<X509Cert>?): CachedIdentifiers {
        val resp = httpClient.get(status.uri) { header(HttpHeaders.Accept, "application/identifierlist+cwt") }
        if (!resp.status.isSuccess()) error("Identifier list fetch returned ${resp.status.value}")
        val cwt = resp.readRawBytes()
        // The signer chain is taken from the CWT's COSE_Sign1 x5chain, then from the status reference's own certificate,
        // then the issuer chain, so the list can be matched against a trust anchor exactly as a status list token is.
        val sign1 = run {
            val decoded = Cbor.decode(cwt)
            (if (decoded is Tagged && decoded.tagNumber == Tagged.COSE_SIGN1) decoded.taggedItem else decoded).asCoseSign1
        }
        val x5chain = (sign1.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)]
            ?: sign1.protectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)])?.asX509CertChain?.certificates
        val signerChain = x5chain ?: status.certificate?.let { listOf(it) } ?: issuerChain
            ?: error("Identifier list token has no x5c and the issuer chain is unknown")
        val match = trustRegistry.match(TrustRole.STATUS_LIST, signerChain) ?: trustRegistry.match(TrustRole.ISSUER, signerChain)
            ?: error("Identifier list signer does not chain to an enabled anchor")
        val list = IdentifierList.fromCwt(
            cwt = cwt,
            trustedRootCert = match.anchor,
            checks = mapOf(WebTokenCheck.SUB to status.uri),
        )
        val until = minOf(list.expirationTime, Clock.System.now() + maxCacheAge)
        return CachedIdentifiers(list, match.environment, until, match.metadata.displayName)
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
        val payload = runCatching { DiwJson.parseToJsonElement(jwt.split('.')[1].fromBase64Url().decodeToString()) as JsonObject }.getOrNull()
        val token = StatusListToken(
            bitsPerItem = list.bitsPerItem,
            issuedAt = list.creationTime,
            expiresAt = (payload?.get("exp") as? JsonPrimitive)?.longOrNull?.let { Instant.fromEpochSeconds(it) },
            ttl = (payload?.get("ttl") as? JsonPrimitive)?.longOrNull,
            signer = signerChain,
            anchorName = match.metadata.displayName,
        )
        return Cached(list, true, match.environment, until, token)
    }

    private fun result(
        state: RevocationCheckState,
        trusted: Boolean,
        env: TrustEnvironment?,
        detail: String?,
        code: Int? = null,
        uri: String? = null,
        index: Int? = null,
        token: StatusListToken? = null,
        mechanism: String? = null,
    ) = CredentialStatus(state, trusted, env, Clock.System.now(), detail, code, uri, index, token, mechanism = mechanism)

    companion object {
        /** Revocation mechanisms in their specifications' own names. */
        const val TOKEN_STATUS_LIST = "Token Status List"
        const val IDENTIFIER_LIST = "Identifier List"

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
