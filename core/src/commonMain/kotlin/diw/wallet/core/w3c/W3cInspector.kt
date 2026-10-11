package diw.wallet.core.w3c

import diw.wallet.core.compat.DialectSet
import diw.wallet.core.compat.SdJwtKeyContext
import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.oid4vci.X509CertChainCheck
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.obj
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.str
import diw.wallet.core.util.wellKnownUrl
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.X509Cert
import kotlin.time.Clock
import kotlin.time.Instant

/** A W3C credential that passed inspection. */
data class InspectedW3c(
    val encoding: W3cEncoding,
    val types: List<String>,
    val issuer: String?,
    val subject: String?,
    /** Holder key the credential is bound to (cnf.jwk, or the key of a did:key/did:jwk subject); null when unbound. */
    val boundKey: EcPublicKey?,
    /** Holder DID the credential is bound to, when it is bound to a DID. */
    val holderDid: String?,
    val issuerChain: List<X509Cert>?,
    val trust: TrustDecision,
    val validFrom: Instant?,
    val validUntil: Instant?,
    /** The credential object with selectively disclosable claims resolved. */
    val credential: JsonObject,
)

/**
 * Verifies W3C Verifiable Credentials (VCDM 1.1 and 2.0): JWT (jwt_vc_json, jwt_vc_json-ld, vc+jwt), SD-JWT wrapped
 * W3C credentials (TWDIW) and JSON-LD credentials with Data Integrity proofs (ldp_vc).
 *
 * Issuer keys come from x5c (X.509 anchors decide the tier), the issuer DID (did:key, did:jwk, did:web; a DID trust
 * source decides the tier), or JWT VC issuer metadata for an https issuer. A jku header is never followed.
 */
class W3cInspector(
    private val httpClient: HttpClient,
    private val trustRegistry: TrustRegistry,
    private val allowInsecureLoopback: Boolean,
    private val didTrust: DidTrust = DidTrust.NONE,
    private val dataIntegrity: DataIntegrity = DataIntegrity(DidResolver(httpClient, allowInsecureLoopback)),
) {
    private val dids = DidResolver(httpClient, allowInsecureLoopback)

    /**
     * Inspects [raw]. [sdJwtAllowed] is true when SD-JWT delivery was announced or a dialect knows it is used;
     * [compat] supplies dialect issuer key lookups for SD-JWTs.
     */
    suspend fun inspect(
        raw: String,
        expectedTypes: List<String> = emptyList(),
        expectedIssuer: String? = null,
        sdJwtAllowed: Boolean = true,
        compat: DialectSet? = null,
        now: Instant = Clock.System.now(),
    ): InspectedW3c {
        val encoding = W3cEncoding.detect(raw)
        if (encoding == W3cEncoding.SD_JWT && !sdJwtAllowed) {
            throw ProtocolException("invalid_credential", "Issuer returned an SD-JWT for a W3C credential format")
        }
        val result = when (encoding) {
            W3cEncoding.JSON_LD -> inspectJsonLd(raw)
            else -> inspectJwt(raw, encoding, expectedIssuer, compat)
        }
        if (expectedTypes.isNotEmpty()) {
            val wanted = expectedTypes.filter { it != "VerifiableCredential" }
            if (wanted.isNotEmpty() && wanted.none { it in result.types }) {
                throw ProtocolException("invalid_credential", "Credential types ${result.types} do not include $wanted")
            }
        }
        result.validUntil?.let { if (it < now) throw ProtocolException("invalid_credential", "Credential already expired") }
        return result
    }

    private suspend fun inspectJwt(raw: String, encoding: W3cEncoding, expectedIssuer: String?, compat: DialectSet?): InspectedW3c {
        val parts = if (encoding == W3cEncoding.SD_JWT) SdJwtDisclosures.parse(raw) else null
        val jws = Jws.parse(parts?.issuerJwt ?: raw.trim())
        val payload = jws.payload
        val iss = payload.str("iss") ?: W3cVc.credentialObject(raw, encoding).idOf("issuer")
        val chain = jws.x5c?.certificates
        var reason: String? = null
        val key: VerificationKey = when {
            chain != null -> {
                X509CertChainCheck.validate(chain)
                VerificationKey.fromCertificate(chain.first())
            }
            iss != null && iss.startsWith("did:") -> {
                // An SD-JWT issuer key outside SD-JWT VC is found by a dialect when one applies (TWDIW: iss DID only).
                val dialectKey = if (encoding == W3cEncoding.SD_JWT) {
                    compat?.firstSuspend { it.sdJwtIssuerKey(SdJwtKeyContext(jws.header, payload, expectedIssuer ?: iss)) }
                } else null
                if (dialectKey != null) {
                    reason = dialectKey.reason
                    VerificationKey.Ec(dialectKey.key)
                } else {
                    reason = "Issuer key comes from the issuer DID $iss, not from an X.509 anchor"
                    dids.resolveKey(iss, jws.kid?.takeIf { it.startsWith("did:") || it.startsWith("#") }).key
                }
            }
            iss != null && isAcceptableEndpoint(iss, allowInsecureLoopback) -> {
                reason = "Issuer key comes from JWT VC issuer metadata, not from an X.509 anchor"
                jwtVcIssuerKey(iss, jws.kid)
            }
            else -> throw ProtocolException("invalid_credential", "No way to find the issuer key (no x5c, DID or https issuer)")
        }
        try {
            jws.verify(key)
        } catch (e: ProtocolException) {
            throw ProtocolException("invalid_credential", "W3C credential issuer signature is invalid", e)
        }
        val resolvedPayload = if (parts != null) SdJwtDisclosures.resolve(payload, parts.disclosures) else payload
        val vc = resolvedPayload.obj("vc") ?: resolvedPayload
        val vcIssuer = vc.idOf("issuer")
        if (payload.str("iss") != null && vcIssuer != null && vcIssuer != payload.str("iss")) {
            throw ProtocolException("invalid_credential", "iss does not match the credential issuer")
        }
        val (from, until) = W3cVc.validity(vc, payload)
        val subject = W3cVc.subject(vc, payload)
        val cnf = payload.obj("cnf")?.obj("jwk")
        val boundKey = cnf?.let { EcPublicKey.fromJwk(it) } ?: subject?.let { subjectKey(it) }
        val trust = when {
            chain != null -> trustRegistry.decide(TrustRole.ISSUER, chain)
            iss != null && iss.startsWith("did:") -> didTrust.decideOrDefault(iss, TrustRole.ISSUER, reason!!)
            else -> TrustDecision(TrustTier.T3, null, false, null, setOf(TrustLabel.UNKNOWN_ANCHOR), listOf(reason!!))
        }
        return InspectedW3c(
            encoding = encoding,
            types = W3cVc.types(vc),
            issuer = iss,
            subject = subject,
            boundKey = boundKey,
            holderDid = subject?.takeIf { it.startsWith("did:") },
            issuerChain = chain,
            trust = trust,
            validFrom = from,
            validUntil = until,
            credential = vc,
        )
    }

    private suspend fun inspectJsonLd(raw: String): InspectedW3c {
        val doc = W3cVc.credentialObject(raw, W3cEncoding.JSON_LD)
        val proof = dataIntegrity.verify(doc, expectedPurpose = "assertionMethod")
        val issuer = doc.idOf("issuer") ?: throw ProtocolException("invalid_credential", "Credential without issuer")
        if (proof.verificationMethod.substringBefore('#') != issuer) {
            throw ProtocolException("invalid_credential", "Proof verification method does not belong to the issuer $issuer")
        }
        val (from, until) = W3cVc.validity(doc, null)
        val subject = W3cVc.subject(doc, null)
        val trust = if (issuer.startsWith("did:")) {
            didTrust.decideOrDefault(issuer, TrustRole.ISSUER, "Issuer key comes from the issuer DID $issuer, not from an X.509 anchor")
        } else TrustDecision.unknown("Issuer is not a DID")
        return InspectedW3c(
            encoding = W3cEncoding.JSON_LD,
            types = W3cVc.types(doc),
            issuer = issuer,
            subject = subject,
            boundKey = subject?.let { subjectKey(it) },
            holderDid = subject?.takeIf { it.startsWith("did:") },
            issuerChain = null,
            trust = trust,
            validFrom = from,
            validUntil = until,
            credential = doc,
        )
    }

    /** Key of a did:key or did:jwk subject (resolved locally); other subjects bind no key here. */
    private suspend fun subjectKey(subject: String): EcPublicKey? {
        if (!subject.startsWith("did:key:") && !subject.startsWith("did:jwk:")) return null
        return (runCatching { dids.resolve(subject).methods.singleOrNull()?.key }.getOrNull() as? VerificationKey.Ec)?.key
    }

    private suspend fun jwtVcIssuerKey(issuer: String, kid: String?): VerificationKey {
        val resp = httpClient.get(wellKnownUrl(issuer, "jwt-vc-issuer"))
        if (!resp.status.isSuccess()) throw ProtocolException("invalid_credential", "jwt-vc-issuer metadata not available")
        val meta = parseJsonObject(resp.bodyAsText(), "invalid_credential")
        if (meta.str("issuer") != issuer) throw ProtocolException("invalid_credential", "jwt-vc-issuer metadata issuer mismatch")
        val jwks = meta.obj("jwks") ?: meta.str("jwks_uri")?.let { uri ->
            if (!isAcceptableEndpoint(uri, allowInsecureLoopback)) throw ProtocolException("invalid_credential", "jwks_uri must be https")
            parseJsonObject(httpClient.get(uri).bodyAsText(), "invalid_credential")
        } ?: throw ProtocolException("invalid_credential", "jwt-vc-issuer metadata has no keys")
        val keys = jwks.arr("keys").orEmpty().filterIsInstance<JsonObject>()
        val jwk = (if (kid != null) keys.firstOrNull { it.str("kid") == kid } else keys.singleOrNull())
            ?: throw ProtocolException("invalid_credential", "No issuer key matches kid '$kid'")
        return VerificationKey.fromJwk(jwk)
    }
}
