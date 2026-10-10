package diw.wallet.core.oid4vci

import diw.wallet.core.jose.Jws
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.hostOf
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
import org.multipaz.cbor.Cbor
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.X509Cert
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObject
import org.multipaz.revocation.RevocationStatus
import org.multipaz.sdjwt.SdJwt
import kotlin.time.Clock
import kotlin.time.Instant

/** What the wallet learned from checking an issued credential before storing it. */
data class InspectedCredential(
    val issuerChain: List<X509Cert>?,
    val trust: TrustDecision,
    val validFrom: Instant?,
    val validUntil: Instant?,
    val revocationStatus: RevocationStatus?,
    /** Holder key the issuer bound the credential to (cnf.jwk or MSO deviceKey); null for keyless SD-JWT VC. */
    val boundKey: EcPublicKey?,
)

/**
 * Checks credentials received from an issuer before they are certified into the document store:
 * issuer signature, type, holder key binding, validity and (mdoc) value digests. Credentials that fail
 * are never stored.
 */
class CredentialInspector(
    private val httpClient: HttpClient,
    private val trustRegistry: TrustRegistry,
    private val allowInsecureLoopback: Boolean,
) {
    suspend fun inspectSdJwt(
        compact: String,
        expectedVct: String?,
        expectedIssuer: String,
        holderKey: EcPublicKey?,
    ): InspectedCredential {
        val sdJwt = try {
            SdJwt.fromCompactSerialization(compact)
        } catch (e: Exception) {
            throw ProtocolException("invalid_credential", "Malformed SD-JWT VC", e)
        }
        val chain = sdJwt.x5c?.certificates
        val header = Jws.parse(compact.substringBefore('~')).header
        val jku = header.str("jku")
        val issuerKey: EcPublicKey = when {
            chain != null -> {
                X509CertChainCheck.validate(chain)
                chain.first().ecPublicKey
            }
            // W3C-style issuers (e.g. TWDIW) publish keys at jku and use a DID as iss.
            jku != null -> resolveJkuKey(jku, header.str("kid"), expectedIssuer)
            else -> resolveJwtVcIssuerKey(sdJwt.issuer ?: expectedIssuer, header.str("kid"))
        }
        try {
            sdJwt.verify(issuerKey)
        } catch (e: Exception) {
            throw ProtocolException("invalid_credential", "SD-JWT VC issuer signature is invalid", e)
        }
        if (expectedVct != null && sdJwt.credentialType != expectedVct) {
            throw ProtocolException("invalid_credential", "vct '${sdJwt.credentialType}' does not match '$expectedVct'")
        }
        if (holderKey != null && sdJwt.kbKey != holderKey) {
            throw ProtocolException("invalid_credential", "Credential is not bound to the requested holder key")
        }
        val now = Clock.System.now()
        sdJwt.validUntil?.let { if (it < now) throw ProtocolException("invalid_credential", "Credential already expired") }
        val trust = if (chain != null) trustRegistry.decide(TrustRole.ISSUER, chain) else TrustDecision(
            tier = TrustTier.T3, environment = null, official = false, anchorName = null,
            labels = setOf(TrustLabel.UNKNOWN_ANCHOR),
            reasons = listOf(
                if (jku != null) "Issuer key comes from jku on the credential issuer's domain, not from an X.509 anchor"
                else "Issuer key comes from JWT VC issuer metadata, not from an X.509 anchor"
            ),
        )
        return InspectedCredential(chain, trust, sdJwt.validFrom, sdJwt.validUntil, sdJwt.revocationStatus, sdJwt.kbKey)
    }

    suspend fun inspectMdoc(
        issuerSignedBytes: ByteArray,
        expectedDocType: String?,
        holderKey: EcPublicKey?,
    ): InspectedCredential {
        val issuerSigned = try {
            Cbor.decode(issuerSignedBytes)
        } catch (e: Exception) {
            throw ProtocolException("invalid_credential", "IssuerSigned is not CBOR", e)
        }
        val issuerAuth = issuerSigned["issuerAuth"].asCoseSign1
        val chain = issuerAuth.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)]?.asX509CertChain?.certificates
            ?: throw ProtocolException("invalid_credential", "issuerAuth has no x5chain")
        X509CertChainCheck.validate(chain)
        val algId = issuerAuth.protectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_ALG)]?.asNumber?.toInt()
            ?: throw ProtocolException("invalid_credential", "issuerAuth has no alg")
        try {
            Cose.coseSign1Check(chain.first().ecPublicKey, null, issuerAuth, Algorithm.fromCoseAlgorithmIdentifier(algId))
        } catch (e: Exception) {
            throw ProtocolException("invalid_credential", "issuerAuth signature is invalid", e)
        }
        val mso = MobileSecurityObject.fromDataItem(Cbor.decode(Cbor.decode(issuerAuth.payload!!).asTagged.asBstr))
        if (expectedDocType != null && mso.docType != expectedDocType) {
            throw ProtocolException("invalid_credential", "docType '${mso.docType}' does not match '$expectedDocType'")
        }
        if (holderKey != null && mso.deviceKey != holderKey) {
            throw ProtocolException("invalid_credential", "MSO deviceKey is not the requested holder key")
        }
        if (mso.validUntil < Clock.System.now()) throw ProtocolException("invalid_credential", "Credential already expired")
        val computed = IssuerNamespaces.fromDataItem(issuerSigned["nameSpaces"]).getValueDigests(mso.digestAlgorithm)
        for ((ns, digests) in computed) {
            val signed = mso.valueDigests[ns] ?: throw ProtocolException("invalid_credential", "Namespace $ns not covered by MSO")
            for ((id, d) in digests) {
                if (signed[id] != d) throw ProtocolException("invalid_credential", "Digest mismatch for $ns/$id")
            }
        }
        return InspectedCredential(chain, trustRegistry.decide(TrustRole.ISSUER, chain), mso.validFrom, mso.validUntil, mso.revocationStatus, mso.deviceKey)
    }

    /**
     * Key lookup through the JWS jku header. The credential arrived over TLS from [credentialIssuer], so a key set on
     * the same host, or a sibling host under the same organisation domain (at least three labels, e.g. wallet.gov.tw),
     * is accepted; anything else could let a third party vouch for the credential.
     */
    private suspend fun resolveJkuKey(jku: String, kid: String?, credentialIssuer: String): EcPublicKey {
        if (!isAcceptableEndpoint(jku, allowInsecureLoopback)) throw ProtocolException("invalid_credential", "jku must be https")
        val keyHost = hostOf(jku).lowercase()
        val issuerHost = hostOf(credentialIssuer).lowercase()
        val parent = issuerHost.substringAfter('.', "")
        val sameOrg = keyHost == issuerHost || (parent.count { it == '.' } >= 2 && keyHost.substringAfter('.', "") == parent)
        if (!sameOrg) throw ProtocolException("invalid_credential", "jku host $keyHost is not on the credential issuer's domain")
        val resp = httpClient.get(jku)
        if (!resp.status.isSuccess()) throw ProtocolException("invalid_credential", "jku key set not available (${resp.status.value})")
        val keys = parseJsonObject(resp.bodyAsText(), "invalid_credential").arr("keys").orEmpty().filterIsInstance<JsonObject>()
        val jwk = (if (kid != null) keys.firstOrNull { it.str("kid") == kid } else keys.singleOrNull())
            ?: keys.singleOrNull() ?: throw ProtocolException("invalid_credential", "No key in jku matches kid '$kid'")
        return EcPublicKey.fromJwk(jwk)
    }

    /** SD-JWT VC issuer metadata (/.well-known/jwt-vc-issuer) key lookup. */
    private suspend fun resolveJwtVcIssuerKey(issuer: String, kid: String?): EcPublicKey {
        if (!isAcceptableEndpoint(issuer, allowInsecureLoopback)) {
            throw ProtocolException("invalid_credential", "SD-JWT VC without x5c and with non-https iss")
        }
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
        return EcPublicKey.fromJwk(jwk)
    }
}
