package diw.testservers

import diw.wallet.core.compat.DialectSet
import diw.wallet.core.compat.Draft13Dialect
import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vci.CredentialInspector
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.oid4vp.RawAuthorizationRequest
import diw.wallet.core.oid4vp.RequestChannel
import diw.wallet.core.oid4vp.RequestValidator
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.DidTrustSource
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.trust.UserDidTrust
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.mdoc.vical.SignedVical
import org.multipaz.mdoc.vical.Vical
import org.multipaz.mdoc.vical.VicalCertificateInfo
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

/**
 * Every path that judges a party uses the same trust sources: a DID the user trusts counts for a standard OpenID4VP
 * verifier and for an SD-JWT VC issuer as it does for W3C credentials and pre-1.0 requests, and a VICAL issuer CA is
 * limited to its document types wherever an mdoc is judged.
 */
class TrustIntegrationTest {
    private val offline = HttpClient(MockEngine { respond("", HttpStatusCode.NotFound) })
    private val key = runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val did = runBlocking { DidKeys.didJwk(key.publicKey) }
    private val signer = AsymmetricKey.AnonymousExplicit(key, Algorithm.ES256)

    private suspend fun userTrust(role: TrustRole): DidTrust {
        val users = UserDidTrust(EphemeralStorage())
        users.put(did, "Example Party", setOf(role), 0)
        return DidTrust(listOf(users))
    }

    private suspend fun didRequest(): RawAuthorizationRequest {
        val clientId = "decentralized_identifier:$did"
        val payload = buildJsonObject {
            put("client_id", clientId)
            put("response_type", "vp_token")
            put("response_mode", "direct_post")
            put("response_uri", "https://verifier.example/callback")
            put("nonce", "a-nonce-that-is-long-enough-1234")
            put("dcql_query", buildJsonObject { put("credentials", buildJsonArray { }) })
        }
        val compact = signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "oauth-authz-req+jwt"); put("kid", "$did#0") },
            payload,
            signer,
        )
        return RawAuthorizationRequest(
            channel = RequestChannel.URI,
            outer = mapOf("client_id" to clientId),
            requestObject = Jws.parse(compact),
            params = payload,
            origin = null,
            walletNonce = null,
        )
    }

    @Test
    fun standardDidVerifierUsesTheDidTrustSources() = runBlocking<Unit> {
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        val unknown = RequestValidator(registry, DidResolver(offline), PresentationPolicy(), false).validate(didRequest())
        assertEquals(TrustTier.T3, unknown.verifier.trust.tier)
        assertTrue(TrustLabel.UNKNOWN_ANCHOR in unknown.verifier.trust.labels)

        val trusted = RequestValidator(registry, DidResolver(offline), PresentationPolicy(), false, userTrust(TrustRole.VERIFIER))
            .validate(didRequest())
        assertEquals(TrustTier.T2, trusted.verifier.trust.tier)
        assertEquals(TrustEnvironment.USER, trusted.verifier.trust.environment)
        assertEquals("Example Party", trusted.verifier.displayName)

        // A failed DID trust source (a declared linked domain that cannot be verified now) leaves a signed request to
        // the user's risk confirmation instead of rejecting it.
        val failing = DidTrust(listOf(object : DidTrustSource {
            override suspend fun decide(did: String, role: TrustRole): TrustDecision? =
                TrustDecision(TrustTier.T4, null, false, null, setOf(TrustLabel.UNKNOWN_ANCHOR), listOf("Linked domain could not be verified"))
        }))
        val t4 = RequestValidator(registry, DidResolver(offline), PresentationPolicy(), false, failing).validate(didRequest())
        assertEquals(TrustTier.T4, t4.verifier.trust.tier)

        // Trusting the DID as an issuer does not make it a trusted verifier.
        val otherRole = RequestValidator(registry, DidResolver(offline), PresentationPolicy(), false, userTrust(TrustRole.ISSUER))
            .validate(didRequest())
        assertEquals(TrustTier.T3, otherRole.verifier.trust.tier)
    }

    private suspend fun didSignedSdJwtVc(): String {
        val now = Clock.System.now().epochSeconds
        val jwt = signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "dc+sd-jwt"); put("kid", "$did#0") },
            buildJsonObject {
                put("iss", did)
                put("vct", "urn:example:membership")
                put("iat", now)
                put("_sd_alg", "sha-256")
                putJsonArray("_sd") { }
            },
            signer,
        )
        return "$jwt~"
    }

    @Test
    fun sdJwtVcIssuerDidUsesTheDidTrustSources() = runBlocking<Unit> {
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        val compat = DialectSet(listOf(Draft13Dialect(offline, false)))
        val unknown = CredentialInspector(offline, registry, false)
            .inspectSdJwt(didSignedSdJwtVc(), null, "https://issuer.example", null, compat)
        assertEquals(TrustTier.T3, unknown.trust.tier)

        val trusted = CredentialInspector(offline, registry, false, userTrust(TrustRole.ISSUER))
            .inspectSdJwt(didSignedSdJwtVc(), null, "https://issuer.example", null, DialectSet(listOf(Draft13Dialect(offline, false))))
        assertEquals(TrustTier.T2, trusted.trust.tier)
        assertEquals(TrustEnvironment.USER, trusted.trust.environment)
        assertEquals("Example Party", trusted.trust.anchorName)
    }

    @Test
    fun vicalIssuerIsLimitedToItsDocumentTypes() = runBlocking<Unit> {
        val pki = TestPki.create()
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addAnchor(TrustRole.TRUST_LIST_PROVIDER, TrustEnvironment.USER, pki.walletProviderRootCert, "List publisher", false, "manual")
        val now = Clock.System.now()
        val vical = SignedVical(
            Vical(
                version = "1.0",
                vicalProvider = "DIW Test Provider",
                date = now,
                nextUpdate = now + 7.days,
                notAfter = now + 30.days,
                vicalIssueID = 1,
                certificateInfos = listOf(VicalCertificateInfo(pki.iacaCert, listOf("org.iso.18013.5.1.mDL"))),
                vicalUrl = "https://example.test/vical",
                extensions = emptyMap(),
            ),
            pki.walletProviderSigner.certChain,
        ).generate(pki.walletProviderSigner)
        registry.importSignedMdocTrustList("vical", vical, "Issuer list", "https://example.test/vical")
        val chain = pki.documentSigner.certChain.certificates

        val mdl = registry.decide(TrustRole.ISSUER, chain, docType = "org.iso.18013.5.1.mDL")
        assertEquals(TrustTier.T2, mdl.tier)
        assertEquals(TrustEnvironment.USER, mdl.environment)

        // The same issuer CA signing a document type the list does not authorise leads to no anchor.
        val pid = registry.decide(TrustRole.ISSUER, chain, docType = "eu.europa.ec.eudi.pid.1")
        assertEquals(TrustTier.T3, pid.tier)
        assertEquals(null, pid.environment)

        // decision() reports a match exactly as decide() does, so a caller that keeps the anchor shows the same result.
        val m = registry.match(TrustRole.ISSUER, chain, docType = "org.iso.18013.5.1.mDL")
        assertEquals(mdl, registry.decision(m))
    }
}
