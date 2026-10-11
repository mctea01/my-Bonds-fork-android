package diw.testservers

import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.ClientIdPrefix
import diw.wallet.core.oid4vp.RequestValidationException
import diw.wallet.core.oid4vp.ext.WalletCredential
import diw.wallet.core.profile.msvid.MsPresentationRequirement
import diw.wallet.core.profile.twdiw.TwdiwTrustEntry
import diw.wallet.core.profile.twdiw.TwdiwTrustList
import diw.wallet.core.profile.twdiw.TwdiwTrustSnapshot
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.x509.x509Hash
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import io.ktor.http.encodeURLParameter
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlinx.serialization.json.addJsonObject
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

/** Trust and credential selection rules of the extended (pre-1.0 and profile) presentation paths. */
class PresentationSafetyTest {
    private val host = "verifier.legacy.diw.invalid"

    private suspend fun legacyRequest(pki: TestPki, clientIdValue: (String) -> String): String {
        val key = pki.readerKey(host)
        val leaf = key.certChain.certificates.first()
        val clientId = "x509_hash:" + clientIdValue(leaf.x509Hash())
        val jws = signJws(
            buildJsonObject {
                put("alg", "ES256"); put("typ", "oauth-authz-req+jwt")
                putJsonArray("x5c") { key.certChain.certificates.forEach { add(kotlinx.serialization.json.JsonPrimitive(Base64.getEncoder().encodeToString(it.encoded.toByteArray()))) } }
            },
            buildJsonObject {
                put("client_id", clientId); put("response_type", "vp_token"); put("response_mode", "direct_post")
                put("response_uri", "https://$host/response"); put("nonce", "n-0S6_WzA2Mj"); put("state", "s1")
                putJsonObject("presentation_definition") {
                    put("id", "pid")
                    putJsonArray("input_descriptors") {
                        addJsonObject {
                            put("id", "pid"); putJsonObject("format") { putJsonObject("vc+sd-jwt") { } }
                            putJsonObject("constraints") { putJsonArray("fields") { addJsonObject { putJsonArray("path") { add(kotlinx.serialization.json.JsonPrimitive("$.given_name")) } } } }
                        }
                    }
                }
            },
            key,
        )
        return "openid4vp://?client_id=${clientId.encodeURLParameter()}&request=$jws"
    }

    @Test
    fun legacyX509HashMustMatchTheSigningCertificate() = runBlocking<Unit> {
        val pki = TestPki.create()
        val w = WalletFixture().init(pki)
        val ok = w.holder.resolveUri(legacyRequest(pki) { it })
        assertEquals(ClientIdPrefix.X509_HASH, ok.verifier.clientId.prefix)
        val e = assertFailsWith<RequestValidationException> { w.holder.resolveUri(legacyRequest(pki) { (if (it.startsWith("A")) "B" else "A") + it.drop(1) }) }
        assertEquals("invalid_client", e.code)
    }

    @Test
    fun expiredCredentialsAreNotOffered() = runBlocking<Unit> {
        val pki = TestPki.create()
        val w = WalletFixture().init(pki)
        w.issueSdJwtPid(pki)
        assertEquals(1, WalletCredential.load(w.documentStore).size)
        assertTrue(WalletCredential.load(w.documentStore, pki.validUntil + 1.days).isEmpty(), "expired credential offered")
    }

    @Test
    fun twdiwOfficialOnlyForTheRegisteredSide() = runBlocking<Unit> {
        val list = TwdiwTrustList(HttpClient(MockEngine { respond("", HttpStatusCode.NotFound) }))
        fun snap(types: Set<Int>) = TwdiwTrustSnapshot(
            TwdiwTrustEntry("did:key:zTest", "x", "測試機關", null, null, null, null, types, null, null, emptyList()),
            "VERIFIED", "0x1", 1, true, Clock.System.now().toEpochMilliseconds(),
        )
        val verifierOnly = snap(setOf(TwdiwTrustList.ORG_TYPE_VERIFIER))
        assertEquals(TrustTier.T1, list.decisionFor(verifierOnly, TrustRole.VERIFIER).tier)
        val asIssuer = list.decisionFor(verifierOnly, TrustRole.ISSUER)
        assertEquals(TrustTier.T2, asIssuer.tier)
        assertFalse(asIssuer.official)
        assertTrue(asIssuer.reasons.any { "not as issuer" in it }, asIssuer.reasons.toString())
        assertEquals(TrustTier.T2, list.decisionFor(snap(setOf(TwdiwTrustList.ORG_TYPE_ISSUER)), TrustRole.VERIFIER).tier)
        assertEquals(TrustTier.T1, list.decisionFor(snap(setOf(1, 2)), TrustRole.ISSUER).tier)
        // The trust list screen judges the entry as listed.
        assertEquals(TrustTier.T1, list.decisionFor(verifierOnly).tier)
    }

    @Test
    fun verifiedIdPresentationLimitedToContractIssuers() {
        val r = MsPresentationRequirement("VerifiedEmployee", true, listOf("did:web:issuer.example"))
        assertTrue(r.accepts(listOf("VerifiableCredential", "VerifiedEmployee"), "did:web:issuer.example"))
        assertFalse(r.accepts(listOf("VerifiableCredential", "VerifiedEmployee"), "did:web:other.example"))
        assertFalse(r.accepts(listOf("VerifiableCredential", "VerifiedEmployee"), null))
        assertFalse(r.accepts(listOf("VerifiableCredential"), "did:web:issuer.example"))
        assertTrue(MsPresentationRequirement("VerifiedEmployee", true, emptyList()).accepts(listOf("VerifiedEmployee"), "did:web:any"))
    }
}
