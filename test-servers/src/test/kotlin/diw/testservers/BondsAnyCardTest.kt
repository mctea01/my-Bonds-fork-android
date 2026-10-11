package diw.testservers

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.signJws
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.BondsOfflineVerifier
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.util.ProtocolException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respondError
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.sdjwt.SdJwt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.time.Clock

/**
 * The Bonds offline presentation beyond TWDIW cards (source "a"): an IETF SD-JWT VC bound by cnf, and a W3C JWT VC
 * bound by its subject DID, each signed into the vp+jwt by the holder key and checked by the verifier, plus the
 * cases a verifier must refuse.
 */
class BondsAnyCardTest {
    private val offline = HttpClient(MockEngine { respondError(HttpStatusCode.ServiceUnavailable) })
    private val resolver = DidResolver(offline)
    private val verifier = BondsOfflineVerifier(resolver)

    private fun request(source: BondsCredentialSource) = BondsPresentationRequest.generate("年齡確認", source)

    private suspend fun sdJwtVc(holder: org.multipaz.crypto.EcPublicKey): String {
        val pki = TestPki.create()
        val now = Clock.System.now()
        return SdJwt.create(
            issuerKey = pki.documentSigner,
            kbKey = holder,
            claims = buildJsonObject { put("given_name", "哲全"); put("birthdate", "1990-01-01") },
            nonSdClaims = buildJsonObject {
                put("iss", "https://issuer.example.com")
                put("vct", "urn:example:pid")
                put("iat", now.epochSeconds)
                put("exp", now.epochSeconds + 86400)
            },
        ).compactSerialization
    }

    @Test
    fun sdJwtVcWithOneDisclosure() = runBlocking<Unit> {
        val holder = Crypto.createEcPrivateKey(EcCurve.P256)
        val compact = sdJwtVc(holder.publicKey)
        val req = request(BondsCredentialSource.ANY)
        val jws = BondsOfflinePresentation.presentSdJwtVc(req, compact, AsymmetricKey.anonymous(holder, Algorithm.ES256), holder.publicKey, setOf("birthdate"))
        val r = verifier.verify(jws, req)
        assertEquals(BondsCredentialSource.ANY, r.source)
        assertEquals(mapOf("birthdate" to "1990-01-01"), r.claims)
        assertEquals("urn:example:pid", r.credentialType)
        assertEquals(DidKeys.didJwk(holder.publicKey), r.holder)
        assertNotNull(r.issuerChain)

        // A Bonds-compatible challenge only takes government wallet cards.
        val bonds = request(BondsCredentialSource.TWDIW)
        val refused = assertFailsWith<ProtocolException> {
            BondsOfflinePresentation.presentSdJwtVc(bonds, compact, AsymmetricKey.anonymous(holder, Algorithm.ES256), holder.publicKey)
        }
        assertEquals("credential_unavailable", refused.code)
        // Even when a presenter tries: the verifier rejects the envelope for that source.
        val forcedJws = BondsOfflinePresentation.sign(
            BondsOfflinePresentation.SD_JWT_PREFIX + compact, bonds, AsymmetricKey.anonymous(holder, Algorithm.ES256),
            DidKeys.didJwk(holder.publicKey), Clock.System.now(),
        )
        assertFailsWith<ProtocolException> { verifier.verify(forcedJws, bonds) }
    }

    @Test
    fun sdJwtVcOfAnotherKeyIsRefused() = runBlocking<Unit> {
        val owner = Crypto.createEcPrivateKey(EcCurve.P256)
        val thief = Crypto.createEcPrivateKey(EcCurve.P256)
        val compact = sdJwtVc(owner.publicKey)
        val req = request(BondsCredentialSource.ANY)
        val holderSide = assertFailsWith<ProtocolException> {
            BondsOfflinePresentation.presentSdJwtVc(req, compact, AsymmetricKey.anonymous(thief, Algorithm.ES256), thief.publicKey)
        }
        assertEquals("invalid_key", holderSide.code)
        // Signed by the thief's own DID around the owner's card: the cnf does not name the presenter.
        val jws = BondsOfflinePresentation.sign(
            BondsOfflinePresentation.SD_JWT_PREFIX + compact, req, AsymmetricKey.anonymous(thief, Algorithm.ES256),
            DidKeys.didJwk(thief.publicKey), Clock.System.now(),
        )
        val e = assertFailsWith<ProtocolException> { verifier.verify(jws, req) }
        assertEquals("invalid_credential", e.code)
    }

    @Test
    fun jwtVcBoundToTheSubjectDid() = runBlocking<Unit> {
        val issuer = Crypto.createEcPrivateKey(EcCurve.P256)
        val issuerDid = DidKeys.didJwk(issuer.publicKey)
        val holder = Crypto.createEcPrivateKey(EcCurve.P256)
        val holderDid = DidKeys.didJwk(holder.publicKey)
        val now = Clock.System.now().epochSeconds
        val jwt = signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "JWT"); put("kid", "$issuerDid#0") },
            buildJsonObject {
                put("iss", issuerDid)
                put("sub", holderDid)
                put("nbf", now)
                put("exp", now + 86400)
                putJsonObject("vc") {
                    putJsonArray("@context") { add("https://www.w3.org/2018/credentials/v1") }
                    putJsonArray("type") { add("VerifiableCredential"); add("MembershipCard") }
                    putJsonObject("credentialSubject") {
                        put("id", holderDid)
                        put("member", "Gold")
                        putJsonObject("address") { put("locality", "台北市") }
                    }
                }
            },
            AsymmetricKey.anonymous(issuer, Algorithm.ES256),
        )
        val req = request(BondsCredentialSource.ANY)
        val jws = BondsOfflinePresentation.presentJwtVc(req, jwt, AsymmetricKey.anonymous(holder, Algorithm.ES256), holder.publicKey, null, resolver)
        val r = verifier.verify(jws, req)
        assertEquals(mapOf("member" to "Gold", "address.locality" to "台北市"), r.claims)
        assertEquals("MembershipCard", r.credentialType)
        assertEquals(issuerDid, r.issuer)

        // Another key cannot present it: the subject DID resolves to the holder's key only.
        val other = Crypto.createEcPrivateKey(EcCurve.P256)
        assertFailsWith<ProtocolException> {
            BondsOfflinePresentation.presentJwtVc(req, jwt, AsymmetricKey.anonymous(other, Algorithm.ES256), other.publicKey, null, resolver)
        }
        val forged = BondsOfflinePresentation.sign(
            BondsOfflinePresentation.VC_JWT_PREFIX + jwt, req, AsymmetricKey.anonymous(other, Algorithm.ES256),
            DidKeys.didJwk(other.publicKey), Clock.System.now(),
        )
        assertFailsWith<ProtocolException> { verifier.verify(forged, req) }
    }
}
