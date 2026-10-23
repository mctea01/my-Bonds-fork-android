package diw.testservers.zktls

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.zktls.WebProofCredentials
import diw.wallet.core.zktls.ZkTlsOutcome
import diw.wallet.core.zktls.ZkTlsSessionRequest
import diw.wallet.core.zktls.ZkTlsTransport
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The receipt a verifier signs for a holder that keeps a zkTLS result, and the holder's check of it. */
class WebProofCredentialsTest {
    private val resolver = DidResolver(HttpClient(Java))
    private val profile = ZkTlsRecordPage.profile(8443)

    private class Party(val key: AsymmetricKey, val did: String)

    private suspend fun party(): Party {
        val k = Crypto.createEcPrivateKey(EcCurve.P256)
        return Party(AsymmetricKey.AnonymousExplicit(k, Algorithm.ES256), DidKeys.didKey(k.publicKey))
    }

    private suspend fun holderJwk(): JsonObject = Crypto.createEcPrivateKey(EcCurve.P256).publicKey.toJwk()

    private suspend fun session(verifier: Party): ZkTlsSessionRequest.Verified {
        val request = ZkTlsSessionRequest.create(
            listOf(ZkTlsTransport.Lan("192.168.1.2", 4000)), ByteArray(32) { 7 }, profile, listOf("name", "date"), "資格確認",
        )
        val jws = ZkTlsSessionRequest.sign(request, verifier.key, did = verifier.did)
        return ZkTlsSessionRequest.verify(jws, resolver)
    }

    private fun outcome(name: String = ZkTlsRecordPage.NAME) = ZkTlsOutcome(
        profile, profile.host, 1_760_000_000, "status=FOUND", true,
        mapOf("name" to name, "date" to ZkTlsRecordPage.DATE), emptyList(), emptyList(),
    )

    private suspend fun receipt(signer: Party, iss: String, s: ZkTlsSessionRequest.Verified, jwk: JsonObject, o: ZkTlsOutcome = outcome()) =
        WebProofCredentials.issue(
            WebProofCredentials.VCT_PROOF, iss, signer.key, jwk,
            WebProofCredentials.source(profile, o.time, listOf(byteArrayOf(1, 2, 3)), null),
            WebProofCredentials.method(s.request.mode), WebProofCredentials.claims(o), session = s.request,
        )

    @Test
    fun receiptFromTheRequesterIsAccepted() = runBlocking<Unit> {
        val verifier = party()
        val s = session(verifier)
        val jwk = holderJwk()
        val compact = receipt(verifier, verifier.did, s, jwk)
        val payload = WebProofCredentials.checkReceipt(compact, s, resolver, jwk, outcome())
        assertEquals(WebProofCredentials.VCT_PROOF, payload.str("vct"))
        assertEquals(ZkTlsRecordPage.NAME, payload.str("name"))
        assertEquals(WebProofCredentials.METHOD_PROXY, payload.str("method"))
        assertEquals(s.request.nonce, (payload["session"] as JsonObject).str("nonce"))
        // Only public members of the holder key reach the credential; the inputs never do.
        assertFalse("\"d\"" in payload.toString())
        assertFalse(ZkTlsRecordPage.SERIAL in compact)
    }

    @Test
    fun receiptsThatDoNotMatchAreRefused() = runBlocking<Unit> {
        val verifier = party()
        val other = party()
        val s = session(verifier)
        val jwk = holderJwk()
        suspend fun refused(compact: String, o: ZkTlsOutcome = outcome(), session: ZkTlsSessionRequest.Verified = s) {
            assertFailsWith<ProtocolException> { WebProofCredentials.checkReceipt(compact, session, resolver, jwk, o) }
        }
        // Signed by someone else than the requester.
        refused(receipt(other, other.did, s, jwk))
        // Bound to another key.
        refused(receipt(verifier, verifier.did, s, holderJwk()))
        // Stating another value than the holder's own reading.
        refused(receipt(verifier, verifier.did, s, jwk, outcome("someone else")))
        // For another request of the same verifier.
        refused(receipt(verifier, verifier.did, session(verifier), jwk))
        // With a disclosure withheld.
        val full = receipt(verifier, verifier.did, s, jwk)
        val parts = full.split('~')
        refused(parts.filterIndexed { i, _ -> i != 1 }.joinToString("~"))
    }

    @Test
    fun reservedFieldNamesCannotBeIssued() = runBlocking<Unit> {
        val verifier = party()
        val s = session(verifier)
        val o = outcome().copy(fields = mapOf("iss" to "x"))
        val e = assertFailsWith<ProtocolException> { receipt(verifier, verifier.did, s, holderJwk(), o) }
        assertTrue("reserved" in e.message!!)
    }
}
