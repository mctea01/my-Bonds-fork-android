package diw.testservers

import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.util.ProtocolException
import kotlinx.datetime.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** A Bonds web age request shares the offline challenge's keys (v, c, b) but is answered online, never offline. */
class BondsAgeRequestTest {
    private val id = "6F9619FF-8B86-D011-B42D-00C04FC964FF"
    private fun request(url: String = "https://verifier.mashbean.net/api/zkp/response/abc", version: Int = 1, source: String = "g") =
        """{"a":18,"b":"$id","c":"n0nce-value","d":"2008-09-04","p":"購買酒類","s":"$source","t":1790000000,"u":"$url","v":$version}"""

    @Test
    fun ageRequestIsNotAnOfflineChallenge() {
        val text = request()
        assertTrue(BondsAgeRequest.looksLike(text))
        assertFalse(BondsPresentationRequest.looksLike(text), "an online age request must not open the offline presentation")
        val offline = BondsPresentationRequest.create("abc", "身分確認", kotlin.time.Clock.System.now(), null, id, BondsCredentialSource.TWDIW).encode()
        assertTrue(BondsPresentationRequest.looksLike(offline))
        assertFalse(BondsAgeRequest.looksLike(offline))
    }

    @Test
    fun parsesFields() {
        val r = BondsAgeRequest.parse(request())
        assertEquals(18, r.minimumAge)
        assertEquals(id, r.requestId)
        assertEquals("n0nce-value", r.nonce)
        assertEquals(LocalDate(2008, 9, 4), r.cutoff)
        assertEquals("購買酒類", r.purpose)
        assertEquals(BondsCredentialSource.TWDIW, r.source)
        assertEquals("verifier.mashbean.net", r.responseHost)
        assertTrue(r.knownHost)
        assertFalse(BondsAgeRequest.parse(request(url = "https://other.example/r")).knownHost)
    }

    @Test
    fun rejectsInsecureOrUnknownVersions() {
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(url = "http://verifier.mashbean.net/r")) }
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(version = 2)) }
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(source = "a")) }
    }
}
