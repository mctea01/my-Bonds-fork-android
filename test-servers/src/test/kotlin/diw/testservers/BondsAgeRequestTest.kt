package diw.testservers

import diw.wallet.core.profile.bonds.BondsAgeCredential
import diw.wallet.core.profile.bonds.BondsAgePackage
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerdict
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsLinkCollector
import diw.wallet.core.profile.bonds.BondsLinkTransport
import diw.wallet.core.profile.bonds.BondsReception
import diw.wallet.core.profile.bonds.BondsTransportException
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.util.ProtocolException
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.multipaz.util.toBase64Url
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A Bonds web age request shares the offline challenge's keys (v, c, b) but is answered online, never offline. */
class BondsAgeRequestTest {
    private val id = "6F9619FF-8B86-D011-B42D-00C04FC964FF"
    private val nonce = ByteArray(32) { it.toByte() }.toBase64Url()
    private fun request(url: String = "https://verifier.mashbean.net/api/zkp/response/abc", version: Int = 1, source: String = "g", c: String = nonce) =
        """{"a":18,"b":"$id","c":"$c","d":"2008-09-04","p":"購買酒類","s":"$source","t":1790000000,"u":"$url","v":$version}"""

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
        assertEquals(nonce, r.nonce)
        assertEquals(LocalDate(2008, 9, 4), r.cutoff)
        assertEquals("購買酒類", r.purpose)
        assertEquals(BondsCredentialSource.TWDIW, r.source)
        assertEquals("verifier.mashbean.net", r.responseHost)
        assertTrue(r.knownHost)
        assertFalse(BondsAgeRequest.parse(request(url = "https://other.example/r")).knownHost)
    }

    @Test
    fun nearbyRequestIsBondsTwoDeviceRequest() {
        val created = BondsAgeRequest.create(20, BondsCredentialSource.SELF_ISSUED, "年齡確認", null)
        assertTrue(created.nearby)
        assertEquals(created.requestId, created.linkServiceId, "Bonds advertises under the request id")
        assertNull(created.responseHost)
        assertFalse(created.knownHost)
        val text = created.encode()
        assertTrue("\"u\"" !in text && "\"b\":\"${created.requestId}\"" in text, text)
        assertTrue(BondsAgeRequest.looksLike(text))
        assertFalse(BondsPresentationRequest.looksLike(text))
        val parsed = BondsAgeRequest.parse(text)
        assertEquals(created, parsed)
        assertEquals(text, parsed.encode())
        assertNull(BondsAgeRequest.create(20, BondsCredentialSource.TWDIW, "x", "https://verifier.mashbean.net/r").linkServiceId)

        // As Bonds' verifier encodes it (sorted keys, no response URL).
        val bonds = BondsAgeRequest.parse("""{"a":18,"b":"$id","c":"$nonce","d":"2008-09-04","p":"購買酒類","s":"g","t":1790000000,"v":1}""")
        assertTrue(bonds.nearby)
        assertEquals(id, bonds.linkServiceId)
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(url = "")) }
    }

    @Test
    fun ageLinkFramingCarriesAFullPackageAndTheVerdict() {
        val pkg = kotlin.random.Random(7).nextBytes(213_000)
        assertFailsWith<BondsTransportException> { BondsLinkTransport.frames(pkg, 20) }
        for (mtu in listOf(23, 185, 517)) {
            val frames = BondsLinkTransport.frames(pkg, mtu - 3, BondsLinkTransport.AGE_MAX_PAYLOAD, BondsLinkTransport.AGE_MAX_CHUNKS)
            assertTrue(frames.all { it.size <= mtu - 3 })
            val collector = BondsLinkCollector(BondsLinkTransport.AGE_MAX_PAYLOAD, BondsLinkTransport.AGE_MAX_CHUNKS)
            val done = frames.shuffled(kotlin.random.Random(mtu)).firstNotNullOf { (collector.accept(it) as? BondsReception.Completed)?.payload }
            assertTrue(done.contentEquals(pkg), "MTU $mtu")
            // The presentation limits still refuse a transfer this long.
            if (frames.size > BondsLinkTransport.MAX_CHUNKS) assertFailsWith<BondsTransportException> { BondsLinkCollector().accept(frames.first()) }
        }
        val verdict = BondsAgeVerdict("accepted", true, null, 20, 812)
        val replies = BondsLinkTransport.frames(verdict.encode().encodeToByteArray(), 20, BondsLinkTransport.REPLY_MAX_PAYLOAD)
        val collector = BondsLinkCollector(BondsLinkTransport.REPLY_MAX_PAYLOAD)
        val back = replies.firstNotNullOf { (collector.accept(it) as? BondsReception.Completed)?.payload }
        assertEquals(verdict, BondsAgeVerdict.parse(back.decodeToString()))
        assertFailsWith<BondsTransportException> { BondsLinkTransport.frames(ByteArray(5000), 200, BondsLinkTransport.REPLY_MAX_PAYLOAD) }
    }

    @Test
    fun rejectsInsecureOrUnknownVersions() {
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(url = "http://verifier.mashbean.net/r")) }
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(version = 2)) }
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(source = "a")) }
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(c = "short-nonce")) }
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(url = "https://verifier.mashbean.net/r#x")) }
        assertFailsWith<ProtocolException> { BondsAgeRequest.parse(request(url = "https://user@verifier.mashbean.net/r")) }
    }

    @Test
    fun freshnessAndCutoffFollowBonds() {
        val r = BondsAgeRequest.parse(request())
        val t = Instant.fromEpochSeconds(1790000000)
        assertTrue(r.isFresh(t + 299.seconds))
        assertFalse(r.isFresh(t + 301.seconds))
        assertTrue(r.isFresh(t - 59.seconds))
        assertFalse(r.isFresh(t - 61.seconds))
        assertEquals(20080904L, r.cutoffValue(BondsAgeRequest.FORMAT_ISO))
        assertEquals(970904L, r.cutoffValue(BondsAgeRequest.FORMAT_ROC))
        assertFailsWith<ProtocolException> { r.cutoffValue(1) }
    }

    @Test
    fun packageMatchesBondsEncoding() {
        val r = BondsAgeRequest.parse(request())
        val pkg = BondsAgePackage(r, "birthdate", 3, "did:key:zTest", byteArrayOf(-1, 0, 1), byteArrayOf(-2), 120, 45, Instant.fromEpochMilliseconds(1790000001234))
        val text = pkg.encode()
        val o = Json.parseToJsonElement(text).jsonObject
        assertEquals(o.keys.sorted(), o.keys.toList(), "sorted keys, as Bonds' encoder writes them")
        assertEquals("/wAB", o["prepareProof"]!!.jsonPrimitive.content, "standard base64 with an unescaped slash")
        assertTrue("\\/" !in text)
        assertEquals("/g==", o["showProof"]!!.jsonPrimitive.content)
        assertEquals(1790000001234, o["createdAt"]!!.jsonPrimitive.long)
        assertEquals("2008-09-04", o["cutoffDate"]!!.jsonPrimitive.content)
        assertEquals(nonce, o["requestNonce"]!!.jsonPrimitive.content)
        assertEquals("g", o["credentialSource"]!!.jsonPrimitive.content)
        assertEquals(listOf(3, 18, 1), listOf("claimFormat", "minimumAge", "version").map { o[it]!!.jsonPrimitive.int })
        assertFailsWith<ProtocolException> { BondsAgePackage(r, "name", 3, "did:key:zTest", byteArrayOf(1), byteArrayOf(1), 0, 0, Instant.DISTANT_PAST) }
        assertFailsWith<ProtocolException> { BondsAgePackage(r, "birthdate", 3, "did:web:x", byteArrayOf(1), byteArrayOf(1), 0, 0, Instant.DISTANT_PAST) }
        assertFailsWith<ProtocolException> { BondsAgePackage(r, "birthdate", 3, "did:key:z", ByteArray(0), byteArrayOf(1), 0, 0, Instant.DISTANT_PAST) }
    }

    @Test
    fun verdictNeedsStatusAndAccepted() {
        val ok = BondsAgeVerdict.parse("""{"status":"verified","accepted":true,"minimumAge":18,"timingMs":{"verify":812,"total":2000}}""")!!
        assertTrue(ok.accepted)
        assertEquals(18, ok.minimumAge)
        assertEquals(812, ok.verifyMs)
        val no = BondsAgeVerdict.parse("""{"status":"rejected","accepted":false,"reason":"nonce already used"}""")!!
        assertFalse(no.accepted)
        assertEquals("nonce already used", no.reason)
        assertNull(BondsAgeVerdict.parse("""{"status":"verified"}"""))
        assertNull(BondsAgeVerdict.parse("""{"status":"verified","accepted":"true"}"""))
        assertNull(BondsAgeVerdict.parse("<html>"))
    }

    @Test
    fun birthDatesNormaliseToRocDigits() {
        assertEquals("0830306", BondsAgeCredential.normalizedBirthdate("民國 083年03月06日"))
        assertEquals("0830306", BondsAgeCredential.normalizedBirthdate("０８３０３０６"))
        assertEquals("1000101", BondsAgeCredential.normalizedBirthdate("1000101"))
        assertNull(BondsAgeCredential.normalizedBirthdate("0830230"))
        assertNull(BondsAgeCredential.normalizedBirthdate("1994-03-06"))
    }
}
