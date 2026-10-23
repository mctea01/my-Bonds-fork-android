package diw.testservers.zktls

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.zktls.NativeZkTlsEngine
import diw.wallet.core.zktls.ZkTlsCheck
import diw.wallet.core.zktls.ZkTlsHolder
import diw.wallet.core.zktls.ZkTlsOutcome
import diw.wallet.core.zktls.ZkTlsPlanner
import diw.wallet.core.zktls.ZkTlsProfile
import diw.wallet.core.zktls.ZkTlsProfiles
import diw.wallet.core.zktls.ZkTlsRange
import diw.wallet.core.zktls.ZkTlsSeen
import diw.wallet.core.zktls.ZkTlsSessionRequest
import diw.wallet.core.zktls.ZkTlsTransport
import io.ktor.client.HttpClient
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.util.toBase64Url
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

/** Verification page profiles, the signed request, the reveal plan and the verifier's reading, without the engine. */
class ZkTlsPlanTest {
    private val profile = ZkTlsRecordPage.profile(8443)
    private val inputs = mapOf("serial" to ZkTlsRecordPage.SERIAL, "code" to ZkTlsRecordPage.CODE)

    private fun transcript(found: Boolean = true): Pair<ByteArray, ByteArray> {
        val sent = ZkTlsPlanner.request(profile, inputs)
        val head = sent.decodeToString()
        val body = ZkTlsRecordPage.respond(if (found) head else head.replace(ZkTlsRecordPage.SERIAL, "Z900000002"))
        val received = "HTTP/1.1 200 OK\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".encodeToByteArray() + body
        return sent to received
    }

    private fun request(fields: List<String> = listOf("name", "date")) = ZkTlsSessionRequest.create(
        listOf(ZkTlsTransport.Wss("wss://verifier.example/zktls/sessions/x/ws")), ByteArray(32) { 7 }, profile, fields, "測試",
    )

    @Test
    fun requestHidesInputsAndRevealsOnlyPathAndHost() {
        val (sent, _) = transcript()
        val text = sent.decodeToString()
        assertTrue(text.startsWith("GET /record?serial=${ZkTlsRecordPage.SERIAL}&code=${ZkTlsRecordPage.CODE} HTTP/1.1\r\nHost: localhost:8443\r\n"))
        assertTrue("Accept-Encoding: identity\r\n" in text && "Connection: close\r\n" in text)
        val reveal = ZkTlsPlanner.sentReveal(profile, sent)
        val shown = reveal.joinToString("|") { sent.copyOfRange(it.start, it.end).decodeToString() }
        assertEquals("GET /record?|Host: localhost:8443\r\n", shown)
        assertFalse(ZkTlsRecordPage.SERIAL in shown || ZkTlsRecordPage.CODE in shown)
    }

    @Test
    fun inputsAreCheckedAgainstTheirPatterns() {
        assertFailsWith<ProtocolException> { ZkTlsPlanner.request(profile, inputs + ("serial" to "A1 HTTP/1.1")) }
        assertFailsWith<ProtocolException> { ZkTlsPlanner.request(profile, mapOf("serial" to ZkTlsRecordPage.SERIAL)) }
    }

    @Test
    fun revealPlanCoversStatusAndFieldsOnly() {
        val (sent, received) = transcript()
        val plan = ZkTlsPlanner.receivedReveal(profile, listOf("name", "date"), received)
        assertTrue(plan.missing.isEmpty())
        val seen = ZkTlsHolder.masked("localhost", emptyList(), 0, sent, received, ZkTlsPlanner.sentReveal(profile, sent), plan.received)
        assertFalse(ZkTlsRecordPage.HIDDEN.encodeToByteArray().let { h -> seen.received.toList().windowed(h.size).any { it == h.toList() } })
        val outcome = ZkTlsCheck.check(request(), profile, seen)
        assertTrue(outcome.passed, outcome.problems.toString())
        assertEquals(mapOf("name" to ZkTlsRecordPage.NAME, "date" to ZkTlsRecordPage.DATE), outcome.fields)
    }

    @Test
    fun notFoundIsReportedAsNotFound() {
        val (sent, received) = transcript(found = false)
        val plan = ZkTlsPlanner.receivedReveal(profile, listOf("name"), received)
        assertEquals(listOf("name"), plan.missing)
        val seen = ZkTlsHolder.masked("localhost", emptyList(), 0, sent, received, ZkTlsPlanner.sentReveal(profile, sent), plan.received)
        val outcome = ZkTlsCheck.check(request(listOf("name")), profile, seen)
        assertFalse(outcome.found)
        assertFalse(outcome.passed)
        assertTrue(outcome.problems.isEmpty())
        assertEquals("<p id=\"status\">NOT_FOUND</p>", outcome.statusText)
    }

    /** A holder that cuts a value short (reveals part of a field) gets nothing read back for it. */
    @Test
    fun truncatedRevealIsNotAValue() {
        val (sent, received) = transcript()
        val plan = ZkTlsPlanner.receivedReveal(profile, listOf("date"), received)
        val date = plan.fields.getValue("date")
        val cut = plan.received.map { if (it == date) ZkTlsRange(it.start, it.end - 6) else it }
        val seen = ZkTlsHolder.masked("localhost", emptyList(), 0, sent, received, ZkTlsPlanner.sentReveal(profile, sent), cut)
        val outcome = ZkTlsCheck.check(request(listOf("date")), profile, seen)
        assertEquals(listOf("date"), outcome.missing)
        assertFalse(outcome.passed)
    }

    @Test
    fun anotherPathOrSiteIsAProblem() {
        val (sent, received) = transcript()
        val plan = ZkTlsPlanner.receivedReveal(profile, listOf("name"), received)
        val longer = sent.decodeToString().replaceFirst("/record?", "/records?").encodeToByteArray()
        val other = ZkTlsSeen("localhost", emptyList(), 0, longer, received, listOf(ZkTlsRange(0, 12)), plan.received)
        assertTrue(ZkTlsCheck.check(request(listOf("name")), profile, other).problems.isNotEmpty())
        val site = ZkTlsHolder.masked("evil.example", emptyList(), 0, sent, received, ZkTlsPlanner.sentReveal(profile, sent), plan.received)
        assertFalse(ZkTlsCheck.check(request(listOf("name")), profile, site).passed)
    }

    @Test
    fun profileValidation() {
        val json = DiwJson.encodeToJsonElement(ZkTlsProfile.serializer(), profile) as JsonObject
        assertEquals(profile, ZkTlsProfile.parse(json))
        assertFailsWith<ProtocolException> { profile.copy(host = "Bad Host").validated() }
        assertFailsWith<ProtocolException> { profile.copy(request = profile.request.copy(headers = mapOf("Host" to "evil.example"))).validated() }
        assertFailsWith<ProtocolException> { profile.copy(fields = listOf(ZkTlsProfile.Field("x", "x", "no-group"))).validated() }
        assertFailsWith<ProtocolException> { profile.copy(limits = ZkTlsProfile.Limits(maxSent = 8192)).validated() }
        assertFailsWith<ProtocolException> { profile.copy(request = profile.request.copy(query = "a={missing}")).validated() }
    }

    @Test
    fun signedRequestRoundTrip() = runBlocking {
        val key = Crypto.createEcPrivateKey(EcCurve.P256)
        val did = DidKeys.didJwk(key.publicKey)
        val request = ZkTlsSessionRequest.create(
            listOf(ZkTlsTransport.Lan("192.168.1.20", 40000), ZkTlsTransport.Relay("wss://relay.example/zktls/relay", ByteArray(16).toBase64Url())),
            ByteArray(32) { 3 }, profile, listOf("name"), "入學查核", inlineProfile = true,
        )
        val jws = ZkTlsSessionRequest.sign(request, AsymmetricKey.AnonymousExplicit(key, Algorithm.ES256), did)
        val link = ZkTlsSessionRequest.link(jws)
        assertTrue(ZkTlsSessionRequest.looksLike(link))
        val verified = ZkTlsSessionRequest.verify(ZkTlsSessionRequest.jwsOf(link), DidResolver(HttpClient()))
        assertEquals(request, verified.request)
        assertEquals(did, verified.did)
        assertContentEquals(ZkTlsSessionRequest.hash(jws), verified.hash)
        assertEquals(profile, ZkTlsProfiles.resolve(verified.request, allowInline = true))
        assertFailsWith<ProtocolException> { ZkTlsProfiles.resolve(verified.request, allowInline = false) }
        val stale = ZkTlsSessionRequest.sign(request, AsymmetricKey.AnonymousExplicit(key, Algorithm.ES256), did)
        assertFailsWith<ProtocolException> { ZkTlsSessionRequest.verify(stale, DidResolver(HttpClient()), now = Clock.System.now() + 11.minutes) }
        val other = Crypto.createEcPrivateKey(EcCurve.P256)
        val forged = ZkTlsSessionRequest.sign(request, AsymmetricKey.AnonymousExplicit(other, Algorithm.ES256), did)
        assertFailsWith<Exception> { ZkTlsSessionRequest.verify(forged, DidResolver(HttpClient())) }
    }

    @Test
    fun transportsOutsideTheRulesAreSkipped() {
        val good = buildJsonObject { put("type", "lan"); put("host", "10.0.0.2"); put("port", 4000) }
        assertEquals(ZkTlsTransport.Lan("10.0.0.2", 4000), ZkTlsTransport.parse(good))
        assertNull(ZkTlsTransport.parse(buildJsonObject { put("type", "lan"); put("host", "8.8.8.8"); put("port", 4000) }))
        assertNull(ZkTlsTransport.parse(buildJsonObject { put("type", "wss"); put("url", "ws://verifier.example/x") }))
        assertEquals(ZkTlsTransport.Wss("ws://localhost:8080/x"), ZkTlsTransport.parse(buildJsonObject { put("type", "wss"); put("url", "ws://localhost:8080/x") }, setOf("localhost:8080")))
        assertNull(ZkTlsTransport.parse(buildJsonObject { put("type", "relay"); put("url", "wss://r.example"); put("room", "short") }))
    }

    @Test
    fun outcomeJsonRoundTrip() {
        val (sent, received) = transcript()
        val plan = ZkTlsPlanner.receivedReveal(profile, listOf("name", "date"), received)
        val seen = ZkTlsHolder.masked("localhost", emptyList(), 1_700_000_000, sent, received, ZkTlsPlanner.sentReveal(profile, sent), plan.received)
        val outcome = ZkTlsCheck.check(request(), profile, seen)
        assertEquals(outcome, ZkTlsOutcome.fromJson(outcome.toJson(), profile))
    }

    @Test
    fun relayAddressAndHandshakeSniffing() {
        assertEquals("wss://age.example/zktls/relay", NativeZkTlsEngine.relayAddress("https://age.example/"))
        assertEquals("ws://localhost:8080/base/zktls/relay", NativeZkTlsEngine.relayAddress("http://localhost:8080/base"))
        assertTrue(NativeZkTlsEngine.opensHandshake(byteArrayOf(0, 48) + ByteArray(48)))
        assertFalse(NativeZkTlsEngine.opensHandshake("GET / HTTP/1.1".encodeToByteArray()))
    }
}
