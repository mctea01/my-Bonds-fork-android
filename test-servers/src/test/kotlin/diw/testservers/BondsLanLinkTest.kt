package diw.testservers

import diw.wallet.core.document.sign.CleartextHttp
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.SocketBondsLanLink
import diw.wallet.core.profile.bonds.postFirst
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The local network route: the verifier's socket server, the holder's clear-text post and the address rules. */
class BondsLanLinkTest {
    @Test
    fun serverAnswersUntilAnExchangeEnds() = runBlocking<Unit> {
        val link = SocketBondsLanLink()
        val url = CompletableDeferred<String>()
        val bodies = mutableListOf<String>()
        val served = async {
            link.serve(listOf("127.0.0.1"), "/age/secret", 4096, { url.complete(it.single()) }) { body ->
                val text = body.decodeToString()
                bodies += text
                """{"status":"$text"}""".encodeToByteArray() to (text == "package")
            }
        }
        val at = withTimeout(10.seconds) { url.await() }
        assertTrue(at.startsWith("http://127.0.0.1:") && at.endsWith("/age/secret"), at)
        val raw = CleartextHttp()
        assertEquals(404, raw.exchange(at.replace("secret", "other"), "x".encodeToByteArray(), "application/json", null).status)
        assertEquals(413, raw.exchange(at, ByteArray(5000), "application/json", null).status)
        assertEquals(200 to """{"status":"junk"}""", link.post(at, "junk".encodeToByteArray(), 10.seconds))
        assertFalse(served.isCompleted, "a body that is not the package does not end the exchange")
        assertEquals(200 to """{"status":"package"}""", link.post(at, "package".encodeToByteArray(), 10.seconds))
        assertEquals("package", withTimeout(10.seconds) { served.await() }.decodeToString())
        assertEquals(listOf("junk", "package"), bodies)
        assertTrue(runCatching { link.post(at, "late".encodeToByteArray(), 2.seconds) }.isFailure, "the server is closed afterwards")
    }

    @Test
    fun cancellingStopsListening() = runBlocking<Unit> {
        val link = SocketBondsLanLink()
        val url = CompletableDeferred<String>()
        val served = async { link.serve(listOf("127.0.0.1"), "/p", 10, { url.complete(it.single()) }) { ByteArray(0) to true } }
        val at = withTimeout(10.seconds) { url.await() }
        served.cancel()
        runCatching { served.await() }
        assertTrue(runCatching { link.post(at, "x".encodeToByteArray(), 2.seconds) }.isFailure)
    }

    @Test
    fun onlyLocalAddressesMayBePlainHttp() {
        for (h in listOf("192.168.1.5", "10.0.0.2", "172.16.4.1", "172.31.255.254", "127.0.0.1")) assertTrue(BondsAgeRequest.lanHost(h), h)
        for (h in listOf("172.32.0.1", "8.8.8.8", "192.169.1.1", "verifier.mashbean.net", "192.168.1", "192.168.1.256", "1.2.3.4.5", "192.168.01x.1")) {
            assertFalse(BondsAgeRequest.lanHost(h), h)
        }
        val lan = BondsAgeRequest.create(18, BondsCredentialSource.TWDIW, "年齡確認", "http://192.168.1.5:41234/age/abc")
        val parsed = BondsAgeRequest.parse(lan.encode())
        assertTrue(parsed.lan && !parsed.nearby)
        assertTrue(runCatching { BondsAgeRequest.parse(lan.encode().replace("192.168.1.5", "example.org")) }.isFailure)
        assertFalse(BondsAgeRequest.create(18, BondsCredentialSource.TWDIW, "x", "https://192.168.1.5/r").lan, "https is ordinary online")

        // A verifier with several network cards lists them all; Bonds reads u, this wallet reads l.
        val many = BondsAgeRequest.create(18, BondsCredentialSource.TWDIW, "年齡確認", "http://192.168.1.5:41234/age/abc",
            otherLanUrls = listOf("http://10.20.0.1:41235/age/abc"))
        val read = BondsAgeRequest.parse(many.encode())
        assertEquals(listOf("http://192.168.1.5:41234/age/abc", "http://10.20.0.1:41235/age/abc"), read.lanUrls)
        assertEquals("http://192.168.1.5:41234/age/abc", read.responseUrl)
        assertEquals(listOf("http://192.168.1.5:41234/age/abc"), parsed.lanUrls)
        assertTrue(runCatching { BondsAgeRequest.parse(many.encode().replace("10.20.0.1", "8.8.8.8")) }.isFailure)
        assertTrue(runCatching {
            BondsAgeRequest.create(18, BondsCredentialSource.TWDIW, "x", "https://verifier.example.org/r", otherLanUrls = listOf("http://10.20.0.1/r"))
        }.isFailure, "other addresses only go with a local network request")
    }

    /** A device with several network cards listens on each; a post to any of them reaches the same exchange. */
    @Test
    fun listensOnEveryAddress() = runBlocking<Unit> {
        val link = SocketBondsLanLink()
        val urls = CompletableDeferred<List<String>>()
        // 127.0.0.2 is local on Linux; where it cannot be bound only one socket listens, which the test still covers.
        val served = async {
            link.serve(listOf("127.0.0.1", "127.0.0.2"), "/age/x", 4096, { urls.complete(it) }) { body ->
                """{"status":"ok"}""".encodeToByteArray() to (body.decodeToString() == "package")
            }
        }
        val at = withTimeout(10.seconds) { urls.await() }
        assertTrue(at.first().startsWith("http://127.0.0.1:"), at.toString())
        assertEquals(200, link.post(at.first(), "junk".encodeToByteArray(), 10.seconds).first)
        assertEquals(200, link.post(at.last(), "package".encodeToByteArray(), 10.seconds).first)
        assertEquals("package", withTimeout(10.seconds) { served.await() }.decodeToString())
        for (u in at) assertTrue(runCatching { link.post(u, "late".encodeToByteArray(), 2.seconds) }.isFailure, "every socket is closed: $u")
    }

    /** The holder tries the verifier's addresses until one answers. */
    @Test
    fun postFirstMovesPastAnAddressThatDoesNotAnswer() = runBlocking<Unit> {
        val link = SocketBondsLanLink()
        val dead = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { "http://127.0.0.1:${it.localPort}/age/x" }
        val url = CompletableDeferred<String>()
        val served = async { link.serve(listOf("127.0.0.1"), "/age/x", 4096, { url.complete(it.single()) }) { "{}".encodeToByteArray() to true } }
        val live = withTimeout(10.seconds) { url.await() }
        assertEquals(200 to "{}", link.postFirst(listOf(dead, live), "package".encodeToByteArray(), 10.seconds))
        withTimeout(10.seconds) { served.await() }
    }

    /** An address on this machine's own subnet goes first, whatever order the verifier listed them in. */
    @Test
    fun ownSubnetFirst() {
        val link = SocketBondsLanLink()
        // Any address of an interface that is up will do here, private or not.
        val own = java.net.NetworkInterface.getNetworkInterfaces().toList().filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.toList() }.filterIsInstance<java.net.Inet4Address>().firstOrNull()?.hostAddress
        org.junit.jupiter.api.Assumptions.assumeTrue(own != null && !own.startsWith("203.0.113."), "no network address on this machine")
        val other = "http://203.0.113.9:1/x"
        val mine = "http://$own:1/x"
        assertEquals(listOf(mine, other), link.preferred(listOf(other, mine)))
    }
}
