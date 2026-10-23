package diw.testservers

import diw.wallet.core.document.sign.CleartextHttp
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.SocketBondsLanLink
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
            link.serve("127.0.0.1", "/age/secret", 4096, { url.complete(it) }) { body ->
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
        val served = async { link.serve("127.0.0.1", "/p", 10, { url.complete(it) }) { ByteArray(0) to true } }
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
    }
}
