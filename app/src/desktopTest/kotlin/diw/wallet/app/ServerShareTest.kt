package diw.wallet.app

import diw.wallet.core.server.ServerShare
import diw.wallet.core.util.ProtocolException
import org.multipaz.util.toBase64Url
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Share links for a production server; the choice between two parties' servers is tested in WalletModelE2eTest. */
class ServerShareTest {
    private val root = "ab".repeat(32)

    private fun raw(json: String) = ServerShare.PREFIX + json.encodeToByteArray().toBase64Url()

    @Test
    fun linkRoundTrip() {
        val share = ServerShare("https://diw.example.org", "範例服務端", root, "did:key:z6Mk", "https://diw.example.org", listOf("relay", "zktls"), "secret-token")
        val link = share.link()
        assertTrue(ServerShare.looksLike(link))
        assertEquals(share, ServerShare.parse(link))
        assertNull(ServerShare.parse(share.withoutToken().link()).token)
        assertEquals("diw.example.org", share.host)
    }

    @Test
    fun refusesWhatItCannotCheck() {
        fun refused(json: String, allowHttp: Boolean = false) = assertFailsWith<ProtocolException> { ServerShare.parse(raw(json), allowHttp) }
        refused("""{"name":"x"}""")
        refused("""{"url":"http://diw.example.org"}""")
        refused("""{"url":"https://user@diw.example.org"}""")
        refused("""{"url":"https://diw.example.org?x=1"}""")
        refused("""{"url":"https://diw.example.org","root":"1234"}""")
        refused("""{"url":"https://diw.example.org","did":"key:z6Mk"}""")
        refused("""{"url":"https://diw.example.org","fed":"ftp://x"}""")
        assertFailsWith<ProtocolException> { ServerShare.parse("diw-server://v1?c=%%%") }
        assertFailsWith<ProtocolException> { ServerShare.parse(ServerShare.PREFIX + "A".repeat(3000)) }
        assertFailsWith<ProtocolException> { ServerShare.parse("https://diw.example.org") }
        // The test environment takes a plain http address.
        assertEquals("http://127.0.0.1:8080", ServerShare.parse(raw("""{"url":"http://127.0.0.1:8080/"}"""), allowHttp = true).url)
        // Upper-case fingerprints are normalised, control characters dropped from the name.
        val s = ServerShare.parse(raw("""{"url":"https://diw.example.org","root":"${root.uppercase()}","name":"a\u0007b"}"""))
        assertEquals(root, s.rootSha256)
        assertEquals("ab", s.name)
    }
}
