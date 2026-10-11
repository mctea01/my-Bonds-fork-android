package diw.testservers

import diw.wallet.core.util.isAcceptableEndpoint
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UrlPolicyTest {
    @Test
    fun httpOnlyForLocalTestHostsWhenAllowed() {
        val local = listOf("http://localhost:8080", "http://127.0.0.1", "http://10.0.2.2:8080", "http://10.133.11.189:8080", "http://172.20.1.5", "http://192.168.1.10/issuer")
        val remote = listOf("http://172.32.0.1", "http://192.169.1.1", "http://8.8.8.8", "http://issuer.example.com", "http://10.0.0.1.example.com")
        local.forEach { assertTrue(isAcceptableEndpoint(it, true), it); assertFalse(isAcceptableEndpoint(it, false), it) }
        remote.forEach { assertFalse(isAcceptableEndpoint(it, true), it) }
        assertTrue(isAcceptableEndpoint("https://issuer.example.com", false))
        assertFalse(isAcceptableEndpoint("ftp://10.0.0.1", true))
    }
}
