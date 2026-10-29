package diw.testservers

import diw.wallet.core.oid4vci.IssuerRoutedWalletProvider
import diw.wallet.core.oid4vci.MultipazTestWalletProvider
import diw.wallet.core.oid4vci.PublicClientWalletProvider
import diw.wallet.core.util.DiwJson
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.util.fromBase64Url
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class MultipazTestIdentityTest {
    private val multipaz = "https://issuer.multipaz.org/issuer"

    private fun part(jwt: String, i: Int): JsonObject =
        DiwJson.decodeFromString(JsonObject.serializer(), jwt.split('.')[i].fromBase64Url().decodeToString())

    @Test
    fun appliesOnlyWhenIssuerAndAuthorizationServerAreMultipaz() {
        assertTrue(MultipazTestWalletProvider.appliesTo(multipaz, multipaz))
        assertFalse(MultipazTestWalletProvider.appliesTo(multipaz, "https://as.example.com"))
        assertFalse(MultipazTestWalletProvider.appliesTo("https://issuer.multipaz.org.example.com/issuer", multipaz))
        assertFalse(MultipazTestWalletProvider.appliesTo("not a url", "not a url"))
    }

    @Test
    fun routedProviderKeepsDefaultForOtherIssuers() {
        val default = PublicClientWalletProvider("diw-wallet")
        val test = MultipazTestWalletProvider()
        val routed = IssuerRoutedWalletProvider(default) { ci, a -> test.takeIf { MultipazTestWalletProvider.appliesTo(ci, a) } }
        assertSame(test, routed.forIssuer(multipaz, multipaz))
        assertSame(default, routed.forIssuer("https://issuer.example.com", "https://issuer.example.com"))
        assertEquals("diw-wallet", routed.clientId)
    }

    @Test
    fun tokensCarryTheKeysMultipazTrusts() = runBlocking {
        val p = MultipazTestWalletProvider()
        val att = p.walletAttestation()
        val attHeader = part(att.jwt, 0)
        assertEquals("oauth-client-attestation+jwt", attHeader["typ"]!!.jsonPrimitive.content)
        // buildJwt leaves the root out of x5c; the issuer holds it as the trusted attestation root.
        assertEquals(1, attHeader["x5c"]!!.jsonArray.size)
        assertEquals(MultipazTestWalletProvider.CLIENT_ID, part(att.jwt, 1)["sub"]!!.jsonPrimitive.content)
        val assertion = p.clientAssertion(multipaz)
        assertEquals("895b72b9-0808-4fcc-bb19-960d14a9e28f", part(assertion, 0)["kid"]!!.jsonPrimitive.content)
        assertEquals(multipaz, part(assertion, 1)["aud"]!!.jsonPrimitive.content)
        assertEquals(null, p.keyAttestation(emptyList(), "n", false))
    }
}
