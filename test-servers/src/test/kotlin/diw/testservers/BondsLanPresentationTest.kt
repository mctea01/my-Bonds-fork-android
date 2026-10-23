package diw.testservers

import diw.wallet.core.did.DidResolver
import diw.wallet.core.profile.bonds.AnimatedQrCollector
import diw.wallet.core.profile.bonds.AnimatedQrTransport
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsLanPresentation
import diw.wallet.core.profile.bonds.BondsLinkTransport
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.BondsOfflineVerifier
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.profile.bonds.BondsReception
import diw.wallet.core.profile.bonds.SocketBondsLanLink
import diw.wallet.core.util.ProtocolException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respondError
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.sdjwt.SdJwt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

/**
 * The non-ZKP Bonds presentation over this wallet's serverless transports: the challenge's local network address and
 * key (l, e) and animated QR flag (q), the presentation sealed to the verifier over a real socket, and the fountain
 * QR carrying the same presentation.
 */
class BondsLanPresentationTest {
    private val offline = HttpClient(MockEngine { respondError(HttpStatusCode.ServiceUnavailable) })
    private val verifier = BondsOfflineVerifier(DidResolver(offline))

    private suspend fun presentation(request: BondsPresentationRequest): String {
        val holder = Crypto.createEcPrivateKey(EcCurve.P256)
        val now = Clock.System.now()
        val compact = SdJwt.create(
            issuerKey = TestPki.create().documentSigner,
            kbKey = holder.publicKey,
            claims = buildJsonObject { put("given_name", "測試"); put("birthdate", "1990-01-01") },
            nonSdClaims = buildJsonObject {
                put("iss", "https://issuer.example.com")
                put("vct", "urn:example:pid")
                put("iat", now.epochSeconds)
                put("exp", now.epochSeconds + 86400)
            },
        ).compactSerialization
        return BondsOfflinePresentation.presentSdJwtVc(request, compact, AsymmetricKey.anonymous(holder, Algorithm.ES256), holder.publicKey, setOf("birthdate"))
    }

    @Test
    fun challengeCarriesAddressKeyAndQrFlag() = runBlocking<Unit> {
        val key = BondsLanPresentation.newKey()
        val keyText = BondsLanPresentation.keyText(key.publicKey)
        val request = BondsPresentationRequest.generate(
            "年齡確認", BondsCredentialSource.ANY, lanUrl = "http://192.168.43.1:41234/vp/abc", lanKey = keyText, qr = true,
        )
        val text = request.encode()
        assertTrue(BondsPresentationRequest.looksLike(text))
        assertFalse(BondsAgeRequest.looksLike(text))
        val parsed = BondsPresentationRequest.parse(text)
        assertEquals(request, parsed)
        assertEquals("http://192.168.43.1:41234/vp/abc", parsed.lanUrl)
        assertTrue(parsed.qr)

        // A Bonds challenge without the extension keys reads as before.
        val plain = BondsPresentationRequest.parse(BondsPresentationRequest.generate("年齡確認", BondsCredentialSource.TWDIW).encode())
        assertNull(plain.lanUrl)
        assertFalse(plain.qr)

        val now = Clock.System.now()
        fun refused(url: String?, k: String?) = assertFailsWith<ProtocolException> {
            BondsPresentationRequest.create("abc", "年齡確認", now, lanUrl = url, lanKey = k)
        }
        refused("http://192.168.43.1:41234/vp", null)
        refused(null, keyText)
        refused("http://8.8.8.8/vp", keyText)
        refused("https://192.168.43.1/vp", keyText)
        refused("http://verifier.example.com/vp", keyText)
        refused("http://192.168.43.1/vp", "AAAA")
    }

    @Test
    fun sealedPresentationOverTheLocalNetwork() = runBlocking<Unit> {
        val link = SocketBondsLanLink()
        val key = BondsLanPresentation.newKey()
        val url = CompletableDeferred<String>()
        var request: BondsPresentationRequest? = null
        var opened: String? = null
        val served = async {
            link.serve("127.0.0.1", "/vp/secret", BondsLanPresentation.MAX_BODY, { at ->
                request = BondsPresentationRequest.generate(
                    "年齡確認", BondsCredentialSource.ANY, lanUrl = at, lanKey = BondsLanPresentation.keyText(key.publicKey), qr = true,
                )
                url.complete(at)
            }) { body ->
                try {
                    opened = BondsLanPresentation.open(body, key, request!!)
                    BondsLanPresentation.received() to true
                } catch (e: ProtocolException) {
                    BondsLanPresentation.refused("不是這次查驗挑戰的出示資料") to false
                }
            }
        }
        val at = withTimeout(10.seconds) { url.await() }
        val holderView = BondsPresentationRequest.parse(request!!.encode())

        // Another challenge's presentation, or one sealed to another key, is refused without ending the check.
        val other = BondsPresentationRequest.generate(
            "年齡確認", BondsCredentialSource.ANY, lanUrl = at, lanKey = BondsLanPresentation.keyText(key.publicKey),
        )
        val wrongChallenge = link.post(at, BondsLanPresentation.seal(presentation(other), other), 10.seconds)
        assertEquals("不是這次查驗挑戰的出示資料", BondsLanPresentation.refusal(wrongChallenge.first, wrongChallenge.second))
        val stranger = BondsPresentationRequest.generate(
            "年齡確認", BondsCredentialSource.ANY, lanUrl = at,
            lanKey = BondsLanPresentation.keyText(BondsLanPresentation.newKey().publicKey),
        )
        val wrongKey = link.post(at, BondsLanPresentation.seal(presentation(holderView), stranger), 10.seconds)
        assertEquals("不是這次查驗挑戰的出示資料", BondsLanPresentation.refusal(wrongKey.first, wrongKey.second))
        assertFalse(served.isCompleted)

        val jws = presentation(holderView)
        val sealed = BondsLanPresentation.seal(jws, holderView)
        assertFalse(sealed.decodeToString().contains(jws.substringBefore('.')), "the presentation does not travel in clear text")
        val (status, text) = link.post(at, sealed, 10.seconds)
        assertNull(BondsLanPresentation.refusal(status, text))
        withTimeout(10.seconds) { served.await() }
        assertEquals(jws, opened)
        assertEquals(mapOf("birthdate" to "1990-01-01"), verifier.verify(opened!!, request!!).claims)
    }

    @Test
    fun fountainQrCarriesThePresentation() = runBlocking<Unit> {
        val request = BondsPresentationRequest.generate("年齡確認", BondsCredentialSource.ANY, qr = true)
        val jws = presentation(request)
        val encoder = AnimatedQrTransport.Encoder(jws.encodeToByteArray())
        val collector = AnimatedQrCollector(BondsLinkTransport.MAX_PAYLOAD)
        // Every third frame is missed, as a camera would; the rest still rebuild the presentation.
        var payload: ByteArray? = null
        var seed = 0
        while (payload == null && seed < encoder.count * 4 + 20) {
            if (seed % 3 != 0) (collector.accept(encoder.frame(seed)) as? BondsReception.Completed)?.let { payload = it.payload }
            seed++
        }
        assertEquals(jws, payload!!.decodeToString())
        assertEquals(mapOf("birthdate" to "1990-01-01"), verifier.verify(payload!!.decodeToString(), request).claims)
    }
}
