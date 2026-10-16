package diw.testservers

import diw.wallet.core.did.DidResolver
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.oid4vp.RequestResolver
import diw.wallet.core.oid4vp.RequestValidationException
import diw.wallet.core.oid4vp.RequestValidator
import diw.wallet.core.trust.TrustRegistry
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.http.URLBuilder
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.JsonWebEncryption
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EncryptedRequestObjectTest {
    private val client = HttpClient(MockEngine { error("Request should be local") })
    private val policy = PresentationPolicy()
    private val redirectId = "redirect_uri:https://verifier.example/callback"

    private fun invocation(clientId: String, request: String): String =
        URLBuilder("openid4vp://").apply {
            parameters.append("client_id", clientId)
            parameters.append("request", request)
        }.buildString()

    @Test
    fun decryptsOnlyWithWalletControlledKeyAndKeepsIdentityUnauthenticated() = runBlocking<Unit> {
        val privateKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val json = buildJsonObject {
            put("client_id", redirectId)
            put("response_type", "vp_token")
            put("response_mode", "direct_post")
            put("response_uri", "https://verifier.example/callback")
            put("nonce", PlatformCrypto.randomBytes(24).joinToString("") { "%02x".format(it) })
            put("dcql_query", buildJsonObject { put("credentials", kotlinx.serialization.json.buildJsonArray { }) })
        }
        val encoded = JsonWebEncryption.encrypt(json, privateKey.publicKey, Algorithm.A256GCM, null, null)
        val valid = RequestResolver(client, policy, false) { listOf(AsymmetricKey.anonymous(privateKey, privateKey.curve.defaultKeyAgreementAlgorithm)) }
        val raw = valid.fromUri(invocation(redirectId, encoded))
        assertEquals(redirectId, raw.params["client_id"]?.toString()?.trim('"'))
        assertNull(raw.requestObject, "JWE encryption must not be mistaken for a verifier signature")
        val noKey = RequestResolver(client, policy, false)
        assertFailsWith<RequestValidationException> { noKey.fromUri(invocation(redirectId, encoded)) }
        assertFailsWith<RequestValidationException> { valid.fromUri(invocation("redirect_uri:https://attacker.example", encoded)) }

        val differentKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val wrong = RequestResolver(client, policy, false) { listOf(AsymmetricKey.anonymous(differentKey, differentKey.curve.defaultKeyAgreementAlgorithm)) }
        assertFailsWith<RequestValidationException> { wrong.fromUri(invocation(redirectId, encoded)) }

        val validator = RequestValidator(
            TrustRegistry(EphemeralStorage(), EnvironmentPolicy()),
            DidResolver(client, false), policy, false
        )
        assertEquals("redirect_uri", validator.validate(raw).verifier.clientId.prefix.wire)
    }

    @Test
    fun aSignedClientCannotUseEncryptionInsteadOfVerifierAuthentication() = runBlocking<Unit> {
        val key = Crypto.createEcPrivateKey(EcCurve.P256)
        val json = buildJsonObject {
            put("client_id", "x509_san_dns:verifier.example")
            put("response_type", "vp_token")
            put("response_mode", "direct_post")
            put("response_uri", "https://verifier.example/callback")
            put("nonce", "an-encrypted-nonce-that-is-long-enough")
            put("dcql_query", buildJsonObject { put("credentials", kotlinx.serialization.json.buildJsonArray { }) })
        }
        val encrypted = JsonWebEncryption.encrypt(json, key.publicKey, Algorithm.A128GCM, null, null)
        val raw = RequestResolver(client, policy, false) { listOf(AsymmetricKey.anonymous(key, key.curve.defaultKeyAgreementAlgorithm)) }
            .fromUri(invocation("x509_san_dns:verifier.example", encrypted))
        val validator = RequestValidator(
            TrustRegistry(EphemeralStorage(), EnvironmentPolicy()),
            DidResolver(client, false), policy, false
        )
        val rejected = assertFailsWith<RequestValidationException> { validator.validate(raw) }
        assertTrue(rejected.message.orEmpty().contains("must be signed"))
    }
}
