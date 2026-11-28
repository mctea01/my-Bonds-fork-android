package diw.testservers

import diw.wallet.core.did.DidResolver
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.oid4vp.DecryptedRequestObject
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.oid4vp.RequestDecryptionKey
import diw.wallet.core.oid4vp.RequestObjectEncryption
import diw.wallet.core.oid4vp.RequestResolver
import diw.wallet.core.oid4vp.RequestValidationException
import diw.wallet.core.oid4vp.RequestValidator
import diw.wallet.core.trust.TrustRegistry
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.http.URLBuilder
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.JsonWebEncryption
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import org.multipaz.webtoken.buildJwt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EncryptedRequestObjectTest {
    private val client = HttpClient(MockEngine { error("Request should be local") })
    private val policy = PresentationPolicy()
    private val redirectId = "redirect_uri:https://verifier.example/callback"

    // Multipaz decrypt always length-prefixes apu and apv in the Concat KDF, so the sender must set both.
    private fun partyInfo(value: String) = ByteString(value.encodeToByteArray())

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
        val encoded = JsonWebEncryption.encrypt(json, privateKey.publicKey, Algorithm.A256GCM, partyInfo("verifier"), partyInfo("wallet"))
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
        val encrypted = JsonWebEncryption.encrypt(json, key.publicKey, Algorithm.A128GCM, partyInfo("verifier"), partyInfo("wallet"))
        val raw = RequestResolver(client, policy, false) { listOf(AsymmetricKey.anonymous(key, key.curve.defaultKeyAgreementAlgorithm)) }
            .fromUri(invocation("x509_san_dns:verifier.example", encrypted))
        val validator = RequestValidator(
            TrustRegistry(EphemeralStorage(), EnvironmentPolicy()),
            DidResolver(client, false), policy, false
        )
        val rejected = assertFailsWith<RequestValidationException> { validator.validate(raw) }
        assertTrue(rejected.message.orEmpty().contains("must be signed"))
    }

    private fun requestClaims(clientId: String) = buildJsonObject {
        put("client_id", clientId)
        put("response_type", "vp_token")
        put("response_mode", "direct_post")
        put("response_uri", "https://verifier.example/callback")
        put("nonce", "an-encrypted-nonce-that-is-long-enough")
        put("dcql_query", buildJsonObject { put("credentials", kotlinx.serialization.json.buildJsonArray { }) })
    }

    /** The JWE code interoperates with Multipaz in both directions (same Concat KDF and AES-GCM layout). */
    @Test
    fun interoperatesWithMultipazJwe() = runBlocking<Unit> {
        val key = RequestDecryptionKey.ephemeral()
        val claims = requestClaims(redirectId)
        for (enc in RequestObjectEncryption.ENC_VALUES) {
            val ours = RequestObjectEncryption.encrypt(claims.toString().encodeToByteArray(), key.key.publicKey as org.multipaz.crypto.EcPublicKey, enc, key.kid)
            assertEquals(claims, JsonWebEncryption.decrypt(ours, key.key))
        }
        val theirs = JsonWebEncryption.encrypt(claims, key.key.publicKey as org.multipaz.crypto.EcPublicKey, Algorithm.A128GCM, partyInfo("v"), partyInfo("w"), kid = key.kid)
        assertEquals(DecryptedRequestObject.Claims(claims), RequestObjectEncryption.decrypt(theirs, key.key, key.kid))
    }

    /** A signed request object encrypted to a registered key (Nested JWT) keeps its signature for validation. */
    @Test
    fun nestedSignedRequestByValueKeepsTheSignature() = runBlocking<Unit> {
        val decryption = RequestDecryptionKey.ephemeral()
        val signer = Crypto.createEcPrivateKey(EcCurve.P256)
        val clientId = "decentralized_identifier:did:jwk:" + signer.publicKey.toJwk().toString().encodeToByteArray().toBase64Url()
        val jws = buildJwt(type = "oauth-authz-req+jwt", key = AsymmetricKey.NamedExplicit("${clientId.removePrefix("decentralized_identifier:")}#0", signer)) {
            for ((k, v) in requestClaims(clientId)) put(k, v)
        }
        val jwe = RequestObjectEncryption.encryptSigned(jws, decryption.publicJwk())
        val header = kotlinx.serialization.json.Json.parseToJsonElement(jwe.substringBefore('.').fromBase64Url().decodeToString()) as kotlinx.serialization.json.JsonObject
        assertEquals("JWT", header["cty"]?.toString()?.trim('"'))
        assertEquals(decryption.kid, header["kid"]?.toString()?.trim('"'))
        val raw = RequestResolver(client, policy, false) { listOf(decryption.key) }.fromUri(invocation(clientId, jwe))
        val signed = assertNotNull(raw.requestObject, "the nested JWS must be kept as the request object")
        assertEquals(jws, signed.compact)
    }

    @Test
    fun refusesWrongKidCompressionAndOtherAlgorithms() = runBlocking<Unit> {
        val key = RequestDecryptionKey.ephemeral()
        val pub = key.key.publicKey as org.multipaz.crypto.EcPublicKey
        val payload = requestClaims(redirectId).toString().encodeToByteArray()
        val otherKid = RequestObjectEncryption.encrypt(payload, pub, "A256GCM", "another-key")
        assertFailsWith<IllegalArgumentException> { RequestObjectEncryption.decrypt(otherKid, key.key, key.kid) }
        val zipped = JsonWebEncryption.encrypt(requestClaims(redirectId), pub, Algorithm.A256GCM, partyInfo("v"), partyInfo("w"), compressionLevel = 6)
        assertFailsWith<IllegalArgumentException> { RequestObjectEncryption.decrypt(zipped, key.key) }
        val ok = RequestObjectEncryption.encrypt(payload, pub)
        val parts = ok.split('.')
        val header = parts[0].fromBase64Url().decodeToString().replace("\"ECDH-ES\"", "\"ECDH-ES+A256KW\"")
        val swapped = (listOf(header.encodeToByteArray().toBase64Url()) + parts.drop(1)).joinToString(".")
        assertFailsWith<IllegalArgumentException> { RequestObjectEncryption.decrypt(swapped, key.key) }
        val tampered = parts.toMutableList().also { it[3] = (it[3].fromBase64Url().also { b -> b[0] = (b[0].toInt() xor 1).toByte() }).toBase64Url() }
        assertFailsWith<Exception> { RequestObjectEncryption.decrypt(tampered.joinToString("."), key.key) }
    }

    /** Keys go into wallet_metadata only when registered for a POST retrieval, and only as public keys. */
    @Test
    fun walletMetadataCarriesOnlyPublicEncryptionKeys() = runBlocking<Unit> {
        val resolver = RequestResolver(client, policy, false)
        assertNull(resolver.walletMetadataJson()["jwks"])
        val key = RequestDecryptionKey.ephemeral()
        val metadata = resolver.walletMetadataJson(listOf(key))
        val jwk = assertNotNull(RequestObjectEncryption.recipientKey(metadata))
        assertEquals(key.kid, jwk["kid"]?.toString()?.trim('"'))
        assertNull(jwk["d"])
        assertEquals("[\"ECDH-ES\"]", metadata["request_object_encryption_alg_values_supported"].toString())
        assertTrue(RequestDecryptionKey.ephemeral().kid != key.kid)
    }
}
