package diw.testservers

import diw.wallet.core.compat.OutboundCredentialContext
import diw.wallet.core.compat.TwdiwAppIdentity
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.oid4vci.IssuerMetadata
import diw.wallet.core.profile.twdiw.TwdiwApplicationKey
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** SDK-compatible wire tests with separate locally generated application and holder keys. */
class TwdiwEcosystemSignatureTest {
    private val holder = runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val appPrivate = runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val application = TwdiwApplicationKey.fromPrivateKey(appPrivate)

    private fun issuer(url: String) = IssuerMetadata(
        credentialIssuer = url, authorizationServers = emptyList(), credentialEndpoint = url + "credential",
        nonceEndpoint = null, deferredCredentialEndpoint = null, notificationEndpoint = null,
        requestEncryption = null, responseEncryption = null, batchSize = 1, display = emptyList(),
        configurations = emptyMap(), trust = TrustDecision.unknown("test"), raw = JsonObject(emptyMap()),
    )

    private fun dialect(
        requests: MutableList<String>,
        status: HttpStatusCode = HttpStatusCode.OK,
        response: String = """{"code":"0","data":{"nonce":"eco-123"}}""",
        key: TwdiwApplicationKey? = application,
    ): TwdiwDialect {
        val http = HttpClient(MockEngine { request ->
            requests += "${request.method.value} ${request.url}"
            check(request.method.value == "GET") { "No registration POST is permitted" }
            check(request.url.parameters["type"] == "ecosyst")
            respond(response, status, headersOf(HttpHeaders.ContentType, "application/json"))
        })
        return TwdiwDialect(http, false, applicationKey = { key },
            appIdentity = { TwdiwAppIdentity("diw.wallet.app", "0.4-test", "Android") })
    }

    private suspend fun headers(dialect: TwdiwDialect, url: String, body: ByteArray) =
        dialect.outboundCredentialHeaders(OutboundCredentialContext(
            issuer(url), body, "did:key:zHolder", holder.publicKey, AsymmetricKey.AnonymousExplicit(holder, Algorithm.ES256),
        ))

    @Test
    fun usesApplicationKeySdkWireShapeAndPrefixedNonce() = runBlocking<Unit> {
        val requests = mutableListOf<String>()
        val body = """{"credential_identifier":"card","proofs":{"jwt":["proof"]}}""".encodeToByteArray()
        val jwt = headers(dialect(requests), "https://moda.wallet.gov.tw/oid4vci/api/issuer/00000000/", body)
            ?.get(TwdiwDialect.ECOSYSTEM_SIGNATURE_HEADER) ?: error("No application signature")
        assertEquals(listOf("GET https://moda.wallet.gov.tw/oid4vci/api/ext/nonce/generate?type=ecosyst"), requests)
        val jws = Jws.parse(jwt)
        jws.verify(VerificationKey.Ec(application.publicKey))
        assertFails { jws.verify(VerificationKey.Ec(holder.publicKey)) }
        assertEquals("""{"alg":"ES256","typ":"JWT"}""", jws.header.toString())
        assertNull(jws.header.str("kid"))
        assertEquals(64, jws.signature.size)
        assertEquals(listOf("appHash", "appPlatform", "appVersion", "bodyHash", "keyId", "nonce", "timestamp"), jws.payload.keys.toList())
        assertEquals("diw.wallet.app", jws.payload.str("appHash"))
        assertEquals("Android", jws.payload.str("appPlatform"))
        assertEquals("0.4-test", jws.payload.str("appVersion"))
        assertEquals(DocCryptoUtil.hex(PlatformCrypto.sha256(body)), jws.payload.str("bodyHash"))
        assertEquals("eco-123", jws.payload.str("nonce"))
        assertTrue(jws.payload.str("timestamp")!!.toLong() > 1_000_000_000_000)
        val spkiText = application.publicKey.toPem().lineSequence().filterNot { it.startsWith("-----") }.joinToString("") { it.trim() }
        val der = Base64.getDecoder().decode(spkiText)
        val javaPublic = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
        val independentVerifier = Signature.getInstance("SHA256withECDSAinP1363Format")
        independentVerifier.initVerify(javaPublic)
        independentVerifier.update(jws.signingInput)
        assertTrue(independentVerifier.verify(jws.signature), "JDK must independently accept the raw JOSE signature")
        val expected = MessageDigest.getInstance("SHA-256").digest(Base64.getEncoder().encode(javaPublic.encoded))
        assertEquals(DocCryptoUtil.hex(expected), jws.payload.str("keyId"))
        assertNotEquals(DocCryptoUtil.hex(MessageDigest.getInstance("SHA-256").digest(der)), jws.payload.str("keyId"))
    }

    @Test
    fun originalBodyWhitespaceIsBoundBySignature() = runBlocking<Unit> {
        val requests = mutableListOf<String>()
        val d = dialect(requests)
        val first = Jws.parse(headers(d, "https://moda.wallet.gov.tw/api/issuer/1/", "{}".encodeToByteArray())!!.values.single())
        val second = Jws.parse(headers(d, "https://moda.wallet.gov.tw/api/issuer/1/", "{}\n".encodeToByteArray())!!.values.single())
        assertNotEquals(first.payload.str("bodyHash"), second.payload.str("bodyHash"))
    }

    @Test
    fun legacyOriginAndUntargetedIssuerRemainSupported() = runBlocking<Unit> {
        val requests = mutableListOf<String>()
        assertTrue(headers(dialect(requests), "https://moda.wallet.gov.tw/", byteArrayOf()) != null)
        assertEquals("GET https://moda.wallet.gov.tw/api/ext/nonce/generate?type=ecosyst", requests.single())
        requests.clear()
        assertNull(headers(dialect(requests), "https://97179430.wallet.gov.tw/oid4vci/api/issuer/97179430/", byteArrayOf()))
        assertTrue(requests.isEmpty())
    }

    @Test
    fun absentExtensionKeepsLegacyRequestUnsigned() = runBlocking<Unit> {
        for (status in listOf(HttpStatusCode.NotFound, HttpStatusCode.Gone)) {
            val requests = mutableListOf<String>()
            assertNull(headers(dialect(requests, status), "https://moda.wallet.gov.tw/oid4vci/api/issuer/1/", byteArrayOf()))
            assertEquals(1, requests.size)
        }
    }

    @Test
    fun noApplicationKeyNeverFallsBackToHolderOrRegistration() = runBlocking<Unit> {
        val requests = mutableListOf<String>()
        assertNull(headers(dialect(requests, key = null), "https://moda.wallet.gov.tw/", byteArrayOf()))
        assertTrue(requests.isEmpty())
    }

    @Test
    fun deployedNonceErrorsDoNotSilentlyDowngrade() = runBlocking<Unit> {
        for ((status, response) in listOf(
            HttpStatusCode.InternalServerError to "{}",
            HttpStatusCode.OK to """{"code":"12","data":{"nonce":"refused"}}""",
            HttpStatusCode.OK to """{"code":"0","data":{}}""",
            HttpStatusCode.OK to "not-json",
        )) {
            val error = assertFailsWith<ProtocolException> {
                headers(dialect(mutableListOf(), status, response), "https://moda.wallet.gov.tw/", byteArrayOf())
            }
            assertEquals("twdiw_ecosystem_nonce_failed", error.code)
        }
    }

    @Test
    fun requestCancellationIsPreserved() = runBlocking<Unit> {
        val http = HttpClient(MockEngine { throw CancellationException("cancel") })
        val dialect = TwdiwDialect(http, false, applicationKey = { application })
        assertFailsWith<CancellationException> { headers(dialect, "https://moda.wallet.gov.tw/", byteArrayOf()) }
    }

    @Test
    fun pemImportValidatesPairAndCurve() = runBlocking<Unit> {
        val imported = TwdiwApplicationKey.fromPem(appPrivate.toPem(), appPrivate.publicKey.toPem())
        assertEquals(application.keyId, imported.keyId)
        assertFails { TwdiwApplicationKey.fromPem(appPrivate.toPem(), holder.publicKey.toPem()) }
        assertFailsWith<IllegalArgumentException> { TwdiwApplicationKey.fromPrivateKey(Crypto.createEcPrivateKey(EcCurve.P384)) }
    }
}
