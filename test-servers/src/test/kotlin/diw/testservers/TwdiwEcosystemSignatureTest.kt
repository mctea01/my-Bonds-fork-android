package diw.testservers

import diw.wallet.core.compat.OutboundCredentialContext
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.oid4vci.IssuerMetadata
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The TWDIW ecosystem signature the official partner-card platform expects: a Twdiw-Signature header over the exact
 * outgoing bytes, bound to a one-time ecosystem nonce, signed with this wallet's own holder key. These tests use a
 * freshly generated key and a synthetic nonce endpoint; no official-app key or real card is involved.
 */
class TwdiwEcosystemSignatureTest {
    private val holderKey = runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }

    private fun issuer(host: String) = IssuerMetadata(
        credentialIssuer = "https://$host/",
        authorizationServers = emptyList(),
        credentialEndpoint = "https://$host/credential",
        nonceEndpoint = null,
        deferredCredentialEndpoint = null,
        notificationEndpoint = null,
        requestEncryption = null,
        responseEncryption = null,
        batchSize = 1,
        display = emptyList(),
        configurations = emptyMap(),
        trust = TrustDecision.unknown("test"),
        raw = JsonObject(emptyMap()),
    )

    private fun dialect(requests: MutableList<String>, hosts: Set<String>, nonceStatus: HttpStatusCode = HttpStatusCode.OK): TwdiwDialect {
        val http = HttpClient(MockEngine { request ->
            requests += request.url.encodedPath + "?" + request.url.parameters.toString()
            if (request.url.encodedPath == "/api/ext/nonce/generate" && request.url.parameters["type"] == "ecosyst") {
                respond(
                    """{"code":"0","data":{"nonce":"eco-123"}}""",
                    nonceStatus,
                    headersOf(HttpHeaders.ContentType, "application/json"),
                )
            } else {
                respond("", HttpStatusCode.NotFound)
            }
        })
        return TwdiwDialect(http, allowInsecureLoopback = false, ecosystemSignatureHosts = { hosts })
    }

    private suspend fun headers(dialect: TwdiwDialect, host: String, bytes: ByteArray): Map<String, String>? =
        dialect.outboundCredentialHeaders(
            OutboundCredentialContext(
                issuer = issuer(host),
                requestBytes = bytes,
                keyId = "did:key:zTestHolder",
                publicKey = holderKey.publicKey,
                signingKey = AsymmetricKey.AnonymousExplicit(holderKey, Algorithm.ES256),
            ),
        )

    @Test
    fun signsExactBytesWithEcosystemNonceForTargetedHost() = runBlocking<Unit> {
        val requests = mutableListOf<String>()
        val body = """{"credential_identifier":"AgeOver18","proofs":{"jwt":["p"]}}""".encodeToByteArray()
        val result = headers(dialect(requests, setOf("moda.wallet.gov.tw")), "moda.wallet.gov.tw", body)
            ?: error("expected a signature header")
        val jwt = result[TwdiwDialect.ECOSYSTEM_SIGNATURE_HEADER] ?: error("missing ${TwdiwDialect.ECOSYSTEM_SIGNATURE_HEADER}")
        assertTrue(requests.any { it.startsWith("/api/ext/nonce/generate") }, "ecosystem nonce was not fetched")
        val jws = Jws.parse(jwt)
        jws.verify(VerificationKey.Ec(holderKey.publicKey))
        assertEquals("JWT", jws.header.str("typ"))
        assertEquals("ES256", jws.header.str("alg"))
        assertEquals(DocCryptoUtil.hex(PlatformCrypto.sha256(body)), jws.payload.str("bodyHash"))
        assertEquals("eco-123", jws.payload.str("nonce"))
        assertEquals("did:key:zTestHolder", jws.payload.str("keyId"))
        assertEquals("android", jws.payload.str("appPlatform"))
        assertTrue(jws.payload.str("timestamp")!!.toLong() > 0)
        // appHash describes this wallet's identity (sha256 of its app id), never the official app's.
        assertEquals(DocCryptoUtil.hex(PlatformCrypto.sha256("diw".encodeToByteArray())), jws.payload.str("appHash"))
    }

    @Test
    fun noHeaderForUntargetedHostAndNoNonceFetch() = runBlocking<Unit> {
        val requests = mutableListOf<String>()
        val result = headers(dialect(requests, setOf("moda.wallet.gov.tw")), "issuer-vc.telecom.example", "x".encodeToByteArray())
        assertNull(result)
        assertTrue(requests.isEmpty(), "no request should be made for an untargeted host")
    }

    @Test
    fun missingNonceEndpointLeavesRequestUnsigned() = runBlocking<Unit> {
        val requests = mutableListOf<String>()
        val result = headers(dialect(requests, setOf("moda.wallet.gov.tw"), HttpStatusCode.NotFound), "moda.wallet.gov.tw", "x".encodeToByteArray())
        assertNull(result)
        assertTrue(requests.any { it.startsWith("/api/ext/nonce/generate") }, "the nonce endpoint should have been tried")
    }
}
