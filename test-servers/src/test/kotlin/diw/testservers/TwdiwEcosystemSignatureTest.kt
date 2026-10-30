package diw.testservers

import diw.wallet.core.compat.OutboundCredentialContext
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.profile.twdiw.TwdiwDeviceKeys
import diw.wallet.core.profile.twdiw.TwdiwKeyBackend
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

    /** A platform mock: nonce endpoint plus api/did/ answering [registration] (status, body); records request bodies. */
    private fun platform(bodies: MutableList<String>, registration: Pair<HttpStatusCode, String>): HttpClient {
        var n = 0
        return HttpClient(MockEngine { request ->
            when (request.url.encodedPath) {
                "/api/ext/nonce/generate" -> respond("""{"code":"0","data":{"nonce":"eco-${++n}"}}""", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
                "/api/did/" -> {
                    bodies += String((request.body as io.ktor.http.content.OutgoingContent.ByteArrayContent).bytes())
                    respond(registration.second, registration.first, headersOf(HttpHeaders.ContentType, "application/json"))
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        })
    }

    private fun deviceKeys(http: HttpClient, area: org.multipaz.securearea.software.SoftwareSecureArea, storage: org.multipaz.storage.Storage) = TwdiwDeviceKeys(
        storage, org.multipaz.securearea.SecureAreaRepository.Builder().add(area).build(), http,
        backends = { listOf(TwdiwKeyBackend(area, "software") { org.multipaz.securearea.software.SoftwareCreateKeySettings.Builder().build() }) },
    )

    @Test
    fun registeredDeviceKeySignsWithItsKeyId() = runBlocking<Unit> {
        val bodies = mutableListOf<String>()
        val http = platform(bodies, HttpStatusCode.OK to """{"code":"0","data":{"keyId":"kid-77","status":"1"}}""")
        val storage = org.multipaz.storage.ephemeral.EphemeralStorage()
        val area = org.multipaz.securearea.software.SoftwareSecureArea.create(storage)
        val keys = deviceKeys(http, area, storage)
        val dialect = TwdiwDialect(http, allowInsecureLoopback = false, deviceKey = { keys.signingKey(it) })
        val body = "{}".encodeToByteArray()
        val jwt = headers(dialect, "moda.wallet.gov.tw", body)?.get(TwdiwDialect.ECOSYSTEM_SIGNATURE_HEADER) ?: error("no header")
        val jws = Jws.parse(jwt)
        val record = keys.record("moda.wallet.gov.tw") ?: error("no record")
        assertEquals("kid-77", record.keyId)
        assertEquals("1", record.status)
        val publicKey = area.getKeyInfo(record.alias).publicKey
        jws.verify(VerificationKey.Ec(publicKey))
        assertEquals("kid-77", jws.header.str("kid"))
        assertEquals("kid-77", jws.payload.str("keyId"))
        // The header's nonce is fetched after registration consumed its own one.
        assertEquals("eco-2", jws.payload.str("nonce"))
        assertEquals(listOf("appHash", "appPlatform", "appVersion", "bodyHash", "keyId", "nonce", "timestamp"), jws.payload.keys.toList())

        val sent = diw.wallet.core.util.DiwJson.parseToJsonElement(bodies.single()) as JsonObject
        assertEquals(record.did, sent.str("did"))
        assertEquals("EC", sent.str("keyType"))
        assertEquals("software://", sent.str("keyPrefix"))
        assertEquals("eco-1", sent.str("nonce"))
        // The proof of possession is signed by the new key over the registration nonce.
        val proof = Jws.parse(sent.str("proof")!!)
        proof.verify(VerificationKey.Ec(publicKey))
        assertEquals("eco-1", proof.payload.str("nonce"))

        // A second issuance reuses the registration without calling api/did again.
        headers(dialect, "moda.wallet.gov.tw", body)
        assertEquals(1, bodies.size)
    }

    @Test
    fun refusedRegistrationFallsBackToHolderKeyAndKeepsTheAnswer() = runBlocking<Unit> {
        val bodies = mutableListOf<String>()
        val http = platform(bodies, HttpStatusCode.BadRequest to """{"code":"40001","message":"unknown app"}""")
        val storage = org.multipaz.storage.ephemeral.EphemeralStorage()
        val area = org.multipaz.securearea.software.SoftwareSecureArea.create(storage)
        val keys = deviceKeys(http, area, storage)
        val dialect = TwdiwDialect(http, allowInsecureLoopback = false, deviceKey = { keys.signingKey(it) })
        val jwt = headers(dialect, "moda.wallet.gov.tw", "{}".encodeToByteArray())?.get(TwdiwDialect.ECOSYSTEM_SIGNATURE_HEADER) ?: error("no header")
        Jws.parse(jwt).verify(VerificationKey.Ec(holderKey.publicKey))
        val record = keys.record("moda.wallet.gov.tw") ?: error("no record")
        assertNull(record.keyId)
        assertEquals(400, record.lastHttpStatus)
        assertTrue(record.lastResponse!!.contains("unknown app"))
        // Within the retry interval the platform is not asked again.
        headers(dialect, "moda.wallet.gov.tw", "{}".encodeToByteArray())
        assertEquals(1, bodies.size)
    }
}
