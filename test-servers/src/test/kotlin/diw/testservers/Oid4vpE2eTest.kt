package diw.testservers

import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.oid4vp.RequestValidationException
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.ServerSocket
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class Oid4vpE2eTest {
    private val port = ServerSocket(0).use { it.localPort }
    private val base = "http://localhost:$port"
    private lateinit var servers: TestServers
    private lateinit var server: io.ktor.server.engine.EmbeddedServer<*, *>

    @BeforeTest
    fun start() = runBlocking {
        servers = TestServers(base, TestPki.create()).init()
        server = servers.start(port, wait = false)
    }

    @AfterTest
    fun stop() {
        server.stop(100, 500)
    }

    private suspend fun createSession(body: JsonObject): Pair<String, String> {
        val text = servers.httpClient.post("$base/verifier/sessions") {
            contentType(ContentType.Application.Json); setBody(body.toString())
        }.bodyAsText()
        val o = DiwJson.parseToJsonElement(text).jsonObject
        return o["id"]!!.jsonPrimitive.content to o["uri"]!!.jsonPrimitive.content
    }

    @Test
    fun verifierTestPage() = runBlocking {
        val page = servers.httpClient.get("$base/verifier").bodyAsText()
        assertTrue("/verifier/sessions" in page && "/verifier/dcapi/sessions" in page && "測試驗證端" in page)
    }

    /** A test server reached by IP address (local network) puts the IP in the x509_san_dns client_id and certificate. */
    @Test
    fun x509SanDnsWithIpAddressHost() = runBlocking {
        val ipPort = ServerSocket(0).use { it.localPort }
        val ipBase = "http://127.0.0.1:$ipPort"
        val ipServers = TestServers(ipBase, servers.pki).init()
        val ipServer = ipServers.start(ipPort, wait = false)
        try {
            val w = wallet()
            val o = DiwJson.parseToJsonElement(ipServers.httpClient.post("$ipBase/verifier/sessions") {
                contentType(ContentType.Application.Json); setBody("{}")
            }.bodyAsText()).jsonObject
            val uri = o["uri"]!!.jsonPrimitive.content
            assertTrue("x509_san_dns%3A127.0.0.1" in uri || "x509_san_dns:127.0.0.1" in uri, uri)
            val prepared = w.holder.prepare(w.holder.resolveUri(uri))
            assertTrue(w.holder.respondDefault(prepared) is PresentationOutcome.Posted)
            val r = DiwJson.parseToJsonElement(ipServers.httpClient.get("$ipBase/verifier/sessions/${o["id"]!!.jsonPrimitive.content}").bodyAsText()).jsonObject
            assertEquals("passed", r["status"]!!.jsonPrimitive.content, "verifier result: $r")
        } finally {
            ipServer.stop(100, 500)
        }
    }

    private suspend fun result(id: String): JsonObject =
        DiwJson.parseToJsonElement(servers.httpClient.get("$base/verifier/sessions/$id").bodyAsText()).jsonObject

    private suspend fun wallet(trustVerifierRoot: Boolean = true) =
        WalletFixture(trustVerifierRoot).init(servers.pki).also { it.issueSdJwtPid(servers.pki); it.issueMdl(servers.pki) }

    private suspend fun presentAndCheck(prefix: String, mode: String, method: String = "get", dcql: JsonObject? = null): diw.wallet.core.oid4vp.ValidatedAuthorizationRequest {
        val w = wallet()
        val (id, uri) = createSession(buildJsonObject {
            put("client_id_prefix", prefix); put("response_mode", mode); put("request_uri_method", method)
            dcql?.let { put("dcql_query", it) }
        })
        val req = w.holder.resolveUri(uri)
        val prepared = w.holder.prepare(req)
        val outcome = w.holder.respondDefault(prepared)
        assertTrue(outcome is PresentationOutcome.Posted)
        val r = result(id)
        assertEquals("passed", r["status"]!!.jsonPrimitive.content, "verifier result: $r")
        return req
    }

    @Test
    fun x509SanDnsEncrypted() = runBlocking {
        val req = presentAndCheck("x509_san_dns", "direct_post.jwt")
        assertEquals(diw.wallet.core.env.TrustEnvironment.TEST, req.verifier.trust.environment)
        assertEquals(TrustTier.T3, req.verifier.trust.tier)
    }

    @Test
    fun x509HashWithPostRequestUri() = runBlocking { presentAndCheck("x509_hash", "direct_post.jwt", "post"); Unit }

    @Test
    fun redirectUriUnsignedIsT4() = runBlocking {
        val req = presentAndCheck("redirect_uri", "direct_post")
        assertEquals(TrustTier.T4, req.verifier.trust.tier)
    }

    @Test
    fun decentralizedIdentifier() = runBlocking { presentAndCheck("decentralized_identifier", "direct_post.jwt"); Unit }

    @Test
    fun verifierAttestation() = runBlocking { presentAndCheck("verifier_attestation", "direct_post.jwt"); Unit }

    @Test
    fun mdocOverDirectPostJwt() = runBlocking {
        val dcql = DiwJson.parseToJsonElement(
            """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
               "claims":[{"path":["org.iso.18013.5.1","given_name"]},{"path":["org.iso.18013.5.1","age_over_18"]}]}]}"""
        ).jsonObject
        presentAndCheck("x509_san_dns", "direct_post.jwt", dcql = dcql); Unit
    }

    private suspend fun expectRejected(tamper: String, code: String, trustRoot: Boolean = true) {
        val w = wallet(trustRoot)
        val (_, uri) = createSession(buildJsonObject { put("tamper", tamper) })
        val e = assertFailsWith<Exception> { w.holder.resolveUri(uri) }
        val actual = (e as? diw.wallet.core.util.ProtocolException)?.code
        assertEquals(code, actual, "tamper=$tamper -> ${e.message}")
    }

    @Test
    fun rejectsSanMismatch() = runBlocking { expectRejected("san_mismatch", "invalid_client") }

    @Test
    fun rejectsBadSignature() = runBlocking { expectRejected("bad_signature", "invalid_signature") }

    @Test
    fun rejectsOuterClientIdMismatch() = runBlocking { expectRejected("outer_client_id_mismatch", "invalid_request_object") }

    @Test
    fun anchoredVerifierMayChooseResponseUri() = runBlocking {
        val w = wallet(true)
        val (_, uri) = createSession(buildJsonObject { put("tamper", "foreign_response_uri") })
        val req = w.holder.resolveUri(uri)
        assertEquals("https://attacker.example", req.responseUri!!.substringBefore("/responses"))
    }

    @Test
    fun unanchoredVerifierCannotRedirectResponse() = runBlocking { expectRejected("foreign_response_uri", "invalid_request", trustRoot = false) }

    @Test
    fun unanchoredVerifierIsT3WithUnknownAnchor() = runBlocking {
        val w = wallet(false)
        val (_, uri) = createSession(buildJsonObject {})
        val req = w.holder.resolveUri(uri)
        assertEquals(TrustTier.T3, req.verifier.trust.tier)
        assertEquals(null, req.verifier.trust.environment)
        assertTrue(diw.wallet.core.trust.TrustLabel.UNKNOWN_ANCHOR in req.verifier.trust.labels)
    }

    private suspend fun dcApi(origin: String, callerOrigin: String, signed: Boolean): JsonObject {
        val w = wallet()
        val text = servers.httpClient.post("$base/verifier/dcapi/sessions") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("origin", origin); put("signed", signed); put("encrypted", true) }.toString())
        }.bodyAsText()
        val o = DiwJson.parseToJsonElement(text).jsonObject
        val req = w.holder.resolveDcApi(o["protocol"]!!.jsonPrimitive.content, o["data"]!!.jsonObject, callerOrigin)
        val prepared = w.holder.prepare(req)
        val outcome = w.holder.respondDefault(prepared) as PresentationOutcome.DcApi
        val res = servers.httpClient.post("$base/verifier/dcapi/responses/${o["id"]!!.jsonPrimitive.content}") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("origin", origin); put("data", outcome.data) }.toString())
        }.bodyAsText()
        return DiwJson.parseToJsonElement(res).jsonObject
    }

    @Test
    fun dcApiSignedMatchingOrigin() = runBlocking {
        val r = dcApi("https://rp.example", "https://rp.example", signed = true)
        assertEquals("passed", r["status"]!!.jsonPrimitive.content, r.toString())
    }

    @Test
    fun dcApiUnsigned() = runBlocking {
        val r = dcApi("https://rp.example", "https://rp.example", signed = false)
        assertEquals("passed", r["status"]!!.jsonPrimitive.content, r.toString())
    }

    @Test
    fun dcApiRejectsOriginNotInExpectedOrigins() = runBlocking {
        val e = assertFailsWith<RequestValidationException> { dcApi("https://rp.example", "https://attacker.example", signed = true) }
        assertTrue(e.message!!.contains("expected_origins"))
    }

    @Test
    fun relayedSdJwtFailsAudienceCheck() = runBlocking {
        // Wallet answers an attacker origin; verifier evaluates with its own origin: KB aud must not match.
        val w = wallet()
        val text = servers.httpClient.post("$base/verifier/dcapi/sessions") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("origin", "https://attacker.example"); put("signed", false); put("encrypted", true) }.toString())
        }.bodyAsText()
        val o = DiwJson.parseToJsonElement(text).jsonObject
        val req = w.holder.resolveDcApi(o["protocol"]!!.jsonPrimitive.content, o["data"]!!.jsonObject, "https://attacker.example")
        val prepared = w.holder.prepare(req)
        val outcome = w.holder.respondDefault(prepared) as PresentationOutcome.DcApi
        val session = servers.verifier.session(o["id"]!!.jsonPrimitive.content)!!
        val r = servers.presentationVerifier.verifyDcApi(outcome.data, session.session, "https://rp.example")
        assertTrue(!r.passed, "relayed response must not pass")
    }
}
