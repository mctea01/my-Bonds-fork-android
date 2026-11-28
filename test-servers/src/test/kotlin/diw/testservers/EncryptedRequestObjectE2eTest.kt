package diw.testservers

import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.oid4vp.RequestValidationException
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
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Request Objects encrypted to the key the wallet registers in wallet_metadata.jwks (request_uri_method=post,
 * OpenID4VP 1.0 section 5.10), signed then encrypted (RFC 9101 section 4), against the test Verifier.
 */
class EncryptedRequestObjectE2eTest {
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

    private suspend fun wallet() =
        WalletFixture(true).init(servers.pki).also { it.issueSdJwtPid(servers.pki) }

    private suspend fun createSession(prefix: String, method: String, tamper: String? = null): Pair<String, String> {
        val body = buildJsonObject {
            put("client_id_prefix", prefix); put("response_mode", "direct_post.jwt"); put("request_uri_method", method)
            put("request_object_encryption", true)
            tamper?.let { put("tamper", it) }
        }
        val text = servers.httpClient.post("$base/verifier/sessions") {
            contentType(ContentType.Application.Json); setBody(body.toString())
        }.bodyAsText()
        val o = DiwJson.parseToJsonElement(text).jsonObject
        return o["id"]!!.jsonPrimitive.content to o["uri"]!!.jsonPrimitive.content
    }

    private suspend fun result(id: String): JsonObject =
        DiwJson.parseToJsonElement(servers.httpClient.get("$base/verifier/sessions/$id").bodyAsText()).jsonObject

    private suspend fun presentEncrypted(prefix: String) {
        val w = wallet()
        val (id, uri) = createSession(prefix, "post")
        val req = w.holder.resolveUri(uri)
        assertTrue(servers.verifier.session(id)!!.requestEncrypted, "the request object should have been encrypted")
        assertEquals(prefix, req.verifier.clientId.prefix.wire)
        assertTrue(w.holder.respondDefault(w.holder.prepare(req)) is PresentationOutcome.Posted)
        assertEquals("passed", result(id)["status"]!!.jsonPrimitive.content)
    }

    @Test
    fun x509SanDnsSignedThenEncrypted() = runBlocking { presentEncrypted("x509_san_dns") }

    @Test
    fun x509HashSignedThenEncrypted() = runBlocking { presentEncrypted("x509_hash") }

    @Test
    fun decentralizedIdentifierSignedThenEncrypted() = runBlocking { presentEncrypted("decentralized_identifier") }

    @Test
    fun verifierAttestationSignedThenEncrypted() = runBlocking { presentEncrypted("verifier_attestation") }

    /** With GET the wallet registers no key, so a Verifier that wants encryption must send the object signed only. */
    @Test
    fun getRetrievalRegistersNoKey() = runBlocking {
        val w = wallet()
        val (id, uri) = createSession("x509_san_dns", "get")
        val req = w.holder.resolveUri(uri)
        assertFalse(servers.verifier.session(id)!!.requestEncrypted)
        assertTrue(w.holder.respondDefault(w.holder.prepare(req)) is PresentationOutcome.Posted)
        assertEquals("passed", result(id)["status"]!!.jsonPrimitive.content)
    }

    /** An object encrypted to any key other than the one registered for this retrieval cannot be opened. */
    @Test
    fun objectEncryptedToAnotherKeyIsRejected() = runBlocking<Unit> {
        val w = wallet()
        val (_, uri) = createSession("x509_san_dns", "post", tamper = "encrypt_to_other_key")
        val e = assertFailsWith<RequestValidationException> { w.holder.resolveUri(uri) }
        assertEquals("invalid_request_object", e.code)
    }

    /** Encryption does not replace the signature: a bad signature inside the JWE is still refused. */
    @Test
    fun badSignatureInsideEncryptionIsRejected() = runBlocking<Unit> {
        val w = wallet()
        val (_, uri) = createSession("x509_san_dns", "post", tamper = "bad_signature")
        val e = assertFailsWith<diw.wallet.core.util.ProtocolException> { w.holder.resolveUri(uri) }
        assertEquals("invalid_signature", e.code)
    }
}
