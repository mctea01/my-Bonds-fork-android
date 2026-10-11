package diw.testservers

import diw.wallet.core.util.DiwJson
import io.ktor.client.engine.java.Java
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
import org.multipaz.presentment.SimplePresentmentSource
import org.multipaz.presentment.digitalCredentialsPresentment
import org.multipaz.presentment.uriSchemePresentment
import java.net.ServerSocket
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The DIW test Verifier against the Multipaz SDK's own wallet presentment code (the code inside Multipaz Wallet),
 * so the development server is checked against a second, independent OpenID4VP implementation.
 */
class MultipazWalletInteropTest {
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

    /** Multipaz presentment source over the fixture's documents; consent is given to the first option of every use case. */
    private suspend fun multipazWallet(): SimplePresentmentSource {
        val w = WalletFixture().init(servers.pki).also { it.issueSdJwtPid(servers.pki); it.issueMdl(servers.pki) }
        return SimplePresentmentSource(
            documentStore = w.documentStore,
            documentTypeRepository = w.documentTypes,
            showConsentPromptFn = { _, _, consent, _, _ -> consent.toCredentialSelection(List(consent.useCases.size) { 0 }) },
            domainsMdocSignature = listOf("mdoc"),
            domainsKeyBoundSdJwt = listOf("sdjwt"),
        )
    }

    private suspend fun status(id: String): JsonObject =
        DiwJson.parseToJsonElement(servers.httpClient.get("$base/verifier/sessions/$id").bodyAsText()).jsonObject

    private fun uriScheme(prefix: String, mode: String, dcql: String? = null) = runBlocking {
        val source = multipazWallet()
        val text = servers.httpClient.post("$base/verifier/sessions") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("client_id_prefix", prefix); put("response_mode", mode)
                dcql?.let { put("dcql_query", DiwJson.parseToJsonElement(it)) }
            }.toString())
        }.bodyAsText()
        val o = DiwJson.parseToJsonElement(text).jsonObject
        uriSchemePresentment(source, o["uri"]!!.jsonPrimitive.content, appId = null, origin = null, httpClientEngineFactory = Java)
        val r = status(o["id"]!!.jsonPrimitive.content)
        assertEquals("passed", r["status"]!!.jsonPrimitive.content, "verifier result: $r")
        println("MULTIPAZ $prefix $mode notes=${r["compatibility_notes"]}")
    }

    @Test
    fun uriSchemeX509SanDnsEncryptedSdJwt() = uriScheme("x509_san_dns", "direct_post.jwt")

    @Test
    fun uriSchemeX509HashPlainSdJwt() = uriScheme("x509_hash", "direct_post")

    @Test
    fun uriSchemeMdoc() = uriScheme(
        "x509_san_dns", "direct_post.jwt",
        """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
            "claims":[{"path":["org.iso.18013.5.1","family_name"]},{"path":["org.iso.18013.5.1","age_over_18"]}]}]}""",
    )

    private fun dcApi(signed: Boolean, encrypted: Boolean) = runBlocking {
        val source = multipazWallet()
        val origin = "https://rp.example"
        val (stored, protocol, data) = servers.verifier.createDcApi(origin, signed = signed, encrypted = encrypted)
        val response = digitalCredentialsPresentment(protocol, data, appId = null, origin = origin, preselectedDocuments = emptyList(), source = source)
        val v = servers.verifier.receiveDcApi(stored.id, response["data"]!!.jsonObject, origin)
        assertEquals(true, v.passed, "verification: $v")
    }

    @Test
    fun dcApiSignedEncrypted() = dcApi(signed = true, encrypted = true)

    @Test
    fun dcApiUnsignedPlain() = dcApi(signed = false, encrypted = false)
}
