package diw.wallet.app

import diw.testservers.TestPki
import diw.testservers.TestServers
import diw.wallet.app.desktop.PinValueCipher
import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.storage.EncryptedStorage
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.util.DiwJson
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.storage.Storage
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.storage.StorageTableSpec
import java.net.ServerSocket
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Drives the shared WalletModel (the code behind both the Android and desktop UI) against the DIW test servers. */
class WalletModelE2eTest {
    private val port = ServerSocket(0).use { it.localPort }
    private val base = "http://localhost:$port"
    private lateinit var servers: TestServers
    private var server: io.ktor.server.engine.EmbeddedServer<*, *>? = null
    private val http = HttpClient(Java) { followRedirects = false }
    private val pin = "246810"

    /** Software-only platform; the browser step follows the issuer's auto-approve redirect and feeds it back like a deep link. */
    private inner class TestPlatform(val storage: Storage) : PlatformServices {
        lateinit var model: WalletModel
        var pinPrompts = 0
        override val platformName = "test"
        override val oid4vciRedirectUri = "diw-wallet://oid4vci/callback"
        override suspend fun openStorage() = storage
        override suspend fun keyBackends(storage: Storage, pinPrompt: suspend (String) -> String?) = listOf(softwareBackend(storage, pinPrompt))
        override fun keyUnlockProvider(pinPrompt: suspend () -> String?): KeyUnlockDataProvider = PinOrPlatformUnlock(pinPrompt, null)
        override fun httpClient() = HttpClient(Java) { followRedirects = false }
        override fun openBrowser(url: String) {
            CoroutineScope(Dispatchers.Default).launch {
                val location = http.get(url).headers[HttpHeaders.Location]!!
                model.handleUri(location)
            }
        }
        override fun openRedirect(url: String) {}
    }

    private suspend fun newWallet(storage: Storage = EphemeralStorage()): Pair<WalletModel, TestPlatform> {
        val p = TestPlatform(storage)
        val m = WalletModel(p)
        p.model = m
        // Answers every App PIN request like a user would.
        CoroutineScope(Dispatchers.Default).launch {
            m.pinRequest.collect { r -> if (r != null) { p.pinPrompts++; r.result.complete(pin) } }
        }
        m.init()
        m.updateSettings { it.copy(testEnvironment = true, allowLoopbackHttp = true, testServerUrl = base) }.join()
        m.importTestAnchors().join()
        return m to p
    }

    private fun start() = runBlocking {
        servers = TestServers(base, TestPki.create()).init()
        server = servers.start(port, wait = false)
    }

    @AfterTest
    fun stop() {
        server?.stop(100, 500)
    }

    private suspend fun offer(configs: List<String>, grant: String = "pre-authorized", txCode: String? = null): String {
        val text = http.post("$base/issuer/offers") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                putJsonArray("configuration_ids") { configs.forEach { add(it) } }
                put("grant", grant)
                txCode?.let { put("tx_code", it) }
            }.toString())
        }.bodyAsText()
        return DiwJson.parseToJsonElement(text).jsonObject["offer_uri"]!!.jsonPrimitive.content
    }

    private suspend fun issue(m: WalletModel, uri: String, txCode: String?): List<IssuanceResult> = withTimeout(60.seconds) {
        m.handleUri(uri)
        val review = m.issuance.first { it is IssuanceUi.Review || it is IssuanceUi.Failed }
        assertIs<IssuanceUi.Review>(review, "review: $review")
        // Unsigned issuer metadata is never better than T3.
        assertEquals(TrustTier.T3, review.trust.tier)
        m.acceptOffer(review, txCode)
        val done = m.issuance.first { it is IssuanceUi.Done || it is IssuanceUi.Failed }
        assertIs<IssuanceUi.Done>(done, "issuance: $done")
        done.results
    }

    @Test
    fun preAuthorizedIssuanceThenPresentation() = runBlocking<Unit> {
        start()
        val (m, p) = newWallet()
        val results = issue(m, offer(listOf("pid_sd_jwt"), txCode = "1234"), "1234")
        val issued = assertIs<IssuanceResult.Issued>(results.single())
        assertEquals(3, issued.credentials.size)
        // The credential itself chains to the imported TEST anchor; TEST is never shown as verified.
        assertEquals(TrustEnvironment.TEST, issued.trust.environment)
        assertEquals(TrustTier.T3, issued.trust.tier)
        assertEquals("software", issued.document.issuanceRecord!!.keyStorage)
        assertEquals(1, p.pinPrompts, "one PIN for the whole batch of software keys")
        m.refreshDocuments().join()
        assertEquals(1, m.documents.value.size)

        val text = http.post("$base/verifier/sessions") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("client_id_prefix", "x509_san_dns") }.toString())
        }.bodyAsText()
        val o = DiwJson.parseToJsonElement(text).jsonObject
        withTimeout(60.seconds) {
            m.handleUri(o["uri"]!!.jsonPrimitive.content)
            val consent = m.presentation.first { it is PresentationUi.Consent || it is PresentationUi.Failed }
            assertIs<PresentationUi.Consent>(consent, "consent: $consent")
            assertEquals(TrustEnvironment.TEST, consent.request.verifier.trust.environment)
            assertTrue(consent.items.single().claims.isNotEmpty())
            m.approve(consent)
            val done = m.presentation.first { it is PresentationUi.Done || it is PresentationUi.Failed }
            assertIs<PresentationOutcome.Posted>(assertIs<PresentationUi.Done>(done, "presentation: $done").outcome)
        }
        assertEquals(2, p.pinPrompts, "presentation unlocks the software key with the App PIN")
        val result = DiwJson.parseToJsonElement(http.get("$base/verifier/sessions/${o["id"]!!.jsonPrimitive.content}").bodyAsText()).jsonObject
        assertEquals("passed", result["status"]!!.jsonPrimitive.content, "verifier result: $result")
    }

    @Test
    fun authorizationCodeIssuanceThroughBrowserRedirect() = runBlocking<Unit> {
        start()
        val (m, _) = newWallet()
        val results = issue(m, offer(listOf("mdl_mdoc"), grant = "authorization_code"), null)
        assertIs<IssuanceResult.Issued>(results.single())
    }

    @Test
    fun dcApiPresentationChecksOrigin() = runBlocking<Unit> {
        start()
        val (m, _) = newWallet()
        issue(m, offer(listOf("pid_sd_jwt")), null)
        val origin = "https://localhost"
        val (stored, protocol, data) = servers.verifier.createDcApi(origin, signed = true, encrypted = true)

        val response = CoroutineScope(Dispatchers.Default).launch {
            val consent = withTimeout(60.seconds) { m.presentation.first { it is PresentationUi.Consent || it is PresentationUi.Failed } }
            m.approve(assertIs<PresentationUi.Consent>(consent, "consent: $consent"))
        }
        val out: JsonObject? = withTimeout(60.seconds) { m.presentDcApi(protocol, data, origin) }
        response.join()
        assertNotNull(out)
        val verification = servers.verifier.receiveDcApi(stored.id, out, origin)
        assertTrue(verification.passed, "verification: $verification")

        // Same request from another origin is rejected by expected_origins before any consent.
        val (_, protocol2, data2) = servers.verifier.createDcApi(origin, signed = true, encrypted = true)
        val rejected = withTimeout(60.seconds) { m.presentDcApi(protocol2, data2, "https://evil.example") }
        assertNull(rejected)
        assertIs<PresentationUi.Failed>(m.presentation.value)
    }

    @Test
    fun encryptedStorageWithPinCipher() = runBlocking<Unit> {
        val dir = Files.createTempDirectory("diw-pin").toFile()
        val cipher = PinValueCipher.unlock(dir, pin)!!
        assertNull(PinValueCipher.unlock(dir, "000000"), "wrong PIN must not open the wallet")
        val inner = EphemeralStorage()
        val spec = StorageTableSpec("T", supportPartitions = true, supportExpiration = false)
        val enc = EncryptedStorage(inner, cipher).getTable(spec)
        val secret = ByteString("credential-bytes".encodeToByteArray())
        enc.insert("k", secret, partitionId = "p1")
        assertEquals(secret, enc.get("k", "p1"))
        val raw = inner.getTable(spec).get("k", "p1")!!
        assertTrue(!raw.toByteArray().decodeToString().contains("credential"), "stored value must be ciphertext")
        // A value moved to another partition fails authentication (AAD binds table and partition).
        inner.getTable(spec).insert("k", raw, partitionId = "p2")
        assertFailsWith<Exception> { enc.get("k", "p2") }
        assertEquals(secret, EncryptedStorage(inner, PinValueCipher.unlock(dir, pin)!!).getTable(spec).get("k", "p1"))
    }
}
