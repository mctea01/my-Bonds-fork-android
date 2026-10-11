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
import kotlin.test.assertFalse
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
    private inner class TestPlatform(val storage: Storage, val proxied: Boolean = false) : PlatformServices {
        lateinit var model: WalletModel
        var pinPrompts = 0
        override val platformName = "test"
        override val oid4vciRedirectUri = "diw-wallet://oid4vci/callback"
        override suspend fun openStorage() = storage
        override suspend fun keyBackends(storage: Storage, pinPrompt: suspend (String) -> String?) = listOf(softwareBackend(storage, pinPrompt))
        override fun keyUnlockProvider(pinPrompt: suspend () -> String?): KeyUnlockDataProvider = PinOrPlatformUnlock(pinPrompt, null)
        override fun httpClient() = HttpClient(Java) {
            followRedirects = false
            val proxy = System.getenv("HTTPS_PROXY") ?: System.getenv("https_proxy")
            if (proxied && !proxy.isNullOrBlank()) engine { this.proxy = io.ktor.client.engine.ProxyBuilder.http(io.ktor.http.Url(proxy)) }
        }
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

    /** A Multipaz issuer URL in the test server field: the anchor import falls back to its signing_certificate endpoint. */
    @Test
    fun anchorImportFromMultipazIssuer() = runBlocking<Unit> {
        org.junit.jupiter.api.Assumptions.assumeTrue(System.getenv("DIW_INTEROP") == "1")
        val p = TestPlatform(EphemeralStorage(), proxied = true)
        val m = WalletModel(p)
        p.model = m
        m.init()
        m.updateSettings { it.copy(testEnvironment = true, testServerUrl = "https://issuer.multipaz.org") }.join()
        m.importTestAnchors().join()
        val text = m.message.value
        println("ANCHORS $text")
        assertTrue(text != null && text.startsWith("已從 Multipaz") && !text.contains(" 0 "), "message: $text")
    }

    /** Bare public issuer hosts: the issuer path is discovered and every configuration listed. */
    @Test
    fun walletInitiatedDiscoveryOnPublicIssuers() = runBlocking<Unit> {
        org.junit.jupiter.api.Assumptions.assumeTrue(System.getenv("DIW_INTEROP") == "1")
        for (host in listOf("issuer.demo.walt.id", "https://issuer.multipaz.org", "https://issuer.eudiw.dev", "https://issuer.mashbean.net")) {
            val p = TestPlatform(EphemeralStorage(), proxied = true)
            val m = WalletModel(p)
            p.model = m
            m.init()
            withTimeout(60.seconds) {
                m.handleUri(host)
                val r = m.issuance.first { it is IssuanceUi.Review || it is IssuanceUi.Failed }
                println("DISCOVERY $host -> " + when (r) {
                    is IssuanceUi.Review -> "${r.session.issuer.credentialIssuer} configs=${r.configurations.size} unsupported=${r.unsupported.size}"
                    is IssuanceUi.Failed -> "failed: ${r.message}"
                    else -> r.toString()
                })
                if (host != "https://issuer.mashbean.net") assertIs<IssuanceUi.Review>(r)
            }
        }
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

    /** Two credentials at once: each opens from the result list, Back returns there, and the details are grouped. */
    @Test
    fun batchIssuanceDetailsAndBackNavigation() = runBlocking<Unit> {
        start()
        val (m, _) = newWallet()
        val results = issue(m, offer(listOf("pid_sd_jwt", "mdl_mdoc")), null)
        assertEquals(2, results.filterIsInstance<IssuanceResult.Issued>().size)
        val first = (results.first() as IssuanceResult.Issued).document
        m.screen.value = Screen.DocumentDetail(first.identifier, from = Screen.Issuance)
        assertTrue(m.back())
        assertEquals(Screen.Issuance, m.screen.value)
        assertTrue(m.back())
        assertEquals(Screen.Home, m.screen.value)
        assertFalse(m.back())

        for (r in results.filterIsInstance<IssuanceResult.Issued>()) {
            val doc = r.document
            val cred = doc.getCertifiedCredentials().first()
            val sections = CredentialDetails.credential(doc.issuanceRecord, cred).associateBy { it.title }
            val chain = sections.getValue("發行者簽章").rows.first { it.certs.isNotEmpty() }.certs
            val key = sections.getValue("持有者金鑰").rows
            assertTrue(key.any { it.label == "公鑰指紋（JWK SHA-256）" }, "key rows: $key")
            assertTrue(key.none { "\"x\"" in it.value || "\"d\"" in it.value }, "raw JWK shown: $key")
            assertTrue(sections.getValue("狀態清單").rows.any { it.label == "索引（idx）" })
            val cert = CredentialDetails.certificate(chain.first()).associateBy { it.title }
            assertTrue(cert.getValue("基本資訊").rows.any { it.label == "版本" && it.value == "v3" })
            assertTrue(cert.getValue("指紋").rows.single().value.count { c -> c == ':' } == 31)

            m.checkStatus(doc).join()
            val status = CredentialDetails.status(m.statuses.value.getValue(doc.identifier)).associateBy { it.title }
            assertEquals("VALID（0x00）", status.getValue("狀態查詢結果").rows.first { it.label == "狀態值" }.value)
            val token = status.getValue("狀態清單權杖").rows
            assertTrue(token.any { it.label == "每項位元數（bits）" }, "token rows: $token")
            assertTrue(token.any { it.certs.isNotEmpty() }, "status list signer is listed: $token")
        }
        // Country codes are shown as issued, not as the document type's option name.
        val mdl = results.filterIsInstance<IssuanceResult.Issued>().first { it.document.issuanceRecord?.format == "mso_mdoc" }
        val claims = diw.wallet.core.credential.ClaimReader.read(mdl.credentials.first(), m.documentTypes).associate { it.path.last() to it.value }
        assertEquals("TW", claims["issuing_country"], "claims: $claims")
    }

    @Test
    fun authorizationCodeIssuanceThroughBrowserRedirect() = runBlocking<Unit> {
        start()
        val (m, _) = newWallet()
        val results = issue(m, offer(listOf("mdl_mdoc"), grant = "authorization_code"), null)
        assertIs<IssuanceResult.Issued>(results.single())
    }

    /** Typing the issuer address lists every configuration (ldp_vc included since P2); the user picks two. */
    @Test
    fun walletInitiatedIssuanceFromIssuerUrl() = runBlocking<Unit> {
        start()
        val (m, _) = newWallet()
        withTimeout(60.seconds) {
            m.handleUri("$base/issuer")
            val review = m.issuance.first { it is IssuanceUi.Review || it is IssuanceUi.Failed }
            assertIs<IssuanceUi.Review>(review, "review: $review")
            assertTrue(review.walletInitiated)
            assertTrue(review.configurations.any { it.id == "mdl_mdoc" } && review.configurations.any { it.id == "pid_sd_jwt" })
            assertTrue(review.configurations.any { it.id == "w3c_ldp_vc" }, "configurations: ${review.configurations.map { it.id }}")
            assertTrue(review.unsupported.isEmpty(), "unsupported: ${review.unsupported}")
            m.acceptOffer(review, null, listOf("pid_sd_jwt", "mdl_mdoc"))
            val done = m.issuance.first { it is IssuanceUi.Done || it is IssuanceUi.Failed }
            assertIs<IssuanceUi.Done>(done, "issuance: $done")
            assertEquals(2, done.results.filterIsInstance<IssuanceResult.Issued>().size, "results: ${done.results} failures: ${done.failures}")
        }
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

        // Same request from another origin is rejected by expected_origins before any consent. The reason stays on
        // screen; leaving it answers invalid_request (OpenID4VP 1.0 A.2) instead of a cancelled request.
        val (_, protocol2, data2) = servers.verifier.createDcApi(origin, signed = true, encrypted = true)
        val leave = CoroutineScope(Dispatchers.Default).launch {
            val failed = withTimeout(60.seconds) { m.presentation.first { it is PresentationUi.Failed } }
            assertTrue("expected_origins" in (failed as PresentationUi.Failed).message, "failure: $failed")
            m.back()
        }
        val rejected = withTimeout(60.seconds) { m.presentDcApi(protocol2, data2, "https://evil.example") }
        leave.join()
        assertEquals(buildJsonObject { put("error", "invalid_request") }, rejected)

        // Declining on the consent screen answers access_denied.
        val (_, protocol3, data3) = servers.verifier.createDcApi(origin, signed = true, encrypted = true)
        val decline = CoroutineScope(Dispatchers.Default).launch {
            val consent = withTimeout(60.seconds) { m.presentation.first { it is PresentationUi.Consent } }
            m.decline(consent as PresentationUi.Consent)
        }
        val declined = withTimeout(60.seconds) { m.presentDcApi(protocol3, data3, origin) }
        decline.join()
        assertEquals(buildJsonObject { put("error", "access_denied") }, declined)
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
