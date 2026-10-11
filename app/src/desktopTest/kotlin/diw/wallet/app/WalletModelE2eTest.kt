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
import androidx.compose.foundation.layout.fillMaxSize
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
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
    private inner class TestPlatform(
        val storage: Storage,
        val proxied: Boolean = false,
        /** Replaces the network, for hosts the local test servers cannot stand in for (https did:web). */
        val client: (() -> HttpClient)? = null,
    ) : PlatformServices {
        lateinit var model: WalletModel
        var pinPrompts = 0
        override val platformName = "test"
        override val oid4vciRedirectUri = "diw-wallet://oid4vci/callback"
        override suspend fun openStorage() = storage
        override suspend fun keyBackends(storage: Storage, pinPrompt: suspend (String) -> String?) = listOf(softwareBackend(storage, pinPrompt))
        override fun keyUnlockProvider(pinPrompt: suspend () -> String?): KeyUnlockDataProvider = PinOrPlatformUnlock(pinPrompt, null)
        override fun httpClient() = client?.invoke() ?: HttpClient(Java) {
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
            // A TEST verifier is not on an official list, so the request is at least medium risk.
            assertNotNull(consent.items.single().documentId)
            assertTrue(consent.risk >= diw.wallet.core.status.RiskLevel.MEDIUM, "risk: ${consent.risk}")
            m.approve(consent)
            val done = m.presentation.first { it is PresentationUi.Done || it is PresentationUi.Failed }
            assertIs<PresentationOutcome.Posted>(assertIs<PresentationUi.Done>(done, "presentation: $done").outcome)
        }
        assertEquals(2, p.pinPrompts, "presentation unlocks the software key with the App PIN")
        val result = DiwJson.parseToJsonElement(http.get("$base/verifier/sessions/${o["id"]!!.jsonPrimitive.content}").bodyAsText()).jsonObject
        assertEquals("passed", result["status"]!!.jsonPrimitive.content, "verifier result: $result")

        // The history keeps who received what and when, with claim names only, and survives a restart.
        val log = withTimeout(10.seconds) { m.history.first { it.size >= 2 } }
        assertEquals(listOf(HistoryKind.PRESENTED, HistoryKind.ISSUED), log.map { it.kind })
        assertTrue(log.all { it.failure == null && it.test && it.tier == "T3" }, "history: $log")
        assertTrue(log.first().claims.isNotEmpty() && log.first().documents.isNotEmpty(), "history: $log")
        withTimeout(10.seconds) { while (HistoryLog(m.storage).load().size < 2) delay(50) }
        assertEquals(log, HistoryLog(m.storage).load())
        m.clearHistory().join()
        assertTrue(m.history.value.isEmpty() && HistoryLog(m.storage).load().isEmpty())
    }

    /**
     * Renders the main screens to PNG files for review without a device: DIW_SCREENSHOTS names the output folder.
     * The wallet holds a PID and an mDL from the test issuer and has presented once.
     */
    @Test
    fun uiScreenshots() = runBlocking<Unit> {
        val dir = System.getenv("DIW_SCREENSHOTS")
        org.junit.jupiter.api.Assumptions.assumeTrue(!dir.isNullOrBlank())
        val out = java.io.File(dir!!).apply { mkdirs() }
        start()
        val (m, _) = newWallet()
        issue(m, offer(listOf("pid_sd_jwt", "mdl_mdoc")), null)
        m.refreshDocuments().join()
        withTimeout(30.seconds) { m.statuses.first { it.size >= 2 } }
        val text = http.post("$base/verifier/sessions") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("client_id_prefix", "x509_san_dns") }.toString())
        }.bodyAsText()
        m.handleUri(DiwJson.parseToJsonElement(text).jsonObject["uri"]!!.jsonPrimitive.content)
        val consent = withTimeout(60.seconds) { m.presentation.first { it is PresentationUi.Consent || it is PresentationUi.Failed } }

        fun shot(name: String, content: @androidx.compose.runtime.Composable () -> Unit) {
            val scene = androidx.compose.ui.ImageComposeScene(412 * 2, 892 * 2, androidx.compose.ui.unit.Density(2f), content = content)
            try {
                var image = scene.render(0)
                // Let effects, flows and card art settle.
                for (i in 1..12) {
                    Thread.sleep(150)
                    image = scene.render(i * 100_000_000L)
                }
                java.io.File(out, "$name.png").writeBytes(image.encodeToData(org.jetbrains.skia.EncodedImageFormat.PNG)!!.bytes)
            } finally {
                scene.close()
            }
        }

        fun screen(name: String, s: Screen, tab: HomeTab = HomeTab.DOCUMENTS) {
            m.tab.value = tab
            m.screen.value = s
            shot(name) { diw.wallet.app.ui.WalletApp(m, scanQr = { null }) }
        }

        screen("05-presentation-consent", Screen.Presentation)
        m.approve(assertIs<PresentationUi.Consent>(consent))
        withTimeout(60.seconds) { m.presentation.first { it is PresentationUi.Done || it is PresentationUi.Failed } }
        screen("06-presentation-done", Screen.Presentation)
        screen("01-documents", Screen.Home, HomeTab.DOCUMENTS)
        screen("02-use", Screen.Home, HomeTab.USE)
        screen("03-history", Screen.Home, HomeTab.HISTORY)
        screen("04-document-detail", Screen.DocumentDetail(m.documents.value.first().identifier))
        screen("07-add-document", Screen.AddDocument)
        screen("08-settings", Screen.Settings)
        screen("09-verify", Screen.Home, HomeTab.VERIFY)
        screen("12-files", Screen.Home, HomeTab.FILES)
        screen("13-trust-anchors", Screen.TrustAnchors)
        m.taiwan.startVerifier("年齡確認")
        screen("11-verifier-challenge", Screen.Offline)
        shot("10-add-sheet") {
            diw.wallet.app.ui.WalletTheme {
                androidx.compose.material3.Surface(androidx.compose.ui.Modifier.fillMaxSize()) {
                    diw.wallet.app.ui.AddDocumentSheet(onDismiss = {}, onList = {}, onScan = {})
                }
            }
        }
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
        // Another tab goes back to the documents tab first; the documents tab leaves the app.
        m.tab.value = HomeTab.HISTORY
        assertTrue(m.back())
        assertEquals(HomeTab.DOCUMENTS, m.tab.value)
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
            val status = CredentialDetails.status(m.statuses.value.getValue(doc.identifier).status).associateBy { it.title }
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

    /**
     * Statuses are kept current without a tap: the issuance queries the new document, a revocation is found by the
     * next background run, announced and recorded, and the results survive a restart. A failed query keeps the
     * last meaningful result.
     */
    @Test
    fun statusMonitorAnnouncesRevocationAndKeepsResults() = runBlocking<Unit> {
        start()
        val storage = EphemeralStorage()
        val (m, _) = newWallet(storage)
        val issued = assertIs<IssuanceResult.Issued>(issue(m, offer(listOf("pid_sd_jwt")), null).single())
        val id = issued.document.identifier
        val first = withTimeout(30.seconds) { m.statuses.first { it[id] != null } }.getValue(id)
        assertEquals(org.multipaz.revocation.RevocationCheckState.VALID, first.status.state)
        // The list chains to a TEST anchor: valid, but a test result never shows as a plain pass.
        assertEquals(TrustEnvironment.TEST, first.status.environment)
        assertEquals(diw.wallet.core.status.StatusVerdict.CAUTION, m.status.decision(issued.document).verdict)
        assertTrue(m.status.decision(issued.document).test)
        // A PID is an identity document: its status is judged at high risk.
        assertEquals(diw.wallet.core.status.RiskLevel.HIGH, m.status.decision(issued.document).risk)

        val list = first.status.uri!!.substringAfterLast('/')
        http.post("$base/issuer/admin/status") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("list", list); put("idx", first.status.index!!); put("status", 1) }.toString())
        }
        m.status.refreshDue(force = true)
        val revoked = withTimeout(30.seconds) {
            m.statuses.first { it[id]?.status?.state == org.multipaz.revocation.RevocationCheckState.INVALID }
        }.getValue(id)
        assertNull(revoked.lastError)
        assertEquals(diw.wallet.core.status.StatusVerdict.REJECT, m.status.decision(issued.document).verdict)
        val entry = withTimeout(10.seconds) { m.history.first { h -> h.any { it.kind == HistoryKind.STATUS } } }.first { it.kind == HistoryKind.STATUS }
        assertEquals("INVALID", entry.status)
        assertEquals(listOf(issued.document.displayName), entry.documents)

        // Offline: the query fails, the revocation stays and the failure is noted.
        server?.stop(100, 500)
        server = null
        m.checkStatus(issued.document).join()
        val offline = m.statuses.value.getValue(id)
        assertEquals(org.multipaz.revocation.RevocationCheckState.INVALID, offline.status.state)
        assertNotNull(offline.lastError)

        // A restart reads the stored results.
        val again = WalletModel(TestPlatform(storage))
        again.init()
        assertEquals(org.multipaz.revocation.RevocationCheckState.INVALID, again.statuses.value.getValue(id).status.state)
    }

    /** A reader as an NFC tag: NDEF engagement goes to the wallet's helper, data transfer to its NFC transport. */
    private class LoopbackTag(
        private val helper: org.multipaz.mdoc.nfc.MdocNfcEngagementHelper,
        /** 261 is a reader limited to short APDUs, as PC/SC contactless readers are. */
        override val maxTransceiveLength: Int = 65536,
    ) : org.multipaz.nfc.NfcIsoTag() {
        private var selected: ByteString? = null
        // The phone leaves the field: the card emulation side drops its transport, as Android's HCE service does.
        override suspend fun close() = org.multipaz.mdoc.transport.NfcTransportMdoc.onDeactivated()
        override suspend fun updateDialogMessage(message: String) {}
        override suspend fun transceive(command: org.multipaz.nfc.CommandApdu): org.multipaz.nfc.ResponseApdu {
            val select = command.ins == org.multipaz.nfc.Nfc.INS_SELECT && command.p1 == org.multipaz.nfc.Nfc.INS_SELECT_P1_APPLICATION
            if (select) selected = command.payload
            if (selected != org.multipaz.nfc.Nfc.ISO_MDOC_NFC_DATA_TRANSFER_APPLICATION_ID) return helper.processApdu(command)
            // The wallet opens its NFC transport just after the handover; until then a SELECT finds no transport and
            // is sent again. Any other APDU waits: NFC is half duplex, so the answer to the last ENVELOPE carries the
            // wallet's response, which comes after the user's consent.
            repeat(if (select) 40 else 1) {
                val answer = kotlinx.coroutines.CompletableDeferred<org.multipaz.nfc.ResponseApdu>()
                org.multipaz.mdoc.transport.NfcTransportMdoc.processCommandApdu(command.encode()) { answer.complete(org.multipaz.nfc.ResponseApdu.decode(it)) }
                (if (select) kotlinx.coroutines.withTimeoutOrNull(500) { answer.await() } else answer.await())?.let { return it }
            }
            error("No answer from the wallet's NFC transport")
        }
    }

    /**
     * In-person presentation by NFC tap (ISO/IEC 18013-5): negotiated handover choosing NFC data transfer, the
     * reader's request on the wallet's own consent screen, the App PIN for the software key, a DeviceResponse the
     * reader verifies, and the history entry.
     */
    @Test
    fun nfcProximityPresentation() = runBlocking<Unit> {
        start()
        val (m, p) = newWallet()
        assertIs<IssuanceResult.Issued>(issue(m, offer(listOf("mdl_mdoc")), null).single())
        m.refreshDocuments().join()
        m.proximity.transportFactory = object : org.multipaz.mdoc.transport.MdocTransportFactory {
            override fun createTransport(
                connectionMethod: org.multipaz.mdoc.connectionmethod.MdocConnectionMethod,
                role: org.multipaz.mdoc.role.MdocRole,
                options: org.multipaz.mdoc.transport.MdocTransportOptions,
            ): org.multipaz.mdoc.transport.MdocTransport = org.multipaz.mdoc.transport.NfcTransportMdoc(role, options, connectionMethod)
        }
        // Not listening: no engagement is offered for a tap.
        assertNull(m.proximity.nfcEngagement())
        m.proximity.open()
        assertEquals(Screen.Proximity, m.screen.value)
        val tag = LoopbackTag(assertNotNull(m.proximity.nfcEngagement(staticHandover = false)))
        val nfc = org.multipaz.mdoc.connectionmethod.MdocConnectionMethodNfc(commandDataFieldMaxLength = 0xffff, responseDataFieldMaxLength = 0x10000)
        val handover = assertNotNull(withTimeout(30.seconds) { org.multipaz.mdoc.nfc.mdocReaderNfcHandover(tag, listOf(nfc)) })
        val method = handover.connectionMethods.single() as org.multipaz.mdoc.connectionmethod.MdocConnectionMethodNfc

        val eReaderKey = org.multipaz.crypto.Crypto.createEcPrivateKey(org.multipaz.crypto.EcCurve.P256)
        val reader = org.multipaz.mdoc.transport.NfcTransportMdocReader(org.multipaz.mdoc.role.MdocRole.MDOC_READER, org.multipaz.mdoc.transport.MdocTransportOptions(), method)
        reader.setTag(tag)
        // open() runs its I/O loop in the caller's scope, which therefore stays active until the reader is closed.
        reader.open(eReaderKey.publicKey)
        val engagement = org.multipaz.mdoc.engagement.DeviceEngagement.fromDataItem(org.multipaz.cbor.Cbor.decode(handover.encodedDeviceEngagement.toByteArray()))
        val transcript = org.multipaz.cbor.buildCborArray {
            add(org.multipaz.cbor.Tagged(org.multipaz.cbor.Tagged.ENCODED_CBOR, org.multipaz.cbor.Bstr(handover.encodedDeviceEngagement.toByteArray())))
            add(org.multipaz.cbor.Tagged(org.multipaz.cbor.Tagged.ENCODED_CBOR, org.multipaz.cbor.Bstr(org.multipaz.cbor.Cbor.encode(eReaderKey.publicKey.toCoseKey().toDataItem()))))
            add(handover.handover)
        }
        val encodedTranscript = org.multipaz.cbor.Cbor.encode(transcript)
        val session = org.multipaz.mdoc.sessionencryption.SessionEncryption(
            role = org.multipaz.mdoc.role.MdocRole.MDOC_READER,
            eSelfKey = eReaderKey,
            remotePublicKey = engagement.eDeviceKey,
            encodedSessionTranscript = encodedTranscript,
        )
        val request = org.multipaz.mdoc.request.DeviceRequestGenerator(encodedTranscript).addDocumentRequest(
            docType = "org.iso.18013.5.1.mDL",
            itemsToRequest = mapOf("org.iso.18013.5.1" to mapOf("family_name" to false, "given_name" to false)),
            requestInfo = null,
            readerKey = null,
            signatureAlgorithm = org.multipaz.crypto.Algorithm.UNSET,
            readerKeyCertificateChain = null,
        ).generate()
        // The reader waits for the response while the user reads the request.
        val exchange = async(Dispatchers.Default) {
            reader.sendMessage(session.encryptMessage(request, null))
            reader.waitForMessage()
        }

        val consent = withTimeout(30.seconds) { m.proximity.state.first { it is ProximityUi.Consent || it is ProximityUi.Failed } }
        assertIs<ProximityUi.Consent>(consent, "consent: $consent")
        assertEquals(ProximityChannel.NFC, consent.channel)
        // No reader authentication: the reader cannot be identified (T4), shown as such.
        assertEquals(TrustTier.T4, consent.trust.tier)
        assertTrue(consent.chain.isEmpty())
        assertEquals(2, consent.items.single().claims.size)
        val pins = p.pinPrompts
        m.proximity.approve(consent)

        val (plain, _) = session.decryptMessage(withTimeout(30.seconds) { exchange.await() })
        val response = org.multipaz.mdoc.response.DeviceResponse.fromDataItem(org.multipaz.cbor.Cbor.decode(assertNotNull(plain)))
        response.verify(sessionTranscript = transcript)
        val doc = response.documents.single()
        assertEquals("org.iso.18013.5.1.mDL", doc.docType)
        assertEquals(setOf("family_name", "given_name"), doc.issuerNamespaces.data.getValue("org.iso.18013.5.1").keys)
        assertEquals(pins + 1, p.pinPrompts, "the software key is unlocked with the App PIN")

        val done = withTimeout(30.seconds) { m.proximity.state.first { it is ProximityUi.Done || it is ProximityUi.Failed } }
        assertIs<ProximityUi.Done>(done, "done: $done")
        val entry = withTimeout(10.seconds) { m.history.first { h -> h.any { it.kind == HistoryKind.PRESENTED } } }.first { it.kind == HistoryKind.PRESENTED }
        assertTrue(entry.note!!.contains("NFC"), "note: ${entry.note}")
        assertEquals(2, entry.claims.size)
        assertTrue(m.back())
        assertFalse(m.proximity.listening.value)
        reader.close()
    }

    /** An NFC reader handed one tag, like a phone held to it. */
    private class LoopbackReader(private val tag: org.multipaz.nfc.NfcIsoTag) : org.multipaz.nfc.NfcTagReader {
        override val external = true
        override val dialogAlwaysShown = false
        override val dialogNeverShown = true
        override suspend fun <T : Any> scan(
            message: String?,
            tagInteractionFunc: suspend (tag: org.multipaz.nfc.NfcIsoTag) -> T?,
            options: org.multipaz.nfc.NfcScanOptions,
            context: kotlin.coroutines.CoroutineContext,
        ): T = try {
            tagInteractionFunc(tag) ?: error("The tag is not an mdoc")
        } catch (e: Throwable) {
            tag.close()
            throw e
        }
    }

    /**
     * One wallet reads another in person (ISO/IEC 18013-5 mdoc reader): NFC engagement, the request on the holder's
     * consent screen, NFC data transfer, and on the reader the integrity checks, the issuer's trust, the status and the
     * history entry with field names only. [maxTransceive] 261 is a PC/SC reader limited to short APDUs.
     */
    private suspend fun readAnotherWallet(maxTransceive: Int, request: ReaderRequest): ReaderUi.Result {
        start()
        val (holder, _) = newWallet()
        assertIs<IssuanceResult.Issued>(issue(holder, offer(listOf("mdl_mdoc")), null).single())
        holder.refreshDocuments().join()
        holder.proximity.transportFactory = object : org.multipaz.mdoc.transport.MdocTransportFactory {
            override fun createTransport(
                connectionMethod: org.multipaz.mdoc.connectionmethod.MdocConnectionMethod,
                role: org.multipaz.mdoc.role.MdocRole,
                options: org.multipaz.mdoc.transport.MdocTransportOptions,
            ): org.multipaz.mdoc.transport.MdocTransport = org.multipaz.mdoc.transport.NfcTransportMdoc(role, options, connectionMethod)
        }
        holder.proximity.open()
        val tag = LoopbackTag(assertNotNull(holder.proximity.nfcEngagement(staticHandover = false)), maxTransceive)

        val (verifier, _) = newWallet()
        verifier.reader.open()
        assertEquals(Screen.Reader, verifier.screen.value)
        verifier.reader.start(NfcReaderOption("Loopback", external = true, reader = LoopbackReader(tag)), request, diw.wallet.core.status.RiskLevel.MEDIUM)

        val consent = withTimeout(30.seconds) { holder.proximity.state.first { it is ProximityUi.Consent || it is ProximityUi.Failed } }
        assertIs<ProximityUi.Consent>(consent, "consent: $consent; reader: ${verifier.reader.state.value}")
        assertTrue(consent.chain.isEmpty(), "the reader does not authenticate")
        holder.proximity.approve(consent)

        val result = withTimeout(60.seconds) { verifier.reader.state.first { it is ReaderUi.Result || it is ReaderUi.Failed } }
        assertIs<ReaderUi.Result>(result, "result: $result")
        assertNull(result.integrityError)
        assertEquals("NFC", result.transport)
        val d = result.documents.single()
        assertEquals("行動駕照", d.title)
        // The test issuer chains to the test IACA: verified, but never official.
        assertEquals(TrustEnvironment.TEST, d.issuerTrust.environment)
        assertEquals(diw.wallet.app.ui.Verdict.CAUTION, diw.wallet.app.ui.readVerdict(d, diw.wallet.core.status.RiskLevel.MEDIUM).first)
        assertEquals(org.multipaz.revocation.RevocationCheckState.VALID, d.status.state)

        val entry = withTimeout(10.seconds) { verifier.history.first { h -> h.any { it.kind == HistoryKind.VERIFIED } } }.first { it.kind == HistoryKind.VERIFIED }
        assertTrue(entry.note!!.contains("感應查驗"), "note: ${entry.note}")
        assertEquals(d.claims.map { it.label }, entry.claims)
        assertNull(entry.failure)
        withTimeout(30.seconds) { holder.proximity.state.first { it is ProximityUi.Done } }
        assertTrue(verifier.back())
        assertEquals(HomeTab.VERIFY, verifier.tab.value)
        return result
    }

    @Test
    fun nfcReaderVerifiesAnotherWallet() = runBlocking<Unit> {
        val d = readAnotherWallet(65536, ReaderRequest.MDL_IDENTITY).documents.single()
        val values = d.claims.associate { it.label to it.value }
        assertTrue("Lin" in values.values && "Che-Chuan" in values.values, "claims: $values")
        assertEquals(3, d.claims.size, "only what the credential holds and the request asked for: $values")
    }

    @Test
    fun nfcReaderWithShortApdus() = runBlocking<Unit> {
        val d = readAnotherWallet(261, ReaderRequest.AGE_OVER_18).documents.single()
        assertEquals(listOf("是"), d.claims.map { it.value })
    }

    /** Without PC/SC (no pcscd, no reader) the list is empty with a reason, never an error. */
    @Test
    fun pcscListWithoutReaders() {
        val list = diw.wallet.app.desktop.PcscReaders.list()
        if (list.readers.isEmpty()) assertNotNull(list.problem)
    }

    /**
     * The Digital Credentials API with the ISO mdoc protocol (ISO/IEC 18013-7 Annex C): the page's DeviceRequest on the
     * wallet's consent screen, and a DeviceResponse HPKE-encrypted to the page's key and bound to its origin, which
     * the page decrypts and verifies.
     */
    @Test
    fun dcApiIsoMdocPresentation() = runBlocking<Unit> {
        start()
        val (m, _) = newWallet()
        assertIs<IssuanceResult.Issued>(issue(m, offer(listOf("mdl_mdoc")), null).single())
        m.refreshDocuments().join()
        val origin = "https://verifier.example.com"
        val nonce = ByteString(diw.wallet.core.jose.PlatformCrypto.randomBytes(16))
        val pageKey = org.multipaz.crypto.Crypto.createEcPrivateKey(org.multipaz.crypto.EcCurve.P256)
        val request = org.multipaz.verification.VerificationUtil.generateDcRequestMdoc(
            exchangeProtocols = listOf("org-iso-mdoc"),
            docType = "org.iso.18013.5.1.mDL",
            claims = listOf(org.multipaz.request.MdocRequestedClaim(docType = "org.iso.18013.5.1.mDL", namespaceName = "org.iso.18013.5.1", dataElementName = "family_name", intentToRetain = false)),
            nonce = nonce,
            origin = origin,
            responseEncryptionKey = pageKey.publicKey,
            verifierIdentities = emptyList(),
            zkSystemSpecs = emptyList(),
        )
        val entry = request["requests"]!!.jsonArray.single().jsonObject
        val answer = async(Dispatchers.Default) { m.proximity.presentDcApi("org-iso-mdoc", entry["data"]!!.jsonObject, origin, null) }
        val consent = withTimeout(30.seconds) { m.proximity.state.first { it is ProximityUi.Consent || it is ProximityUi.Failed } }
        assertIs<ProximityUi.Consent>(consent, "consent: $consent")
        assertEquals(ProximityChannel.DC_API, consent.channel)
        assertEquals(origin, consent.verifier, "an unauthenticated page is named by its origin")
        m.proximity.approve(consent)
        val response = assertNotNull(withTimeout(30.seconds) { answer.await() })
        val clear = org.multipaz.verification.VerificationUtil.decryptDcResponse(response, nonce, origin, org.multipaz.crypto.AsymmetricKey.anonymous(pageKey))
        assertIs<org.multipaz.verification.MdocApiDcResponse>(clear)
        val deviceResponse = org.multipaz.mdoc.response.DeviceResponse.fromDataItem(clear.deviceResponse)
        deviceResponse.verify(sessionTranscript = clear.sessionTranscript)
        assertEquals(setOf("family_name"), deviceResponse.documents.single().issuerNamespaces.data.getValue("org.iso.18013.5.1").keys)
        val entryLog = withTimeout(10.seconds) { m.history.first { h -> h.any { it.kind == HistoryKind.PRESENTED } } }.first { it.kind == HistoryKind.PRESENTED }
        assertTrue(entryLog.note!!.contains("Annex C"), "note: ${entryLog.note}")
    }

    /**
     * A held document follows its trust sources: removing the anchor it was trusted through judges it again (here it
     * moves to another anchor, then to no anchor), and adding an anchor brings an unanchored document under it. Each
     * change is written to the document and recorded.
     */
    @Test
    fun trustSourceChangesReevaluateHeldDocuments() = runBlocking<Unit> {
        start()
        val (m, _) = newWallet()
        assertIs<IssuanceResult.Issued>(issue(m, offer(listOf("mdl_mdoc")), null).single())
        m.refreshDocuments().join()
        suspend fun record(): diw.wallet.core.oid4vci.IssuanceRecord {
            m.refreshDocuments().join()
            return assertNotNull(m.documents.value.single().issuanceRecord)
        }
        assertEquals("DIW TEST IACA", record().anchorName)
        val pem = http.get("$base/pki/iaca.pem").bodyAsText()
        m.importAnchor(pem, "Example IACA", setOf(diw.wallet.core.trust.TrustRole.ISSUER)).join()
        // Already anchored: a new source does not move it.
        assertEquals("DIW TEST IACA", record().anchorName)

        m.loadAnchors().join()
        val testIaca = m.anchors.value!!.first {
            it.environment == TrustEnvironment.TEST && it.role == diw.wallet.core.trust.TrustRole.ISSUER && it.metadata.displayName == "DIW TEST IACA"
        }
        m.removeAnchor(testIaca).join()
        assertEquals("Example IACA", record().anchorName)
        assertEquals(TrustEnvironment.USER, record().trustEnvironment)

        val user = m.anchors.value!!.first { it.environment == TrustEnvironment.USER }
        m.removeAnchor(user).join()
        assertNull(record().anchorName, "the removed anchor is no longer shown")
        assertNull(record().trustEnvironment)

        m.importAnchor(pem, "Example IACA", setOf(diw.wallet.core.trust.TrustRole.ISSUER)).join()
        assertEquals("Example IACA", record().anchorName)
        val notes = m.history.value.filter { it.kind == HistoryKind.STATUS }.mapNotNull { it.note }
        assertTrue(notes.any { "移除信任錨點「DIW TEST IACA」" in it }, "notes: $notes")
        assertTrue(notes.any { "移除信任錨點「Example IACA」" in it }, "notes: $notes")
        assertTrue(notes.any { "加入信任錨點" in it }, "notes: $notes")
    }

    /**
     * A DID the user trusts stays trusted when its Linked Domains configuration cannot be verified: the user's own
     * decision is asked before the domain linkage, whose failure would otherwise make it T4.
     */
    @Test
    fun userTrustedDidOverridesBrokenDomainLink() = runBlocking<Unit> {
        val host = "partner.mock.example"
        val did = "did:web:$host"
        val jwk = org.multipaz.crypto.Crypto.createEcPrivateKey(org.multipaz.crypto.EcCurve.P256).publicKey.toJwk()
        val doc = buildJsonObject {
            put("id", did)
            putJsonArray("verificationMethod") {
                add(buildJsonObject { put("id", "$did#key1"); put("type", "JsonWebKey2020"); put("controller", did); put("publicKeyJwk", jwk) })
            }
            putJsonArray("assertionMethod") { add("$did#key1") }
            putJsonArray("service") {
                add(buildJsonObject { put("id", "$did#domain"); put("type", "LinkedDomains"); put("serviceEndpoint", "https://$host/") })
            }
        }
        val engine = io.ktor.client.engine.mock.MockEngine { request ->
            if (request.url.host == host && request.url.encodedPath == "/.well-known/did.json") {
                respond(doc.toString(), io.ktor.http.HttpStatusCode.OK, io.ktor.http.headersOf(HttpHeaders.ContentType, "application/json"))
            } else {
                // The domain's did-configuration.json, the TWDIW list and anything else are unreachable.
                respond("not found", io.ktor.http.HttpStatusCode.NotFound)
            }
        }
        val p = TestPlatform(EphemeralStorage(), client = { HttpClient(engine) { followRedirects = false } })
        val m = WalletModel(p)
        p.model = m
        m.init()
        val before = assertNotNull(m.didTrust.decide(did, diw.wallet.core.trust.TrustRole.ISSUER))
        assertEquals(TrustTier.T4, before.tier, "an unverifiable domain link alone is T4")
        m.trustDid(did, "Partner", setOf(diw.wallet.core.trust.TrustRole.ISSUER)).join()
        val after = assertNotNull(m.didTrust.decide(did, diw.wallet.core.trust.TrustRole.ISSUER))
        assertEquals(TrustTier.T3, after.tier)
        assertEquals(TrustEnvironment.USER, after.environment)
        assertEquals("Partner", after.anchorName)
    }

    /** Anchors are not limited to TWDIW: a PEM root imported by the user is a USER anchor (T3) until removed. */
    @Test
    fun userAnchorImportAndRemoval() = runBlocking<Unit> {
        start()
        val (m, _) = newWallet()
        val pem = http.get("$base/pki/verifier-root.pem").bodyAsText()
        m.importAnchor(pem, "Example Root", setOf(diw.wallet.core.trust.TrustRole.ISSUER, diw.wallet.core.trust.TrustRole.STATUS_LIST)).join()
        withTimeout(10.seconds) { m.anchors.first { a -> a?.any { it.environment == TrustEnvironment.USER } == true } }
        val user = m.anchors.value!!.filter { it.environment == TrustEnvironment.USER }
        assertEquals(setOf(diw.wallet.core.trust.TrustRole.ISSUER, diw.wallet.core.trust.TrustRole.STATUS_LIST), user.map { it.role }.toSet())
        assertTrue(user.all { it.metadata.displayName == "Example Root" && !it.official })
        val stored = m.trust.anchors(diw.wallet.core.trust.TrustRole.ISSUER, TrustEnvironment.USER).map { it.first }
        assertTrue(user.first().certificate in stored)
        // USER anchors are consulted in production use, without the test environment.
        assertTrue(TrustEnvironment.USER in diw.wallet.core.env.EnvironmentPolicy().enabledEnvironments())
        user.forEach { m.removeAnchor(it).join() }
        m.loadAnchors().join()
        assertTrue(m.anchors.value!!.none { it.environment == TrustEnvironment.USER })
        // Not a certificate: nothing is added and the reason is shown.
        m.importAnchor("hello", "", setOf(diw.wallet.core.trust.TrustRole.ISSUER)).join()
        assertTrue(m.message.value!!.startsWith("匯入失敗"), "message: ${m.message.value}")
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
