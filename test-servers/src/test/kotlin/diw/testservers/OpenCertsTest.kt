package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.opencerts.OaMethod
import diw.wallet.core.document.opencerts.OpenAttestationDocument
import diw.wallet.core.document.opencerts.OpenAttestationOnline
import diw.wallet.core.document.opencerts.OpenCertOffline
import diw.wallet.core.document.opencerts.OpenCertRenderer
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

/**
 * OpenAttestation (OpenCerts) documents: integrity of version 2 (plain, obfuscated, DID signed) and version 3, the
 * view the file screen shows, and the online checks (document store, DNS-TXT, DNS-DID) against mocked DNS-over-HTTPS
 * and JSON-RPC. The fixtures are fictional and were wrapped with @govtechsg/open-attestation 6.9.7 (generate.js).
 */
class OpenCertsTest {
    private fun sample(name: String): ByteArray = javaClass.getResourceAsStream("/documents/opencerts/$name")!!.readBytes()

    private fun doc(name: String) = assertNotNull(OpenAttestationDocument.parse(sample(name)), name)

    private val store = "0x1111111111111111111111111111111111111111"
    private val didAddress = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"

    @Test
    fun integrityOfVersionTwoAndThree() {
        assertEquals(Check.PASS, doc("oa-v2-store.json").integrity)
        assertEquals(Check.PASS, doc("oa-v2-store-obfuscated.json").integrity)
        assertEquals(Check.PASS, doc("oa-v2-did.json").integrity)
        assertEquals(Check.PASS, doc("oa-v3-store.json").integrity)
        assertEquals(Check.FAIL, doc("oa-v2-tampered.json").integrity)
        assertNull(OpenAttestationDocument.parse("""{"name":"plain json"}""".encodeToByteArray()))
    }

    @Test
    fun viewOfACertificate() {
        val d = doc("oa-v2-store.json")
        assertFalse(d.v3)
        val v = d.view()
        assertEquals("Bachelor of Testing", v.title)
        assertTrue(("姓名" to "Test Person") in v.recipient, v.recipient.toString())
        assertTrue(("學號" to "S0001") in v.recipient, v.recipient.toString())
        assertTrue(("證書編號" to "TEST-CERT-A") in v.main, v.main.toString())
        val issuer = v.issuers.single()
        assertEquals(OaMethod.DOCUMENT_STORE, issuer.method)
        assertEquals(store, issuer.value)
        assertEquals("DNS-TXT", issuer.identityType)
        assertEquals("certs.test.example", issuer.identityLocation)
        val signatory = v.signatories.single()
        assertEquals("Test Dean", signatory.name)
        assertNotNull(signatory.image)
        assertEquals(2, v.transcript.size)
        assertTrue("成績" in v.transcriptColumns, v.transcriptColumns.toString())
        assertEquals("test attachment", v.attachments.single().bytes.decodeToString())
        assertTrue(v.images.isNotEmpty())
        assertTrue(v.other.any { it.second == "Honours" }, v.other.toString())
        // Nothing of the raw layout leaks into the other fields.
        assertFalse(v.other.any { (k, _) -> k.contains("certSignatories") || k.contains('.') }, v.other.toString())
        assertEquals("https://demo-renderer.opencerts.io", v.templateUrl)

        val hidden = doc("oa-v2-store-obfuscated.json").view()
        assertFalse(hidden.recipient.any { it.first == "電子郵件" }, hidden.recipient.toString())
    }

    @Test
    fun versionThreeIssuer() {
        val d = doc("oa-v3-store.json")
        assertTrue(d.v3)
        val issuer = d.issuers.single()
        assertEquals(OaMethod.DOCUMENT_STORE, issuer.method)
        assertEquals("0x2222222222222222222222222222222222222222", issuer.value)
        assertEquals("v3.test.example", issuer.identityLocation)
        assertEquals("Test University V3", issuer.name)
        assertTrue(d.view().recipient.any { it.second == "Test Person" })
    }

    @Test
    fun inspectorReportsTheCertificate() = runBlocking<Unit> {
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        val trust = object : DocumentTrustSource {
            override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision = registry.decide(role, chain, at)
            override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
        }
        val r = DocumentInspector.inspect(sample("oa-v3-store.json"), "cert.json", trust, null, Instant.parse("2026-10-15T00:00:00Z"))
        assertEquals(DocumentFormat.OPENCERTS, r.format)
        assertEquals(Check.PASS, r.openCert?.integrity)
        assertEquals(DocumentVerdict.PARTIAL, r.verdict)
        val claims = DerivedCredentials.suggestedClaims(r, "cert.json", "使用者自行匯入").associate { it.name to it.value }
        assertEquals("Test Person", claims["recipientName"])
        assertEquals("2026-06-30T00:00:00Z", claims["issuedOn"])
        assertEquals("Test University V3", claims["documentIssuer"])
        assertFalse(claims.keys.any { it.startsWith("openAttestationMetadata") || it.startsWith("issuer.") || it == "type.0" }, claims.keys.toString())
        val tampered = DocumentInspector.inspect(sample("oa-v2-tampered.json"), "bad.json", trust, null, Instant.parse("2026-10-15T00:00:00Z"))
        assertEquals(DocumentVerdict.INVALID, tampered.verdict)
    }

    @Test
    fun dnsRecordsAndDidAddresses() {
        val txt = OpenAttestationOnline.parseRecord("\"openatts net=ethereum netId=11155111 addr=$store\"")!!
        assertEquals("ethereum", txt.net)
        assertEquals("11155111", txt.netId)
        assertEquals(store, txt.addr)
        val did = OpenAttestationOnline.parseRecord("openatts a=dns-did; p=did:ethr:$didAddress#controller; v=1.0;")!!
        assertEquals("did:ethr:$didAddress#controller", did.didKey)
        assertNull(OpenAttestationOnline.parseRecord("v=spf1 -all"))
        assertEquals(didAddress.removePrefix("0x"), OpenAttestationOnline.ethrAddress("did:ethr:$didAddress#controller"))
        assertEquals(didAddress.removePrefix("0x"), OpenAttestationOnline.ethrAddress("did:ethr:sepolia:$didAddress"))
        assertNull(OpenAttestationOnline.ethrAddress("did:key:z6Mk"))
    }

    // ---------------------------------------------------------------- online, mocked

    private fun selector(signature: String) = "0x" + OpenAttestationDocument.keccakHex(signature).take(8)

    private class Chain(val issued: Set<String>, val revoked: Set<String> = emptySet(), val batchable: Boolean = false)

    private fun online(txt: Map<String, List<String>>, chains: Map<String, Chain>, registry: String? = null): OpenAttestationOnline {
        val supports = selector("supportsInterface(bytes4)")
        val isIssued = selector("isIssued(bytes32)")
        val isRevoked = selector("isRevoked(bytes32)")
        val isIssuedBatch = selector("isIssued(bytes32,bytes32,bytes32[])")
        val isRevokedBatch = selector("isRevoked(bytes32,bytes32,bytes32[])")
        suspend fun MockRequestHandleScope.handle(request: HttpRequestData): HttpResponseData {
            val json = headersOf(HttpHeaders.ContentType, "application/json")
            val host = request.url.host
            if (host == "dns.test") {
                val name = request.url.parameters["name"]!!
                val answers = txt[name].orEmpty().joinToString(",") { """{"name":"$name","type":16,"data":"\"$it\""}""" }
                return respond("""{"Status":0,"Answer":[$answers]}""", HttpStatusCode.OK, json)
            }
            if (host == "registry.test") {
                return if (registry == null) respond("", HttpStatusCode.NotFound) else respond(registry, HttpStatusCode.OK, json)
            }
            val chain = chains[host.removePrefix("rpc")] ?: return respond("", HttpStatusCode.ServiceUnavailable)
            val body = DiwJson.parseToJsonElement(request.body.toByteArray().decodeToString()) as JsonObject
            val data = ((body["params"] as JsonArray)[0] as JsonObject)["data"]!!.jsonPrimitive.content
            val arg = data.drop(10).take(64)
            val result = when (data.take(10)) {
                supports -> chain.batchable
                isIssued -> arg in chain.issued
                isRevoked -> arg in chain.revoked
                isIssuedBatch -> if (chain.batchable) arg in chain.issued else false
                isRevokedBatch -> if (chain.batchable) arg in chain.revoked || data.drop(74).take(64) in chain.revoked else false
                else -> return respond("""{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}""", HttpStatusCode.OK, json)
            }
            return respond("""{"jsonrpc":"2.0","id":1,"result":"0x${(if (result) "1" else "0").padStart(64, '0')}"}""", HttpStatusCode.OK, json)
        }
        val http = HttpClient(MockEngine { request -> handle(request) })
        return OpenAttestationOnline(
            http,
            rpc = mapOf("1" to listOf("https://rpc1/"), "11155111" to listOf("https://rpc11155111/")),
            dohs = listOf("https://dns.test/resolve"),
            registryUrl = "https://registry.test/registry.json",
        )
    }

    @Test
    fun documentStoreIssuedAndRevoked() = runBlocking<Unit> {
        val d = doc("oa-v2-store.json")
        val root = d.merkleRoot!!
        val txt = mapOf("certs.test.example" to listOf("openatts net=ethereum netId=11155111 addr=$store"))

        val ok = online(txt, mapOf("11155111" to Chain(setOf(root)))).verify(d)
        assertEquals(Check.PASS, ok.issuance, ok.issuanceDetail.toString())
        assertEquals(Check.PASS, ok.identity, ok.identityDetail.toString())
        assertTrue(ok.issuanceDetail.single().contains("Sepolia"), ok.issuanceDetail.toString())

        val revoked = online(txt, mapOf("11155111" to Chain(setOf(root), revoked = setOf(d.targetHash!!)))).verify(d)
        assertEquals(Check.FAIL, revoked.issuance)
        assertTrue(revoked.issuanceDetail.single().contains("撤銷"))

        val notIssued = online(txt, mapOf("11155111" to Chain(emptySet()))).verify(d)
        assertEquals(Check.FAIL, notIssued.issuance)

        // The domain does not point at the store: issuance can hold while the identity fails.
        val wrongDns = online(mapOf("certs.test.example" to listOf("openatts net=ethereum netId=1 addr=0x3333333333333333333333333333333333333333")), mapOf("1" to Chain(setOf(root)))).verify(d)
        assertEquals(Check.PASS, wrongDns.issuance)
        assertEquals(Check.FAIL, wrongDns.identity)

        // The OpenCerts registry alone proves the issuer.
        val registered = online(emptyMap(), mapOf("1" to Chain(setOf(root))), """{"issuers":{"$store":{"name":"Test University (registry)"}}}""").verify(d)
        assertEquals(Check.PASS, registered.identity, registered.identityDetail.toString())
        assertEquals("Test University (registry)", registered.registryName)

        // No node answers: nothing is decided.
        val offline = online(txt, emptyMap()).verify(d)
        assertEquals(Check.NOT_CHECKED, offline.issuance, offline.issuanceDetail.toString())
    }

    @Test
    fun batchedDocumentStore() = runBlocking<Unit> {
        val d = doc("oa-v3-store.json")
        val txt = mapOf("v3.test.example" to listOf("openatts net=ethereum netId=1 addr=0x2222222222222222222222222222222222222222"))
        val r = online(txt, mapOf("1" to Chain(setOf(d.merkleRoot!!), batchable = true))).verify(d)
        assertEquals(Check.PASS, r.issuance, r.issuanceDetail.toString())
        assertEquals(Check.PASS, r.identity)
        val revoked = online(txt, mapOf("1" to Chain(setOf(d.merkleRoot!!), revoked = setOf(d.targetHash!!), batchable = true))).verify(d)
        assertEquals(Check.FAIL, revoked.issuance, revoked.issuanceDetail.toString())
        val plain = online(txt, mapOf("1" to Chain(setOf(d.merkleRoot!!)))).verify(d)
        assertEquals(Check.PASS, plain.issuance, plain.issuanceDetail.toString())
    }

    @Test
    fun didSignedDocument() = runBlocking<Unit> {
        val d = doc("oa-v2-did.json")
        assertEquals(OaMethod.DID, d.issuers.single().method)
        val txt = mapOf("did.test.example" to listOf("openatts a=dns-did; p=did:ethr:$didAddress#controller; v=1.0;"))
        val r = online(txt, emptyMap()).verify(d)
        assertEquals(Check.PASS, r.issuance, r.issuanceDetail.toString())
        assertEquals(Check.PASS, r.identity, r.identityDetail.toString())

        // Another key's signature over the same root does not hold.
        val raw = DiwJson.parseToJsonElement(sample("oa-v2-did.json").decodeToString()) as JsonObject
        val proof = (raw["proof"] as JsonArray)[0] as JsonObject
        val sig = proof["signature"]!!.jsonPrimitive.content
        val flipped = sig.dropLast(4) + (if (sig.takeLast(4) == "0000") "0001" else "0000")
        val forged = JsonObject(raw + ("proof" to JsonArray(listOf(JsonObject(proof + ("signature" to JsonPrimitive(flipped)))))))
        val bad = online(txt, emptyMap()).verify(OpenAttestationDocument.parse(forged.toString().encodeToByteArray())!!)
        assertEquals(Check.FAIL, bad.issuance, bad.issuanceDetail.toString())
    }

    @Test
    fun rendererHostPage() {
        val d = doc("oa-v2-store.json")
        val html = OpenCertRenderer.hostPage(d)!!
        assertTrue(html.contains("https://demo-renderer.opencerts.io"))
        assertTrue(html.contains("RENDER_DOCUMENT"))
        // The renderer gets the plain data as the document and the wrapped one as rawDocument.
        assertTrue(html.contains("\"name\":\"Test Person\""), html)
        assertTrue(html.contains(":string:Test Person"))
        // Only https templates are loaded.
        val http = d.raw.toString().replace("https://demo-renderer.opencerts.io", "http://renderer.test")
        assertNull(OpenCertRenderer.hostPage(OpenAttestationDocument.parse(http.encodeToByteArray())!!))
    }

    /** A version 2 document with [data] salted as "salt:type:value" (integrity is not checked by the layouts). */
    private fun v2(data: JsonObject): OpenAttestationDocument {
        fun salt(e: kotlinx.serialization.json.JsonElement): kotlinx.serialization.json.JsonElement = when (e) {
            is JsonObject -> JsonObject(e.mapValues { salt(it.value) })
            is JsonArray -> JsonArray(e.map { salt(it) })
            is JsonPrimitive -> JsonPrimitive("00000000-0000-4000-8000-000000000000:" + (if (e.isString) "string" else "number") + ":" + e.content)
            else -> e
        }
        val raw = JsonObject(mapOf("version" to JsonPrimitive("https://schema.openattestation.com/2.0/schema.json"), "data" to salt(data),
            "signature" to JsonObject(mapOf("type" to JsonPrimitive("SHA3MerkleProof"), "targetHash" to JsonPrimitive("00"), "merkleRoot" to JsonPrimitive("00"), "proof" to JsonArray(emptyList())))))
        return assertNotNull(OpenAttestationDocument.parse(raw.toString().encodeToByteArray()))
    }

    private fun json(text: String) = DiwJson.parseToJsonElement(text) as JsonObject

    /** No script, no remote load: only inline styles and data: images. */
    private fun assertInert(html: String) {
        assertTrue("default-src 'none'; img-src data:; style-src 'unsafe-inline'" in html)
        assertFalse(Regex("<script|<iframe|<[a-z][^>]*\\son[a-z]+=|=\"javascript:", RegexOption.IGNORE_CASE).containsMatchIn(html), html)
        assertFalse(Regex("src=\"https?:", RegexOption.IGNORE_CASE).containsMatchIn(html), html)
    }

    @Test
    fun offlineDemoRendererTemplates() {
        val page = OpenCertOffline.page(doc("oa-v2-store.json"))
        assertTrue(page.builtIn)
        assertEquals(listOf("Certificate", "Transcript", "Media"), page.tabs)
        val html = page.html
        assertInert(html)
        assertTrue("Test Person" in html && "OpenCerts Demo" in html && "GovTech Singapore" in html)
        assertTrue("Dated 30/06/2026" in html, html)
        // The transcript shows dates as the demo renderer does: month and year in Singapore time.
        assertTrue(":&nbsp; JUN 2026" in html && ":&nbsp; SEP 2022" in html)
        assertTrue("<td>T101</td><td>Testing 101</td><td>A</td><td>4</td><td>1</td>" in html)
        assertTrue("Test Dean" in html && "src=\"data:image/png;base64," in html)

        // Version 3: the subject is the credential subject, the date its issuance date.
        val v3 = OpenCertOffline.page(doc("oa-v3-store.json"))
        assertTrue(v3.builtIn)
        assertTrue("<b>Test Person</b>" in v3.html && "Dated 30/06/2026" in v3.html)

        // An unknown name on the demo renderer falls back to its default templates, as that renderer does.
        val other = v2(json("""{"${'$'}template":{"name":"SOMETHING_ELSE","url":"https://demo-renderer.opencerts.io"},"name":"X","recipient":{"name":"Someone"}}"""))
        assertEquals(listOf("Certificate", "Transcript", "Media"), OpenCertOffline.page(other).tabs)
    }

    @Test
    fun offlineTestimonialKeepsIssuerHtmlInert() {
        val content = "<p onclick=\"steal()\">Good <b>student</b></p><script>alert(1)</script><img src=\"https://evil.test/x.png\"><a href=\"javascript:x()\">x</a><a href=\"https://school.test\">school</a><iframe src=\"https://evil.test\"></iframe>"
        val d = v2(JsonObject(mapOf(
            "\$template" to json("""{"name":"TESTIMONIALS","url":"https://demo-renderer.opencerts.io"}"""),
            "recipient" to json("""{"name":"Test Student","studentId":"S1"}"""),
            "testimonial" to json("""{"instituteName":"Test School","achievementDate":"2025-11-30"}"""),
            "referee" to json("""{"designation":"Principal"}"""),
            "content" to JsonPrimitive(content),
        )))
        val page = OpenCertOffline.page(d)
        assertTrue(page.builtIn)
        assertInert(page.html)
        assertTrue("Good <b>student</b>" in page.html && "Year of Graduation: 2025" in page.html && "Test School" in page.html)
        assertTrue("href=\"https://school.test\"" in OpenCertOffline.safeHtml(content))
        assertFalse("evil.test" in page.html || "alert(1)" in page.html)
    }

    @Test
    fun offlineLayoutForOtherRenderers() {
        val raw = sample("oa-v2-store.json").decodeToString().replace("https://demo-renderer.opencerts.io", "https://renderer.example.edu")
        val page = OpenCertOffline.page(OpenAttestationDocument.parse(raw.encodeToByteArray())!!)
        assertFalse(page.builtIn)
        assertInert(page.html)
        val html = page.html
        assertTrue("<h1>Bachelor of Testing</h1>" in html && "Test University" in html && "Test Person" in html)
        assertTrue("Testing 102" in html && "Honours" in html && "note.txt" in html && "Test Dean" in html)
        // A certificate of award without the fields that template requires is laid out by the wallet.
        val award = v2(json("""{"${'$'}template":{"name":"CERTIFICATE_OF_AWARD","url":"https://demo-renderer.opencerts.io"},"name":"Award","recipient":{"name":"A"}}"""))
        assertFalse(OpenCertOffline.page(award).builtIn)
        // HTML in values is shown as text.
        val tricky = v2(json("""{"name":"<img src=x onerror=alert(1)>","recipient":{"name":"<b>N</b>"}}"""))
        val t = OpenCertOffline.page(tricky).html
        assertInert(t)
        assertTrue("&lt;b&gt;N&lt;/b&gt;" in t)
    }
}
