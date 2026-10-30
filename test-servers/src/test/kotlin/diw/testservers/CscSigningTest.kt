package diw.testservers

import diw.wallet.core.document.sign.CscClient
import diw.wallet.core.document.sign.CscEnvironment
import diw.wallet.core.document.sign.CscException
import diw.wallet.core.document.sign.CscService
import diw.wallet.core.document.sign.CscSigner
import diw.wallet.core.document.sign.CscUserAgent
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SignerKeyType
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.content.OutgoingContent
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import io.ktor.http.parseQueryString
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** CSC API v2 remote signing against a mock QTSP that behaves like the EUDI wallet-centric signer. */
class CscSigningTest {
    private val service = CscService(
        id = "mock", name = "Mock QTSP", baseUrl = "https://qtsp.example/csc/v2", clientId = "wallet-client",
        clientSecret = "secret", redirectUri = "rqes://oauth/callback", environment = CscEnvironment.TEST,
    )

    /** The mock service: keys, issued codes and tokens, and what each credential token may sign. */
    private class Qtsp(
        val ec: Boolean, val authMode: String = "oauth2code",
        /** Offer oauth2/pushed_authorize, answer signHash asynchronously, offer timestamps, or only signDoc. */
        val par: Boolean = false, val async: Boolean = false, val timestamps: Boolean = false, val signDocOnly: Boolean = false,
    ) {
        val key: KeyPair = if (ec) KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        else KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val cert: ByteArray = JcaX509v3CertificateBuilder(
            X500Name("CN=Test Signer"), BigInteger.ONE, Date(System.currentTimeMillis() - 86_400_000), Date(System.currentTimeMillis() + 86_400_000),
            X500Name("CN=Test Signer"), key.public,
        ).build(JcaContentSignerBuilder(if (ec) "SHA256withECDSA" else "SHA256withRSA").build(key.private)).encoded
        val codes = mutableMapOf<String, Pair<String, Map<String, String>>>()
        val tokens = mutableMapOf<String, Map<String, String>>()
        var signHashCalls = 0
        var authorizations = 0
        var pins = mutableListOf<String>()
        val pushed = mutableMapOf<String, Map<String, String>>()
        var polls = 0
        var timestampRequests = mutableListOf<JsonObject>()
        var signDocRequests = mutableListOf<JsonObject>()

        fun authorizeRedirect(url: String): String {
            authorizations++
            val raw = parseQueryString(Url(url).encodedQuery).entries().associate { it.key to it.value.first() }
            // With PAR the browser carries only client_id and request_uri; the parameters were pushed before.
            val q = raw["request_uri"]?.let { uri ->
                check(raw.keys == setOf("client_id", "request_uri")) { "PAR authorize must carry only client_id and request_uri: $raw" }
                pushed.remove(uri) ?: error("unknown request_uri")
            } ?: raw.also { check(!par) { "parameters must be pushed" } }
            val code = "code-$authorizations"
            codes[code] = q["code_challenge"]!! to q
            return "${q["redirect_uri"]}?code=$code&state=${q["state"]}"
        }

        fun handle(scope: MockRequestHandleScope, req: HttpRequestData): HttpResponseData {
            val path = req.url.encodedPath
            val body = (req.body as? TextContent)?.text ?: (req.body as? OutgoingContent.ByteArrayContent)?.bytes()?.decodeToString() ?: ""
            fun json(o: JsonObject, status: HttpStatusCode = HttpStatusCode.OK) =
                scope.respond(o.toString(), status, headersOf(HttpHeaders.ContentType, "application/json"))
            fun error(msg: String) = json(buildJsonObject { put("error", "invalid_request"); put("error_description", msg) }, HttpStatusCode.BadRequest)
            val bearer = req.headers[HttpHeaders.Authorization]?.removePrefix("Bearer ")
            return when (path) {
                "/csc/v2/info" -> json(buildJsonObject {
                    put("name", "Mock QTSP")
                    put("oauth2", "https://qtsp.example")
                    putJsonArray("authType") { add(JsonPrimitive("oauth2code")) }
                    putJsonArray("methods") {
                        buildList {
                            add("credentials/list"); add("credentials/authorize")
                            add(if (signDocOnly) "signatures/signDoc" else "signatures/signHash")
                            if (par) add("oauth2/pushed_authorize")
                            if (timestamps) add("signatures/timestamp")
                            if (async) add("signatures/signPolling")
                        }.forEach { add(JsonPrimitive(it)) }
                    }
                    put("asynchronousOperationMode", async)
                })
                "/oauth2/pushed_authorize" -> {
                    if (req.headers[HttpHeaders.Authorization] != "Basic " + Base64.getEncoder().encodeToString("wallet-client:secret".toByteArray())) return error("client authentication failed")
                    val uri = "urn:qtsp:par:" + pushed.size
                    pushed[uri] = parseQueryString(body).entries().associate { it.key to it.value.first() }
                    json(buildJsonObject { put("request_uri", uri); put("expires_in", 90) }, HttpStatusCode.Created)
                }
                "/csc/v2/signatures/timestamp" -> {
                    if (tokens[bearer]?.get("scope") != "service") return error("service token required")
                    val o = Json.parseToJsonElement(body).jsonObject
                    timestampRequests += o
                    json(buildJsonObject { put("timestamp", Base64.getEncoder().encodeToString("TST:".toByteArray() + Base64.getDecoder().decode(o["hash"]!!.jsonPrimitive.content))) })
                }
                "/csc/v2/signatures/signPolling" -> {
                    polls++
                    val id = Json.parseToJsonElement(body).jsonObject["requestID"]!!.jsonPrimitive.content
                    val ready = pending[id] ?: return error("unknown requestID")
                    if (polls < 2) scope.respond("", HttpStatusCode.Accepted) else json(ready)
                }
                "/csc/v2/signatures/signDoc" -> {
                    val o = Json.parseToJsonElement(body).jsonObject
                    signDocRequests += o
                    val t = tokens[bearer] ?: return error("unknown token")
                    if (t["scope"] != "credential") return error("credential token required")
                    val d = o["documentDigests"]!!.jsonArray.single().jsonObject
                    if (d["signature_format"]!!.jsonPrimitive.content != "P") return error("only PAdES")
                    val hash = Base64.getDecoder().decode(d["hashes"]!!.jsonArray.single().jsonPrimitive.content)
                    if (!hash.contentEquals(Base64.getUrlDecoder().decode(t["hashes"]!!))) return error("hash not authorized")
                    json(buildJsonObject { putJsonArray("SignatureObject") { add(JsonPrimitive(Base64.getEncoder().encodeToString(padesCms(hash)))) } })
                }
                "/oauth2/token" -> {
                    val basic = req.headers[HttpHeaders.Authorization]
                    if (basic != "Basic " + Base64.getEncoder().encodeToString("wallet-client:secret".toByteArray())) return error("client authentication failed: $basic")
                    val form = parseQueryString(body)
                    val (challenge, params) = codes.remove(form["code"]) ?: return error("unknown code")
                    val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(form["code_verifier"]!!.toByteArray()))
                    if (expected != challenge) return error("PKCE failed")
                    if (form["redirect_uri"] != "rqes://oauth/callback") return error("redirect_uri mismatch")
                    val token = "tok-" + tokens.size
                    tokens[token] = params
                    json(buildJsonObject { put("access_token", token); put("token_type", "Bearer"); put("expires_in", 3600) })
                }
                "/csc/v2/credentials/list" -> {
                    if (tokens[bearer]?.get("scope") != "service") return error("service token required")
                    json(buildJsonObject {
                        putJsonArray("credentialIDs") { add(JsonPrimitive("disabled")); add(JsonPrimitive("cred-1")) }
                        putJsonArray("credentialInfos") {
                            add(info("disabled", enabled = false))
                            add(info("cred-1", enabled = true))
                        }
                    })
                }
                "/csc/v2/credentials/authorize" -> {
                    val o = Json.parseToJsonElement(body).jsonObject
                    if (tokens[bearer]?.get("scope") != "service") return error("service token required")
                    pins += o["PIN"]?.jsonPrimitive?.content ?: ""
                    if (o["PIN"]?.jsonPrimitive?.content != "1234") return error("wrong PIN")
                    val sad = "sad-" + pins.size
                    tokens[sad] = mapOf("hashes" to o["hashes"]!!.jsonArray.joinToString(",") { it.jsonPrimitive.content })
                    json(buildJsonObject { put("SAD", sad) })
                }
                "/csc/v2/signatures/signHash" -> {
                    signHashCalls++
                    val o = Json.parseToJsonElement(body).jsonObject
                    val hashes = o["hashes"]!!.jsonArray.map { Base64.getDecoder().decode(it.jsonPrimitive.content) }
                    val authorized = if (authMode == "oauth2code") {
                        val t = tokens[bearer] ?: return error("unknown token")
                        if (t["scope"] != "credential" || t["credentialID"] != o["credentialID"]!!.jsonPrimitive.content) return error("credential token required")
                        t["hashes"]!!.split(',').map { Base64.getUrlDecoder().decode(it) }
                    } else {
                        tokens[o["SAD"]!!.jsonPrimitive.content]!!["hashes"]!!.split(',').map { Base64.getDecoder().decode(it) }
                    }
                    if (hashes.size != authorized.size || hashes.zip(authorized).any { !it.first.contentEquals(it.second) }) return error("hash not authorized")
                    val expectedAlg = if (ec) "1.2.840.10045.4.3.2" else "1.2.840.113549.1.1.11"
                    if (o["signAlgo"]!!.jsonPrimitive.content != expectedAlg) return error("unsupported signAlgo")
                    val signatures = hashes.map { h ->
                        if (ec) {
                            // Raw r || s, as some services return; the wallet turns it into DER.
                            val der = Signature.getInstance("NONEwithECDSA").apply { initSign(key.private); update(h) }.sign()
                            Base64.getEncoder().encodeToString(derToRaw(der))
                        } else {
                            val digestInfo = byteArrayOf(0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20) + h
                            Base64.getEncoder().encodeToString(Signature.getInstance("NONEwithRSA").apply { initSign(key.private); update(digestInfo) }.sign())
                        }
                    }
                    val result = buildJsonObject { put("signatures", JsonArray(signatures.map { JsonPrimitive(it) })) }
                    if (async) {
                        val id = "resp-" + pending.size
                        pending[id] = result
                        json(buildJsonObject { put("responseID", id) })
                    } else json(result)
                }
                else -> scope.respond("", HttpStatusCode.NotFound)
            }
        }

        val pending = mutableMapOf<String, JsonObject>()

        /** A detached CMS SignedData whose message digest is [hash] (the PDF byte-range digest), as a signDoc service returns. */
        fun padesCms(hash: ByteArray): ByteArray {
            val holder = org.bouncycastle.cert.X509CertificateHolder(cert)
            val digests = org.bouncycastle.operator.DigestCalculatorProvider { alg ->
                object : org.bouncycastle.operator.DigestCalculator {
                    private val sink = java.io.ByteArrayOutputStream()
                    override fun getAlgorithmIdentifier() = alg
                    override fun getOutputStream() = sink
                    override fun getDigest() = hash
                }
            }
            val gen = org.bouncycastle.cms.CMSSignedDataGenerator()
            gen.addSignerInfoGenerator(org.bouncycastle.cms.SignerInfoGeneratorBuilder(digests)
                .build(JcaContentSignerBuilder(if (ec) "SHA256withECDSA" else "SHA256withRSA").build(key.private), holder))
            gen.addCertificate(holder)
            return gen.generate(org.bouncycastle.cms.CMSAbsentContent(), false).encoded
        }

        private fun info(id: String, enabled: Boolean) = buildJsonObject {
            put("credentialID", id)
            putJsonObject("key") {
                put("status", if (enabled) "enabled" else "disabled")
                putJsonArray("algo") {
                    if (ec) { add(JsonPrimitive("1.2.840.10045.2.1")); add(JsonPrimitive("1.2.840.10045.4.3.2")) }
                    else { add(JsonPrimitive("1.2.840.113549.1.1.1")); add(JsonPrimitive("1.2.840.113549.1.1.11")) }
                }
            }
            putJsonObject("cert") {
                put("status", "valid")
                putJsonArray("certificates") { add(JsonPrimitive(Base64.getEncoder().encodeToString(cert))) }
                put("subjectDN", "CN=Test Signer")
            }
            putJsonObject("auth") {
                put("mode", authMode)
                if (authMode == "explicit") putJsonArray("objects") { add(buildJsonObject { put("type", "PIN"); put("id", "PIN") }) }
            }
            put("SCAL", "2")
        }

        private fun derToRaw(der: ByteArray): ByteArray {
            val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(der)
            fun fixed(i: Int): ByteArray {
                val v = (seq.getObjectAt(i) as org.bouncycastle.asn1.ASN1Integer).value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
                return ByteArray(32 - v.size) + v
            }
            return fixed(0) + fixed(1)
        }
    }

    private fun agent(qtsp: Qtsp, pin: String? = null) = object : CscUserAgent {
        override suspend fun authorize(url: String, redirectUri: String, purpose: String): String {
            assertTrue(url.startsWith("https://qtsp.example/oauth2/authorize?"), url)
            if (qtsp.par) assertTrue("request_uri=" in url && "code_challenge" !in url, url)
            return qtsp.authorizeRedirect(url)
        }
        override suspend fun askSecret(label: String, numeric: Boolean): String? = pin
    }

    private fun client(qtsp: Qtsp) = HttpClient(MockEngine { req -> qtsp.handle(this, req) })

    private fun verifyCades(cms: ByteArray, content: ByteArray, cert: ByteArray) {
        val x509 = CertificateFactory.getInstance("X.509").generateCertificate(cert.inputStream()) as X509Certificate
        val parsed = CMSSignedData(org.bouncycastle.cms.CMSProcessableByteArray(content), cms)
        assertTrue(parsed.signerInfos.signers.first().verify(JcaSimpleSignerInfoVerifierBuilder().build(x509)))
    }

    @Test
    fun ecCredentialSignsAfterServiceAndCredentialAuthorization() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = true)
        val signer = CscSigner(CscClient(client(qtsp), service), agent(qtsp), hint = "test.pdf")
        val c = signer.load()
        assertEquals("cred-1", c.id, "the disabled credential is skipped")
        assertEquals(SignerKeyType.EC_P256, signer.keyType)
        val content = "hello csc".toByteArray()
        val cms = DocumentSigning.signCades(content, signer, true, null)
        verifyCades(cms, content, qtsp.cert)
        assertEquals(2, qtsp.authorizations, "one sign-in and one approval of the signature")
        assertEquals(1, qtsp.signHashCalls)
    }

    @Test
    fun rsaCredentialSignsAndReusesTheServiceToken() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = false)
        val http = client(qtsp)
        val first = CscSigner(CscClient(http, service), agent(qtsp))
        first.load()
        assertEquals(SignerKeyType.RSA, first.keyType)
        val content = "first".toByteArray()
        verifyCades(DocumentSigning.signCades(content, first, true, null), content, qtsp.cert)
        // A second signing in the same run starts from the service token and only approves its own hash.
        val second = CscSigner(CscClient(http, service), agent(qtsp), serviceToken = first.serviceToken)
        second.load()
        val more = "second".toByteArray()
        verifyCades(DocumentSigning.signCades(more, second, true, null), more, qtsp.cert)
        assertEquals(3, qtsp.authorizations)
    }

    @Test
    fun explicitCredentialUsesPinAndSad() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = true, authMode = "explicit")
        val signer = CscSigner(CscClient(client(qtsp), service), agent(qtsp, pin = "1234"))
        signer.load()
        val content = "pin".toByteArray()
        verifyCades(DocumentSigning.signCades(content, signer, true, null), content, qtsp.cert)
        assertEquals(listOf("1234"), qtsp.pins)
        assertEquals(1, qtsp.authorizations, "only the sign-in goes through OAuth")
    }

    @Test
    fun wrongStateIsRefused() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = true)
        val agent = object : CscUserAgent {
            override suspend fun authorize(url: String, redirectUri: String, purpose: String): String =
                qtsp.authorizeRedirect(url).replace(Regex("state=[^&]+"), "state=forged")
            override suspend fun askSecret(label: String, numeric: Boolean): String? = null
        }
        val e = assertFailsWith<CscException> { CscSigner(CscClient(client(qtsp), service), agent).load() }
        assertTrue("state" in e.message!!)
    }

    @Test
    fun insecureOAuthEndpointsAreRejected() = runBlocking<Unit> {
        val http = HttpClient(MockEngine {
            respond(
                """{"name":"Insecure QTSP","oauth2":"http://insecure.example"}""",
                HttpStatusCode.OK,
                headersOf(HttpHeaders.ContentType, "application/json"),
            )
        })
        val production = service.copy(environment = CscEnvironment.PRODUCTION)
        val error = assertFailsWith<CscException> { CscClient(http, production).authorizationRequest("service") }
        assertTrue(error.message.orEmpty().contains("HTTPS"))
    }

    @Test
    fun wrongOAuthCallbackUriIsRejected() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = true)
        val client = CscClient(client(qtsp), service)
        val request = client.authorizationRequest("service")
        val result = qtsp.authorizeRedirect(request.url)
        val changed = result.replace("rqes://oauth/callback", "https://attacker.example/oauth/callback")
        val error = assertFailsWith<CscException> { client.code(changed, request) }
        assertTrue(error.message.orEmpty().contains("redirect_uri"))
    }

    @Test
    fun authorizationErrorIsReported() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = true)
        val agent = object : CscUserAgent {
            override suspend fun authorize(url: String, redirectUri: String, purpose: String): String =
                "$redirectUri?error=access_denied&error_description=user%20cancelled&state=x"
            override suspend fun askSecret(label: String, numeric: Boolean): String? = null
        }
        val e = assertFailsWith<CscException> { CscSigner(CscClient(client(qtsp), service), agent).load() }
        assertEquals("access_denied", e.error)
        assertTrue("user cancelled" in e.message!!)
    }

    @Test
    fun authorizationRequestCarriesTheHashAsTheEudiServiceExpects() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = true)
        val urls = mutableListOf<String>()
        val agent = object : CscUserAgent {
            override suspend fun authorize(url: String, redirectUri: String, purpose: String): String {
                urls += url
                return qtsp.authorizeRedirect(url)
            }
            override suspend fun askSecret(label: String, numeric: Boolean): String? = null
        }
        val signer = CscSigner(CscClient(client(qtsp), service), agent)
        signer.load()
        val data = "to be signed".toByteArray()
        signer.sign(data)
        val q = parseQueryString(Url(urls[1]).encodedQuery)
        assertEquals("credential", q["scope"])
        assertEquals("cred-1", q["credentialID"])
        assertEquals("1", q["numSignatures"])
        assertEquals("2.16.840.1.101.3.4.2.1", q["hashAlgorithmOID"])
        assertContentEquals(MessageDigest.getInstance("SHA-256").digest(data), Base64.getUrlDecoder().decode(q["hashes"]))
        assertEquals("S256", q["code_challenge_method"])
        assertEquals("service", parseQueryString(Url(urls[0]).encodedQuery)["scope"])
    }

    @Test
    fun pushedAuthorizationKeepsParametersOutOfTheBrowser() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = true, par = true)
        val signer = CscSigner(CscClient(client(qtsp), service), agent(qtsp))
        signer.load()
        val content = "par".toByteArray()
        verifyCades(DocumentSigning.signCades(content, signer, true, null), content, qtsp.cert)
        assertEquals(2, qtsp.authorizations)
        assertTrue(qtsp.pushed.isEmpty(), "each pushed request is used once")
    }

    @Test
    fun asynchronousSignHashIsPolled() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = false, async = true)
        val signer = CscSigner(CscClient(client(qtsp), service), agent(qtsp))
        signer.load()
        val content = "async".toByteArray()
        verifyCades(DocumentSigning.signCades(content, signer, true, null), content, qtsp.cert)
        assertEquals(2, qtsp.polls, "one 202 Accepted, then the result")
    }

    @Test
    fun serviceTimestampCarriesHashAndNonce() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = true, timestamps = true)
        val signer = CscSigner(CscClient(client(qtsp), service), agent(qtsp))
        signer.load()
        val ts = signer.timestamper() ?: error("the service lists signatures/timestamp")
        val data = "stamp me".toByteArray()
        val token = ts.timestamp(data)
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        assertContentEquals("TST:".toByteArray() + digest, token)
        val req = qtsp.timestampRequests.single()
        assertEquals("2.16.840.1.101.3.4.2.1", req["hashAlgo"]!!.jsonPrimitive.content)
        assertTrue(req["nonce"]!!.jsonPrimitive.content.matches(Regex("[0-9a-f]{32}")))
        // Without the method there is no remote time stamp.
        val plain = CscSigner(CscClient(client(Qtsp(ec = true)), service), agent(Qtsp(ec = true)))
        assertEquals(null, runCatching { plain.load(); plain.timestamper() }.getOrNull())
    }

    @Test
    fun signDocOnlyServiceProducesAValidPades() = runBlocking<Unit> {
        val qtsp = Qtsp(ec = true, signDocOnly = true)
        val signer = CscSigner(CscClient(client(qtsp), service), agent(qtsp))
        signer.load()
        assertEquals(false, signer.supportsSignHash())
        assertEquals(true, signer.supportsSignDoc())
        val pdf = diw.testservers.fixtures.PdfComposer.compose("CSC", listOf(diw.testservers.fixtures.PdfComposer.Block.Paragraph("signDoc")), emptyList())
        val prepared = diw.wallet.core.document.pdf.PdfIncrementalSigner.prepare(pdf, diw.wallet.core.document.pdf.PdfSignOptions(reserve = 64 * 1024))
        val cms = signer.signPadesDigest(prepared.signedData(), "AdES-B-B")
        diw.wallet.core.document.sign.DocumentSigning.verifyDetached(cms, prepared.signedData(), signer.certificateChain.first())
        assertFailsWith<diw.wallet.core.document.sign.SigningException> {
            diw.wallet.core.document.sign.DocumentSigning.verifyDetached(cms, prepared.signedData() + 0, signer.certificateChain.first())
        }
        val signed = prepared.finish(cms)
        val report = diw.wallet.core.document.DocumentInspector.inspect(signed, "csc.pdf", object : diw.wallet.core.document.DocumentTrustSource {
            val registry = diw.wallet.core.trust.TrustRegistry(org.multipaz.storage.ephemeral.EphemeralStorage(), diw.wallet.core.env.EnvironmentPolicy())
            override suspend fun decide(role: diw.wallet.core.trust.TrustRole, chain: List<org.multipaz.crypto.X509Cert>, at: kotlin.time.Instant) = registry.decide(role, chain, at)
            override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
        })
        assertEquals(diw.wallet.core.document.Check.PASS, report.signatures.single().integrity, report.signatures.single().problems.toString())
        val req = qtsp.signDocRequests.single()
        assertEquals("AdES-B-B", req["documentDigests"]!!.jsonArray.single().jsonObject["conformance_level"]!!.jsonPrimitive.content)
    }

    @Test
    fun cscProfileImportsServices() = runBlocking<Unit> {
        val json = """[{"type":"csc-profile","name":"QTSP A","baseUrl":"https://a.example/csc/v2/","clientId":"wallet","environment":"production"},
            {"name":"QTSP B","baseUrl":"https://b.example/csc/v2","clientId":"w2","clientSecret":"s","redirectUri":"app://cb","environment":"test","note":"sandbox"}]"""
        val list = diw.wallet.core.document.sign.CscServices.fromProfile(json)
        assertEquals(2, list.size)
        assertEquals("https://a.example/csc/v2", list[0].baseUrl)
        assertEquals(diw.wallet.core.document.sign.CscServices.WALLET_REDIRECT, list[0].redirectUri)
        assertEquals(CscEnvironment.PRODUCTION, list[0].environment)
        assertEquals(CscEnvironment.TEST, list[1].environment)
        assertEquals("s", list[1].clientSecret)
        // Round trip without the secret; the same address and client_id give the same id.
        val again = diw.wallet.core.document.sign.CscServices.fromProfile(diw.wallet.core.document.sign.CscServices.profileOf(list[1]))
        assertEquals(list[1].id, again.single().id)
        assertEquals(null, again.single().clientSecret)
        assertFailsWith<CscException> { diw.wallet.core.document.sign.CscServices.fromProfile("""{"name":"x","baseUrl":"http://x.example","clientId":"c"}""") }
        assertFailsWith<CscException> { diw.wallet.core.document.sign.CscServices.fromProfile("""{"type":"other","name":"x","baseUrl":"https://x.example","clientId":"c"}""") }
    }
}
