package diw.testservers

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.Oid4vpHolder
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import java.net.ServerSocket
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
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

    /** Creates a DC API session on the test verifier: id, protocol and the request data member. */
    private suspend fun dcApiSession(origin: String, signed: Boolean, dcql: JsonObject? = null): JsonObject {
        val text = servers.httpClient.post("$base/verifier/dcapi/sessions") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("origin", origin); put("signed", signed); put("encrypted", true)
                dcql?.let { put("dcql_query", it) }
            }.toString())
        }.bodyAsText()
        return DiwJson.parseToJsonElement(text).jsonObject
    }

    private suspend fun dcApi(origin: String, callerOrigin: String, signed: Boolean): JsonObject {
        val w = wallet()
        val o = dcApiSession(origin, signed)
        val req = w.holder.resolveDcApi(o["protocol"]!!.jsonPrimitive.content, o["data"]!!.jsonObject, callerOrigin)
        val prepared = w.holder.prepare(req)
        val outcome = w.holder.respondDefault(prepared) as PresentationOutcome.DcApi
        val res = servers.httpClient.post("$base/verifier/dcapi/responses/${o["id"]!!.jsonPrimitive.content}") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("origin", origin); put("data", outcome.data) }.toString())
        }.bodyAsText()
        return DiwJson.parseToJsonElement(res).jsonObject
    }

    private suspend fun multiSignedData(origin: String): JsonObject {
        val original = dcApiSession(origin, signed = true)["data"]!!.jsonObject
        val parsed = Jws.parse(original["request"]!!.jsonPrimitive.content)
        val clientId = parsed.payload["client_id"]!!.jsonPrimitive.content
        val payload = JsonObject(parsed.payload.filterKeys { it != "client_id" && it != "verifier_info" })
        val header = JsonObject(parsed.header + ("client_id" to JsonPrimitive(clientId)))
        val compact = signJws(header, payload, servers.pki.readerKey("localhost"))
        val parts = compact.split('.')
        return buildJsonObject {
            put("request", buildJsonObject {
                put("payload", parts[1])
                put("signatures", JsonArray(listOf(
                    buildJsonObject { put("protected", parts[0]); put("signature", parts[2]) },
                    buildJsonObject { put("protected", parts[0]); put("signature", "AAAA") },
                )))
            })
        }
    }

    @Test
    fun dcApiMultiSignedChoosesAnAuthenticatedVerifier() = runBlocking<Unit> {
        val data = multiSignedData("https://rp.example")
        val w = wallet()
        val request = w.holder.resolveDcApi("openid4vp-v1-multisigned", data, "https://rp.example")
        assertEquals("x509_san_dns:localhost", request.verifier.clientId.raw)
        assertTrue(request.raw.requestObject != null)
        assertTrue(request.warnings.any { it.contains("Multi-signed DC API") })
        assertTrue(w.holder.respondDefault(w.holder.prepare(request)) is PresentationOutcome.DcApi)
    }

    @Test
    fun dcApiMultiSignedRejectsForgedSignaturesAndOrigins() = runBlocking<Unit> {
        val data = multiSignedData("https://rp.example")
        val w = wallet()
        val mismatch = assertFailsWith<RequestValidationException> {
            w.holder.resolveDcApi("openid4vp-v1-multisigned", data, "https://attacker.example")
        }
        assertEquals("invalid_request_object", mismatch.code)
        val envelope = data["request"]!!.jsonObject
        val forged = buildJsonObject {
            put("request", buildJsonObject {
                put("payload", envelope["payload"]!!)
                put("signatures", JsonArray((envelope["signatures"] as JsonArray).map {
                    JsonObject(it.jsonObject + ("signature" to JsonPrimitive("AAAA")))
                }))
            })
        }
        assertFailsWith<RequestValidationException> {
            w.holder.resolveDcApi("openid4vp-v1-multisigned", forged, "https://rp.example")
        }
    }

    @Test
    fun dcApiSignedProtocolCannotDowngradeToUnsigned() = runBlocking<Unit> {
        val w = wallet()
        val data = dcApiSession("https://rp.example", signed = false)["data"]!!.jsonObject
        assertFailsWith<RequestValidationException> {
            w.holder.resolveDcApi("openid4vp-v1-signed", data, "https://rp.example")
        }
        assertFailsWith<RequestValidationException> {
            w.holder.resolveDcApi("openid4vp-v1-multisigned", data, "https://rp.example")
        }
    }

    private fun mdocQesRequest(): JsonObject {
        val item = """{"type":"qes_authorization","credential_ids":["mdl"],"numSignatures":1}"""
        val encoded = item.encodeToByteArray().toBase64Url()
        return buildJsonObject {
            put("response_type", "vp_token")
            put("response_mode", "dc_api")
            put("nonce", "a-transaction-nonce-with-adequate-length")
            put("dcql_query", DiwJson.parseToJsonElement(
                """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","given_name"]}]}]}"""
            ))
            put("transaction_data", JsonArray(listOf(JsonPrimitive(encoded))))
        }
    }

    @Test
    fun mdocTransactionDataIsBoundToAuthorizedDeviceNamespace() = runBlocking<Unit> {
        val w = WalletFixture().init(servers.pki)
        w.issueMdl(servers.pki, listOf("qes_authorization"))
        val request = w.holder.resolveDcApi("openid4vp-v1-unsigned", mdocQesRequest(), "https://rp.example")
        val outcome = w.holder.respondDefault(w.holder.prepare(request)) as PresentationOutcome.DcApi
        val token = outcome.data["vp_token"]!!.jsonObject["mdl"]!!.jsonArray.first().jsonPrimitive.content
        val encodedResponse = org.multipaz.cbor.Cbor.decode(token.fromBase64Url())
        // Examine serialized DeviceSigned claims; DeviceResponse.documents requires a separate
        // signature verification with the exact session transcript.
        val document = org.multipaz.mdoc.response.MdocDocument.fromDataItem(
            encodedResponse["documents"].asArray.first()
        )
        val payload = document.deviceNamespaces.data["qes_authorization"]
        assertTrue(payload?.containsKey("transactionDataHash") == true)
    }

    @Test
    fun dcApiAcceptsDraft24Openid4vpProtocol() = runBlocking<Unit> {
        val w = WalletFixture().init(servers.pki)
        w.issueMdl(servers.pki, listOf("qes_authorization"))
        // OpenID4VP Draft 24 registers the DC API protocol as the plain "openid4vp"; an unsigned request must resolve.
        val request = w.holder.resolveDcApi("openid4vp", mdocQesRequest(), "https://rp.example")
        val outcome = w.holder.respondDefault(w.holder.prepare(request)) as PresentationOutcome.DcApi
        assertTrue(outcome.data["vp_token"]!!.jsonObject.containsKey("mdl"))
    }

    @Test
    fun mdocTransactionWithoutIssuerKeyAuthorizationIsRejected() = runBlocking<Unit> {
        val w = WalletFixture().init(servers.pki)
        w.issueMdl(servers.pki)
        val request = w.holder.resolveDcApi("openid4vp-v1-unsigned", mdocQesRequest(), "https://rp.example")
        assertFailsWith<diw.wallet.core.util.ProtocolException> {
            w.holder.respondDefault(w.holder.prepare(request))
        }
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

    /** A caller origin reported with a trailing slash is the same origin, also for the KB-JWT audience. */
    @Test
    fun dcApiOriginWithTrailingSlash() = runBlocking {
        val r = dcApi("https://rp.example", "https://rp.example/", signed = true)
        assertEquals("passed", r["status"]!!.jsonPrimitive.content, r.toString())
    }

    /** OpenID4VP 1.0 A.2: an origin outside expected_origins is answered with invalid_request instead of a cancelled flow. */
    @Test
    fun dcApiOriginMismatchReturnsInvalidRequest() = runBlocking {
        val data = dcApiSession("https://rp.example", signed = true)["data"]!!.jsonObject
        val e = assertFailsWith<RequestValidationException> { wallet().holder.resolveDcApi("openid4vp-v1-signed", data, "https://attacker.example") }
        assertEquals(buildJsonObject { put("error", "invalid_request") }, Oid4vpHolder.dcApiError(data, e))
        assertNull(Oid4vpHolder.dcApiError(data, IllegalStateException("not a validation failure")))
    }

    /** OpenID4VP 1.0 section 15.9.2: no error before consent for value matching, which could reveal the claim value. */
    @Test
    fun dcApiErrorWithheldForValueMatching() = runBlocking {
        val dcql = DiwJson.parseToJsonElement(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
              "claims":[{"path":["nationality"],"values":["TW"]}]}]}"""
        ).jsonObject
        val data = dcApiSession("https://rp.example", signed = true, dcql)["data"]!!.jsonObject
        val w = wallet()
        val e = assertFailsWith<RequestValidationException> { w.holder.resolveDcApi("openid4vp-v1-signed", data, "https://attacker.example") }
        assertNull(Oid4vpHolder.dcApiError(data, e))
        // Declining such a request cancels the flow instead of answering access_denied.
        assertNull(w.holder.decline(w.holder.resolveDcApi("openid4vp-v1-signed", data, "https://rp.example")))
    }

    /**
     * CSC qes-approval transaction data (as the EUDI remote signing service sends it): the KB-JWT carries the hash of
     * the encoded entry and names sha-256 explicitly, which the EUDI verifier requires although OpenID4VP 1.0 makes
     * it the default.
     */
    /**
     * A request without transaction data gets a KB-JWT without transaction claims: Multipaz writes an empty
     * transaction_data_hashes, which the walt.id verifier rejects (dc+sd-jwt/transaction-data-hash-check). The request
     * is the one walt.id's verifier serves for the Digital Credentials API (unsigned, with expected_origins).
     */
    @Test
    fun noTransactionClaimsWithoutTransactionData() = runBlocking<Unit> {
        val w = wallet()
        val data = DiwJson.parseToJsonElement(
            """{"response_type":"vp_token","response_mode":"dc_api","nonce":"waltid-nonce",
              "dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["${EUPersonalID.EUPID_VCT}"]},
                "claims":[{"path":["family_name"]}]}]},
              "client_metadata":{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]}},
                "client_name":"Verifier2"},
              "expected_origins":["https://portal2.demo.walt.id"]}"""
        ).jsonObject
        val req = w.holder.resolveDcApi("openid4vp-v1-unsigned", data, "https://portal2.demo.walt.id")
        val outcome = w.holder.respondDefault(w.holder.prepare(req)) as PresentationOutcome.DcApi
        val presentation = outcome.data["vp_token"]!!.jsonObject["pid"]!!.jsonArray[0].jsonPrimitive.content
        val kb = DiwJson.parseToJsonElement(presentation.substringAfterLast('~').split('.')[1].fromBase64Url().decodeToString()).jsonObject
        assertEquals("origin:https://portal2.demo.walt.id", kb["aud"]!!.jsonPrimitive.content)
        assertNull(kb["transaction_data_hashes"], kb.toString())
        assertNull(kb["transaction_data_hashes_alg"], kb.toString())
    }

    @Test
    fun transactionDataHashesNameTheirAlgorithm() = runBlocking<Unit> {
        val w = wallet()
        val entry = buildJsonObject {
            put("type", diw.wallet.core.oid4vp.QesApprovalTransaction.CSC_2025)
            put("credential_ids", kotlinx.serialization.json.buildJsonArray { add(kotlinx.serialization.json.JsonPrimitive("pid")) })
            put("numSignatures", 1)
        }.toString().encodeToByteArray().toBase64Url()
        val data = DiwJson.parseToJsonElement(
            """{"response_type":"vp_token","response_mode":"dc_api","nonce":"tx-nonce",
              "dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["${EUPersonalID.EUPID_VCT}"]},
                "claims":[{"path":["given_name"]}]}]},
              "transaction_data":["$entry"]}"""
        ).jsonObject
        val req = w.holder.resolveDcApi("openid4vp-v1-unsigned", data, "https://rp.example")
        val outcome = w.holder.respondDefault(w.holder.prepare(req)) as PresentationOutcome.DcApi
        val presentation = outcome.data["vp_token"]!!.jsonObject["pid"]!!.jsonArray[0].jsonPrimitive.content
        val kb = presentation.substringAfterLast('~').split('.')[1].fromBase64Url().decodeToString()
        val claims = DiwJson.parseToJsonElement(kb).jsonObject
        assertEquals("sha-256", claims["transaction_data_hashes_alg"]!!.jsonPrimitive.content)
        val expected = java.security.MessageDigest.getInstance("SHA-256").digest(entry.encodeToByteArray()).toBase64Url()
        assertEquals(listOf(expected), claims["transaction_data_hashes"]!!.jsonArray.map { it.jsonPrimitive.content })
    }

    /** EUDI TS12 payment (urn:eudi:sca:payment:1) on a Multipaz payment credential: shown to the holder and hashed into the KB-JWT. */
    @Test
    fun paymentTransactionIsDescribedAndBound() = runBlocking<Unit> {
        val w = WalletFixture().init(servers.pki)
        w.issueSdJwtPayment(servers.pki)
        val entry = """{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"transaction_data_hashes_alg":["sha-256"],
            "payload":{"transaction_id":"3AD99006-6E0D-4D07-AE75-5DAEF0FE21D9","currency":"EUR","amount":1234.5,
            "payee":{"name":"Linux Foundation","id":"01234"},"recurrence":{"frequency":"MNTH","number":12}}}"""
            .encodeToByteArray().toBase64Url()
        val lines = diw.wallet.core.oid4vp.WalletTransactionTypes.describe(entry)
        assertEquals("付款授權：向 Linux Foundation 支付 1,234.50 EUR", lines.first())
        assertTrue(lines.any { it == "定期付款：每月，共 12 次" }, lines.toString())
        val data = DiwJson.parseToJsonElement(
            """{"response_type":"vp_token","response_mode":"dc_api","nonce":"payment-nonce",
              "dcql_query":{"credentials":[{"id":"pay","format":"dc+sd-jwt","meta":{"vct_values":["org.multipaz.payment.sca.1"]},
                "claims":[{"path":["holder_name"]}]}]},
              "transaction_data":["$entry"]}"""
        ).jsonObject
        val req = w.holder.resolveDcApi("openid4vp-v1-unsigned", data, "https://rp.example")
        val outcome = w.holder.respondDefault(w.holder.prepare(req)) as PresentationOutcome.DcApi
        val presentation = outcome.data["vp_token"]!!.jsonObject["pay"]!!.jsonArray[0].jsonPrimitive.content
        val claims = DiwJson.parseToJsonElement(presentation.substringAfterLast('~').split('.')[1].fromBase64Url().decodeToString()).jsonObject
        val expected = java.security.MessageDigest.getInstance("SHA-256").digest(entry.encodeToByteArray()).toBase64Url()
        assertEquals(listOf(expected), claims["transaction_data_hashes"]!!.jsonArray.map { it.jsonPrimitive.content })
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
