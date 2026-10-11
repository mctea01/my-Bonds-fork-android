package diw.testservers

import diw.wallet.core.compat.Draft11Dialect
import diw.wallet.core.compat.Draft13Dialect
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.KeyRequest
import diw.wallet.core.oid4vci.Oid4vciClient
import diw.wallet.core.oid4vci.PublicClientWalletProvider
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import diw.wallet.core.w3c.W3cVcCredential
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.encodeURLParameter
import io.ktor.http.headersOf
import io.ktor.http.parseQueryString
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKey
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Issuers still on OpenID4VCI draft 11/12 (credentials_supported, user_pin, token_endpoint in issuer metadata,
 * format + types requests) and draft 13 (c_nonce in the token response, no nonce endpoint, format based request
 * with a single proof), served by a MockEngine, issuing W3C jwt_vc_json credentials signed by a did:jwk issuer.
 */
class DraftIssuersTest {
    private enum class Draft { D11, D13 }

    private val issuerKey = runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val issuerDid = runBlocking { DidKeys.didJwk(issuerKey.publicKey) }
    private val errors = mutableListOf<String>()
    private var nonce = "n-0"
    private lateinit var draft: Draft

    private fun MockRequestHandleScope.json(o: JsonObject, status: HttpStatusCode = HttpStatusCode.OK) =
        respond(o.toString(), status, headersOf(HttpHeaders.ContentType, "application/json"))

    private fun MockRequestHandleScope.fail(message: String): HttpResponseData {
        errors += message
        return json(buildJsonObject { put("error", "invalid_request"); put("error_description", message) }, HttpStatusCode.BadRequest)
    }

    private suspend fun MockRequestHandleScope.handle(request: HttpRequestData): HttpResponseData {
        if (request.url.host != HOST) return respond("", HttpStatusCode.NotFound)
        val body = request.body.toByteArray().decodeToString()
        return when (request.url.encodedPath) {
            "/.well-known/openid-credential-issuer" -> json(if (draft == Draft.D11) metadata11() else metadata13())
            "/.well-known/oauth-authorization-server" ->
                if (draft == Draft.D13) json(buildJsonObject {
                    put("issuer", ISSUER); put("token_endpoint", "$ISSUER/token")
                    put("pre-authorized_grant_anonymous_access_supported", true)
                }) else respond("", HttpStatusCode.NotFound)
            "/token" -> {
                val form = parseQueryString(body)
                if (form["pre-authorized_code"] != "code-1") return fail("pre-authorized_code ${form["pre-authorized_code"]}")
                if (draft == Draft.D11 && form["user_pin"] != "1234") return fail("user_pin ${form["user_pin"]}")
                nonce = "n-" + Clock.System.now().toEpochMilliseconds()
                json(buildJsonObject {
                    put("access_token", "at-1"); put("token_type", "bearer"); put("expires_in", 300)
                    put("c_nonce", nonce); put("c_nonce_expires_in", 300)
                })
            }
            "/credential" -> credential(request, DiwJson.parseToJsonElement(body) as JsonObject)
            else -> respond("", HttpStatusCode.NotFound)
        }
    }

    private fun metadata11() = buildJsonObject {
        put("credential_issuer", ISSUER)
        put("credential_endpoint", "$ISSUER/credential")
        put("token_endpoint", "$ISSUER/token")
        putJsonArray("credentials_supported") {
            addJsonObject {
                put("format", "jwt_vc_json")
                putJsonArray("types") { add("VerifiableCredential"); add("UniversityDegree") }
                putJsonArray("cryptographic_binding_methods_supported") { add("did:jwk") }
                putJsonArray("cryptographic_suites_supported") { add("ES256") }
                putJsonArray("display") { addJsonObject { put("name", "模擬學位證書"); put("locale", "zh-TW") } }
                putJsonObject("credentialSubject") { putJsonObject("degree") { putJsonArray("display") { addJsonObject { put("name", "學位") } } } }
            }
        }
    }

    private fun metadata13() = buildJsonObject {
        put("credential_issuer", ISSUER)
        put("credential_endpoint", "$ISSUER/credential")
        putJsonObject("credential_configurations_supported") {
            putJsonObject("UniversityDegree_jwt") {
                put("format", "jwt_vc_json")
                putJsonArray("cryptographic_binding_methods_supported") { add("did:jwk") }
                putJsonArray("credential_signing_alg_values_supported") { add("ES256") }
                putJsonObject("proof_types_supported") { putJsonObject("jwt") { putJsonArray("proof_signing_alg_values_supported") { add("ES256") } } }
                putJsonObject("credential_definition") { putJsonArray("type") { add("VerifiableCredential"); add("UniversityDegree") } }
                putJsonArray("display") { addJsonObject { put("name", "模擬學位證書"); put("locale", "zh-TW") } }
            }
        }
    }

    private suspend fun MockRequestHandleScope.credential(request: HttpRequestData, body: JsonObject): HttpResponseData {
        if (request.headers[HttpHeaders.Authorization]?.substringAfter(' ') != "at-1") return fail("access token")
        // A draft 13 issuer rejects the 1.0 request shape; the wallet retries with the draft shape.
        if (body["proofs"] != null || body["credential_configuration_id"] != null) {
            return json(buildJsonObject { put("error", "invalid_credential_request") }, HttpStatusCode.BadRequest)
        }
        if (body.str("format") != "jwt_vc_json") return fail("format ${body.str("format")}")
        val types = if (draft == Draft.D11) body.strList("types") else body.obj("credential_definition")?.strList("type").orEmpty()
        if ("UniversityDegree" !in types) return fail("types $types")
        val proof = body.obj("proof") ?: return fail("no single proof")
        if (proof.str("proof_type") != "jwt") return fail("proof_type ${proof.str("proof_type")}")
        val jws = Jws.parse(proof.str("jwt") ?: return fail("no proof jwt"))
        if (jws.payload.str("nonce") != nonce) return fail("nonce ${jws.payload.str("nonce")}")
        if (jws.payload.str("aud") != ISSUER) return fail("aud ${jws.payload.str("aud")}")
        val kid = jws.kid
        val holderDid: String?
        val holderKey: EcPublicKey
        if (kid != null && kid.startsWith("did:")) {
            holderDid = kid.substringBefore('#')
            holderKey = (DidResolver(HttpClient(MockEngine { respond("", HttpStatusCode.NotFound) })).resolveKey(holderDid, kid).key as VerificationKey.Ec).key
        } else {
            holderDid = null
            holderKey = EcPublicKey.fromJwk(jws.header.obj("jwk") ?: return fail("proof without kid or jwk"))
        }
        jws.verify(VerificationKey.Ec(holderKey))
        val holderJwk = holderKey.toJwk()
        val now = Clock.System.now().epochSeconds
        val vc = signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "JWT"); put("kid", "$issuerDid#0") },
            buildJsonObject {
                put("iss", issuerDid); put("nbf", now); put("exp", now + 86400); put("jti", "urn:uuid:degree-1")
                holderDid?.let { put("sub", it) } ?: putJsonObject("cnf") { put("jwk", holderJwk) }
                putJsonObject("vc") {
                    putJsonArray("@context") { add("https://www.w3.org/2018/credentials/v1") }
                    putJsonArray("type") { add("VerifiableCredential"); add("UniversityDegree") }
                    put("issuer", issuerDid)
                    putJsonObject("credentialSubject") { holderDid?.let { put("id", it) }; put("degree", "資訊工程學士") }
                }
            },
            AsymmetricKey.AnonymousExplicit(issuerKey, Algorithm.ES256),
        )
        return json(buildJsonObject { put("format", "jwt_vc_json"); put("credential", vc); put("c_nonce", "n-next") })
    }

    private suspend fun issue(d: Draft, offer: JsonObject, configurationId: String, txCode: String?): IssuanceResult.Issued {
        draft = d
        val http = HttpClient(MockEngine { request -> handle(request) }) { followRedirects = false }
        val w = WalletFixture(trustVerifierRoot = false, trustIssuer = false, httpClient = http, env = EnvironmentPolicy(testEnvironmentEnabled = true)).init()
        val client = Oid4vciClient(
            http, w.trust, w.env, PublicClientWalletProvider("diw-wallet"), w.documentStore,
            dialects = listOf(TwdiwDialect(http, false), Draft13Dialect(http, false), Draft11Dialect()),
            holderIdentities = w.holderIdentities,
        )
        val session = client.startFromOffer("openid-credential-offer://?credential_offer=" + offer.toString().encodeURLParameter())
        assertEquals(configurationId, session.selectedConfigurations.single().id)
        client.authorizePreAuthorized(session, txCode)
        val keys = KeyRequest(w.secureArea, { SoftwareCreateKeySettings.Builder().build() }, count = 1, keyStorage = "software")
        val r = client.issue(session, configurationId, keys) as IssuanceResult.Issued
        assertTrue(errors.isEmpty(), "mock errors: $errors")
        return r
    }

    @Test
    fun draft11ByValueOfferWithUserPin() = runBlocking<Unit> {
        val offer = buildJsonObject {
            put("credential_issuer", ISSUER)
            putJsonArray("credentials") {
                addJsonObject { put("format", "jwt_vc_json"); putJsonArray("types") { add("VerifiableCredential"); add("UniversityDegree") } }
            }
            putJsonObject("grants") {
                putJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code") { put("pre-authorized_code", "code-1"); put("user_pin_required", true) }
            }
        }
        val r = issue(Draft.D11, offer, "jwt_vc_json:UniversityDegree", "1234")
        val cred = r.credentials.single() as W3cVcCredential
        assertEquals("資訊工程學士", (cred.credentialJson().obj("credentialSubject")?.get("degree") as JsonPrimitive).content)
        assertTrue("OpenID4VCI draft 11/12" in r.document.issuanceRecord!!.specs, "specs: ${r.document.issuanceRecord!!.specs}")
    }

    @Test
    fun draft13FormatRequestAfterRejection() = runBlocking<Unit> {
        val offer = buildJsonObject {
            put("credential_issuer", ISSUER)
            putJsonArray("credential_configuration_ids") { add("UniversityDegree_jwt") }
            putJsonObject("grants") {
                putJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code") { put("pre-authorized_code", "code-1") }
            }
        }
        val r = issue(Draft.D13, offer, "UniversityDegree_jwt", null)
        val cred = r.credentials.single() as W3cVcCredential
        assertTrue(cred.holderDid?.startsWith("did:jwk:") == true, "holder ${cred.holderDid}")
        assertTrue("OpenID4VCI draft 13" in r.document.issuanceRecord!!.specs, "specs: ${r.document.issuanceRecord!!.specs}")
    }

    companion object {
        const val HOST = "draft.mock.example"
        const val ISSUER = "https://$HOST"
    }
}
