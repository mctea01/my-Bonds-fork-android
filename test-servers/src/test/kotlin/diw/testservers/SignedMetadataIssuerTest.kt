package diw.testservers

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
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
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
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import kotlin.test.Test
import diw.wallet.core.compat.Draft11Dialect
import diw.wallet.core.compat.Draft13Dialect
import diw.wallet.core.compat.EudiDialect
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.oid4vci.issuanceRecord
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * An OpenID4VCI 1.0 issuer shaped like walt.id issuer2: issuer metadata is served as a JWT signed with a key in its
 * own header (jwk, no x5c), and a jwt_vc_json configuration lists jwk next to DID methods but takes the subject DID
 * from the proof kid, so a proof carrying only a jwk is rejected.
 */
class SignedMetadataIssuerTest {
    private val issuerKey = runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val issuerDid = runBlocking { DidKeys.didJwk(issuerKey.publicKey) }
    private val signer = AsymmetricKey.AnonymousExplicit(issuerKey, Algorithm.ES256)
    private val errors = mutableListOf<String>()
    private var nonce = "n-0"

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
            "/.well-known/openid-credential-issuer" ->
                if (request.headers[HttpHeaders.Accept].orEmpty().contains("application/jwt")) {
                    respond(signedMetadata(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/jwt"))
                } else json(metadata())
            "/.well-known/oauth-authorization-server" -> json(buildJsonObject {
                put("issuer", ISSUER); put("token_endpoint", "$ISSUER/token")
                putJsonArray("grant_types_supported") { add("urn:ietf:params:oauth:grant-type:pre-authorized_code") }
                put("pre-authorized_grant_anonymous_access_supported", true)
            })
            "/token" -> {
                if (parseQueryString(body)["pre-authorized_code"] != "code-1") return fail("pre-authorized_code")
                json(buildJsonObject { put("access_token", "at-1"); put("token_type", "Bearer"); put("expires_in", 300) })
            }
            "/nonce" -> {
                nonce = "n-" + Clock.System.now().toEpochMilliseconds()
                json(buildJsonObject { put("c_nonce", nonce) })
            }
            "/credential" -> credential(request, DiwJson.parseToJsonElement(body) as JsonObject)
            else -> respond("", HttpStatusCode.NotFound)
        }
    }

    private fun metadata() = buildJsonObject {
        put("credential_issuer", ISSUER)
        put("credential_endpoint", "$ISSUER/credential")
        put("nonce_endpoint", "$ISSUER/nonce")
        putJsonObject("credential_configurations_supported") {
            putJsonObject("OpenBadgeCredential_jwt_vc_json") {
                put("format", "jwt_vc_json")
                putJsonArray("cryptographic_binding_methods_supported") { add("jwk"); add("did:key"); add("did:web"); add("did:jwk") }
                putJsonArray("credential_signing_alg_values_supported") { add("ES256") }
                putJsonObject("proof_types_supported") { putJsonObject("jwt") { putJsonArray("proof_signing_alg_values_supported") { add("ES256") } } }
                putJsonObject("credential_definition") { putJsonArray("type") { add("VerifiableCredential"); add("OpenBadgeCredential") } }
                putJsonObject("credential_metadata") { putJsonArray("display") { addJsonObject { put("name", "Open Badge"); put("locale", "en") } } }
            }
        }
    }

    private suspend fun signedMetadata(): String {
        val now = Clock.System.now().epochSeconds
        return signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "openidvci-issuer-metadata+jwt"); put("kid", "k-1"); put("jwk", issuerKey.publicKey.toJwk()) },
            JsonObject(metadata() + buildJsonObject { put("iss", ISSUER); put("sub", ISSUER); put("iat", now) }),
            signer,
        )
    }

    private suspend fun MockRequestHandleScope.credential(request: HttpRequestData, body: JsonObject): HttpResponseData {
        if (request.headers[HttpHeaders.Authorization]?.substringAfter(' ') != "at-1") return fail("access token")
        if (body.str("credential_configuration_id") != "OpenBadgeCredential_jwt_vc_json") return fail("configuration ${body.str("credential_configuration_id")}")
        val jwt = (body.obj("proofs")?.arr("jwt")?.firstOrNull() as? JsonPrimitive)?.content ?: return fail("no jwt proof")
        val jws = Jws.parse(jwt)
        if (jws.payload.str("nonce") != nonce) return fail("nonce")
        val kid = jws.kid?.takeIf { it.startsWith("did:") } ?: return fail("Cannot find in context: subjectDid")
        val holderDid = kid.substringBefore('#')
        jws.verify(DidResolver(HttpClient(MockEngine { respond("", HttpStatusCode.NotFound) })).resolveKey(holderDid, kid).key as VerificationKey)
        val now = Clock.System.now().epochSeconds
        val vc = signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "JWT"); put("kid", "$issuerDid#0") },
            buildJsonObject {
                put("iss", issuerDid); put("sub", holderDid); put("nbf", now); put("exp", now + 86400); put("jti", "urn:uuid:badge-1")
                putJsonObject("vc") {
                    putJsonArray("@context") { add("https://www.w3.org/2018/credentials/v1") }
                    putJsonArray("type") { add("VerifiableCredential"); add("OpenBadgeCredential") }
                    put("issuer", issuerDid)
                    putJsonObject("credentialSubject") { put("id", holderDid); put("achievement", "Wallet interop") }
                }
            },
            signer,
        )
        return json(buildJsonObject { putJsonArray("credentials") { addJsonObject { put("credential", vc) } } })
    }

    @Test
    fun jwkSignedMetadataAndDidKidProof() = runBlocking<Unit> {
        val http = HttpClient(MockEngine { request -> handle(request) }) { followRedirects = false }
        val w = WalletFixture(trustVerifierRoot = false, trustIssuer = false, httpClient = http, env = EnvironmentPolicy()).init()
        // Every dialect the app runs is present: none of them may label this walt.id-style session.
        val client = Oid4vciClient(
            http, w.trust, w.env, PublicClientWalletProvider("diw-wallet"), w.documentStore,
            dialects = listOf(TwdiwDialect(http, false), Draft13Dialect(http, false), Draft11Dialect(), EudiDialect()),
        )
        val offer = buildJsonObject {
            put("credential_issuer", ISSUER)
            putJsonArray("credential_configuration_ids") { add("OpenBadgeCredential_jwt_vc_json") }
            putJsonObject("grants") {
                putJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code") { put("pre-authorized_code", "code-1") }
            }
        }
        val session = client.startFromOffer("openid-credential-offer://?credential_offer=" + offer.toString().encodeURLParameter())
        // The header key proves nothing about who the issuer is, so the metadata counts as self-asserted.
        assertTrue(TrustLabel.UNSIGNED_METADATA in session.issuer.trust.labels)
        client.authorizePreAuthorized(session, null)
        val keys = KeyRequest(w.secureArea, { SoftwareCreateKeySettings.Builder().build() }, count = 1, keyStorage = "software")
        val r = client.issue(session, "OpenBadgeCredential_jwt_vc_json", keys) as IssuanceResult.Issued
        assertTrue(errors.isEmpty(), "mock errors: $errors")
        val cred = r.credentials.single() as W3cVcCredential
        assertTrue(cred.holderDid?.startsWith("did:jwk:") == true, "holder ${cred.holderDid}")
        assertEquals("Wallet interop", (cred.credentialJson().obj("credentialSubject")?.get("achievement") as JsonPrimitive).content)
        val record = r.document.issuanceRecord!!
        assertEquals(emptyList(), record.specs, "specs ${record.specs}")
        assertEquals(null, record.profile)
    }

    companion object {
        const val HOST = "walt.mock.example"
        const val ISSUER = "https://$HOST"
    }
}
