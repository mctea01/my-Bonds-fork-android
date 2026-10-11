package diw.testservers

import diw.wallet.core.credential.ClaimReader
import diw.wallet.core.did.DidResolver
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vci.KeyRequest
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.oid4vp.Oid4vpHolder
import diw.wallet.core.oid4vp.PreparedExtended
import diw.wallet.core.oid4vp.compat.MsVerifiedIdPresentationDialect
import diw.wallet.core.profile.msvid.LinkedDomains
import diw.wallet.core.profile.msvid.MsVerifiedIdIssuance
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.w3c.W3cInspector
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
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Microsoft Entra Verified ID issuance (request with prompt=create, signed contract, id_token_hint with PIN,
 * self-issued claims, Linked Domains trust, callback) against a mock issuer on a did:web domain.
 */
class MsVerifiedIdTest {
    private val issuerKey = runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val issuerJwk = runBlocking { issuerKey.publicKey.toJwk() }
    private val signer = AsymmetricKey.AnonymousExplicit(issuerKey, Algorithm.ES256)
    private val callbacks = mutableListOf<JsonObject>()
    private val errors = mutableListOf<String>()
    private var linkDomain = true
    /** Card type the presentation request asks for in its Presentation Exchange 1.0 schema. */
    private var presentType = "MockEmployee"
    private val presented = mutableListOf<Map<String, String>>()

    private fun MockRequestHandleScope.json(o: JsonObject) = respond(o.toString(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))

    private suspend fun MockRequestHandleScope.handle(request: HttpRequestData): HttpResponseData {
        if (request.url.host != HOST) return respond("", HttpStatusCode.NotFound)
        return when (request.url.encodedPath) {
            "/.well-known/did.json" -> json(buildJsonObject {
                put("id", DID)
                putJsonArray("verificationMethod") {
                    addJsonObject { put("id", KID); put("type", "JsonWebKey2020"); put("controller", DID); put("publicKeyJwk", issuerJwk) }
                }
                putJsonArray("assertionMethod") { add(KID) }
                putJsonArray("service") {
                    addJsonObject {
                        put("id", "$DID#linkeddomains"); put("type", "LinkedDomains")
                        putJsonObject("serviceEndpoint") { putJsonArray("origins") { add("$ORIGIN/") } }
                    }
                }
            })
            "/.well-known/did-configuration.json" -> {
                val linkage = sign(buildJsonObject {
                    put("iss", DID); put("sub", DID); put("nbf", now())
                    putJsonObject("vc") {
                        putJsonArray("@context") { add("https://www.w3.org/2018/credentials/v1") }
                        putJsonArray("type") { add("VerifiableCredential"); add("DomainLinkageCredential") }
                        put("issuer", DID)
                        putJsonObject("credentialSubject") { put("id", DID); put("origin", ORIGIN) }
                    }
                })
                json(buildJsonObject {
                    put("@context", "https://identity.foundation/.well-known/did-configuration/v1")
                    putJsonArray("linked_dids") { if (linkDomain) add(linkage) }
                })
            }
            "/request/1" -> respond(requestJwt(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/oauth-authz-req+jwt"))
            "/request/2" -> respond(presentationJwt(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/oauth-authz-req+jwt"))
            "/present" -> {
                val form = parseQueryString(request.body.toByteArray().decodeToString())
                presented += form.names().associateWith { form[it]!! }
                respond("", HttpStatusCode.OK)
            }
            "/manifest" -> {
                if (request.headers["x-ms-sign-contract"] != "true") errors += "contract fetched without x-ms-sign-contract"
                json(buildJsonObject { put("token", contractJwt()) })
            }
            "/issue" -> issue(request)
            "/callback" -> {
                callbacks += DiwJson.parseToJsonElement(request.body.toByteArray().decodeToString()) as JsonObject
                respond("", HttpStatusCode.OK)
            }
            else -> respond("", HttpStatusCode.NotFound)
        }
    }

    private fun now() = Clock.System.now().epochSeconds

    private suspend fun sign(payload: JsonObject) =
        signJws(buildJsonObject { put("alg", "ES256"); put("typ", "JWT"); put("kid", KID) }, payload, signer)

    private suspend fun requestJwt() = sign(buildJsonObject {
        put("response_type", "id_token"); put("response_mode", "post")
        put("client_id", DID)
        put("redirect_uri", "$ORIGIN/callback")
        put("scope", "openid")
        put("nonce", "n-1"); put("state", "s-1")
        put("prompt", "create")
        put("id_token_hint", HINT)
        putJsonObject("pin") { put("length", 4); put("type", "numeric"); put("salt", SALT) }
        putJsonObject("registration") { put("client_name", "模擬人資系統") }
        putJsonObject("claims") {
            putJsonObject("vp_token") {
                putJsonObject("presentation_definition") {
                    put("id", "pd-1")
                    putJsonArray("input_descriptors") {
                        addJsonObject {
                            put("id", "MockEmployee")
                            putJsonArray("issuance") { addJsonObject { put("manifest", "$ORIGIN/manifest") } }
                        }
                    }
                }
            }
        }
        put("iat", now()); put("exp", now() + 300)
    })

    /** A presentation request as the Verified ID request service signs it (no prompt, PE 1.0 schema, form post). */
    private suspend fun presentationJwt() = sign(buildJsonObject {
        put("jti", "p-2"); put("iat", now()); put("exp", now() + 300)
        put("response_type", "id_token"); put("response_mode", "post"); put("scope", "openid")
        put("client_id", DID)
        put("redirect_uri", "$ORIGIN/present")
        put("nonce", "n-2"); put("state", "s-2")
        putJsonObject("registration") {
            put("client_name", "模擬驗證端")
            putJsonArray("subject_syntax_types_supported") { add("did:web"); add("did:jwk") }
            putJsonObject("vp_formats") {
                putJsonObject("jwt_vp") { putJsonArray("alg") { add("ES256"); add("ES256K"); add("EdDSA") } }
                putJsonObject("jwt_vc") { putJsonArray("alg") { add("ES256"); add("ES256K"); add("EdDSA") } }
            }
        }
        putJsonObject("claims") {
            putJsonObject("vp_token") {
                putJsonObject("presentation_definition") {
                    put("id", "pd-2")
                    putJsonArray("input_descriptors") {
                        addJsonObject {
                            put("id", presentType); put("name", presentType); put("purpose", "確認在職")
                            putJsonArray("schema") { addJsonObject { put("uri", presentType) } }
                        }
                    }
                }
            }
        }
    })

    private suspend fun contractJwt() = sign(buildJsonObject {
        put("id", "MockEmployee")
        putJsonObject("display") {
            putJsonObject("card") {
                put("title", "模擬員工證"); put("issuedBy", "模擬公司")
                put("backgroundColor", "#0F6CBD"); put("textColor", "#FFFFFF")
                putJsonObject("logo") { put("uri", "$ORIGIN/logo.png") }
            }
            putJsonObject("consent") { put("title", "是否加入模擬員工證？") }
            putJsonObject("claims") { putJsonObject("vc.credentialSubject.displayName") { put("label", "姓名"); put("type", "String") } }
        }
        putJsonObject("input") {
            put("credentialIssuer", "$ORIGIN/issue")
            put("issuer", DID)
            putJsonObject("attestations") {
                putJsonObject("selfIssued") { putJsonArray("claims") { addJsonObject { put("claim", "displayName"); put("required", true) } } }
                putJsonArray("idTokens") {
                    addJsonObject { put("configuration", MsVerifiedIdIssuance.ID_TOKEN_HINT_CONFIGURATION); put("required", true) }
                }
            }
        }
    })

    private suspend fun MockRequestHandleScope.issue(request: HttpRequestData): HttpResponseData {
        val jws = Jws.parse(request.body.toByteArray().decodeToString())
        val p = jws.payload
        val holderDid = p.str("did") ?: return fail("no did")
        if (!holderDid.startsWith("did:jwk:")) return fail("holder DID $holderDid")
        if (jws.kid?.substringBefore('#') != holderDid) return fail("kid ${jws.kid}")
        jws.verify(DidResolver(HttpClient(MockEngine { respond("", HttpStatusCode.NotFound) })).resolveKey(holderDid, jws.kid).key)
        if (p.str("contract") != "$ORIGIN/manifest") return fail("contract ${p.str("contract")}")
        if (p.str("aud") != "$ORIGIN/issue") return fail("aud ${p.str("aud")}")
        if (p.str("iss") != MsVerifiedIdIssuance.SELF_ISSUED_V1) return fail("iss ${p.str("iss")}")
        val att = p.obj("attestations") ?: return fail("no attestations")
        if (att.obj("idTokens")?.str(MsVerifiedIdIssuance.ID_TOKEN_HINT_CONFIGURATION) != HINT) return fail("id_token_hint not returned")
        val expectedPin = Base64.encode(PlatformCrypto.sha256((SALT + PIN).encodeToByteArray()))
        if (p.str("pin") != expectedPin) {
            return respond(buildJsonObject {
                putJsonObject("error") { put("code", "badOrMissingField"); put("message", "PIN mismatch"); putJsonObject("innererror") { put("code", "pin_mismatch") } }
            }.toString(), HttpStatusCode.BadRequest, headersOf(HttpHeaders.ContentType, "application/json"))
        }
        val name = att.obj("selfIssued")?.str("displayName") ?: return fail("no displayName")
        val vc = sign(buildJsonObject {
            put("iss", DID); put("sub", holderDid); put("nbf", now()); put("exp", now() + 86400); put("jti", "urn:pic:1")
            putJsonObject("vc") {
                putJsonArray("@context") { add("https://www.w3.org/2018/credentials/v1") }
                putJsonArray("type") { add("VerifiableCredential"); add("MockEmployee") }
                putJsonObject("credentialSubject") { put("displayName", name) }
            }
        })
        return json(buildJsonObject { put("vc", vc) })
    }

    private fun MockRequestHandleScope.fail(message: String): HttpResponseData {
        errors += message
        return respond(message, HttpStatusCode.BadRequest)
    }

    private class Wallet(val w: WalletFixture, val issuance: MsVerifiedIdIssuance)

    private fun wallet(): Wallet = runBlocking {
        val http = HttpClient(MockEngine { request -> handle(request) }) { followRedirects = false }
        val w = WalletFixture(trustVerifierRoot = false, trustIssuer = false, httpClient = http, env = EnvironmentPolicy(testEnvironmentEnabled = true)).init()
        val resolver = DidResolver(http)
        val linked = LinkedDomains(http, resolver)
        val inspector = W3cInspector(http, w.trust, false, DidTrust(listOf(linked)))
        Wallet(w, MsVerifiedIdIssuance(http, resolver, linked, inspector, w.holderIdentities, w.documentStore))
    }

    private fun keys(w: WalletFixture) = KeyRequest(
        secureArea = w.secureArea,
        createKeySettings = { SoftwareCreateKeySettings.Builder().build() },
        count = 1,
        keyStorage = "software",
    )

    private val uri = "openid-vc://?request_uri=" + "$ORIGIN/request/1".encodeURLParameter()

    @Test
    fun issuanceWithPinAndSelfIssuedClaims() = runBlocking<Unit> {
        val (w, issuance) = wallet().let { it.w to it.issuance }
        val request = assertNotNull(issuance.resolve(uri))
        assertEquals("模擬員工證", request.cardTitle)
        assertEquals("模擬人資系統", request.clientName)
        // Linked Domains proves the domain, not the organisation: T3 with the domain as the name.
        assertEquals(TrustTier.T3, request.trust.tier)
        assertEquals(HOST, request.trust.anchorName)
        assertEquals(listOf("displayName"), request.selfIssuedClaims.map { it.claim })
        assertTrue(request.tokenRequirements.single().injected)
        assertEquals(4, request.pinRequirement?.length)
        assertEquals(listOf("displayName", "pin"), request.missing())
        assertFailsWith<ProtocolException> { issuance.complete(request, keys(w)) }

        request.selfIssued["displayName"] = "林哲全"
        request.pin = "0000"
        val wrong = assertFailsWith<ProtocolException> { issuance.complete(request, keys(w)) }
        assertEquals("pin_mismatch", wrong.code)
        assertEquals("issuance_failed", callbacks.last().str("code"))

        request.pin = PIN
        val doc = issuance.complete(request, keys(w))
        assertTrue(errors.isEmpty(), "mock errors: $errors")
        assertEquals("issuance_successful", callbacks.last().str("code"))
        assertEquals("s-1", callbacks.last().str("state"))
        val record = doc.issuanceRecord!!
        assertEquals("msvid", record.profile)
        assertEquals("$ORIGIN/logo.png", record.logoUri)
        assertEquals("#0F6CBD", record.backgroundColor)
        assertEquals(listOf(MsVerifiedIdIssuance.SPEC), record.specs)
        val holder = assertNotNull(w.holderIdentities.find(HolderIdentities.MS_VERIFIED_ID))
        assertEquals(holder.did, record.holderDid)
        val cred = doc.getCertifiedCredentials().single() as W3cVcCredential
        val claims = ClaimReader.read(cred, w.documentTypes).associate { it.label to it.value }
        assertEquals("林哲全", claims["displayName"])
    }

    /**
     * Presentation as Verified ID verifiers ask for it: openid-vc:// with request_uri only (client_id is in the signed
     * request), the card type in a Presentation Exchange 1.0 schema, and a form post of id_token, vp_token and state.
     */
    @Test
    fun presentationWithRequestUriOnly() = runBlocking<Unit> {
        val wallet = wallet()
        val w = wallet.w
        val issue = assertNotNull(wallet.issuance.resolve(uri))
        issue.selfIssued["displayName"] = "林哲全"
        issue.pin = PIN
        wallet.issuance.complete(issue, keys(w))
        val holder = Oid4vpHolder(
            w.httpClient, w.trust, w.source, w.env, holderIdentities = w.holderIdentities,
            didTrust = DidTrust(listOf(LinkedDomains(w.httpClient, DidResolver(w.httpClient)))),
            dialects = listOf(MsVerifiedIdPresentationDialect()),
        )
        val presentUri = "openid-vc://?request_uri=" + "$ORIGIN/request/2".encodeURLParameter()
        val request = holder.resolveUri(presentUri, MsVerifiedIdPresentationDialect.ENTRY_HINT)
        assertEquals(DID, request.verifier.did)
        assertEquals(TrustTier.T3, request.verifier.trust.tier)
        val prepared = assertIs<PreparedExtended>(holder.prepare(request))
        assertEquals(1, prepared.prepared.lines.size)
        holder.respond(prepared)
        assertTrue(errors.isEmpty(), "mock errors: $errors")
        val post = presented.single()
        assertEquals("s-2", post["state"])
        val idToken = Jws.parse(assertNotNull(post["id_token"])).payload
        assertEquals(MsVerifiedIdPresentationDialect.SELF_ISSUED, idToken.str("iss"))
        assertEquals("n-2", idToken.str("nonce"))
        assertEquals(DID, idToken.str("aud"))
        val vp = Jws.parse(assertNotNull(post["vp_token"])).payload
        assertEquals("n-2", vp.str("nonce"))
        // Resolved as the Verified ID service does (wallet library PresentationResponseFormatter): jwt_vp at "$",
        // then jwt_vc at "$.verifiableCredential[i]" inside the vp claim. A real verifier answered 401 "The
        // presentation does not include any verifiable credentials" to the $.vp.verifiableCredential[i] path.
        val submission = assertNotNull(idToken.obj("_vp_token")?.obj("presentation_submission"))
        assertNull(post["presentation_submission"])
        val descriptor = submission.arr("descriptor_map")!!.single() as JsonObject
        assertEquals(presentType, descriptor.str("id"))
        assertEquals("jwt_vp", descriptor.str("format"))
        assertEquals("\$", descriptor.str("path"))
        val nested = assertNotNull(descriptor.obj("path_nested"))
        assertEquals("jwt_vc", nested.str("format"))
        val index = assertNotNull(Regex("""^\$\.verifiableCredential\[(\d+)]$""").find(nested.str("path")!!), "path: ${nested.str("path")}").groupValues[1].toInt()
        val vc = Jws.parse((vp.obj("vp")!!.arr("verifiableCredential")!![index] as JsonPrimitive).content).payload
        assertEquals(DID, vc.str("iss"))
        assertEquals(vp.str("iss"), vc.str("sub"), "the card is bound to the DID that signs the presentation")
        assertEquals(vp.str("iss"), idToken.str("sub"))

        // The schema names the card type: a request for another type finds nothing to present.
        presentType = "OtherCard"
        val other = holder.resolveUri(presentUri, MsVerifiedIdPresentationDialect.ENTRY_HINT)
        val none = assertFailsWith<ProtocolException> { holder.prepare(other) }
        assertEquals("access_denied", none.code)
    }

    @Test
    fun brokenDomainLinkIsT4() = runBlocking<Unit> {
        linkDomain = false
        val issuance = wallet().issuance
        val request = assertNotNull(issuance.resolve(uri))
        assertEquals(TrustTier.T4, request.trust.tier)
    }

    companion object {
        const val HOST = "verifiedid.mock.example"
        const val ORIGIN = "https://$HOST"
        const val DID = "did:web:$HOST"
        const val KID = "$DID#key1"
        const val HINT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJlbXBsb3llZSJ9."
        const val SALT = "s4lt"
        const val PIN = "4826"
    }
}
