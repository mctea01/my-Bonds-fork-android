package diw.testservers

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.decodeURLPart
import io.ktor.http.encodeURLParameter
import io.ktor.http.headersOf
import io.ktor.http.parseQueryString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64
import org.multipaz.util.toBase64Url
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream
import javax.imageio.ImageIO
import kotlin.time.Clock

/**
 * The TWDIW platform as the official issuer, verifier and frontend behave (see research/twdiw.md), served over
 * https *.wallet.gov.tw hosts through a ktor MockEngine so that the wallet's https-only TWDIW gates apply unchanged.
 *
 * - frontend: trust list (/api/did), card and offline service catalogues;
 * - issuer: metadata appended to the credential_issuer, no AS metadata, token at {issuer}token with client_id
 *   moda_dw and tx_code, c_nonce in the token response, proof kid = bare did:key (jwk_jcs), {credential} response,
 *   jwt_vc_json announced but an SD-JWT delivered (typ vc+sd-jwt, iss did:key, jku, two StatusList2021 entries);
 * - status lists wrapped as {statusList: jwt};
 * - verifier: signed request objects from a bare did:key client, Presentation Exchange with vc+sd-jwt descriptors,
 *   direct_post answered with code 0, custom_data, and the DWVP-05 offline barcode.
 */
class TwdiwPlatformMock private constructor(
    private val issuerKey: EcPrivateKey,
    val issuerDid: String,
    private val verifierKey: EcPrivateKey,
    val verifierDid: String,
) {
    /** One accepted presentation as the verifier saw it. */
    class Received(
        val requestId: String,
        val vpPayload: JsonObject,
        val submission: JsonObject,
        val disclosedNames: List<String>,
        val customData: List<JsonObject>,
        /** Payload of the presented card (issuer-signed part). */
        val card: JsonObject? = null,
    )

    private class PendingRequest(val id: String, val definitionId: String, val nonce: String, val fields: List<String>)

    val revocation = BooleanArray(STATUS_BITS)
    val suspension = BooleanArray(STATUS_BITS)
    val received = mutableListOf<Received>()
    val userAgents = mutableListOf<Pair<String, String?>>()
    val errors = mutableListOf<String>()
    var issuedIndex = 6
        private set
    var lastTransactionCompleted = false
        private set

    /**
     * Metadata names the issuer without the trailing slash the offer has, as the live telecom card issuer
     * (97179430.wallet.gov.tw) does; token, credential and proof aud keep the offer's form.
     */
    var metadataIssuerWithoutSlash = false

    /**
     * Request object kid; null uses the did:key verification method id. Verifiers set up on the live platform
     * sign with "<did>#0", the did:jwk convention.
     */
    var requestKid: String? = null

    private val pending = mutableMapOf<String, PendingRequest>()
    private var accessToken: String? = null
    private var cNonce: String? = null
    private val transactions = mutableMapOf<String, String>()
    private val dids = DidResolver(HttpClient(MockEngine { respond("", HttpStatusCode.NotFound) }))

    val engine = MockEngine { request -> handle(request) }

    fun offerDeepLink(): String {
        val offer = buildJsonObject {
            put("credential_issuer", ISSUER)
            putJsonArray("credential_configuration_ids") { add(CONFIG_ID) }
            putJsonObject("grants") {
                putJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code") { put("pre-authorized_code", PRE_AUTH_CODE) }
            }
        }
        // The official deep link has a CR/LF after the '?'.
        return "modadigitalwallet://credential_offer?\r\ncredential_offer=" + offer.toString().encodeURLParameter()
    }

    /** An online presentation request (the verifier's QR) asking for [fields] of the card. */
    fun presentationDeepLink(fields: List<String> = listOf("name")): String {
        val id = "online-" + (pending.size + 1)
        pending[id] = PendingRequest(id, VP_UID_ONLINE, "nonce-$id", fields)
        return deepLink(id)
    }

    /** The same request as a plain openid4vp:// link (Bonds and other wallets scan these). */
    fun presentationUri(fields: List<String> = listOf("name")): String {
        val id = "online-" + (pending.size + 1)
        pending[id] = PendingRequest(id, VP_UID_ONLINE, "nonce-$id", fields)
        return "openid4vp://?client_id=${verifierDid.encodeURLParameter()}&request_uri=${"$VERIFIER/api/oidvp/request/$id".encodeURLParameter()}"
    }

    /** A Bonds self-issued card request (vc+moica descriptor for a NationalIDCredential) as a plain openid4vp:// link. */
    fun moicaPresentationUri(fields: List<String>): String {
        val id = "moica-" + (pending.size + 1)
        pending[id] = PendingRequest(id, VP_UID_MOICA, "nonce-$id", fields)
        return "openid4vp://?client_id=${verifierDid.encodeURLParameter()}&request_uri=${"$VERIFIER/api/oidvp/request/$id".encodeURLParameter()}"
    }

    private fun deepLink(id: String) =
        "modadigitalwallet://authorize?\r\nclient_id=${verifierDid.encodeURLParameter()}&request_uri=${"$VERIFIER/api/oidvp/request/$id".encodeURLParameter()}"

    private suspend fun MockRequestHandleScope.handle(request: HttpRequestData): HttpResponseData {
        val host = request.url.host
        userAgents += host to request.headers[HttpHeaders.UserAgent]
        return try {
            when (host) {
                FRONTEND_HOST -> frontend(request)
                ISSUER_HOST -> issuer(request)
                VERIFIER_HOST -> verifier(request)
                // A status key set moved off the platform (statusJkuHost), for the TLS-only jku path.
                statusJkuHost -> if (request.url.encodedPath == "/api/keys") json(keySet()) else notFound()
                else -> notFound()
            }
        } catch (e: MockFailure) {
            errors += e.message!!
            respond(e.message!!, HttpStatusCode.BadRequest)
        }
    }

    private class MockFailure(message: String) : Exception(message)

    private fun fail(message: String): Nothing = throw MockFailure(message)

    private fun expect(condition: Boolean, message: () -> String) {
        if (!condition) fail(message())
    }

    private fun MockRequestHandleScope.json(o: JsonObject, status: HttpStatusCode = HttpStatusCode.OK) =
        respond(o.toString(), status, headersOf(HttpHeaders.ContentType, "application/json"))

    private fun MockRequestHandleScope.notFound() = respond("not found", HttpStatusCode.NotFound)

    private suspend fun bodyText(request: HttpRequestData) = request.body.toByteArray().decodeToString()

    // ------------------------------------------------------------------ frontend

    private suspend fun MockRequestHandleScope.frontend(request: HttpRequestData): HttpResponseData {
        val path = request.url.encodedPath
        val q = request.url.parameters
        return when {
            path == "/api/did" -> {
                val list = if (q["page"] == "0") when (q["orgType"]) {
                    "1" -> listOf(issuerOrg())
                    "2" -> listOf(verifierOrg())
                    else -> emptyList()
                } else emptyList()
                json(buildJsonObject { put("code", "0"); putJsonObject("data") { put("dids", JsonArray(list)) } })
            }
            path.startsWith("/api/did/") -> {
                val did = path.removePrefix("/api/did/").decodeURLPart()
                val entry = when (did) {
                    issuerDid -> issuerOrg()
                    verifierDid -> verifierOrg()
                    else -> return json(buildJsonObject { put("code", "404"); put("message", "not found") })
                }
                json(buildJsonObject { put("code", "0"); put("data", JsonObject(entry + ("status" to JsonPrimitive(1)))) })
            }
            path == "/api/moda/dwapp/offline/vpList" -> json(buildJsonObject {
                put("code", "0")
                putJsonObject("data") {
                    putJsonArray("vpItems") {
                        addJsonObject {
                            put("vpUid", VP_UID_PICKUP); put("name", "模擬超商取貨"); put("verifierModuleUrl", VERIFIER)
                        }
                    }
                }
            })
            path == "/api/moda/dwapp/apply/vcList" -> json(buildJsonObject {
                put("code", "0")
                putJsonObject("data") {
                    putJsonArray("vcItems") {
                        addJsonObject {
                            put("vcUid", CONFIG_ID); put("name", "模擬會員卡"); put("type", 2); put("issuerServiceUrl", "$ISSUER_ORIGIN/apply")
                            put("logoUrl", LOGO_URL)
                        }
                    }
                }
            })
            else -> notFound()
        }
    }

    private suspend fun org(key: EcPrivateKey, did: String, name: String, orgType: Int, base: String): JsonObject {
        val jwk = key.publicKey.toJwk()
        val document = signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "JWT"); put("kid", DidKeys.verificationMethod(did)) },
            buildJsonObject {
                put("id", did)
                putJsonArray("verificationMethod") {
                    addJsonObject { put("id", DidKeys.verificationMethod(did)); put("type", "JsonWebKey2020"); put("controller", did); put("publicKeyJwk", jwk) }
                }
            },
            AsymmetricKey.AnonymousExplicit(key, Algorithm.ES256),
        )
        return buildJsonObject {
            put("id", did)
            put("did", document)
            put("orgType", orgType)
            putJsonObject("org") {
                put("name", name); put("name_en", "Mock $orgType"); put("taxId", "0000000$orgType")
                put("issuerMetadataBaseURL", base); put("serviceBaseURL", base)
            }
            putJsonArray("onChainHistory") {}
        }
    }

    private suspend fun issuerOrg() = org(issuerKey, issuerDid, "模擬發證機關", 1, ISSUER_ORIGIN)

    private suspend fun verifierOrg() = org(verifierKey, verifierDid, "模擬驗證機關", 2, VERIFIER)

    // ------------------------------------------------------------------ issuer

    private suspend fun MockRequestHandleScope.issuer(request: HttpRequestData): HttpResponseData {
        val url = request.url.toString().substringBefore('?')
        return when {
            url == ISSUER + ".well-known/openid-credential-issuer" -> json(metadata())
            url == ISSUER + "token" && request.method == HttpMethod.Post -> token(request)
            url == ISSUER + "credential" && request.method == HttpMethod.Post -> credential(request)
            url == ISSUER + "nonce" && request.method == HttpMethod.Post && nonceEndpointPublished -> {
                endpointNonces++
                json(buildJsonObject { put("c_nonce", "endpoint-nonce-$endpointNonces") })
            }
            url == "$ISSUER_ORIGIN/api/keys" -> json(keySet())
            // Like the platform, card faces and catalog logos come back as a data URI in a text/plain body.
            url == COVER_URL || url == LOGO_URL -> respond("data:image/png;base64," + png().toBase64(), HttpStatusCode.OK,
                headersOf(HttpHeaders.ContentType, "text/plain;charset=UTF-8"))
            url.startsWith("$ISSUER_ORIGIN/api/status-list/$CONFIG_ID/") -> {
                val group = url.substringAfterLast('/')
                val purpose = when {
                    group.startsWith("r") -> "revocation"
                    group.startsWith("s") -> "suspension"
                    else -> return notFound()
                }
                json(buildJsonObject { put("statusList", statusList(purpose, url)) })
            }
            else -> notFound()
        }
    }

    private fun metadata() = buildJsonObject {
        put("credential_issuer", if (metadataIssuerWithoutSlash) ISSUER.trimEnd('/') else ISSUER)
        put("credential_endpoint", ISSUER + "credential")
        if (nonceEndpointPublished) put("nonce_endpoint", ISSUER + "nonce")
        putJsonArray("display") { addJsonObject { put("name", "模擬發證機關"); put("locale", "zh-TW") } }
        putJsonObject("credential_configurations_supported") {
            putJsonObject(CONFIG_ID) {
                put("format", "jwt_vc_json")
                put("scope", CONFIG_ID)
                putJsonArray("cryptographic_binding_methods_supported") { add("did:key") }
                putJsonArray("credential_signing_alg_values_supported") { add("ES256") }
                putJsonObject("proof_types_supported") {
                    putJsonObject("jwt") { putJsonArray("proof_signing_alg_values_supported") { add("ES256") } }
                }
                putJsonObject("credential_definition") {
                    putJsonArray("type") { add("VerifiableCredential"); add(CONFIG_ID) }
                    putJsonObject("credentialSubject") {
                        for ((k, label) in listOf("name" to "姓名", "birthDate" to "出生日期", "cardNumber" to "卡號")) {
                            putJsonObject(k) { putJsonArray("display") { addJsonObject { put("name", label); put("locale", "zh-TW") } } }
                        }
                    }
                }
                putJsonArray("display") {
                    addJsonObject {
                        put("name", "模擬會員卡"); put("locale", "zh-TW")
                        putJsonObject("logo") { put("uri", "$ISSUER_ORIGIN/logo.png") }
                        put("background_color", "#1A4C8B"); put("text_color", "#FFFFFF")
                        putJsonObject("background_image") { put("uri", if (cardFaceInMetadata) COVER_URL else "") }
                    }
                }
            }
        }
    }

    private suspend fun MockRequestHandleScope.token(request: HttpRequestData): HttpResponseData {
        val form = parseQueryString(bodyText(request))
        expect(form["grant_type"] == "urn:ietf:params:oauth:grant-type:pre-authorized_code") { "grant_type ${form["grant_type"]}" }
        expect(form["pre-authorized_code"] == PRE_AUTH_CODE) { "pre-authorized_code ${form["pre-authorized_code"]}" }
        expect(form["client_id"] == CLIENT_ID) { "client_id ${form["client_id"]}" }
        expect(form.contains("tx_code")) { "tx_code missing" }
        val details = form["authorization_details"]?.let { DiwJson.parseToJsonElement(it) as? JsonArray } ?: fail("authorization_details missing")
        expect((details.single() as JsonObject).str("credential_configuration_id") == CONFIG_ID) { "authorization_details $details" }
        accessToken = "AT-" + Crypto.digest(Algorithm.SHA256, Clock.System.now().toString().encodeToByteArray()).toBase64Url().take(12)
        cNonce = "cn-" + Clock.System.now().toEpochMilliseconds()
        return json(buildJsonObject {
            put("access_token", accessToken); put("token_type", "Bearer"); put("expires_in", 600)
            put("c_nonce", cNonce); put("c_nonce_expires_in", 600)
        })
    }

    private suspend fun MockRequestHandleScope.credential(request: HttpRequestData): HttpResponseData {
        expect(request.headers[HttpHeaders.Authorization] == "Bearer $accessToken") { "Authorization ${request.headers[HttpHeaders.Authorization]}" }
        val body = DiwJson.parseToJsonElement(bodyText(request)) as JsonObject
        expect(body.str("credential_identifier") == CONFIG_ID) { "credential_identifier ${body.str("credential_identifier")}" }
        val proof = (body.obj("proofs")?.arr("jwt")?.singleOrNull() as? JsonPrimitive)?.content ?: fail("proofs.jwt missing")
        val jws = Jws.parse(proof)
        expect(jws.header.str("typ") == "openid4vci-proof+jwt") { "proof typ ${jws.header.str("typ")}" }
        expect(jws.header["jwk"] == null) { "proof carries a jwk" }
        val kid = jws.kid ?: fail("proof kid missing")
        expect(kid.startsWith("did:key:") && '#' !in kid) { "proof kid is not a bare did:key: $kid" }
        val holderKey = (dids.resolveKey(kid, null).key as VerificationKey.Ec).key
        expect(DidKeys.didKeyJwkJcs(holderKey) == kid) { "proof kid is not a jwk_jcs did:key" }
        jws.verify(VerificationKey.Ec(holderKey))
        expect(jws.payload.str("iss") == CLIENT_ID) { "proof iss ${jws.payload.str("iss")}" }
        expect(jws.payload.str("aud") == ISSUER) { "proof aud ${jws.payload.str("aud")}" }
        // As moda.wallet.gov.tw behaves: a proof over a nonce from its nonce endpoint passes the proof checks, and the
        // credential service then fails.
        if (nonceEndpointPublished && jws.payload.str("nonce")?.startsWith("endpoint-nonce-") == true) {
            return json(buildJsonObject { put("resp_code", 11500); put("resp_message", "Interal server error") }, HttpStatusCode.InternalServerError)
        }
        expect(jws.payload.str("nonce") == cNonce) { "proof nonce ${jws.payload.str("nonce")}" }
        // The official handler answers 500 with its own body once token and proof passed but the credential service failed.
        credentialServiceFailure?.let { (code, message) ->
            return json(buildJsonObject { put("resp_code", code); put("resp_message", message) }, HttpStatusCode.InternalServerError)
        }
        issuedIndex++
        return json(buildJsonObject { put("credential", mintCard(holderKey, kid, issuedIndex)) })
    }

    private suspend fun mintCard(holder: EcPublicKey, holderDid: String, index: Int): String {
        val now = Clock.System.now().epochSeconds
        val disclosures = CLAIMS.map { (k, v) ->
            buildJsonArray { add(Crypto.digest(Algorithm.SHA256, "$k$index".encodeToByteArray()).toBase64Url().take(22)); add(k); add(v) }
                .toString().encodeToByteArray().toBase64Url()
        }
        val digests = disclosures.map { Crypto.digest(Algorithm.SHA256, it.encodeToByteArray()).toBase64Url() }
        val holderJwk = holder.toJwk()
        val jwt = signJws(
            buildJsonObject {
                put("typ", "vc+sd-jwt"); put("alg", "ES256")
                put("kid", DidKeys.verificationMethod(issuerDid)); put("jku", "$ISSUER_ORIGIN/api/keys")
            },
            buildJsonObject {
                put("iss", issuerDid)
                put("sub", holderDid)
                put("jti", "$ISSUER_ORIGIN/api/credential/$index")
                put("nbf", now)
                put("exp", now + 365L * 86400)
                put("nonce", "Ab3dE6gH")
                putJsonObject("cnf") { put("jwk", holderJwk) }
                put("_sd_alg", "sha-256")
                putJsonObject("vc") {
                    putJsonArray("@context") { add("https://www.w3.org/2018/credentials/v1") }
                    putJsonArray("type") { add("VerifiableCredential"); add(CONFIG_ID) }
                    putJsonObject("credentialSubject") { putJsonArray("_sd") { digests.forEach { add(it) } } }
                    putJsonArray("credentialStatus") {
                        for ((purpose, letter) in listOf("revocation" to "r", "suspension" to "s")) addJsonObject {
                            val list = "$ISSUER_ORIGIN/api/status-list/$CONFIG_ID/${letter}0"
                            put("id", "$list#$index")
                            put("type", "StatusList2021Entry")
                            put("statusPurpose", purpose)
                            put("statusListIndex", index.toString())
                            put("statusListCredential", list)
                        }
                    }
                    putJsonObject("credentialSchema") { put("id", "$ISSUER_ORIGIN/api/schema/$CONFIG_ID"); put("type", "JsonSchema") }
                }
            },
            AsymmetricKey.AnonymousExplicit(issuerKey, Algorithm.ES256),
        )
        return jwt + disclosures.joinToString("") { "~$it" } + "~"
    }

    /** TWDIW signs status lists with key-2, published only at /api/keys (jku), not in the issuer DID. */
    var statusListSignedByIssuerDid = false

    /** Whether the issuer metadata names a nonce_endpoint, as newer TWDIW issuers do; [endpointNonces] counts its use. */
    var nonceEndpointPublished = false
    var endpointNonces = 0

    /** Whether the configuration display names a card face; the platform writes an empty uri when there is none. */
    var cardFaceInMetadata = true

    /** resp_code and resp_message the credential endpoint fails with after accepting the proof; null issues the card. */
    var credentialServiceFailure: Pair<Int, String>? = null

    /** Host of the status lists' jku; the platform's issuer host unless a test moves it. */
    var statusJkuHost = ISSUER_HOST

    /** The key set at /api/keys: key-1 is the issuer DID's key, key-2 signs the status lists. */
    private suspend fun keySet(): JsonObject {
        val key1 = issuerKey.publicKey.toJwk()
        val key2 = statusKey.publicKey.toJwk()
        return buildJsonObject {
            putJsonArray("keys") {
                addJsonObject { key1.forEach { (k, v) -> put(k, v) }; put("kid", "key-1"); put("use", "sig"); put("alg", "ES256") }
                addJsonObject { key2.forEach { (k, v) -> put(k, v) }; put("kid", "key-2"); put("use", "sig"); put("alg", "ES256") }
            }
        }
    }
    private val statusKey = kotlinx.coroutines.runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }

    private suspend fun statusList(purpose: String, url: String): String {
        val bits = if (purpose == "revocation") revocation else suspension
        val bytes = ByteArray(STATUS_BITS / 8)
        bits.forEachIndexed { i, set -> if (set) bytes[i / 8] = (bytes[i / 8].toInt() or (0x80 ushr (i % 8))).toByte() }
        val gz = ByteArrayOutputStream().also { out -> GZIPOutputStream(out).use { it.write(bytes) } }.toByteArray()
        val now = Clock.System.now().epochSeconds
        return signJws(
            buildJsonObject {
                put("typ", "JWT"); put("alg", "ES256")
                put("kid", if (statusListSignedByIssuerDid) DidKeys.verificationMethod(issuerDid) else "key-2"); put("jku", "https://$statusJkuHost/api/keys")
            },
            buildJsonObject {
                put("iss", issuerDid)
                put("sub", url)
                put("nbf", now)
                put("jti", url)
                putJsonObject("vc") {
                    putJsonArray("@context") { add("https://www.w3.org/2018/credentials/v1"); add("https://w3id.org/vc/status-list/2021/v1") }
                    putJsonArray("type") { add("VerifiableCredential"); add("StatusList2021Credential") }
                    putJsonObject("credentialSubject") {
                        put("id", "$url#list"); put("type", "StatusList2021"); put("statusPurpose", purpose)
                        put("encodedList", gz.toBase64Url())
                    }
                }
            },
            AsymmetricKey.AnonymousExplicit(if (statusListSignedByIssuerDid) issuerKey else statusKey, Algorithm.ES256),
        )
    }

    // ------------------------------------------------------------------ verifier

    private suspend fun MockRequestHandleScope.verifier(request: HttpRequestData): HttpResponseData {
        val path = request.url.encodedPath
        return when {
            path.startsWith("/api/oidvp/request/") -> {
                val p = pending[path.substringAfterLast('/')] ?: return notFound()
                respond(requestObject(p), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/oauth-authz-req+jwt"))
            }
            path == "/api/oidvp/response" && request.method == HttpMethod.Post -> response(request)
            path == "/api/ext/offline/qrcode/$VP_UID_PICKUP" -> {
                val tx = "tx-" + (transactions.size + 1)
                val id = "offline-$tx"
                pending[id] = PendingRequest(id, VP_UID_PICKUP, "nonce-$id", listOf("name"))
                transactions[tx] = id
                json(buildJsonObject {
                    put("code", "0")
                    putJsonObject("data") {
                        put("transactionId", tx)
                        put("deepLink", deepLink(id))
                        put("description", "出示會員卡以取貨")
                        putJsonArray("fields") {
                            addJsonObject { put("cname", "手機號碼"); put("ename", "phone"); put("regex", "^09\\d{8}$") }
                        }
                    }
                })
            }
            path == "/api/ext/offline/getEncryptionData" && request.method == HttpMethod.Post -> encryptionData(request)
            else -> notFound()
        }
    }

    private suspend fun requestObject(p: PendingRequest): String {
        val now = Clock.System.now().epochSeconds
        return signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "oauth-authz-req+jwt"); put("kid", requestKid ?: DidKeys.verificationMethod(verifierDid)) },
            buildJsonObject {
                put("client_id", verifierDid)
                put("response_type", "vp_token")
                put("response_mode", "direct_post")
                put("response_uri", "$VERIFIER/api/oidvp/response")
                put("nonce", p.nonce)
                put("state", p.id)
                put("iat", now)
                put("exp", now + 300)
                putJsonObject("presentation_definition") {
                    put("id", p.definitionId)
                    if (p.definitionId == VP_UID_MOICA) {
                        // Bonds' self-issued card request: one descriptor in the vc+moica format.
                        putJsonArray("input_descriptors") {
                            addJsonObject {
                                put("id", "credential")
                                putJsonObject("format") { putJsonObject("vc+moica") { putJsonArray("alg") { add("RS256"); add("ES256") } } }
                                putJsonObject("constraints") {
                                    putJsonArray("fields") {
                                        addJsonObject {
                                            putJsonArray("path") { add("$.type") }
                                            putJsonObject("filter") { put("type", "array"); putJsonObject("contains") { put("const", "NationalIDCredential") } }
                                        }
                                        for (f in p.fields) addJsonObject { putJsonArray("path") { add("$.credentialSubject.$f") } }
                                    }
                                }
                            }
                        }
                    } else if (p.definitionId == VP_UID_PICKUP) {
                        // Shape seen from TWDIW-based services: a descriptor format per input descriptor.
                        putJsonArray("input_descriptors") {
                            addJsonObject {
                                put("id", CONFIG_ID)
                                putJsonObject("format") { putJsonObject("vc+sd-jwt") { putJsonArray("alg") { add("ES256") } } }
                                putJsonObject("constraints") {
                                    putJsonArray("fields") {
                                        for (f in p.fields) addJsonObject { putJsonArray("path") { add("$.credentialSubject.$f") } }
                                    }
                                }
                            }
                        }
                    } else {
                        // The official verifier's shape: no descriptor format, the card type as a $.type filter, groups,
                        // and the consent terms as a JSON string in purpose.
                        put("purpose", DiwJson.encodeToString(JsonObject.serializer(), buildJsonObject {
                            put("client", "模擬驗證機關"); put("terms_uri", TERMS_URL); put("scenario", "皮夾夥伴卡驗證"); put("purpose", "確認會員身分")
                        }))
                        putJsonArray("submission_requirements") {
                            addJsonObject { put("name", "姓名"); put("rule", "pick"); put("max", 1); put("from", "Group_1") }
                        }
                        putJsonArray("input_descriptors") {
                            for ((i, type) in listOf("99999999_other_card", CONFIG_ID).withIndex()) addJsonObject {
                                put("id", "${type}_${i + 1}")
                                put("name", "{\"org_tw_name\":\"模擬發證機關\",\"vc_name\":\"$type\"}")
                                putJsonArray("group") { add("Group_1") }
                                putJsonObject("constraints") {
                                    putJsonArray("fields") {
                                        addJsonObject {
                                            putJsonArray("path") { add("$.type") }
                                            putJsonObject("filter") { put("type", "array"); putJsonObject("contains") { put("const", type) } }
                                        }
                                        for (f in p.fields) addJsonObject { putJsonArray("path") { add("$.credentialSubject.$f") } }
                                    }
                                    put("limit_disclosure", "required")
                                }
                            }
                        }
                    }
                }
                putJsonObject("client_metadata") {
                    putJsonObject("vp_formats") {
                        putJsonObject("jwt_vc") { putJsonArray("alg") { add("ES256") } }
                        putJsonObject("jwt_vp") { putJsonArray("alg") { add("ES256") } }
                    }
                }
            },
            AsymmetricKey.AnonymousExplicit(verifierKey, Algorithm.ES256),
        )
    }

    private suspend fun MockRequestHandleScope.response(request: HttpRequestData): HttpResponseData {
        val form = parseQueryString(bodyText(request))
        val p = pending[form["state"] ?: fail("state missing")] ?: fail("unknown state")
        val vpToken = form["vp_token"] ?: fail("vp_token missing")
        val vp = Jws.parse(vpToken)
        expect(vp.header.str("typ") == "JWT") { "vp typ ${vp.header.str("typ")}" }
        val jwk = vp.header.obj("jwk") ?: fail("vp header without jwk")
        val holder = EcPublicKey.fromJwk(jwk)
        vp.verify(VerificationKey.Ec(holder))
        val holderDid = DidKeys.didKeyJwkJcs(holder)
        expect(vp.payload.str("iss") == holderDid && vp.payload.str("sub") == holderDid) { "vp iss/sub ${vp.payload.str("iss")}" }
        expect(vp.payload.str("aud") == verifierDid) { "vp aud ${vp.payload.str("aud")}" }
        expect(vp.payload.str("nonce") == p.nonce) { "vp nonce ${vp.payload.str("nonce")}" }
        val submission = DiwJson.parseToJsonElement(form["presentation_submission"] ?: fail("presentation_submission missing")) as JsonObject
        expect(submission.str("definition_id") == p.definitionId) { "definition_id ${submission.str("definition_id")}" }
        val map = submission.arr("descriptor_map")?.singleOrNull() as? JsonObject ?: fail("descriptor_map")
        if (p.definitionId == VP_UID_MOICA) {
            expect(map.str("id") == "credential" && map.str("format") == "jwt_vp" && map.str("path") == "$") { "descriptor $map" }
            val nestedMoica = map.obj("path_nested") ?: fail("path_nested missing")
            expect(nestedMoica.str("id") == "credential" && nestedMoica.str("format") == "vc+moica" && nestedMoica.str("path") == "$.vp.verifiableCredential[0]") { "path_nested $nestedMoica" }
            val envelope = (vp.payload.obj("vp")?.arr("verifiableCredential")?.singleOrNull() as? JsonPrimitive)?.content ?: fail("no card")
            val moica = MoicaSignedCredential.parse(envelope)
            expect(moica.issuerJws != null) { "no issuer JWS" }
            val subject = moica.credential().obj("credentialSubject")?.str("id") ?: fail("no subject")
            expect(dids.resolveKey(subject, null).key == VerificationKey.Ec(holder)) { "card subject is not the presenter" }
            val names = BondsOfflinePresentation.disclosableClaims(moica).map { it.first }
            received += Received(p.id, vp.payload, submission, names, emptyList())
            return json(buildJsonObject { put("code", "0"); put("message", "SUCCESS") })
        }
        val expectedId = if (p.definitionId == VP_UID_PICKUP) CONFIG_ID else "${CONFIG_ID}_2"
        expect(map.str("id") == expectedId) { "descriptor id ${map.str("id")}" }
        expect(map.str("format") == "jwt_vp" && map.str("path") == "$") { "descriptor $map" }
        val nested = map.obj("path_nested") ?: fail("path_nested missing")
        expect(nested.str("format") == "jwt_vc" && nested.str("path") == "$.vp.verifiableCredential[0]") { "path_nested $nested" }
        val card = (vp.payload.obj("vp")?.arr("verifiableCredential")?.singleOrNull() as? JsonPrimitive)?.content ?: fail("no card")
        val parts = card.split('~')
        val cardJws = Jws.parse(parts[0])
        cardJws.verify(VerificationKey.Ec(issuerKey.publicKey))
        expect(cardJws.payload.str("sub") == holderDid) { "card subject ${cardJws.payload.str("sub")} is not the presenter" }
        val sd = cardJws.payload.obj("vc")?.obj("credentialSubject")?.arr("_sd")?.map { (it as JsonPrimitive).content }.orEmpty()
        val names = parts.drop(1).filter { it.isNotEmpty() }.map { d ->
            expect(Crypto.digest(Algorithm.SHA256, d.encodeToByteArray()).toBase64Url() in sd) { "disclosure not in _sd" }
            ((DiwJson.parseToJsonElement(d.fromBase64Url().decodeToString()) as JsonArray)[1] as JsonPrimitive).content
        }
        val custom = form["custom_data"]?.let { token ->
            val j = Jws.parse(token)
            j.verify(VerificationKey.Ec(EcPublicKey.fromJwk(j.header.obj("jwk") ?: fail("custom_data without jwk"))))
            j.payload.arr("customData").orEmpty().filterIsInstance<JsonObject>()
        }.orEmpty()
        received += Received(p.id, vp.payload, submission, names, custom, cardJws.payload)
        return json(buildJsonObject { put("code", "0"); put("message", "SUCCESS") })
    }

    private suspend fun MockRequestHandleScope.encryptionData(request: HttpRequestData): HttpResponseData {
        val body = DiwJson.parseToJsonElement(bodyText(request)) as JsonObject
        val jws = Jws.parse(body.str("jwt") ?: fail("jwt missing"))
        val kid = jws.kid ?: fail("kid missing")
        jws.verify(dids.resolveKey(kid, null).key)
        val tx = jws.payload.str("transactionId") ?: fail("transactionId missing")
        val requestId = transactions[tx] ?: fail("unknown transaction")
        val presented = received.lastOrNull { it.requestId == requestId } ?: fail("transaction $tx has no presentation")
        expect(presented.vpPayload.str("iss") == kid) { "barcode requested by ${kid}, presented by ${presented.vpPayload.str("iss")}" }
        lastTransactionCompleted = true
        return json(buildJsonObject {
            put("code", "0")
            putJsonObject("data") { put("qrcode", "data:image/png;base64," + png().toBase64()); put("totptimeout", 120) }
        })
    }

    fun png(): ByteArray {
        val image = BufferedImage(21, 21, BufferedImage.TYPE_BYTE_BINARY)
        return ByteArrayOutputStream().also { ImageIO.write(image, "png", it) }.toByteArray()
    }

    companion object {
        const val FRONTEND_HOST = "frontend.mock.wallet.gov.tw"
        const val ISSUER_HOST = "issuer.mock.wallet.gov.tw"
        const val VERIFIER_HOST = "verifier.mock.wallet.gov.tw"
        const val FRONTEND = "https://$FRONTEND_HOST"
        const val ISSUER_ORIGIN = "https://$ISSUER_HOST"
        const val ISSUER = "$ISSUER_ORIGIN/oid4vci/api/issuer/00000000/"
        const val VERIFIER = "https://$VERIFIER_HOST"
        const val CONFIG_ID = "00000000_mock_card"
        const val TERMS_URL = "https://verifier.example.com/terms/wallet_partner"
        const val COVER_URL = "$ISSUER_ORIGIN/api/images/cover/00000000/mock_card"
        const val LOGO_URL = "$ISSUER_ORIGIN/vc/api/logo/square/00000000"
        const val VP_UID_ONLINE = "00000000_mock_vp"
        const val VP_UID_PICKUP = "00000000_mock_pickup"
        const val VP_UID_MOICA = "00000000_mock_moica"
        const val CLIENT_ID = "moda_dw"
        const val PRE_AUTH_CODE = "pre-auth-0001"
        const val STATUS_BITS = 16 * 1024 * 8
        val CLAIMS = listOf("name" to "林哲全", "birthDate" to "1990-01-01", "cardNumber" to "A123456789")

        suspend fun create(): TwdiwPlatformMock {
            val issuer = Crypto.createEcPrivateKey(EcCurve.P256)
            val verifier = Crypto.createEcPrivateKey(EcCurve.P256)
            return TwdiwPlatformMock(issuer, DidKeys.didKeyJwkJcs(issuer.publicKey), verifier, DidKeys.didKeyJwkJcs(verifier.publicKey))
        }
    }
}
