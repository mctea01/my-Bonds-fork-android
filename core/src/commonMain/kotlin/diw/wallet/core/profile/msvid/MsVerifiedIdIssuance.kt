package diw.wallet.core.profile.msvid

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.jwkThumbprint
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vci.CredentialDomains
import diw.wallet.core.oid4vci.IssuanceRecord
import diw.wallet.core.oid4vci.KeyRequest
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.oid4vp.compat.MsVerifiedIdPresentationDialect
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.obj
import diw.wallet.core.util.queryParameters
import diw.wallet.core.util.str
import diw.wallet.core.w3c.W3cInspector
import diw.wallet.core.w3c.W3cVcCredential
import io.ktor.client.HttpClient
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.util.toBase64Url
import kotlin.time.Clock

/** A claim the holder types in (selfIssued attestation). */
data class MsSelfIssuedClaim(val claim: String, val required: Boolean)

/** An identity provider sign-in the contract asks for (idTokens / accessTokens attestation). */
data class MsTokenRequirement(
    val configuration: String,
    val clientId: String,
    val redirectUri: String,
    val scope: String,
    val required: Boolean,
    val accessToken: Boolean,
    /** Satisfied by the request's id_token_hint (configuration https://self-issued.me). */
    val injected: Boolean,
)

/** A credential the contract asks the holder to present (presentations attestation). */
data class MsPresentationRequirement(val credentialType: String, val required: Boolean, val issuers: List<String>)

/** PIN the issuer requires with an id_token_hint. */
data class MsPinRequirement(val length: Int, val type: String, val salt: String?)

/**
 * A Microsoft Entra Verified ID issuance request (openid-vc request with prompt=create) and its contract.
 * Fill [selfIssued], [tokens] and [presentations], set [pin] when [pinRequirement] is present, then [MsVerifiedIdIssuance.complete].
 */
class MsIssuanceRequest internal constructor(
    val requestUri: String,
    val clientId: String,
    val clientName: String?,
    val contractUrl: String,
    val contract: JsonObject,
    val issuerDid: String,
    val credentialIssuer: String,
    val trust: TrustDecision,
    val state: String?,
    val callbackUrl: String?,
    val idTokenHint: String?,
    val pinRequirement: MsPinRequirement?,
    val selfIssuedClaims: List<MsSelfIssuedClaim>,
    val tokenRequirements: List<MsTokenRequirement>,
    val presentationRequirements: List<MsPresentationRequirement>,
) {
    val cardTitle: String? get() = contract.obj("display")?.obj("card")?.str("title")
    val issuedBy: String? get() = contract.obj("display")?.obj("card")?.str("issuedBy")
    val consentTitle: String? get() = contract.obj("display")?.obj("consent")?.str("title")

    val selfIssued = mutableMapOf<String, String>()
    val tokens = mutableMapOf<String, String>()
    val presentations = mutableMapOf<String, W3cVcCredential>()
    var pin: String? = null

    internal val pendingLogins = mutableMapOf<String, Pair<String, String>>()

    /** Requirements still missing, by name, for the consent screen. */
    fun missing(): List<String> = buildList {
        selfIssuedClaims.filter { it.required && selfIssued[it.claim].isNullOrEmpty() }.forEach { add(it.claim) }
        tokenRequirements.filter { it.required && !it.injected && tokens[it.configuration] == null }.forEach { add(it.configuration) }
        presentationRequirements.filter { it.required && presentations[it.credentialType] == null }.forEach { add(it.credentialType) }
        if (pinRequirement != null && pin.isNullOrEmpty()) add("pin")
    }
}

/**
 * Holder side of Microsoft Entra Verified ID issuance (the request/contract flow of the Verified ID wallet library and
 * Microsoft Authenticator). The contract is fetched with x-ms-sign-contract and verified against the issuer DID, the
 * issuer's linked domain decides the trust tier, and the issuance response is a self-issued JWT signed by the wallet's
 * Verified ID holder DID (did:jwk), posted as text to the contract's credentialIssuer. Completion is reported to the
 * request's redirect_uri with its state.
 */
class MsVerifiedIdIssuance(
    private val httpClient: HttpClient,
    private val didResolver: DidResolver,
    private val linkedDomains: LinkedDomains,
    private val inspector: W3cInspector,
    private val holderIdentities: HolderIdentities,
    private val documentStore: DocumentStore,
    private val allowInsecureLoopback: Boolean = false,
) {
    /** Fetches and verifies the request behind an openid-vc URI; null when it is not an issuance request. */
    suspend fun resolve(uri: String): MsIssuanceRequest? {
        val params = queryParameters(uri)
        val requestUri = params["request_uri"]
        val requestJwt = when {
            requestUri != null -> fetchText(requestUri, "application/oauth-authz-req+jwt, application/jwt")
            params["request"] != null -> params["request"]!!
            else -> return null
        }
        val jws = Jws.parse(requestJwt.trim().removeSurrounding("\""))
        val claims = jws.payload
        if (claims.str("prompt") != PROMPT_CREATE) return null
        val clientId = claims.str("client_id") ?: params["client_id"] ?: throw ProtocolException("invalid_request", "Request without client_id")
        val kid = jws.kid ?: throw ProtocolException("invalid_request", "Request without kid")
        if (kid.substringBefore('#') != clientId) throw ProtocolException("invalid_request", "Request is not signed by $clientId")
        jws.verify(didResolver.resolveKey(clientId, kid).key)
        val descriptor = claims.obj("claims")?.obj("vp_token")?.obj("presentation_definition")
            ?.arr("input_descriptors")?.firstOrNull() as? JsonObject
            ?: throw ProtocolException("invalid_request", "Issuance request without input descriptor")
        val contractUrl = (descriptor.arr("issuance")?.firstOrNull() as? JsonObject)?.str("manifest")
            ?: throw ProtocolException("invalid_request", "Issuance request without manifest")
        val contract = fetchContract(contractUrl)
        val input = contract.obj("input") ?: throw ProtocolException("invalid_contract", "Contract without input")
        val issuerDid = input.str("issuer") ?: throw ProtocolException("invalid_contract", "Contract without issuer")
        val credentialIssuer = input.str("credentialIssuer") ?: throw ProtocolException("invalid_contract", "Contract without credentialIssuer")
        if (!isAcceptableEndpoint(credentialIssuer, allowInsecureLoopback)) throw ProtocolException("invalid_contract", "credentialIssuer is not https")
        val trust = linkedDomains.decide(issuerDid, TrustRole.ISSUER)
            ?: TrustDecision.unknown("Issuer $issuerDid declares no linked domain")
        val att = input.obj("attestations") ?: JsonObject(emptyMap())
        val selfIssued = att.obj("selfIssued")?.arr("claims").orEmpty().filterIsInstance<JsonObject>().mapNotNull {
            MsSelfIssuedClaim(it.str("claim") ?: return@mapNotNull null, (it["required"] as? JsonPrimitive)?.content == "true")
        }
        val hint = claims.str("id_token_hint")
        fun tokens(name: String, access: Boolean) = att.arr(name).orEmpty().filterIsInstance<JsonObject>().mapNotNull {
            val conf = it.str("configuration") ?: return@mapNotNull null
            MsTokenRequirement(
                configuration = conf,
                clientId = it.str("client_id") ?: "",
                redirectUri = it.str("redirect_uri") ?: "",
                scope = it.str("scope") ?: "openid",
                required = (it["required"] as? JsonPrimitive)?.content == "true",
                accessToken = access,
                injected = !access && conf == ID_TOKEN_HINT_CONFIGURATION && hint != null,
            )
        }
        val presentations = att.arr("presentations").orEmpty().filterIsInstance<JsonObject>().mapNotNull { p ->
            MsPresentationRequirement(
                p.str("credentialType") ?: return@mapNotNull null,
                (p["required"] as? JsonPrimitive)?.content == "true",
                p.arr("issuers").orEmpty().mapNotNull { (it as? JsonObject)?.str("iss") },
            )
        }
        val pin = claims.obj("pin")?.let { MsPinRequirement((it["length"] as? JsonPrimitive)?.content?.toIntOrNull() ?: 4, it.str("type") ?: "numeric", it.str("salt")) }
        return MsIssuanceRequest(
            requestUri = requestUri ?: uri,
            clientId = clientId,
            clientName = claims.obj("registration")?.str("client_name"),
            contractUrl = contractUrl,
            contract = contract,
            issuerDid = issuerDid,
            credentialIssuer = credentialIssuer,
            trust = trust,
            state = claims.str("state"),
            callbackUrl = claims.str("redirect_uri")?.takeIf { isAcceptableEndpoint(it, allowInsecureLoopback) },
            idTokenHint = hint,
            pinRequirement = if (hint != null) pin else null,
            selfIssuedClaims = selfIssued,
            tokenRequirements = tokens("idTokens", false) + tokens("accessTokens", true),
            presentationRequirements = presentations,
        )
    }

    /** The browser URL for an identity provider sign-in; finish with [completeLogin]. */
    suspend fun beginLogin(request: MsIssuanceRequest, requirement: MsTokenRequirement): String {
        val discovery = fetchJson(requirement.configuration)
        val endpoint = discovery.str("authorization_endpoint") ?: throw ProtocolException("invalid_configuration", "No authorization_endpoint")
        val verifier = PlatformCrypto.randomBytes(32).toBase64Url()
        val state = PlatformCrypto.randomBytes(16).toBase64Url()
        request.pendingLogins[state] = requirement.configuration to verifier
        return URLBuilder(endpoint).apply {
            parameters.append("response_type", "code")
            parameters.append("client_id", requirement.clientId)
            parameters.append("redirect_uri", requirement.redirectUri)
            parameters.append("scope", requirement.scope)
            parameters.append("state", state)
            parameters.append("nonce", nonce())
            parameters.append("code_challenge", PlatformCrypto.sha256(verifier.encodeToByteArray()).toBase64Url())
            parameters.append("code_challenge_method", "S256")
        }.buildString()
    }

    /** Exchanges the authorization code from [redirectedTo] for the id_token or access_token the contract asked for. */
    suspend fun completeLogin(request: MsIssuanceRequest, redirectedTo: String) {
        val params = queryParameters(redirectedTo.replace('#', '?'))
        params["error"]?.let { throw ProtocolException(it, params["error_description"] ?: "Sign-in failed") }
        val state = params["state"] ?: throw ProtocolException("invalid_request", "Sign-in response without state")
        val (configuration, verifier) = request.pendingLogins.remove(state) ?: throw ProtocolException("invalid_request", "Unknown sign-in state")
        val requirement = request.tokenRequirements.first { it.configuration == configuration }
        val discovery = fetchJson(configuration)
        val tokenEndpoint = discovery.str("token_endpoint") ?: throw ProtocolException("invalid_configuration", "No token_endpoint")
        val resp = httpClient.submitForm(tokenEndpoint, parameters {
            append("grant_type", "authorization_code")
            append("code", params["code"] ?: throw ProtocolException("invalid_request", "Sign-in response without code"))
            append("redirect_uri", requirement.redirectUri)
            append("client_id", requirement.clientId)
            append("code_verifier", verifier)
        })
        val json = DiwJson.parseToJsonElement(resp.bodyAsText()) as JsonObject
        val token = (if (requirement.accessToken) json.str("access_token") else json.str("id_token"))
            ?: throw ProtocolException("invalid_grant", json.str("error_description") ?: "Token endpoint returned no token")
        request.tokens[configuration] = token
    }

    /**
     * Sends the issuance response and stores the issued card under the Verified ID holder identity, then reports
     * the outcome to the request's callback. Throws when the issuer refuses; the failure is reported as well.
     */
    suspend fun complete(request: MsIssuanceRequest, keys: KeyRequest): Document {
        val missing = request.missing()
        if (missing.isNotEmpty()) throw ProtocolException("missing_requirements", "Missing ${missing.joinToString()}")
        return try {
            issue(request, keys).also { callback(request, true, null) }
        } catch (e: Exception) {
            callback(request, false, if (e is ProtocolException) "issuance_service_error" else "unspecified_error")
            throw e
        }
    }

    /** Tells the issuer the user declined. */
    suspend fun cancel(request: MsIssuanceRequest) = callback(request, false, "user_canceled")

    private suspend fun issue(request: MsIssuanceRequest, keys: KeyRequest): Document {
        val settings = keys.createKeySettings(ByteString(PlatformCrypto.randomBytes(16)))
        val holder = holderIdentities.getOrCreate(HolderIdentities.MS_VERIFIED_ID, "did:jwk", keys.secureArea, settings)
        val did = holder.did ?: HolderKey.didFor(holder.publicKey, "did:jwk")
        val now = Clock.System.now().epochSeconds
        val jwk = holder.publicKey.toJwk()
        val idTokens = buildMap {
            request.idTokenHint?.let { h -> if (request.tokenRequirements.any { it.injected }) put(ID_TOKEN_HINT_CONFIGURATION, h) }
            request.tokenRequirements.filter { !it.accessToken }.forEach { r -> request.tokens[r.configuration]?.let { put(r.configuration, it) } }
        }
        val accessTokens = request.tokenRequirements.filter { it.accessToken }.mapNotNull { r -> request.tokens[r.configuration]?.let { r.configuration to it } }.toMap()
        val vps = request.presentations.mapValues { (_, cred) -> presentation(cred, request.issuerDid, holder, did) }
        val payload = buildJsonObject {
            put("contract", request.contractUrl)
            if (request.selfIssued.isNotEmpty() || idTokens.isNotEmpty() || accessTokens.isNotEmpty() || vps.isNotEmpty()) {
                putJsonObject("attestations") {
                    if (request.selfIssued.isNotEmpty()) putJsonObject("selfIssued") { request.selfIssued.forEach { (k, v) -> put(k, v) } }
                    if (idTokens.isNotEmpty()) putJsonObject("idTokens") { idTokens.forEach { (k, v) -> put(k, v) } }
                    if (accessTokens.isNotEmpty()) putJsonObject("accessTokens") { accessTokens.forEach { (k, v) -> put(k, v) } }
                    if (vps.isNotEmpty()) putJsonObject("presentations") { vps.forEach { (k, v) -> put(k, v) } }
                }
            }
            put("did", did)
            put("sub", jwkThumbprint(jwk))
            put("aud", request.credentialIssuer)
            put("sub_jwk", jwk)
            put("iat", now)
            put("exp", now + RESPONSE_LIFETIME)
            put("jti", uuid())
            put("iss", SELF_ISSUED_V1)
            hashPin(request)?.let { put("pin", it) }
        }
        val responseJwt = signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "JWT"); put("kid", DidKeys.verificationMethod(did)) },
            payload,
            holder.signingKey("ES256"),
        )
        val resp = httpClient.post(request.credentialIssuer) {
            contentType(ContentType.Text.Plain)
            setBody(responseJwt)
        }
        val text = resp.bodyAsText()
        if (!resp.status.isSuccess()) {
            val err = runCatching { DiwJson.parseToJsonElement(text) as JsonObject }.getOrNull()
            val code = err?.obj("error")?.obj("innererror")?.str("code") ?: err?.obj("error")?.str("code") ?: "issuance_failed"
            throw ProtocolException(code, err?.obj("error")?.str("message") ?: "Issuer returned ${resp.status.value}")
        }
        val vc = (DiwJson.parseToJsonElement(text) as JsonObject).str("vc") ?: throw ProtocolException("invalid_credential_response", "No vc in response")
        val inspected = inspector.inspect(vc, sdJwtAllowed = false, expectedIssuer = request.issuerDid)
        if (inspected.issuer != request.issuerDid) throw ProtocolException("invalid_credential", "Card issued by ${inspected.issuer}, contract names ${request.issuerDid}")
        if (inspected.holderDid != null && inspected.holderDid != did) throw ProtocolException("invalid_credential", "Card bound to another holder")
        val trust = if (request.trust.tier.ordinal > inspected.trust.tier.ordinal) request.trust else inspected.trust
        val record = IssuanceRecord(
            credentialIssuer = request.credentialIssuer,
            configurationId = request.contractUrl,
            format = FORMAT,
            tier = TrustTier.T4.name,
            issuedAt = now,
            keyStorage = keys.keyStorage,
            claimNames = claimLabels(request.contract),
            w3cTypes = inspected.types,
            profile = MsVerifiedIdPresentationDialect.ID,
            holderDid = did,
            specs = listOf(SPEC),
        ).withTrust(trust)
        val document = documentStore.createDocument(
            displayName = request.cardTitle ?: inspected.types.lastOrNull() ?: "Verified ID",
            typeDisplayName = request.issuedBy ?: request.issuerDid,
            appData = record.encode(),
        )
        val credential = W3cVcCredential.createKeyBound(document, CredentialDomains.W3C, FORMAT, inspected.types, holder.secureArea, holder.alias, true, did)
        credential.setIssuedFormBeforeCertify(inspected.encoding, inspected.types, did)
        credential.certify(vc.encodeToByteString())
        document.edit {
            appData = (document.issuanceRecord ?: record).encode()
            provisioned = true
        }
        return document
    }

    private suspend fun presentation(credential: W3cVcCredential, audience: String, holder: HolderKey, did: String): String {
        val now = Clock.System.now().epochSeconds
        return signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "JWT"); put("kid", DidKeys.verificationMethod(did)) },
            buildJsonObject {
                put("jti", uuid())
                putJsonObject("vp") {
                    putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/2018/credentials/v1")) }
                    putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
                    putJsonArray("verifiableCredential") { add(JsonPrimitive(credential.raw)) }
                }
                put("iss", did)
                put("iat", now)
                put("nbf", now)
                put("exp", now + RESPONSE_LIFETIME)
                put("aud", audience)
            },
            holder.signingKey("ES256"),
        )
    }

    private suspend fun callback(request: MsIssuanceRequest, success: Boolean, details: String?) {
        val url = request.callbackUrl ?: return
        val state = request.state ?: return
        runCatching {
            httpClient.post(url) {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject {
                    put("code", if (success) "issuance_successful" else "issuance_failed")
                    put("state", state)
                    details?.let { put("details", it) }
                }.toString())
            }
        }
    }

    private fun hashPin(request: MsIssuanceRequest): String? {
        val value = (request.pinRequirement?.salt ?: "") + (request.pin ?: "")
        if (request.pin.isNullOrEmpty()) return null
        return kotlin.io.encoding.Base64.encode(PlatformCrypto.sha256(value.encodeToByteArray()))
    }

    private suspend fun fetchContract(url: String): JsonObject {
        if (!isAcceptableEndpoint(url, allowInsecureLoopback)) throw ProtocolException("invalid_request", "Manifest URL is not https")
        val resp = httpClient.get(url) { header("x-ms-sign-contract", "true"); header(HttpHeaders.Accept, "application/json") }
        if (!resp.status.isSuccess()) throw ProtocolException("fetch_contract_error", "Manifest returned ${resp.status.value}")
        val body = resp.bodyAsText().trim()
        val token = runCatching { (DiwJson.parseToJsonElement(body) as JsonObject).str("token") }.getOrNull() ?: body
        val jws = Jws.parse(token)
        val contract = jws.payload
        val issuer = contract.obj("input")?.str("issuer") ?: throw ProtocolException("invalid_contract", "Contract without issuer")
        val kid = jws.kid ?: throw ProtocolException("invalid_contract", "Contract without kid")
        if (kid.substringBefore('#') != issuer) throw ProtocolException("invalid_contract", "Contract is not signed by its issuer")
        jws.verify(didResolver.resolveKey(issuer, kid).key)
        return contract
    }

    private suspend fun fetchText(url: String, accept: String): String {
        if (!isAcceptableEndpoint(url, allowInsecureLoopback)) throw ProtocolException("invalid_request", "request_uri is not https")
        val resp = httpClient.get(url) { header(HttpHeaders.Accept, accept) }
        if (!resp.status.isSuccess()) throw ProtocolException("invalid_request_uri", "request_uri returned ${resp.status.value}")
        val body = resp.bodyAsText().trim()
        return runCatching { (DiwJson.parseToJsonElement(body) as? JsonObject)?.let { it.str("request") ?: it.str("token") } }.getOrNull() ?: body
    }

    private suspend fun fetchJson(url: String): JsonObject {
        if (!isAcceptableEndpoint(url, allowInsecureLoopback)) throw ProtocolException("invalid_request", "$url is not https")
        val resp = httpClient.get(url)
        if (!resp.status.isSuccess()) throw ProtocolException("invalid_configuration", "$url returned ${resp.status.value}")
        return DiwJson.parseToJsonElement(resp.bodyAsText()) as JsonObject
    }

    private fun claimLabels(contract: JsonObject): Map<String, String> =
        contract.obj("display")?.obj("claims")?.mapNotNull { (path, v) ->
            val label = (v as? JsonObject)?.str("label") ?: return@mapNotNull null
            path.removePrefix("vc.") to label
        }?.toMap().orEmpty()

    private suspend fun nonce(): String {
        val did = holderIdentities.find(HolderIdentities.MS_VERIFIED_ID)?.did ?: ""
        return PlatformCrypto.randomBytes(32).toBase64Url() + "." + org.multipaz.crypto.Crypto.digest(org.multipaz.crypto.Algorithm.SHA512, did.encodeToByteArray()).toBase64Url()
    }

    private fun uuid(): String = diw.wallet.core.oid4vp.ext.ExtendedPresenter.uuid()

    companion object {
        const val PROMPT_CREATE = "create"
        const val ID_TOKEN_HINT_CONFIGURATION = "https://self-issued.me"
        const val SELF_ISSUED_V1 = "https://self-issued.me"
        const val FORMAT = "jwt_vc_json"
        const val SPEC = "Microsoft Entra Verified ID"
        private const val RESPONSE_LIFETIME = 600L
    }
}
