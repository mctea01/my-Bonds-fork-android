package diw.wallet.core.oid4vp.ext

import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.oid4vp.ClientId
import diw.wallet.core.oid4vp.ClientIdPrefix
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.oid4vp.RawAuthorizationRequest
import diw.wallet.core.oid4vp.RequestChannel
import diw.wallet.core.oid4vp.RequestValidationException
import diw.wallet.core.oid4vp.ResponseMode
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.VerifierIdentityInfo
import diw.wallet.core.oid4vp.compat.PresentationDialect
import diw.wallet.core.oid4vp.transactionDataStrings
import diw.wallet.core.oid4vp.verifierInfoEntries
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.hostOf
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.long
import diw.wallet.core.util.obj
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import diw.wallet.core.x509.displaySubject
import diw.wallet.core.x509.organization
import diw.wallet.core.x509.subjectAltNames
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonObject
import kotlin.time.Clock

/**
 * Validation for requests outside OpenID4VP 1.0: drafts 13 to 23 (client_id_scheme, did: and x509_san_uri
 * client identifiers, Presentation Exchange, presentation_definition_uri, client_metadata_uri), SIOPv2 (id_token,
 * registration), OAuth response modes (fragment, query, form_post / post), and profile requests (TWDIW, Microsoft
 * Verified ID). The Verifier is authenticated with whatever the request offers; an unauthenticated Verifier is T4.
 */
class LegacyRequestValidator(
    private val httpClient: HttpClient,
    private val trustRegistry: TrustRegistry,
    private val didResolver: DidResolver,
    private val didTrust: DidTrust,
    private val policy: PresentationPolicy,
    private val allowInsecureLoopback: Boolean,
    private val dialects: List<PresentationDialect>,
) {
    suspend fun validate(raw: RawAuthorizationRequest): ValidatedAuthorizationRequest {
        val p = raw.params
        val warnings = mutableListOf<String>()
        val specs = linkedSetOf<String>()
        val dialect = dialects.firstOrNull { it.owns(raw, p) }
        dialect?.let { specs += it.spec }

        val responseTypes = (p.str("response_type") ?: "vp_token").split(' ').filter { it.isNotBlank() }.toSet()
        if (responseTypes.none { it == "vp_token" || it == "id_token" }) {
            throw RequestValidationException("unsupported_response_type", "response_type ${responseTypes.joinToString(" ")} is not supported")
        }
        if ("id_token" in responseTypes) specs += "SIOPv2"
        val responseMode = ResponseMode.fromWire(p.str("response_mode") ?: "fragment")
            ?: throw RequestValidationException("invalid_request", "Unsupported response_mode '${p.str("response_mode")}'")
        if (responseMode.dcApi && raw.channel != RequestChannel.DC_API) {
            throw RequestValidationException("invalid_request", "dc_api response modes are only valid over the DC API")
        }
        val nonce = p.str("nonce") ?: throw RequestValidationException("invalid_request", "nonce is required")

        // What is asked for: DCQL (draft 22+), Presentation Exchange (by value, by reference or in claims), or only an id_token.
        val dcql = p.obj("dcql_query")
        val definition = p.obj("presentation_definition")
            ?: p.str("presentation_definition_uri")?.let { fetchJson(it, "presentation_definition_uri") }
            ?: p.obj("claims")?.obj("vp_token")?.obj("presentation_definition")
        if ("vp_token" in responseTypes && dcql == null && definition == null) {
            throw RequestValidationException("invalid_request", "vp_token requested without dcql_query or presentation_definition")
        }
        if (definition != null) specs += "DIF Presentation Exchange 2.0"
        specs += if (dcql != null) "OpenID4VP draft 22-28 (DCQL)" else "OpenID4VP draft 13-21"

        val clientMetadata = p.obj("client_metadata") ?: p.obj("registration")
            ?: p.str("client_metadata_uri")?.let { fetchJson(it, "client_metadata_uri") }
            ?: p.str("registration_uri")?.let { fetchJson(it, "registration_uri") }

        val responseUri = p.str("response_uri") ?: if (responseMode == ResponseMode.DIRECT_POST || responseMode == ResponseMode.DIRECT_POST_JWT) p.str("redirect_uri") else null
        val redirectUri = if (responseUri == null) p.str("redirect_uri") else null
        val target = responseUri ?: redirectUri
        if (!responseMode.dcApi) {
            if (target == null) throw RequestValidationException("invalid_request", "No response_uri or redirect_uri")
            // Fragment and query responses are opened by the system and may use a custom scheme; posts need https.
            if (responseMode.posted && !isAcceptableEndpoint(target, allowInsecureLoopback)) {
                throw RequestValidationException("invalid_request", "Response endpoint must be an https URL")
            }
        }

        val jws = raw.requestObject
        if (jws != null) {
            val now = Clock.System.now().epochSeconds
            jws.payload.long("exp")?.let { if (it < now - 60) throw RequestValidationException("invalid_request_object", "Request object expired") }
            jws.payload.long("nbf")?.let { if (it > now + 60) throw RequestValidationException("invalid_request_object", "Request object not yet valid") }
            raw.outer["client_id"]?.let { outer ->
                jws.payload.str("client_id")?.let { inner ->
                    if (inner != outer) throw RequestValidationException("invalid_request_object", "client_id in request object differs from the invocation")
                }
            }
        }
        val verifier = authenticate(raw, jws, target, warnings)

        var request = ValidatedAuthorizationRequest(
            raw = raw,
            verifier = verifier,
            responseMode = responseMode,
            responseUri = responseUri,
            nonce = nonce,
            state = p.str("state"),
            dcqlQuery = dcql ?: JsonObject(emptyMap()),
            transactionData = p.transactionDataStrings(),
            clientMetadata = clientMetadata,
            verifierInfo = p.verifierInfoEntries(),
            expectedOrigins = p.strList("expected_origins"),
            warnings = warnings,
            presentationDefinition = definition,
            responseTypes = responseTypes,
            redirectUri = redirectUri,
            profile = dialect?.id ?: "legacy",
            specs = specs.toList(),
        )
        if (dialect != null) {
            val did = verifier.did
            val trust = did?.let { dialect.verifierTrust(it, request) }
            request = request.copy(
                verifier = if (trust != null) verifier.copy(trust = trust) else verifier,
                warnings = warnings + dialect.warnings(request),
            )
        }
        return request
    }

    private suspend fun authenticate(raw: RawAuthorizationRequest, jws: Jws?, target: String?, warnings: MutableList<String>): VerifierIdentityInfo {
        val p = raw.params
        val rawClientId = p.str("client_id") ?: raw.outer["client_id"]
            ?: throw RequestValidationException("invalid_request", "client_id is required")
        // Drafts 15-21 name the scheme in client_id_scheme; drafts 22-23 prefix the client_id (did:, x509_san_dns:, x509_san_uri:).
        val scheme = p.str("client_id_scheme") ?: when {
            rawClientId.startsWith("did:") -> "did"
            rawClientId.startsWith("decentralized_identifier:") -> "did"
            rawClientId.startsWith("x509_san_dns:") -> "x509_san_dns"
            rawClientId.startsWith("x509_san_uri:") -> "x509_san_uri"
            rawClientId.startsWith("x509_hash:") -> "x509_hash"
            rawClientId.startsWith("redirect_uri:") -> "redirect_uri"
            jws?.x5c != null -> "x509_san_dns"
            else -> "pre-registered"
        }
        val value = rawClientId.substringAfter("$scheme:", rawClientId).removePrefix("decentralized_identifier:")
        val unknown = TrustDecision.unknown("The Verifier is not authenticated", labels = setOf(TrustLabel.UNSIGNED_REQUEST))
        return when (scheme) {
            "did" -> {
                val req = jws ?: throw RequestValidationException("invalid_request", "DID clients must sign their requests")
                val did = value
                val kid = req.kid
                if (kid != null && kid.contains('#') && !kid.startsWith("#") && kid.substringBefore('#') != did) {
                    throw RequestValidationException("invalid_request_object", "kid does not reference the client DID")
                }
                val vm = try {
                    didResolver.resolveKey(did, kid?.takeIf { it.contains('#') })
                } catch (e: Exception) {
                    throw RequestValidationException("invalid_client", "DID resolution failed: ${e.message}", cause = e)
                }
                try {
                    req.verify(vm.key)
                } catch (e: Exception) {
                    throw RequestValidationException("invalid_request_object", "Request object is not signed by $did", cause = e)
                }
                val trust = didTrust.decideOrDefault(did, TrustRole.VERIFIER, "Request signed by a key of $did; the DID is not in a trust list")
                VerifierIdentityInfo(ClientId(rawClientId, ClientIdPrefix.DECENTRALIZED_IDENTIFIER, did), rawClientId, trust.anchorName ?: did, null, emptyList(), did, trust)
            }
            "x509_san_dns", "x509_san_uri", "x509_hash" -> {
                val req = jws ?: throw RequestValidationException("invalid_request", "$scheme clients must sign their requests")
                val chain = req.x5c ?: throw RequestValidationException("invalid_request_object", "x5c header is required")
                try {
                    chain.validate(requireBasicConstraints = false)
                } catch (e: Exception) {
                    throw RequestValidationException("invalid_request_object", "x5c chain is invalid: ${e.message}", cause = e)
                }
                val leaf = chain.certificates.first()
                req.verify(VerificationKey.fromCertificate(leaf))
                val san = leaf.subjectAltNames()
                val ok = when (scheme) {
                    "x509_san_dns" -> san.dnsNames.any { it.equals(value, ignoreCase = true) }
                    "x509_san_uri" -> san.uris.any { it == value }
                    else -> true
                }
                if (!ok) throw RequestValidationException("invalid_client", "client_id $value is not a SAN of the signing certificate")
                val trust = trustRegistry.decide(TrustRole.VERIFIER, chain.certificates)
                if (trust.environment == null && !policy.allowUnanchoredX509) {
                    throw RequestValidationException("access_denied", "Verifier certificate does not chain to a trusted anchor")
                }
                if (scheme == "x509_san_dns" && trust.environment == null && target != null && runCatching { hostOf(target) }.getOrNull()?.let { h -> h == value || h.endsWith(".$value") } != true) {
                    warnings += "Response endpoint host is not the certificate's name $value"
                }
                VerifierIdentityInfo(ClientId(rawClientId, ClientIdPrefix.X509_SAN_DNS, value), rawClientId, leaf.organization() ?: leaf.displaySubject(), chain, san.dnsNames, null, trust)
            }
            "redirect_uri" -> {
                if (jws != null) warnings += "redirect_uri client signed its request; the signature cannot be checked against anything"
                if (target != null && target != value) throw RequestValidationException("invalid_request", "Response endpoint must equal the redirect_uri client identifier")
                VerifierIdentityInfo(ClientId(rawClientId, ClientIdPrefix.REDIRECT_URI, value), rawClientId, runCatching { hostOf(value) }.getOrDefault(value), null, emptyList(), null, unknown)
            }
            else -> {
                val reg = policy.preRegistered.firstOrNull { it.clientId == rawClientId }
                if (reg != null) {
                    if (jws != null && reg.keys.none { k -> runCatching { jws.verify(k) }.isSuccess }) {
                        throw RequestValidationException("invalid_request_object", "Request object not signed by a registered key")
                    }
                    VerifierIdentityInfo(ClientId.parse(rawClientId), rawClientId, reg.displayName, null, emptyList(), null,
                        TrustDecision(if (reg.official) TrustTier.T1 else TrustTier.T3, null, reg.official, reg.displayName, emptySet()))
                } else {
                    // An unregistered client_id without a scheme cannot be authenticated; the consent screen says so.
                    warnings += "client_id '$rawClientId' is not authenticated"
                    val name = runCatching { hostOf(target ?: rawClientId) }.getOrNull() ?: rawClientId
                    VerifierIdentityInfo(ClientId(rawClientId, ClientIdPrefix.PRE_REGISTERED, rawClientId), rawClientId, name, null, emptyList(), null, unknown)
                }
            }
        }
    }

    private suspend fun fetchJson(url: String, name: String): JsonObject {
        if (!isAcceptableEndpoint(url, allowInsecureLoopback)) throw RequestValidationException("invalid_request", "$name must be https")
        val resp = httpClient.get(url)
        if (!resp.status.isSuccess()) throw RequestValidationException("invalid_request", "$name returned HTTP ${resp.status.value}")
        return parseJsonObject(resp.bodyAsText(), "invalid_request")
    }
}
