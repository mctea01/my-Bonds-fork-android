package diw.wallet.core.oid4vp

import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
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
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import diw.wallet.core.x509.displaySubject
import diw.wallet.core.x509.dnsMatches
import diw.wallet.core.x509.organization
import diw.wallet.core.x509.subjectAltNames
import diw.wallet.core.x509.x509Hash
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.X509CertChain
import kotlin.time.Clock

/**
 * The wallet-side request validation layer that Multipaz 0.101.0 lacks: it authenticates the Verifier
 * according to the client_id prefix, binds the client_id to the signing certificate or key, enforces
 * expected_origins for DC API requests and checks the response endpoint.
 */
class RequestValidator(
    private val trustRegistry: TrustRegistry,
    private val didResolver: DidResolver,
    private val policy: PresentationPolicy,
    private val allowInsecureLoopback: Boolean,
    /**
     * Trust for a Verifier identified by a DID: the same sources as for DID issuers and pre-1.0 DID clients (TWDIW
     * trust list, DIDs the user trusts, Linked Domains). A DID none of them knows stays T3.
     */
    private val didTrust: DidTrust = DidTrust.NONE,
) {
    suspend fun validate(raw: RawAuthorizationRequest): ValidatedAuthorizationRequest {
        val p = raw.params
        val warnings = mutableListOf<String>()

        // Response type and mode.
        val responseType = p.str("response_type")
        if (responseType != "vp_token") {
            throw RequestValidationException("unsupported_response_type", "response_type must be vp_token (got $responseType)")
        }
        val responseMode = ResponseMode.fromWire(p.str("response_mode") ?: if (raw.channel == RequestChannel.DC_API) "dc_api" else "fragment")
            ?: throw RequestValidationException("invalid_request", "Unsupported response_mode '${p.str("response_mode")}'")
        if (!responseMode.standard) throw RequestValidationException("invalid_request", "response_mode ${responseMode.wire} is not part of OpenID4VP 1.0")
        if (raw.channel == RequestChannel.DC_API && !responseMode.dcApi) {
            throw RequestValidationException("invalid_request", "DC API requests must use dc_api or dc_api.jwt")
        }
        if (raw.channel == RequestChannel.URI && responseMode.dcApi) {
            throw RequestValidationException("invalid_request", "dc_api response modes are only valid over the DC API")
        }
        if (policy.haip && !responseMode.encrypted) {
            throw RequestValidationException("invalid_request", "HAIP requires an encrypted response (direct_post.jwt / dc_api.jwt)")
        }
        val nonce = p.str("nonce") ?: throw RequestValidationException("invalid_request", "nonce is required")
        if (nonce.length < 16) warnings += "nonce is shorter than 16 characters"
        val dcql = p.obj("dcql_query")
            ?: if (p.containsKey("presentation_definition") || p.containsKey("presentation_definition_uri"))
                throw RequestValidationException("invalid_request", "Presentation Exchange is not part of OpenID4VP 1.0")
            else throw RequestValidationException("invalid_request", "dcql_query is required")
        if (p.containsKey("presentation_definition")) {
            throw RequestValidationException("invalid_request", "dcql_query and presentation_definition must not both be present")
        }
        val state = p.str("state")
        val responseUri = p.str("response_uri")
        if (!responseMode.dcApi) {
            if (responseUri == null) throw RequestValidationException("invalid_request", "response_uri is required for ${responseMode.wire}")
            if (p.containsKey("redirect_uri")) throw RequestValidationException("invalid_request", "redirect_uri must not be used with ${responseMode.wire}")
            if (!isAcceptableEndpoint(responseUri, allowInsecureLoopback)) {
                throw RequestValidationException("invalid_request", "response_uri must be an https URL")
            }
        }
        val clientMetadata = p.obj("client_metadata")
        if (responseMode.encrypted) {
            val keys = clientMetadata?.obj("jwks")?.get("keys") as? kotlinx.serialization.json.JsonArray
            if (keys.isNullOrEmpty()) {
                throw RequestValidationException("invalid_request", "Encrypted response requested but client_metadata.jwks has no keys")
            }
        }

        // Request object generic checks.
        val jws = raw.requestObject
        if (jws != null) {
            if (policy.requireRequestObjectTyp && jws.typ != "oauth-authz-req+jwt") {
                throw RequestValidationException("invalid_request_object", "Request object typ must be oauth-authz-req+jwt (got ${jws.typ})")
            }
            val now = Clock.System.now().epochSeconds
            jws.payload.long("exp")?.let { if (it < now - 60) throw RequestValidationException("invalid_request_object", "Request object expired") }
            jws.payload.long("nbf")?.let { if (it > now + 60) throw RequestValidationException("invalid_request_object", "Request object not yet valid") }
            raw.outer["client_id"]?.let { outerId ->
                if (jws.payload.str("client_id") != outerId) {
                    throw RequestValidationException("invalid_request_object", "client_id in request object differs from the invocation")
                }
            }
            if (raw.walletNonce != null && jws.payload.str("wallet_nonce") != raw.walletNonce) {
                throw RequestValidationException("invalid_request_object", "wallet_nonce mismatch")
            }
        } else if (policy.haip) {
            throw RequestValidationException("invalid_request", "HAIP requires signed requests")
        }

        // Client authentication.
        val verifier = authenticateClient(raw, responseMode, responseUri, warnings)

        // DC API origin binding.
        val expectedOrigins = p.strList("expected_origins")
        if (raw.channel == RequestChannel.DC_API && jws != null) {
            val origin = raw.origin ?: throw RequestValidationException("invalid_request", "Caller origin unknown for signed DC API request")
            if (expectedOrigins.isEmpty()) {
                throw RequestValidationException("invalid_request", "Signed DC API requests must contain expected_origins")
            }
            if (expectedOrigins.none { it.removeSuffix("/") == origin }) {
                throw RequestValidationException("invalid_request", "Caller origin $origin is not in expected_origins")
            }
        }

        val transactionData = p.transactionDataStrings()
        val labels = buildSet {
            addAll(verifier.trust.labels)
            if (transactionData.isNotEmpty()) add(TrustLabel.HAS_TRANSACTION_DATA)
        }
        return ValidatedAuthorizationRequest(
            raw = raw,
            verifier = verifier.copy(trust = verifier.trust.copy(labels = labels)),
            responseMode = responseMode,
            responseUri = responseUri,
            nonce = nonce,
            state = state,
            dcqlQuery = dcql,
            transactionData = transactionData,
            clientMetadata = clientMetadata,
            verifierInfo = p.verifierInfoEntries(),
            expectedOrigins = expectedOrigins,
            warnings = warnings,
        )
    }

    private suspend fun authenticateClient(
        raw: RawAuthorizationRequest,
        responseMode: ResponseMode,
        responseUri: String?,
        warnings: MutableList<String>,
    ): VerifierIdentityInfo {
        val jws = raw.requestObject

        // Unsigned DC API request: the client_id is ignored and replaced by the caller origin.
        if (raw.channel == RequestChannel.DC_API && jws == null) {
            val origin = raw.origin ?: throw RequestValidationException("invalid_request", "Caller origin unknown")
            if (raw.params.containsKey("client_id")) warnings += "client_id ignored for unsigned DC API request"
            return VerifierIdentityInfo(
                clientId = ClientId("web-origin:$origin", ClientIdPrefix.WEB_ORIGIN, origin),
                effectiveClientId = "origin:$origin",
                displayName = origin,
                certificateChain = null,
                dnsNames = emptyList(),
                did = null,
                trust = TrustDecision.unknown("Unsigned request; only the browser-provided origin is known", labels = setOf(TrustLabel.UNSIGNED_REQUEST)),
            )
        }

        val rawClientId = raw.params.str("client_id") ?: throw RequestValidationException("invalid_request", "client_id is required")
        val clientId = ClientId.parse(rawClientId)
        if (policy.haip && clientId.prefix != ClientIdPrefix.X509_HASH) {
            throw RequestValidationException("invalid_client", "HAIP requires the x509_hash client identifier prefix")
        }
        return when (clientId.prefix) {
            ClientIdPrefix.ORIGIN, ClientIdPrefix.WEB_ORIGIN ->
                throw RequestValidationException("invalid_client", "Prefix '${clientId.prefix.wire}' is reserved for the wallet")

            ClientIdPrefix.REDIRECT_URI -> {
                if (!policy.allowRedirectUriClients) throw RequestValidationException("invalid_client", "redirect_uri clients are disabled")
                if (jws != null) throw RequestValidationException("invalid_request", "redirect_uri client requests must not be signed")
                if (raw.channel == RequestChannel.DC_API) throw RequestValidationException("invalid_client", "redirect_uri prefix is not allowed over the DC API")
                if (responseUri != clientId.value) {
                    throw RequestValidationException("invalid_request", "response_uri must equal the redirect_uri client identifier")
                }
                VerifierIdentityInfo(
                    clientId, rawClientId, hostOf(clientId.value), null, emptyList(), null,
                    TrustDecision.unknown("Unsigned request; the Verifier is not authenticated", labels = setOf(TrustLabel.UNSIGNED_REQUEST))
                )
            }

            ClientIdPrefix.X509_SAN_DNS, ClientIdPrefix.X509_HASH -> authenticateX509(raw, jws, clientId, responseMode, responseUri, warnings)

            ClientIdPrefix.DECENTRALIZED_IDENTIFIER -> {
                if (!policy.allowDecentralizedIdentifier) throw RequestValidationException("invalid_client", "decentralized_identifier clients are disabled")
                val req = jws ?: throw RequestValidationException("invalid_request", "decentralized_identifier requests must be signed")
                val did = clientId.value
                if (!did.startsWith("did:")) throw RequestValidationException("invalid_client", "decentralized_identifier value is not a DID")
                val kid = req.kid ?: throw RequestValidationException("invalid_request_object", "kid header is required for DID-signed requests")
                if (!kid.startsWith("#") && kid.substringBefore('#') != did) {
                    throw RequestValidationException("invalid_request_object", "kid does not reference the client DID")
                }
                val vm = try {
                    didResolver.resolveKey(did, kid)
                } catch (e: Exception) {
                    throw RequestValidationException("invalid_client", "DID resolution failed: ${e.message}", cause = e)
                }
                req.verify(vm.key)
                val trust = didTrust.decideOrDefault(did, TrustRole.VERIFIER, "Request signed by a key of $did; the DID is not in a trust list")
                VerifierIdentityInfo(clientId, rawClientId, trust.anchorName ?: did, null, emptyList(), did, trust)
                    .also { checkSignedResponseTarget(it, responseMode, raw) }
            }

            ClientIdPrefix.VERIFIER_ATTESTATION -> authenticateVerifierAttestation(raw, jws, clientId, responseUri)

            ClientIdPrefix.OPENID_FEDERATION ->
                throw RequestValidationException("invalid_client", "openid_federation trust chains are not supported yet")

            ClientIdPrefix.PRE_REGISTERED -> {
                val reg = policy.preRegistered.firstOrNull { it.clientId == rawClientId }
                    ?: throw RequestValidationException("invalid_client", "Unknown client_id '$rawClientId' (not pre-registered and no supported prefix)")
                if (jws != null) {
                    if (reg.keys.none { k -> runCatching { jws.verify(k) }.isSuccess }) {
                        throw RequestValidationException("invalid_request_object", "Request object not signed by a registered key")
                    }
                } else if (reg.keys.isNotEmpty()) {
                    throw RequestValidationException("invalid_request", "Registered client must sign its requests")
                }
                if (responseUri != null && reg.responseUris.isNotEmpty() && responseUri !in reg.responseUris) {
                    throw RequestValidationException("invalid_request", "response_uri is not registered for this client")
                }
                VerifierIdentityInfo(
                    clientId, rawClientId, reg.displayName, null, emptyList(), null,
                    TrustDecision(if (reg.official) TrustTier.T1 else TrustTier.T2, null, reg.official, reg.displayName, emptySet())
                )
            }
        }
    }

    private suspend fun authenticateX509(
        raw: RawAuthorizationRequest,
        jws: Jws?,
        clientId: ClientId,
        responseMode: ResponseMode,
        responseUri: String?,
        warnings: MutableList<String>,
    ): VerifierIdentityInfo {
        val req = jws ?: throw RequestValidationException("invalid_request", "${clientId.prefix.wire} requests must be signed")
        val chain: X509CertChain = req.x5c ?: throw RequestValidationException("invalid_request_object", "x5c header is required")
        val leaf = chain.certificates.first()
        try {
            chain.validate(requireBasicConstraints = false)
        } catch (e: Exception) {
            throw RequestValidationException("invalid_request_object", "x5c chain is invalid: ${e.message}", cause = e)
        }
        req.verify(VerificationKey.fromCertificate(leaf))

        val san = leaf.subjectAltNames()
        when (clientId.prefix) {
            ClientIdPrefix.X509_SAN_DNS -> {
                if (san.dnsNames.none { it.equals(clientId.value, ignoreCase = true) }) {
                    throw RequestValidationException("invalid_client", "client_id ${clientId.value} is not a dNSName SAN of the signing certificate")
                }
            }
            ClientIdPrefix.X509_HASH -> {
                if (leaf.x509Hash() != clientId.value) {
                    throw RequestValidationException("invalid_client", "x509_hash does not match the signing certificate")
                }
            }
            else -> error("unreachable")
        }

        val decision = trustRegistry.decide(TrustRole.VERIFIER, chain.certificates)
        if (decision.environment == null && !policy.allowUnanchoredX509) {
            throw RequestValidationException("access_denied", "Verifier certificate does not chain to a trusted anchor")
        }
        // For x509_san_dns, an unanchored client may not pick an arbitrary response_uri.
        if (clientId.prefix == ClientIdPrefix.X509_SAN_DNS && decision.environment == null && responseUri != null) {
            if (!dnsMatches(clientId.value, hostOf(responseUri))) {
                throw RequestValidationException("invalid_request", "response_uri host must match the x509_san_dns client identifier")
            }
        }
        // x509_hash puts no constraint on response_uri (OpenID4VP 1.0). Without an anchor the certificate is self-asserted,
        // so a host check would not add protection; the consent screen shows the destination and this warning instead.
        if (clientId.prefix == ClientIdPrefix.X509_HASH && decision.environment == null && responseUri != null) {
            val host = hostOf(responseUri)
            if (san.dnsNames.none { dnsMatches(it, host) } && san.uris.none { u -> runCatching { hostOf(u) }.getOrNull()?.let { dnsMatches(it, host) } == true }) {
                warnings += "response_uri host $host is not among the names in the unanchored signing certificate"
            }
        }
        val display = leaf.organization() ?: leaf.displaySubject()
        return VerifierIdentityInfo(
            clientId = clientId,
            effectiveClientId = clientId.raw,
            displayName = display,
            certificateChain = chain,
            dnsNames = san.dnsNames,
            did = null,
            trust = decision,
        ).also { checkSignedResponseTarget(it, responseMode, raw) }
    }

    private suspend fun authenticateVerifierAttestation(
        raw: RawAuthorizationRequest,
        jws: Jws?,
        clientId: ClientId,
        responseUri: String?,
    ): VerifierIdentityInfo {
        val req = jws ?: throw RequestValidationException("invalid_request", "verifier_attestation requests must be signed")
        val attJwt = req.header.str("jwt") ?: throw RequestValidationException("invalid_request_object", "jwt header with the Verifier attestation is required")
        val att = Jws.parse(attJwt)
        if (att.typ != "verifier-attestation+jwt") throw RequestValidationException("invalid_client", "Verifier attestation typ must be verifier-attestation+jwt")
        val chain = att.x5c ?: throw RequestValidationException("invalid_client", "Verifier attestation must carry x5c")
        try {
            chain.validate(requireBasicConstraints = false)
        } catch (e: Exception) {
            throw RequestValidationException("invalid_client", "Verifier attestation chain invalid: ${e.message}", cause = e)
        }
        att.verify(VerificationKey.fromCertificate(chain.certificates.first()))
        val claims = att.payload
        if (claims.str("sub") != clientId.value) throw RequestValidationException("invalid_client", "Verifier attestation sub does not match client_id")
        claims.long("exp")?.let { if (it < Clock.System.now().epochSeconds) throw RequestValidationException("invalid_client", "Verifier attestation expired") }
        val cnfJwk = claims.obj("cnf")?.obj("jwk") ?: throw RequestValidationException("invalid_client", "Verifier attestation without cnf.jwk")
        req.verify(VerificationKey.fromJwk(cnfJwk))
        val redirectUris = claims.strList("redirect_uris")
        if (responseUri != null && redirectUris.isNotEmpty() && responseUri !in redirectUris) {
            throw RequestValidationException("invalid_request", "response_uri not listed in the Verifier attestation")
        }
        val decision = trustRegistry.decide(TrustRole.VERIFIER, chain.certificates)
        if (decision.environment == null) {
            throw RequestValidationException("invalid_client", "Verifier attestation issuer is not trusted")
        }
        return VerifierIdentityInfo(
            clientId, clientId.raw, claims.str("name") ?: clientId.value, chain, emptyList(), null, decision
        )
    }

    private fun checkSignedResponseTarget(info: VerifierIdentityInfo, mode: ResponseMode, raw: RawAuthorizationRequest) {
        if (raw.channel == RequestChannel.DC_API && !mode.dcApi) {
            throw RequestValidationException("invalid_request", "DC API request with non DC API response mode")
        }
        // A DID client already proved its key by the request signature; a T4 from a DID trust source (a declared
        // linked domain that cannot be verified now) is a risk for the user to confirm, not an unauthenticated request.
        if (info.trust.tier == TrustTier.T4 && raw.requestObject != null && info.did == null) {
            throw RequestValidationException("invalid_request_object", "Signed request without an authenticated Verifier")
        }
    }
}
