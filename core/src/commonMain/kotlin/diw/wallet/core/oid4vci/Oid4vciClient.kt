package diw.wallet.core.oid4vci

import diw.wallet.core.compat.DialectSet
import diw.wallet.core.compat.Draft11Dialect
import diw.wallet.core.compat.HolderProfile
import diw.wallet.core.compat.IssuanceDialect
import diw.wallet.core.compat.OutboundCredentialContext
import diw.wallet.core.compat.ProofKid
import diw.wallet.core.compat.ProofStyle
import diw.wallet.core.compat.TokenContext
import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.w3c.DataIntegrity
import diw.wallet.core.w3c.W3cEncoding
import diw.wallet.core.w3c.W3cInspector
import diw.wallet.core.w3c.W3cVc
import diw.wallet.core.w3c.W3cVcCredential
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.cose.CoseTextLabel
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.long
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.queryParameters
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import kotlin.coroutines.cancellation.CancellationException
import io.ktor.client.HttpClient
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.URLBuilder
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.coroutines.delay
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
import org.multipaz.crypto.JsonWebEncryption
import org.multipaz.credential.Credential
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.sdjwt.credential.KeyBoundSdJwtVcCredential
import org.multipaz.sdjwt.credential.KeylessSdJwtVcCredential
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import org.multipaz.webtoken.buildJwt
import kotlin.time.Clock

/** How credential keys are created for one issuance. */
data class KeyRequest(
    val secureArea: SecureArea,
    /** Builds key settings; the argument is the issuer c_nonce (used as attestation challenge). */
    val createKeySettings: suspend (challenge: ByteString) -> CreateKeySettings,
    /** Number of credentials (keys) to request; capped by the issuer batch size. */
    val count: Int = 1,
    /** Whether the keys require user verification (reported in key attestation). */
    val userAuthentication: Boolean = false,
    /** Storage label for UI and records, e.g. strongbox, tee, software. */
    val keyStorage: String? = null,
)

data class AccessToken(
    val value: String,
    val type: String,
    val expiresAt: Long?,
    val refreshToken: String?,
    /** credential_configuration_id to credential_identifiers from authorization_details. */
    val credentialIdentifiers: Map<String, List<String>>,
    /** The token response as received, for dialects that read fields outside OpenID4VCI 1.0. */
    val raw: JsonObject = JsonObject(emptyMap()),
) {
    val authorizationHeader: String get() = if (type.equals("DPoP", ignoreCase = true)) "DPoP $value" else "Bearer $value"
}

/** State of one issuance interaction with one credential issuer. Not thread safe. */
class IssuanceSession internal constructor(
    val offer: CredentialOffer?,
    val issuer: IssuerMetadata,
    val authServer: AuthServerMetadata,
    internal val dpop: DpopSigner?,
    internal val issuerState: String?,
    /** Dialects of this session; the owner, if any, is the profile the issuer follows. */
    internal val compat: DialectSet,
    /** Wallet provider for this issuer (client_id, client and key attestations). */
    internal val provider: WalletProvider,
) {
    /** Specifications this session followed besides OpenID4VCI 1.0, e.g. TWDIW or OpenID4VCI draft 13. */
    val specs: Set<String> get() = compat.specs

    /** Profile that owns the session (twdiw, draft11), or null for an OpenID4VCI 1.0 issuer. */
    val profile: String? get() = compat.owner?.id

    var accessToken: AccessToken? = null
        internal set
    internal var pkceVerifier: String? = null
    internal var state: String? = null
    internal var redirectUri: String? = null
    internal var requestedConfigurations: List<String> = emptyList()
    internal var anonymous: Boolean = false
    internal var attestationChallenge: String? = null
    internal var clientAuthMethod: String? = null
    /** Response encryption key of each deferred transaction; issuers may encrypt the deferred response with it. */
    internal val responseKeys = mutableMapOf<String, EcPrivateKey>()

    val txCode: TxCode? get() = offer?.preAuthorized?.txCode
    val offeredConfigurations: List<CredentialConfiguration>
        get() = (offer?.credentialConfigurationIds ?: requestedConfigurations).mapNotNull { issuer.configurations[it] }

    private var selection: List<String>? = null

    /** Configurations the user chose to receive; defaults to everything offered (or requested). */
    val selectedConfigurations: List<CredentialConfiguration>
        get() = selection?.mapNotNull { issuer.configurations[it] } ?: offeredConfigurations

    /** Restricts this issuance to [ids]; for a wallet-initiated session any supported configuration may be chosen. */
    fun select(ids: List<String>) {
        val allowed = offer?.credentialConfigurationIds ?: issuer.configurations.keys
        selection = ids.filter { it in allowed && it in issuer.configurations }
        if (offer == null) requestedConfigurations = selection!!
    }
}

sealed class IssuanceResult {
    abstract val document: Document

    data class Issued(
        override val document: Document,
        val credentials: List<Credential>,
        val trust: TrustDecision,
        val notificationId: String?,
    ) : IssuanceResult()

    data class Deferred(
        override val document: Document,
        val transactionId: String,
        val intervalSeconds: Long,
        val configurationId: String,
        /** True for a draft 11 acceptance_token, sent as a bearer token to the deferred endpoint. */
        val acceptanceToken: Boolean = false,
    ) : IssuanceResult()
}

/**
 * OpenID4VCI 1.0 wallet client: offers, pre-authorized and authorization code flows (PKCE, PAR),
 * DPoP, wallet attestation client authentication, nonce endpoint, jwt and attestation proofs, batch,
 * request and response encryption, deferred issuance and notifications.
 */
class Oid4vciClient(
    private val httpClient: HttpClient,
    private val trustRegistry: TrustRegistry,
    private val environment: EnvironmentPolicy,
    private val walletProvider: WalletProvider,
    private val documentStore: DocumentStore,
    private val locales: List<String> = listOf("zh-TW", "en"),
    private val preferEncryption: Boolean = true,
    /** Non-standard or pre-1.0 behaviour (see [IssuanceDialect]); empty means OpenID4VCI 1.0 only. */
    private val dialects: List<IssuanceDialect> = emptyList(),
    /** Wallet-level holder keys for profiles that bind all their credentials to one holder (TWDIW). */
    private val holderIdentities: HolderIdentities? = null,
    /** Trust for issuers identified by a DID (TWDIW trust list, linked domains). */
    private val didTrust: DidTrust = DidTrust.NONE,
    /** OpenID Federation Trust Anchors; an issuer that resolves to one takes its metadata and tier from the chain. */
    federationAnchors: suspend () -> List<diw.wallet.core.federation.FederationAnchor> = { emptyList() },
) {
    private val loopback = environment.insecureLoopbackAllowed
    private val metadata = MetadataFetcher(
        httpClient, trustRegistry, loopback, didTrust,
        diw.wallet.core.federation.FederationResolver(httpClient, { federationAnchors() }, loopback),
    )
    private val offers = CredentialOfferResolver(httpClient, loopback)
    private val inspector = CredentialInspector(httpClient, trustRegistry, loopback, didTrust)
    private val w3cInspector = W3cInspector(httpClient, trustRegistry, loopback, didTrust)

    // ---------------------------------------------------------------- session start

    /**
     * Starts from a credential offer. [entryHint] names the profile whose entry point delivered the offer
     * (twdiw for the modadigitalwallet scheme), so that profile owns the session.
     */
    suspend fun startFromOffer(uri: String, entryHint: String? = null): IssuanceSession {
        val compat = DialectSet(dialects)
        val offer = offers.resolve(uri, compat)
        compat.claimFor(offer.credentialIssuer, entryHint)
        val issuer = withDialectTrust(metadata.issuer(offer.credentialIssuer, compat), compat)
        val unknown = offer.credentialConfigurationIds.filter { it !in issuer.configurations }
        if (unknown.isNotEmpty()) {
            throw ProtocolException("invalid_credential_offer", "Offer references unknown configurations $unknown")
        }
        val asHint = offer.preAuthorized?.authorizationServer ?: offer.authorizationCode?.authorizationServer
        val asMeta = authorizationServer(issuer, asHint, compat)
        return IssuanceSession(offer, issuer, asMeta, newDpop(asMeta), offer.authorizationCode?.issuerState, compat, walletProvider.forIssuer(issuer.credentialIssuer, asMeta.issuer))
    }

    suspend fun startWalletInitiated(credentialIssuer: String, configurationIds: List<String>, entryHint: String? = null): IssuanceSession {
        val compat = DialectSet(dialects)
        compat.claimFor(credentialIssuer, entryHint)
        val issuer = withDialectTrust(metadata.issuer(credentialIssuer, compat), compat)
        val asMeta = authorizationServer(issuer, null, compat)
        return IssuanceSession(null, issuer, asMeta, newDpop(asMeta), null, compat, walletProvider.forIssuer(issuer.credentialIssuer, asMeta.issuer)).also {
            it.requestedConfigurations = configurationIds.filter { id -> id in issuer.configurations }
        }
    }

    /**
     * The display the issuer currently publishes for [configurationId] (name, logo, colours, card face), read through
     * the same dialects as issuance; [profile] is the profile that owned the original session (twdiw for TWDIW).
     * Null when the configuration is no longer listed.
     */
    suspend fun credentialDisplay(credentialIssuer: String, configurationId: String, profile: String? = null): DisplayInfo? {
        val compat = DialectSet(dialects)
        compat.claimFor(credentialIssuer, profile)
        val issuer = metadata.issuer(credentialIssuer, compat)
        return issuer.configurations[configurationId]?.display?.pick(locales)
    }

    /**
     * Claims the session from the metadata, then lets the owning dialect place an issuer the metadata leads to no
     * trust root (unsigned metadata) through its own registry; a registry failure keeps the metadata decision.
     */
    private suspend fun withDialectTrust(issuer: IssuerMetadata, compat: DialectSet): IssuerMetadata {
        compat.claimFor(issuer)
        val d = compat.owner ?: return issuer
        val trust = runCatching { d.issuerTrust(issuer) }.getOrNull() ?: return issuer
        compat.record(d)
        return issuer.copy(trust = trust)
    }

    /** Authorization server metadata, or what a dialect knows for issuers that publish none (draft 11, TWDIW). */
    private suspend fun authorizationServer(issuer: IssuerMetadata, hint: String?, compat: DialectSet): AuthServerMetadata {
        val identifier = issuer.authorizationServerFor(hint)
        val standard = runCatching { metadata.authorizationServer(identifier) }
        standard.getOrNull()?.let { return it }
        for (d in listOfNotNull(compat.owner) + compat.all) {
            val fallback = d.authorizationServerFallback(issuer) ?: continue
            compat.claim(d)
            return metadata.checkFallback(fallback)
        }
        throw standard.exceptionOrNull()!!
    }

    private suspend fun newDpop(asMeta: AuthServerMetadata): DpopSigner? {
        if (!asMeta.usesDpop) return null
        val supported = asMeta.dpopAlgorithms
        if ("ES256" !in supported && "ESP256" !in supported) return null
        val alg = if ("ES256" in supported) Algorithm.ES256 else Algorithm.ESP256
        return DpopSigner(AsymmetricKey.AnonymousExplicit(Crypto.createEcPrivateKey(EcCurve.P256), alg))
    }

    // ---------------------------------------------------------------- authorization

    /** Pre-authorized code flow; [txCode] is what the user typed when the offer asks for one. */
    suspend fun authorizePreAuthorized(session: IssuanceSession, txCode: String?) {
        val grant = session.offer?.preAuthorized
            ?: throw ProtocolException("invalid_request", "Offer has no pre-authorized code grant")
        if (grant.txCode != null && txCode.isNullOrEmpty()) throw ProtocolException("invalid_tx_code", "Transaction code is required")
        grant.txCode?.length?.let { len ->
            if (txCode!!.length != len) throw ProtocolException("invalid_tx_code", "Transaction code must have $len characters")
        }
        val auth = clientAuthenticationFor(session)
        val extra = session.compat.owned {
            it.tokenParameters(TokenContext(session.offer, session.issuer, session.selectedConfigurations.map { c -> c.id }, txCode?.takeIf { grant.txCode != null }))
        }.orEmpty()
        session.anonymous = auth.method == "none" && session.authServer.preAuthorizedAnonymousAccess && "client_id" !in extra
        val form = Parameters.build {
            append("grant_type", GRANT_PRE_AUTHORIZED_CODE)
            append("pre-authorized_code", grant.preAuthorizedCode)
            if (txCode != null && grant.txCode != null) append("tx_code", txCode)
            if (!session.anonymous) append("client_id", session.provider.clientId)
            for ((k, v) in extra) set(k, v)
        }
        session.accessToken = tokenRequest(session, form, auth)
    }

    /**
     * Starts the authorization code flow and returns the URL to open in a browser.
     * [redirectUri] must be registered for the wallet (custom scheme or claimed https link).
     */
    suspend fun beginAuthorizationCode(session: IssuanceSession, redirectUri: String, configurationIds: List<String>? = null): String {
        val asMeta = session.authServer
        val endpoint = asMeta.authorizationEndpoint
            ?: throw ProtocolException("invalid_as_metadata", "Authorization server has no authorization_endpoint")
        if (asMeta.codeChallengeMethods.isNotEmpty() && "S256" !in asMeta.codeChallengeMethods) {
            throw ProtocolException("invalid_as_metadata", "Authorization server does not support PKCE S256")
        }
        val ids = configurationIds ?: session.selectedConfigurations.map { it.id }
        session.requestedConfigurations = ids
        val verifier = PlatformCrypto.randomBytes(32).toBase64Url()
        val state = PlatformCrypto.randomBytes(16).toBase64Url()
        session.pkceVerifier = verifier
        session.state = state
        session.redirectUri = redirectUri
        val challenge = PlatformCrypto.sha256(verifier.encodeToByteArray()).toBase64Url()
        val details = buildJsonArray {
            for (id in ids) addJsonObject {
                put("type", "openid_credential")
                put("credential_configuration_id", id)
                if (session.authServer.issuer != session.issuer.credentialIssuer) {
                    putJsonArray("locations") { add(session.issuer.credentialIssuer) }
                }
            }
        }
        // OpenID4VCI 1.0 allows scope or authorization_details. Some issuers (EUDI reference issuer) fail when both
        // are sent, so scope alone is used when every requested configuration has one.
        val scopes = ids.mapNotNull { session.issuer.configurations[it]?.scope }.distinct()
        val useScope = ids.all { session.issuer.configurations[it]?.scope != null }
        val params = Parameters.build {
            append("response_type", "code")
            append("client_id", session.provider.clientId)
            append("redirect_uri", redirectUri)
            append("state", state)
            append("code_challenge", challenge)
            append("code_challenge_method", "S256")
            if (useScope) append("scope", scopes.joinToString(" ")) else append("authorization_details", details.toString())
            session.issuerState?.let { append("issuer_state", it) }
        }
        val par = asMeta.parEndpoint
        if (par == null && asMeta.requirePar) throw ProtocolException("invalid_as_metadata", "PAR required but no endpoint")
        return if (par != null) {
            val auth = clientAuthenticationFor(session)
            val resp = postFormWithDpop(session, par, params, auth, null)
            val json = parseJsonObject(resp.bodyAsText(), "invalid_par_response")
            if (!resp.status.isSuccess()) throw authError(session, auth, json, "PAR failed (${resp.status.value})")
            val requestUri = json.str("request_uri") ?: throw ProtocolException("invalid_par_response", "PAR response without request_uri")
            URLBuilder(endpoint).apply {
                parameters.append("client_id", session.provider.clientId)
                parameters.append("request_uri", requestUri)
            }.buildString()
        } else {
            URLBuilder(endpoint).apply { parameters.appendAll(params) }.buildString()
        }
    }

    /** Completes the authorization code flow with the URL the browser was redirected to. */
    suspend fun completeAuthorizationCode(session: IssuanceSession, redirectedTo: String) {
        val expectedRedirect = session.redirectUri ?: throw ProtocolException("invalid_request", "Authorization was not started")
        if (!redirectedTo.startsWith(expectedRedirect.substringBefore('?'))) {
            throw ProtocolException("invalid_request", "Redirect does not match the registered redirect_uri")
        }
        val q = queryParameters(redirectedTo)
        q["error"]?.let { throw ProtocolException(it, q["error_description"] ?: "Authorization failed") }
        if (q["state"] != session.state) throw ProtocolException("invalid_state", "state mismatch")
        val iss = q["iss"]
        if (iss != null && iss != session.authServer.issuer) {
            if (!session.compat.any { it.acceptsAuthorizationResponseIssuer(session.authServer, iss) }) {
                throw ProtocolException("invalid_request", "iss $iss does not match authorization server ${session.authServer.issuer} (mix-up)")
            }
        }
        if (iss == null && session.authServer.responseIssParameterSupported) {
            throw ProtocolException("invalid_request", "Authorization response is missing iss")
        }
        val code = q["code"] ?: throw ProtocolException("invalid_request", "Authorization response without code")
        val form = Parameters.build {
            append("grant_type", GRANT_AUTHORIZATION_CODE)
            append("code", code)
            append("redirect_uri", expectedRedirect)
            append("code_verifier", session.pkceVerifier!!)
            append("client_id", session.provider.clientId)
        }
        session.state = null
        session.accessToken = tokenRequest(session, form, clientAuthenticationFor(session))
    }

    private data class ClientAuthentication(
        val method: String,
        val attestation: WalletAttestation? = null,
        val assertion: String? = null,
    )

    private suspend fun clientAuthenticationFor(session: IssuanceSession): ClientAuthentication {
        val meta = session.authServer
        val methods = meta.tokenEndpointAuthMethods
        val selected = session.clientAuthMethod
        // Metadata without token_endpoint_auth_methods_supported says nothing about attestation; issuers built on
        // Credo (Animo) still require it, and an unused OAuth-Client-Attestation header is ignored by the rest. That
        // attempt is best effort and only for 1.0 issuers: dialect sessions (TWDIW, draft 11) stay public clients, and
        // a wallet backend that cannot attest leaves the public client path as it was.
        val implicit = selected == null && methods.isEmpty() && session.compat.owner == null
        if (selected == "attest_jwt_client_auth" || (selected == null && "attest_jwt_client_auth" in methods) || implicit) {
            val attestation = try {
                session.provider.walletAttestation()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (implicit || (e is ProtocolException && e.code == "wallet_provider_unsupported")) null
                else throw e
            }
            if (attestation != null) {
                if (meta.challengeEndpoint != null && session.attestationChallenge == null) {
                    val response = httpClient.post(meta.challengeEndpoint)
                    if (response.status.isSuccess()) {
                        session.attestationChallenge = parseJsonObject(response.bodyAsText()).str("attestation_challenge")
                    }
                }
                session.clientAuthMethod = "attest_jwt_client_auth"
                return ClientAuthentication("attest_jwt_client_auth", attestation = attestation)
            }
        }
        if (selected == "private_key_jwt" || (selected == null && "private_key_jwt" in methods)) {
            val assertion = try {
                session.provider.clientAssertion(meta.issuer)
            } catch (e: ProtocolException) {
                if (e.code == "wallet_provider_unsupported") null
                else throw e
            }
            if (assertion != null) {
                session.clientAuthMethod = "private_key_jwt"
                return ClientAuthentication("private_key_jwt", assertion = assertion)
            }
        }
        // Public client: the wallet sends only client_id and the server decides. Many servers (Keycloak, the EUDI
        // issuer) accept public clients with PKCE without listing "none"; a refusal is reported by authError.
        session.clientAuthMethod = "none"
        return ClientAuthentication("none")
    }

    /**
     * An OAuth error response; a refused public client becomes client_authentication_unavailable when the
     * server only lists methods this wallet could not provide.
     */
    private fun authError(session: IssuanceSession, auth: ClientAuthentication, json: JsonObject, fallback: String): ProtocolException {
        val methods = session.authServer.tokenEndpointAuthMethods
        if (auth.method == "none" && json.str("error") == "invalid_client" && methods.isNotEmpty() && "none" !in methods) {
            return ProtocolException(
                "client_authentication_unavailable",
                "Authorization server requires registered client authentication (" + methods.joinToString(", ") + "): " +
                    (json.str("error_description") ?: fallback),
            )
        }
        return oauthError(json, failure(session.compat, json, fallback))
    }

    private suspend fun tokenRequest(session: IssuanceSession, form: Parameters, auth: ClientAuthentication): AccessToken {
        val resp = postFormWithDpop(session, session.authServer.tokenEndpoint, form, auth, null)
        val text = resp.bodyAsText()
        val json = runCatching { parseJsonObject(text) }.getOrElse { JsonObject(emptyMap()) }
        if (!resp.status.isSuccess()) throw authError(session, auth, json, "Token request failed (${resp.status.value})")
        val token = json.str("access_token") ?: throw ProtocolException("invalid_token_response", "No access_token")
        val type = json.str("token_type") ?: "Bearer"
        if (type.equals("DPoP", true) && session.dpop == null) {
            throw ProtocolException("invalid_token_response", "DPoP token issued without DPoP proof")
        }
        val ids = json.arr("authorization_details").orEmpty().filterIsInstance<JsonObject>()
            .filter { it.str("type") == "openid_credential" }
            .mapNotNull { d -> d.str("credential_configuration_id")?.let { it to d.strList("credential_identifiers") } }
            .toMap()
        return AccessToken(
            value = token,
            type = type,
            expiresAt = json.long("expires_in")?.let { Clock.System.now().epochSeconds + it },
            refreshToken = json.str("refresh_token"),
            credentialIdentifiers = ids,
            raw = json,
        )
    }

    /** POSTs a form to the AS with DPoP and client attestation, retrying once on use_dpop_nonce. */
    private suspend fun postFormWithDpop(
        session: IssuanceSession,
        url: String,
        form: Parameters,
        auth: ClientAuthentication,
        accessToken: String?,
    ): HttpResponse {
        var retried = false
        while (true) {
            val current = if (retried) clientAuthenticationFor(session) else auth
            val requestForm = if (current.assertion != null) Parameters.build {
                appendAll(form)
                append("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                append("client_assertion", current.assertion)
            } else form
            val resp = httpClient.post(url) {
                applyDpop(session, "POST", url, accessToken)
                val attestation = current.attestation
                if (attestation != null) {
                    header("OAuth-Client-Attestation", attestation.jwt)
                    header(
                        "OAuth-Client-Attestation-PoP",
                        clientAttestationPop(attestation, session.provider.clientId, session.authServer.issuer, session.attestationChallenge)
                    )
                }
                setBody(FormDataContent(requestForm))
            }
            session.dpop?.updateNonce(url, resp.headers["DPoP-Nonce"])
            resp.headers["OAuth-Client-Attestation-Challenge"]?.let { session.attestationChallenge = it }
            if (!retried && (resp.status == HttpStatusCode.BadRequest || resp.status == HttpStatusCode.Unauthorized)) {
                val err = runCatching { parseJsonObject(resp.bodyAsText()).str("error") }.getOrNull()
                if ((err == "use_dpop_nonce" && resp.headers["DPoP-Nonce"] != null) || err == "use_attestation_challenge") {
                    retried = true
                    continue
                }
            }
            return resp
        }
    }

    private suspend fun HttpRequestBuilder.applyDpop(session: IssuanceSession, method: String, url: String, accessToken: String?) {
        session.dpop?.let { header("DPoP", it.proof(method, url, accessToken)) }
    }

    // ---------------------------------------------------------------- issuance

    /** Requests one credential configuration, verifies the result, and stores it in a new document. */
    suspend fun issue(session: IssuanceSession, configurationId: String, keys: KeyRequest): IssuanceResult {
        val token = session.accessToken ?: throw ProtocolException("invalid_request", "Not authorized")
        val config = session.issuer.configurations[configurationId]
            ?: throw ProtocolException("invalid_request", "Unknown configuration $configurationId")
        val document = createDocument(session, config, keys)
        try {
            return requestAndStore(session, token, config, document, keys)
        } catch (e: Exception) {
            documentStore.deleteDocument(document.identifier)
            throw e
        }
    }

    private suspend fun requestAndStore(
        session: IssuanceSession,
        token: AccessToken,
        config: CredentialConfiguration,
        document: Document,
        keys: KeyRequest,
    ): IssuanceResult {
        val compat = session.compat
        val profile = if (config.format.isW3c) compat.owned { it.holderProfile(session.issuer) } else null
        // A shared holder identity has one key, so one credential is requested.
        val count = if (profile != null) 1 else keys.count.coerceIn(1, session.issuer.batchSize)
        var nonce = fetchNonce(session, token, compat)
        var pending = createPendingCredentials(session, document, config, keys, nonce, count, profile)
        var attempt = 0
        // A dialect that answered a rejected 1.0 request, with that rejection; later attempts use its request shape.
        var alternative: Triple<IssuanceDialect, HttpStatusCode, JsonObject>? = null
        while (true) {
            val holderKeys = if (config.keyBound) pending.map { holderKeyOf(it) } else emptyList()
            val built = if (config.keyBound) buildProofs(session, config, holderKeys, nonce, keys) else null
            val proofs = built?.json
            val identifier = token.credentialIdentifiers[config.id]?.firstOrNull()
            val alt = alternative
            val batch = alt?.first?.batchEndpoint(session.issuer)?.takeIf { (proofs?.arr("jwt")?.size ?: 0) > 1 }
            val (status, json) = if (alt != null && batch != null) {
                // Draft 13 batch endpoint: one single-proof request per key.
                val requests = proofs!!.arr("jwt")!!.mapNotNull { jwt ->
                    alt.first.alternativeCredentialRequest(session.issuer, config, identifier, buildJsonObject { putJsonArray("jwt") { add(jwt) } }, alt.second, alt.third)
                }
                credentialEndpointCall(session, batch, buildJsonObject { putJsonArray("credential_requests") { requests.forEach { add(it) } } }, token)
            } else {
                val body = alt?.let { (d, st, err) -> d.alternativeCredentialRequest(session.issuer, config, identifier, proofs, st, err) }
                    ?: compat.owned { it.credentialRequest(session.issuer, config, identifier, proofs) }
                    ?: buildJsonObject {
                        if (identifier != null) put("credential_identifier", identifier) else put("credential_configuration_id", config.id)
                        proofs?.let { put("proofs", it) }
                    }
                credentialEndpointCall(session, session.issuer.credentialEndpoint, body, token, signingHolder = holderKeys.firstOrNull())
            }
            if (!status.isSuccess() && alternative == null && json.str("error") != "invalid_nonce") {
                val d = dialects.firstOrNull { it.alternativeCredentialRequest(session.issuer, config, identifier, proofs, status, json) != null }
                if (d != null) {
                    compat.record(d)
                    alternative = Triple(d, status, json)
                    compat.first { it.nonceFromError(json) }?.let { nonce = it }
                    continue
                }
            }
            if (status == HttpStatusCode.BadRequest && json.str("error") == "invalid_nonce" && attempt == 0 && config.keyBound) {
                attempt++
                nonce = compat.first { it.nonceFromError(json) } ?: fetchNonce(session, token, compat)
                // Key attestation challenges are bound at key creation, so attested keys must be recreated.
                if (config.proofTypes.values.any { it.keyAttestationsRequired != null } || "jwt" !in config.proofTypes) {
                    pending.forEach { document.deleteCredential(it.identifier) }
                    pending = createPendingCredentials(session, document, config, keys, nonce, count, profile)
                }
                continue
            }
            if (status == HttpStatusCode.Accepted) {
                val tx = json.str("transaction_id") ?: throw ProtocolException("invalid_credential_response", "202 without transaction_id")
                return deferred(document, tx, json, config, false)
            }
            if (!status.isSuccess()) {
                val e = oauthError(json, failure(compat, json, "Credential request failed (${status.value})"))
                if (built?.missingKeyAttestation != true) throw e
                throw ProtocolException(e.code, "${e.message} (the issuer requires key attestation; no wallet provider gave one)")
            }
            if (json["credentials"] == null) {
                compat.first { it.deferral(json) }?.let { return deferred(document, it.id, json, config, it.acceptanceToken) }
            }
            return storeCredentials(session, config, document, pending, json, compat)
        }
    }

    private suspend fun deferred(document: Document, id: String, json: JsonObject, config: CredentialConfiguration, acceptanceToken: Boolean): IssuanceResult.Deferred {
        val record = document.issuanceRecord!!.copy(pendingTransactionId = id)
        document.edit { appData = record.encode() }
        return IssuanceResult.Deferred(document, id, json.long("interval") ?: 5, config.id, acceptanceToken)
    }

    /** Polls the deferred endpoint once. Returns Deferred again while the issuer is not ready. */
    suspend fun pollDeferred(session: IssuanceSession, deferred: IssuanceResult.Deferred): IssuanceResult {
        val endpoint = session.issuer.deferredCredentialEndpoint
            ?: throw ProtocolException("invalid_issuer_metadata", "No deferred_credential_endpoint")
        val config = session.issuer.configurations[deferred.configurationId]!!
        val reuseKey = session.responseKeys[deferred.transactionId]
        val (status, json) = if (deferred.acceptanceToken) {
            // Draft 11: the acceptance token is the bearer token of the deferred request.
            val token = AccessToken(deferred.transactionId, "Bearer", null, null, emptyMap())
            credentialEndpointCall(session, endpoint, JsonObject(emptyMap()), token, reuseKey)
        } else {
            val token = session.accessToken ?: throw ProtocolException("invalid_request", "Not authorized")
            credentialEndpointCall(session, endpoint, buildJsonObject { put("transaction_id", deferred.transactionId) }, token, reuseKey)
        }
        if (status == HttpStatusCode.Accepted || (!status.isSuccess() && session.compat.any { it.isIssuancePending(status, json) })) {
            return deferred.copy(intervalSeconds = json.long("interval") ?: deferred.intervalSeconds)
        }
        session.responseKeys.remove(deferred.transactionId)
        if (!status.isSuccess()) {
            documentStore.deleteDocument(deferred.document.identifier)
            throw oauthError(json, failure(session.compat, json, "Deferred credential request failed (${status.value})"))
        }
        val pending = deferred.document.getPendingCredentials()
        val record = deferred.document.issuanceRecord!!.copy(pendingTransactionId = null)
        deferred.document.edit { appData = record.encode() }
        return storeCredentials(session, config, deferred.document, pending, json, session.compat)
    }

    /** Sends a notification (credential_accepted, credential_failure, credential_deleted). Best effort. */
    suspend fun notify(session: IssuanceSession, notificationId: String, event: String, description: String? = null): Boolean {
        val endpoint = session.issuer.notificationEndpoint ?: return false
        val token = session.accessToken ?: return false
        val body = buildJsonObject {
            put("notification_id", notificationId)
            put("event", event)
            description?.let { put("event_description", it) }
        }
        val resp = withDpopRetry(session, endpoint, token) {
            contentType(ContentType.Application.Json)
            setBody(body.toString())
        }
        return resp.status.isSuccess()
    }

    /** Local type of an SD-JWT configuration: its vct, or what a dialect derives for issuers that omit it. */
    private fun sdJwtType(config: CredentialConfiguration, compat: DialectSet): String =
        config.vct ?: compat.first { it.storageType(config) }
            ?: throw ProtocolException(
                "invalid_issuer_metadata",
                "SD-JWT VC configuration without vct" + if (compat.isEmpty) "" else " (profiles tried: ${compat.ids.joinToString()})",
            )

    /** c_nonce from the nonce endpoint; issuers without one get no nonce unless a dialect knows where theirs is. */
    private suspend fun fetchNonce(session: IssuanceSession, token: AccessToken, compat: DialectSet): String? {
        val endpoint = session.issuer.nonceEndpoint ?: return compat.first { it.nonceWithoutEndpoint(token.raw) }
        var resp = httpClient.post(endpoint)
        // A gateway error (502 to 504) is the issuer's front end failing for a moment; the nonce request has no
        // effect on the issuer, so it is asked once more before giving up.
        if (resp.status.value in 502..504) {
            delay(1500)
            resp = httpClient.post(endpoint)
        }
        session.dpop?.updateNonce(endpoint, resp.headers["DPoP-Nonce"])
        if (!resp.status.isSuccess()) {
            throw ProtocolException("invalid_nonce", "Nonce endpoint returned ${resp.status.value}" +
                if (resp.status.value in 502..504) "（發行端伺服器暫時無法回應，請稍後再試）" else "")
        }
        return parseJsonObject(resp.bodyAsText(), "invalid_nonce").str("c_nonce")
            ?: throw ProtocolException("invalid_nonce", "Nonce response without c_nonce")
    }

    private suspend fun createPendingCredentials(
        session: IssuanceSession,
        document: Document,
        config: CredentialConfiguration,
        keys: KeyRequest,
        nonce: String?,
        count: Int,
        profile: HolderProfile?,
    ): List<Credential> {
        val compat = session.compat
        if (!config.keyBound) {
            return listOf(
                if (config.format.isW3c) W3cVcCredential.createKeyless(document, CredentialDomains.W3C, config.format.wire, config.types)
                else KeylessSdJwtVcCredential.create(document, null, CredentialDomains.SD_JWT_KEYLESS, sdJwtType(config, compat))
            )
        }
        val settings = keys.createKeySettings(ByteString((nonce ?: PlatformCrypto.randomBytes(16).toBase64Url()).encodeToByteArray()))
        if (config.format.isW3c) {
            if (profile != null) {
                val identities = holderIdentities
                    ?: throw ProtocolException("holder_identity_unavailable", "Profile ${profile.id} needs a wallet holder identity store")
                val hk = identities.getOrCreate(profile.id, profile.didMethod, keys.secureArea, settings)
                return listOf(W3cVcCredential.createKeyBound(document, CredentialDomains.W3C, config.format.wire, config.types, hk.secureArea, hk.alias, true, hk.did))
            }
            val style = compat.owned { it.proofStyle(session.issuer, config) }
            val needsDid = config.prefersDidKid || (style != null && style.kid != ProofKid.JWK)
            return List(count) {
                val info = keys.secureArea.createKey(null, settings)
                val did = if (needsDid) HolderKey.didFor(info.publicKey, didMethodFor(config)) else null
                W3cVcCredential.createKeyBound(document, CredentialDomains.W3C, config.format.wire, config.types, keys.secureArea, info.alias, false, did)
            }
        }
        return List(count) {
            when (config.format) {
                CredentialFormatId.MSO_MDOC -> MdocCredential.create(
                    document, null, CredentialDomains.MDOC, keys.secureArea,
                    config.docType ?: throw ProtocolException("invalid_issuer_metadata", "mso_mdoc configuration without doctype"),
                    settings,
                )
                else -> KeyBoundSdJwtVcCredential.create(
                    document, null, CredentialDomains.SD_JWT, keys.secureArea,
                    sdJwtType(config, compat),
                    settings,
                )
            }
        }
    }

    /** DID method for a holder bound to a DID: did:jwk when allowed (or any DID), else did:key. */
    private fun didMethodFor(config: CredentialConfiguration): String {
        val m = config.didMethods
        return when {
            m.isEmpty() || "did" in m || "did:jwk" in m -> "did:jwk"
            "did:key" in m -> "did:key"
            else -> throw ProtocolException("unsupported_binding_method", "Issuer binds to ${m.joinToString()}, this wallet uses did:jwk or did:key")
        }
    }

    private suspend fun holderKeyOf(c: Credential): HolderKey = when (c) {
        is SecureAreaBoundCredential -> HolderKey(c.secureArea, c.secureArea.getKeyInfo(c.alias), shared = false)
        is W3cVcCredential -> {
            val sa = c.secureArea ?: throw ProtocolException("invalid_request", "Credential has no holder key")
            HolderKey(sa, sa.getKeyInfo(c.alias!!), c.sharedKey, c.holderDid)
        }
        else -> throw ProtocolException("invalid_request", "Credential has no holder key")
    }

    /** The proofs of a credential request; [missingKeyAttestation] when the issuer asks for key attestation and none was available. */
    private class Proofs(val json: JsonObject, val missingKeyAttestation: Boolean)

    private suspend fun buildProofs(
        session: IssuanceSession,
        config: CredentialConfiguration,
        holderKeys: List<HolderKey>,
        nonce: String?,
        keys: KeyRequest,
    ): Proofs {
        val jwtInfo = config.proofTypes["jwt"]
        val attInfo = config.proofTypes["attestation"]
        val diInfo = config.proofTypes["di_vp"] ?: config.proofTypes["ldp_vp"]
        val cwtInfo = config.proofTypes["cwt"]
        val attestations by lazy { holderKeys.mapNotNull { it.keyInfo.attestation } }
        val style = session.compat.owned { it.proofStyle(session.issuer, config) }
            ?: ProofStyle(if (config.prefersDidKid) ProofKid.DID_URL else ProofKid.JWK, null)
        return when {
            jwtInfo != null || (attInfo == null && diInfo == null && cwtInfo == null && config.bindingMethods.isNotEmpty()) -> {
                val algs = jwtInfo?.signingAlgorithms.orEmpty()
                val required = jwtInfo?.keyAttestationsRequired != null
                // Without key attestation the jwt proofs are still sent; enforcing key_attestations_required is the issuer's call.
                val keyAttestation = if (required) session.provider.keyAttestation(attestations, nonce, keys.userAuthentication) else null
                val signers = if (keyAttestation != null) holderKeys.take(1) else holderKeys
                val jwts = signers.map { proofJwt(session, config, it, algs, nonce, keyAttestation, style) }
                Proofs(buildJsonObject { putJsonArray("jwt") { jwts.forEach { add(it) } } }, required && keyAttestation == null)
            }
            attInfo != null -> {
                val ka = session.provider.keyAttestation(attestations, nonce, keys.userAuthentication)
                    ?: throw ProtocolException("key_attestation_unavailable", "Issuer requires an attestation proof but the wallet provider gave none")
                Proofs(buildJsonObject { putJsonArray("attestation") { add(ka) } }, false)
            }
            diInfo != null -> {
                val vps = holderKeys.map { diVpProof(session, it, nonce, config) }
                Proofs(buildJsonObject { putJsonArray(if (config.proofTypes.containsKey("di_vp")) "di_vp" else "ldp_vp") { vps.forEach { add(it) } } }, false)
            }
            cwtInfo != null -> {
                val cwts = holderKeys.map { cwtProof(session, it, nonce, style) }
                Proofs(buildJsonObject { putJsonArray("cwt") { cwts.forEach { add(it) } } }, false)
            }
            else -> throw ProtocolException("unsupported_proof_type", "No supported proof type for ${config.id}")
        }
    }

    private fun proofAlg(holder: HolderKey, algs: List<String>): String {
        val curve = holder.publicKey.curve
        return when (curve) {
            EcCurve.P256 -> listOf("ES256", "ESP256")
            EcCurve.P384 -> listOf("ES384", "ESP384")
            EcCurve.P521 -> listOf("ES512", "ESP512")
            EcCurve.ED25519 -> listOf("EdDSA", "Ed25519")
            else -> listOf(holder.keyInfo.algorithm.joseAlgorithmIdentifier ?: "ES256")
        }.let { candidates -> if (algs.isEmpty()) candidates.first() else candidates.firstOrNull { it in algs } }
            ?: throw ProtocolException("unsupported_proof_alg", "Issuer accepts $algs, key curve is $curve")
    }

    private suspend fun proofJwt(
        session: IssuanceSession,
        config: CredentialConfiguration,
        holder: HolderKey,
        algs: List<String>,
        nonce: String?,
        keyAttestation: String?,
        style: ProofStyle,
    ): String {
        val label = proofAlg(holder, algs)
        // A key without its own DID (SD-JWT VC, mdoc) is named with a method the issuer lists.
        val did = if (style.kid != ProofKid.JWK) holder.did ?: HolderKey.didFor(holder.publicKey, didMethodFor(config)) else null
        return buildJwt(
            type = "openid4vci-proof+jwt",
            key = holder.signingKey(label),
            header = {
                when {
                    // The signing key is also named by jwk (allowed next to key_attestation); Credo needs it to pick a verifier.
                    keyAttestation != null -> { put("key_attestation", keyAttestation); put("jwk", holder.publicKey.toJwk()) }
                    style.kid == ProofKid.BARE_DID -> put("kid", did!!)
                    style.kid == ProofKid.DID_URL -> put("kid", DidKeys.verificationMethod(did!!))
                    else -> put("jwk", holder.publicKey.toJwk())
                }
            },
        ) {
            val iss = style.iss ?: session.provider.clientId.takeIf { !session.anonymous }
            iss?.let { put("iss", it) }
            put("aud", session.issuer.credentialIssuer)
            nonce?.let { put("nonce", it) }
        }
    }

    /** di_vp (OpenID4VCI 1.0) / ldp_vp (draft 13) proof: a presentation with a Data Integrity authentication proof. */
    private suspend fun diVpProof(session: IssuanceSession, holder: HolderKey, nonce: String?, config: CredentialConfiguration): JsonObject {
        val did = holder.did ?: HolderKey.didFor(holder.publicKey, if ("did:key" in config.didMethods) "did:key" else "did:jwk")
        val vp = buildJsonObject {
            putJsonArray("@context") { add(if (config.proofTypes.containsKey("di_vp")) W3cVc.CONTEXT_V2 else W3cVc.CONTEXT_V1) }
            putJsonArray("type") { add("VerifiablePresentation") }
            put("holder", did)
        }
        return DataIntegrity(DidResolver(httpClient, loopback)).sign(
            unsecured = vp,
            key = holder.signingKey(),
            verificationMethod = DidKeys.verificationMethod(did),
            proofPurpose = "authentication",
            challenge = nonce,
            domain = session.issuer.credentialIssuer,
        )
    }

    /** cwt proof (OpenID4VCI draft 13): COSE_Sign1 over CWT claims, with the holder key as COSE_Key in the protected header. */
    private suspend fun cwtProof(session: IssuanceSession, holder: HolderKey, nonce: String?, style: ProofStyle): String {
        val key = holder.signingKey(proofAlg(holder, emptyList()))
        val claims = buildCborMap {
            (style.iss ?: session.provider.clientId.takeIf { !session.anonymous })?.let { put(1, it) }
            put(3, session.issuer.credentialIssuer)
            put(6, Clock.System.now().epochSeconds)
            nonce?.let { put(10, it.encodeToByteArray()) }
        }
        val sign1 = Cose.coseSign1Sign(
            key,
            Cbor.encode(claims),
            true,
            mapOf(
                CoseNumberLabel(Cose.COSE_LABEL_ALG) to key.algorithm.coseAlgorithmIdentifier!!.toDataItem(),
                CoseNumberLabel(3) to "openid4vci-proof+cwt".toDataItem(),
                CoseTextLabel("COSE_Key") to Bstr(Cbor.encode(holder.publicKey.toCoseKey().toDataItem())),
            ),
            emptyMap(),
        )
        return Cbor.encode(sign1.toDataItem()).toBase64Url()
    }

    /**
     * Calls the credential or deferred endpoint with optional request/response encryption. A deferred call reuses the
     * transaction's response key ([reuseKey]): some issuers (issuer.eudiw.dev) encrypt the deferred response with the key
     * of the original request and ignore a new one.
     */
    private suspend fun credentialEndpointCall(
        session: IssuanceSession,
        url: String,
        plainBody: JsonObject,
        token: AccessToken,
        reuseKey: EcPrivateKey? = null,
        signingHolder: HolderKey? = null,
    ): Pair<HttpStatusCode, JsonObject> {
        val issuer = session.issuer
        val respEnc = issuer.responseEncryption
        val reqEnc = issuer.requestEncryption
        val encryptResponse = respEnc != null && (respEnc.required || (preferEncryption && reqEnc != null))
        val responseKey = if (encryptResponse) reuseKey ?: Crypto.createEcPrivateKey(EcCurve.P256) else null
        val encValue = respEnc?.let { pickEnc(it.encValues) }
        val responseJwk = responseKey?.publicKey?.toJwk()
        val body1_0 = if (responseJwk != null) {
            JsonObject(plainBody + ("credential_response_encryption" to buildJsonObject {
                put("jwk", JsonObject(responseJwk + mapOf(
                    "alg" to JsonPrimitive("ECDH-ES"),
                    "use" to JsonPrimitive("enc"),
                    "kid" to JsonPrimitive(PlatformCrypto.randomBytes(8).toBase64Url()),
                )))
                put("enc", encValue!!.joseAlgorithmIdentifier)
            }))
        } else plainBody
        val body = session.compat.first { it.adaptRequestBody(issuer, body1_0) } ?: body1_0
        val encryptRequest = reqEnc != null && (reqEnc.required || encryptResponse)
        val (contentType, payload) = if (encryptRequest) {
            val jwk = reqEnc!!.jwks.filterIsInstance<JsonObject>().firstOrNull {
                (it.str("alg") == null || it.str("alg") == "ECDH-ES") && it.str("kty") == "EC" && (it.str("use") == null || it.str("use") == "enc")
            } ?: throw ProtocolException("unsupported_encryption", "No usable ECDH-ES key in credential_request_encryption")
            val jwe = JsonWebEncryption.encrypt(
                claimsSet = body,
                recipientPublicKey = EcPublicKey.fromJwk(jwk),
                encAlg = pickEnc(reqEnc.encValues),
                apu = PlatformCrypto.randomBytes(16).let { ByteString(it) },
                apv = PlatformCrypto.randomBytes(16).let { ByteString(it) },
                kid = jwk.str("kid"),
            )
            ContentType("application", "jwt") to jwe
        } else ContentType.Application.Json to body.toString()

        // A dialect may sign an extra header over the exact outgoing bytes (TWDIW ecosystem signature), with the
        // session's own holder key, after any body adaptation and encryption; it must not set a protected header.
        val owner = session.compat.owner
        val dialectHeaders = if (signingHolder != null && owner != null) {
            val keyId = signingHolder.did ?: HolderKey.didFor(signingHolder.publicKey, HolderKey.DID_KEY_JWK_JCS)
            owner.outboundCredentialHeaders(
                OutboundCredentialContext(issuer, payload.encodeToByteArray(), keyId, signingHolder.publicKey, signingHolder.signingKey("ES256"))
            )?.also { session.compat.record(owner) }
        } else null
        val resp = withDpopRetry(session, url, token) {
            contentType(contentType)
            dialectHeaders?.forEach { (name, value) ->
                if (!name.equals("Authorization", true) && !name.equals("Content-Type", true) && !name.startsWith("DPoP", true)) header(name, value)
            }
            setBody(payload)
        }
        val text = resp.bodyAsText()
        val isJwe = resp.contentType()?.match(ContentType("application", "jwt")) == true || text.count { it == '.' } == 4 && !text.trimStart().startsWith("{")
        val json = when {
            text.isBlank() -> JsonObject(emptyMap())
            isJwe -> {
                val k = responseKey ?: throw ProtocolException("invalid_credential_response", "Encrypted response that was not requested")
                JsonWebEncryption.decrypt(text.trim(), AsymmetricKey.AnonymousExplicit(k, Algorithm.ECDH_P256))
            }
            else -> {
                if (responseKey != null && resp.status.isSuccess()) {
                    throw ProtocolException("invalid_credential_response", "Issuer ignored response encryption")
                }
                runCatching { parseJsonObject(text) }.getOrElse { JsonObject(emptyMap()) }
            }
        }
        if (resp.status == HttpStatusCode.Accepted && responseKey != null) {
            json.str("transaction_id")?.let { session.responseKeys[it] = responseKey }
        }
        return resp.status to json
    }

    private fun pickEnc(values: List<String>): Algorithm {
        val prefs = listOf("A128GCM", "A256GCM", "A192GCM")
        val name = if (values.isEmpty()) "A128GCM" else prefs.firstOrNull { it in values }
            ?: throw ProtocolException("unsupported_encryption", "No supported enc in $values")
        return Algorithm.fromJoseAlgorithmIdentifier(name)
    }

    /** Resource server call with access token and DPoP, retrying once on use_dpop_nonce (RFC 9449 Section 9). */
    private suspend fun withDpopRetry(
        session: IssuanceSession,
        url: String,
        token: AccessToken,
        block: HttpRequestBuilder.() -> Unit,
    ): HttpResponse {
        var retried = false
        while (true) {
            val resp = httpClient.post(url) {
                header("Authorization", token.authorizationHeader)
                applyDpop(session, "POST", url, token.value.takeIf { session.dpop != null })
                block()
            }
            val newNonce = resp.headers["DPoP-Nonce"]
            session.dpop?.updateNonce(url, newNonce)
            val www = resp.headers["WWW-Authenticate"].orEmpty()
            if (!retried && resp.status == HttpStatusCode.Unauthorized && newNonce != null && "use_dpop_nonce" in www) {
                retried = true
                continue
            }
            return resp
        }
    }

    private suspend fun storeCredentials(
        session: IssuanceSession,
        config: CredentialConfiguration,
        document: Document,
        pending: List<Credential>,
        json: JsonObject,
        compat: DialectSet,
    ): IssuanceResult.Issued {
        val issued = (json["credentials"] as? JsonArray)?.mapNotNull { (it as? JsonObject)?.get("credential")?.let(Draft11Dialect::credentialText) }
            ?: compat.first { it.credentialsFromResponse(json) }
            ?: throw ProtocolException("invalid_credential_response", "Response has no credentials array")
        if (issued.isEmpty()) throw ProtocolException("invalid_credential_response", "Empty credentials array")
        val byKey = mutableMapOf<EcPublicKey?, Credential>()
        for (c in pending) {
            val key = when (c) {
                is SecureAreaBoundCredential -> c.secureArea.getKeyInfo(c.alias).publicKey
                is W3cVcCredential -> c.holderPublicKey()
                else -> null
            }
            byKey[key] = c
        }
        var trust: TrustDecision? = null
        val certified = mutableListOf<Credential>()
        var holderDid: String? = null
        for (raw in issued) {
            if (config.format.isW3c) {
                // A dialect that allows SD-JWT delivery is recorded only when the issuer actually sent one: a plain
                // JWT VC from another issuer must not be labelled with that dialect.
                val sdJwtDialect = compat.firstWhere { it.w3cDeliveredAsSdJwt(config) }
                val inspected = w3cInspector.inspect(raw, config.types, session.issuer.credentialIssuer, sdJwtDialect != null, compat)
                if (sdJwtDialect != null && inspected.encoding == W3cEncoding.SD_JWT) compat.record(sdJwtDialect)
                // A credential bound to nothing this wallet can check (e.g. a did:web subject) is matched to the only key.
                val target = (byKey.remove(inspected.boundKey) ?: if (inspected.boundKey == null && byKey.size == 1) byKey.remove(byKey.keys.first()) else null)
                    as? W3cVcCredential
                    ?: throw ProtocolException("invalid_credential", "Issued credential is bound to a key this wallet did not request")
                if (target.holderDid != null && inspected.holderDid != null && inspected.holderDid != target.holderDid) {
                    throw ProtocolException("invalid_credential", "Issued credential is bound to a different holder DID")
                }
                target.setIssuedFormBeforeCertify(inspected.encoding, inspected.types, inspected.holderDid)
                target.certify(raw.encodeToByteString())
                holderDid = target.holderDid
                certified += target
                trust = weaker(trust, inspected.trust)
                continue
            }
            val (inspected, data) = when (config.format) {
                CredentialFormatId.MSO_MDOC -> {
                    val bytes = raw.fromBase64Url()
                    inspector.inspectMdoc(bytes, config.docType, null) to ByteString(bytes)
                }
                else -> inspector.inspectSdJwt(raw, config.vct, session.issuer.credentialIssuer, null, compat) to raw.encodeToByteString()
            }
            val target = byKey.remove(inspected.boundKey)
                ?: throw ProtocolException("invalid_credential", "Issued credential is bound to a key this wallet did not request")
            target.certify(data)
            certified += target
            trust = weaker(trust, inspected.trust)
        }
        // Keys the issuer did not use are discarded (a shared holder key is kept by the credential type).
        byKey.values.forEach { document.deleteCredential(it.identifier) }
        val finalTrust = trust!!.let { t ->
            if (session.issuer.trust.labels.contains(TrustLabel.UNSIGNED_METADATA)) t.copy(labels = t.labels + TrustLabel.UNSIGNED_METADATA) else t
        }
        val notificationId = json.str("notification_id")
        // Specifications followed outside OpenID4VCI 1.0 / the credential format are recorded, whichever step needed them.
        val record = document.issuanceRecord!!.withTrust(finalTrust).copy(
            notificationId = notificationId,
            specs = compat.specs.toList(),
            profile = compat.owner?.id,
            holderDid = holderDid,
        )
        document.edit {
            appData = record.encode()
            provisioned = true
        }
        return IssuanceResult.Issued(document, certified, finalTrust, notificationId)
    }

    private fun weaker(a: TrustDecision?, b: TrustDecision): TrustDecision =
        if (a == null || b.tier.ordinal > a.tier.ordinal) b else a

    private suspend fun createDocument(session: IssuanceSession, config: CredentialConfiguration, keys: KeyRequest): Document {
        val display = config.display.pick(locales)
        val issuerDisplay = session.issuer.display.pick(locales)
        val record = IssuanceRecord(
            credentialIssuer = session.issuer.credentialIssuer,
            configurationId = config.id,
            format = config.format.wire,
            docType = config.docType,
            vct = config.vct,
            tier = TrustTier.T4.name,
            issuedAt = Clock.System.now().epochSeconds,
            keyStorage = keys.keyStorage,
            claimNames = diw.wallet.core.credential.ClaimLabels.issuerNames(config),
            w3cTypes = config.types,
            profile = session.compat.owner?.id,
            logoUri = display?.logoUri ?: issuerDisplay?.logoUri,
            backgroundColor = display?.backgroundColor,
            textColor = display?.textColor,
            backgroundImageUri = display?.backgroundImageUri,
            displayCheckedAt = Clock.System.now().epochSeconds,
            displayDescription = display?.description,
            clientAuthentication = session.clientAuthMethod,
            tokenType = session.accessToken?.type,
        )
        return documentStore.createDocument(
            displayName = display?.name ?: config.docType ?: config.vct ?: W3cVc.displayType(config.types) ?: config.id,
            typeDisplayName = issuerDisplay?.name ?: session.issuer.credentialIssuer,
            appData = record.encode(),
        )
    }

    private fun oauthError(json: JsonObject, fallback: String): ProtocolException =
        ProtocolException(json.str("error") ?: "server_error", json.str("error_description") ?: fallback)

    /** [base] followed by the owning dialect's reading of an error body that carries no error_description. */
    private fun failure(compat: DialectSet, json: JsonObject, base: String): String {
        if (json.str("error_description") != null) return base
        val detail = compat.owned { it.errorDetail(json) } ?: return base
        return "$base: $detail"
    }

    companion object {
        /** Checks a URL before the wallet opens it as an authorization page. */
        fun isSafeAuthorizationUrl(url: String, allowInsecureLoopback: Boolean) = isAcceptableEndpoint(url, allowInsecureLoopback)
    }
}
