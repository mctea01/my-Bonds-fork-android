package diw.wallet.core.oid4vci

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.long
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.queryParameters
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
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
    /** c_nonce from the token response (draft-era issuers without a nonce endpoint). */
    val cNonce: String? = null,
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
) {
    var accessToken: AccessToken? = null
        internal set
    internal var pkceVerifier: String? = null
    internal var state: String? = null
    internal var redirectUri: String? = null
    internal var requestedConfigurations: List<String> = emptyList()
    internal var anonymous: Boolean = false
    internal var attestationChallenge: String? = null
    internal val responseKeys = mutableMapOf<String, EcPrivateKey>()

    val txCode: TxCode? get() = offer?.preAuthorized?.txCode
    val offeredConfigurations: List<CredentialConfiguration>
        get() = (offer?.credentialConfigurationIds ?: requestedConfigurations).mapNotNull { issuer.configurations[it] }
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
) {
    private val loopback = environment.insecureLoopbackAllowed
    private val metadata = MetadataFetcher(httpClient, trustRegistry, loopback)
    private val offers = CredentialOfferResolver(httpClient, loopback)
    private val inspector = CredentialInspector(httpClient, trustRegistry, loopback)

    // ---------------------------------------------------------------- session start

    suspend fun startFromOffer(uri: String): IssuanceSession {
        val offer = offers.resolve(uri)
        val issuer = metadata.issuer(offer.credentialIssuer)
        val unknown = offer.credentialConfigurationIds.filter { it !in issuer.configurations }
        if (unknown.isNotEmpty()) {
            throw ProtocolException("invalid_credential_offer", "Offer references unknown configurations $unknown")
        }
        val asHint = offer.preAuthorized?.authorizationServer ?: offer.authorizationCode?.authorizationServer
        val asMeta = metadata.authorizationServer(issuer.authorizationServerFor(asHint))
        return IssuanceSession(offer, issuer, asMeta, newDpop(asMeta), offer.authorizationCode?.issuerState)
    }

    suspend fun startWalletInitiated(credentialIssuer: String, configurationIds: List<String>): IssuanceSession {
        val issuer = metadata.issuer(credentialIssuer)
        val asMeta = metadata.authorizationServer(issuer.authorizationServerFor(null))
        return IssuanceSession(null, issuer, asMeta, newDpop(asMeta), null).also {
            it.requestedConfigurations = configurationIds.filter { id -> id in issuer.configurations }
        }
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
        val attestation = clientAttestationFor(session)
        session.anonymous = attestation == null && session.authServer.preAuthorizedAnonymousAccess
        val form = Parameters.build {
            append("grant_type", GRANT_PRE_AUTHORIZED_CODE)
            append("pre-authorized_code", grant.preAuthorizedCode)
            if (txCode != null && grant.txCode != null) append("tx_code", txCode)
            if (!session.anonymous) append("client_id", walletProvider.clientId)
        }
        session.accessToken = tokenRequest(session, form, attestation)
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
        val ids = configurationIds ?: session.offeredConfigurations.map { it.id }
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
        val scopes = ids.mapNotNull { session.issuer.configurations[it]?.scope }.distinct()
        val params = Parameters.build {
            append("response_type", "code")
            append("client_id", walletProvider.clientId)
            append("redirect_uri", redirectUri)
            append("state", state)
            append("code_challenge", challenge)
            append("code_challenge_method", "S256")
            append("authorization_details", details.toString())
            if (scopes.isNotEmpty()) append("scope", scopes.joinToString(" "))
            session.issuerState?.let { append("issuer_state", it) }
        }
        val par = asMeta.parEndpoint
        if (par == null && asMeta.requirePar) throw ProtocolException("invalid_as_metadata", "PAR required but no endpoint")
        return if (par != null) {
            val attestation = clientAttestationFor(session)
            val resp = postFormWithDpop(session, par, params, attestation, null)
            val json = parseJsonObject(resp.bodyAsText(), "invalid_par_response")
            if (!resp.status.isSuccess()) throw oauthError(json, "PAR failed (${resp.status.value})")
            val requestUri = json.str("request_uri") ?: throw ProtocolException("invalid_par_response", "PAR response without request_uri")
            URLBuilder(endpoint).apply {
                parameters.append("client_id", walletProvider.clientId)
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
        if (iss != null && iss != session.authServer.issuer) throw ProtocolException("invalid_request", "iss does not match authorization server (mix-up)")
        if (iss == null && session.authServer.responseIssParameterSupported) {
            throw ProtocolException("invalid_request", "Authorization response is missing iss")
        }
        val code = q["code"] ?: throw ProtocolException("invalid_request", "Authorization response without code")
        val form = Parameters.build {
            append("grant_type", GRANT_AUTHORIZATION_CODE)
            append("code", code)
            append("redirect_uri", expectedRedirect)
            append("code_verifier", session.pkceVerifier!!)
            append("client_id", walletProvider.clientId)
        }
        session.state = null
        session.accessToken = tokenRequest(session, form, clientAttestationFor(session))
    }

    private suspend fun clientAttestationFor(session: IssuanceSession): WalletAttestation? {
        val asMeta = session.authServer
        if (!asMeta.usesClientAttestation && asMeta.tokenEndpointAuthMethods.isNotEmpty()) return null
        val att = walletProvider.walletAttestation() ?: return null
        val challengeEndpoint = asMeta.challengeEndpoint
        if (challengeEndpoint != null && session.attestationChallenge == null) {
            val r = httpClient.post(challengeEndpoint)
            if (r.status.isSuccess()) {
                session.attestationChallenge = parseJsonObject(r.bodyAsText()).str("attestation_challenge")
            }
        }
        return att
    }

    private suspend fun tokenRequest(session: IssuanceSession, form: Parameters, attestation: WalletAttestation?): AccessToken {
        val resp = postFormWithDpop(session, session.authServer.tokenEndpoint, form, attestation, null)
        val text = resp.bodyAsText()
        val json = runCatching { parseJsonObject(text) }.getOrElse { JsonObject(emptyMap()) }
        if (!resp.status.isSuccess()) throw oauthError(json, "Token request failed (${resp.status.value})")
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
            cNonce = json.str("c_nonce"),
        )
    }

    /** POSTs a form to the AS with DPoP and client attestation, retrying once on use_dpop_nonce. */
    private suspend fun postFormWithDpop(
        session: IssuanceSession,
        url: String,
        form: Parameters,
        attestation: WalletAttestation?,
        accessToken: String?,
    ): HttpResponse {
        var retried = false
        while (true) {
            val resp = httpClient.post(url) {
                applyDpop(session, "POST", url, accessToken)
                if (attestation != null) {
                    header("OAuth-Client-Attestation", attestation.jwt)
                    header(
                        "OAuth-Client-Attestation-PoP",
                        clientAttestationPop(attestation, walletProvider.clientId, session.authServer.issuer, session.attestationChallenge)
                    )
                }
                setBody(FormDataContent(form))
            }
            session.dpop?.updateNonce(url, resp.headers["DPoP-Nonce"])
            resp.headers["OAuth-Client-Attestation-Challenge"]?.let { session.attestationChallenge = it }
            if (!retried && resp.status == HttpStatusCode.BadRequest) {
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
        val count = keys.count.coerceIn(1, session.issuer.batchSize)
        var nonce = fetchNonce(session)
        var pending = if (config.keyBound) createPendingCredentials(document, config, keys, nonce, count) else
            listOf(KeylessSdJwtVcCredential.create(document, null, CredentialDomains.SD_JWT_KEYLESS, config.storageType))
        var attempt = 0
        while (true) {
            val proofs = if (config.keyBound) buildProofs(session, config, pending.map { it as SecureAreaBoundCredential }, nonce, keys) else null
            val body = buildJsonObject {
                val identifiers = token.credentialIdentifiers[config.id]
                if (!identifiers.isNullOrEmpty()) put("credential_identifier", identifiers.first())
                else put("credential_configuration_id", config.id)
                proofs?.let { put("proofs", it) }
            }
            val (status, json) = credentialEndpointCall(session, session.issuer.credentialEndpoint, body, token)
            if (status == HttpStatusCode.BadRequest && json.str("error") == "invalid_nonce" && attempt == 0 && config.keyBound) {
                attempt++
                nonce = json.str("c_nonce") ?: fetchNonce(session)
                // Key attestation challenges are bound at key creation, so attested keys must be recreated.
                if (config.proofTypes.values.any { it.keyAttestationsRequired != null } || "jwt" !in config.proofTypes) {
                    pending.forEach { document.deleteCredential(it.identifier) }
                    pending = createPendingCredentials(document, config, keys, nonce, count)
                }
                continue
            }
            if (status == HttpStatusCode.Accepted) {
                val tx = json.str("transaction_id") ?: throw ProtocolException("invalid_credential_response", "202 without transaction_id")
                val record = document.issuanceRecord!!.copy(pendingTransactionId = tx)
                document.edit { appData = record.encode() }
                return IssuanceResult.Deferred(document, tx, json.long("interval") ?: 5, config.id)
            }
            if (!status.isSuccess()) throw oauthError(json, "Credential request failed (${status.value})")
            return storeCredentials(session, config, document, pending, json)
        }
    }

    /** Polls the deferred endpoint once. Returns Deferred again while the issuer is not ready. */
    suspend fun pollDeferred(session: IssuanceSession, deferred: IssuanceResult.Deferred): IssuanceResult {
        val endpoint = session.issuer.deferredCredentialEndpoint
            ?: throw ProtocolException("invalid_issuer_metadata", "No deferred_credential_endpoint")
        val token = session.accessToken ?: throw ProtocolException("invalid_request", "Not authorized")
        val config = session.issuer.configurations[deferred.configurationId]!!
        val body = buildJsonObject { put("transaction_id", deferred.transactionId) }
        val (status, json) = credentialEndpointCall(session, endpoint, body, token)
        if (status == HttpStatusCode.Accepted) {
            return deferred.copy(intervalSeconds = json.long("interval") ?: deferred.intervalSeconds)
        }
        if (!status.isSuccess()) {
            documentStore.deleteDocument(deferred.document.identifier)
            throw oauthError(json, "Deferred credential request failed (${status.value})")
        }
        val pending = deferred.document.getPendingCredentials()
        val record = deferred.document.issuanceRecord!!.copy(pendingTransactionId = null)
        deferred.document.edit { appData = record.encode() }
        return storeCredentials(session, config, deferred.document, pending, json)
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

    private suspend fun fetchNonce(session: IssuanceSession): String? {
        val endpoint = session.issuer.nonceEndpoint ?: return session.accessToken?.cNonce
        val resp = httpClient.post(endpoint)
        session.dpop?.updateNonce(endpoint, resp.headers["DPoP-Nonce"])
        if (!resp.status.isSuccess()) throw ProtocolException("invalid_nonce", "Nonce endpoint returned ${resp.status.value}")
        return parseJsonObject(resp.bodyAsText(), "invalid_nonce").str("c_nonce")
            ?: throw ProtocolException("invalid_nonce", "Nonce response without c_nonce")
    }

    private suspend fun createPendingCredentials(
        document: Document,
        config: CredentialConfiguration,
        keys: KeyRequest,
        nonce: String?,
        count: Int,
    ): List<Credential> {
        val settings = keys.createKeySettings(ByteString((nonce ?: PlatformCrypto.randomBytes(16).toBase64Url()).encodeToByteArray()))
        return List(count) {
            when (config.format) {
                CredentialFormatId.MSO_MDOC -> MdocCredential.create(
                    document, null, CredentialDomains.MDOC, keys.secureArea,
                    config.docType ?: throw ProtocolException("invalid_issuer_metadata", "mso_mdoc configuration without doctype"),
                    settings,
                )
                else -> KeyBoundSdJwtVcCredential.create(
                    document, null, CredentialDomains.SD_JWT, keys.secureArea,
                    config.storageType,
                    settings,
                )
            }
        }
    }

    private suspend fun buildProofs(
        session: IssuanceSession,
        config: CredentialConfiguration,
        credentials: List<SecureAreaBoundCredential>,
        nonce: String?,
        keys: KeyRequest,
    ): JsonObject {
        val jwtInfo = config.proofTypes["jwt"]
        val attInfo = config.proofTypes["attestation"]
        val attestations = credentials.map { it.getAttestation() }
        return when {
            jwtInfo != null || (attInfo == null && config.bindingMethods.isNotEmpty()) -> {
                val algs = jwtInfo?.signingAlgorithms.orEmpty()
                val keyAttestation = if (jwtInfo?.keyAttestationsRequired != null) {
                    walletProvider.keyAttestation(attestations, nonce, keys.userAuthentication)
                        ?: throw ProtocolException("key_attestation_unavailable", "Issuer requires key attestation but the wallet provider gave none")
                } else null
                val signers = if (keyAttestation != null) credentials.take(1) else credentials
                val jwts = signers.map { proofJwt(session, it, algs, nonce, keyAttestation) }
                buildJsonObject { putJsonArray("jwt") { jwts.forEach { add(it) } } }
            }
            attInfo != null -> {
                val ka = walletProvider.keyAttestation(attestations, nonce, keys.userAuthentication)
                    ?: throw ProtocolException("key_attestation_unavailable", "Issuer requires an attestation proof but the wallet provider gave none")
                buildJsonObject { putJsonArray("attestation") { add(ka) } }
            }
            else -> throw ProtocolException("unsupported_proof_type", "No supported proof type for ${config.id}")
        }
    }

    private suspend fun proofJwt(
        session: IssuanceSession,
        credential: SecureAreaBoundCredential,
        algs: List<String>,
        nonce: String?,
        keyAttestation: String?,
    ): String {
        val info = credential.secureArea.getKeyInfo(credential.alias)
        val curve = info.publicKey.curve
        val label = when (curve) {
            EcCurve.P256 -> listOf("ES256", "ESP256")
            EcCurve.P384 -> listOf("ES384", "ESP384")
            EcCurve.P521 -> listOf("ES512", "ESP512")
            EcCurve.ED25519 -> listOf("EdDSA", "Ed25519")
            else -> listOf(info.algorithm.joseAlgorithmIdentifier ?: "ES256")
        }.let { candidates -> if (algs.isEmpty()) candidates.first() else candidates.firstOrNull { it in algs } }
            ?: throw ProtocolException("unsupported_proof_alg", "Issuer accepts $algs, key curve is $curve")
        val key = AsymmetricKey.AnonymousSecureAreaBased(
            alias = credential.alias,
            secureArea = credential.secureArea,
            keyInfo = info,
            algorithm = Algorithm.fromJoseAlgorithmIdentifier(label),
        )
        return buildJwt(
            type = "openid4vci-proof+jwt",
            key = key,
            header = {
                if (keyAttestation != null) put("key_attestation", keyAttestation)
                else put("jwk", info.publicKey.toJwk())
            },
        ) {
            if (!session.anonymous) put("iss", walletProvider.clientId)
            put("aud", session.issuer.credentialIssuer)
            nonce?.let { put("nonce", it) }
        }
    }

    /** Calls the credential or deferred endpoint with optional request/response encryption. */
    private suspend fun credentialEndpointCall(
        session: IssuanceSession,
        url: String,
        plainBody: JsonObject,
        token: AccessToken,
    ): Pair<HttpStatusCode, JsonObject> {
        val issuer = session.issuer
        val respEnc = issuer.responseEncryption
        val reqEnc = issuer.requestEncryption
        val encryptResponse = respEnc != null && (respEnc.required || (preferEncryption && reqEnc != null))
        val responseKey = if (encryptResponse) Crypto.createEcPrivateKey(EcCurve.P256) else null
        val encValue = respEnc?.let { pickEnc(it.encValues) }
        val responseJwk = responseKey?.publicKey?.toJwk()
        val body = if (responseJwk != null) {
            JsonObject(plainBody + ("credential_response_encryption" to buildJsonObject {
                put("jwk", JsonObject(responseJwk + mapOf(
                    "alg" to JsonPrimitive("ECDH-ES"),
                    "use" to JsonPrimitive("enc"),
                    "kid" to JsonPrimitive(PlatformCrypto.randomBytes(8).toBase64Url()),
                )))
                put("enc", encValue!!.joseAlgorithmIdentifier)
            }))
        } else plainBody
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

        val resp = withDpopRetry(session, url, token) {
            contentType(contentType)
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
    ): IssuanceResult.Issued {
        // Draft-era issuers answer with a single "credential" string.
        val issued = (json["credentials"] as? JsonArray)?.mapNotNull { (it as? JsonObject)?.str("credential") }
            ?: json.str("credential")?.let { listOf(it) }
            ?: throw ProtocolException("invalid_credential_response", "Response has no credentials array")
        if (issued.isEmpty()) throw ProtocolException("invalid_credential_response", "Empty credentials array")
        val byKey = mutableMapOf<EcPublicKey?, Credential>()
        for (c in pending) {
            byKey[(c as? SecureAreaBoundCredential)?.let { it.secureArea.getKeyInfo(it.alias).publicKey }] = c
        }
        var trust: TrustDecision? = null
        val certified = mutableListOf<Credential>()
        for (raw in issued) {
            val (inspected, data) = when (config.format) {
                CredentialFormatId.MSO_MDOC -> {
                    val bytes = raw.fromBase64Url()
                    inspector.inspectMdoc(bytes, config.docType, null) to ByteString(bytes)
                }
                else -> inspector.inspectSdJwt(raw, config.vct, session.issuer.credentialIssuer, null) to raw.encodeToByteString()
            }
            val target = byKey.remove(inspected.boundKey)
                ?: throw ProtocolException("invalid_credential", "Issued credential is bound to a key this wallet did not request")
            target.certify(data)
            certified += target
            trust = weaker(trust, inspected.trust)
        }
        // Keys the issuer did not use are discarded.
        byKey.values.forEach { document.deleteCredential(it.identifier) }
        val finalTrust = trust!!.let { t ->
            if (session.issuer.trust.labels.contains(TrustLabel.UNSIGNED_METADATA)) t.copy(labels = t.labels + TrustLabel.UNSIGNED_METADATA) else t
        }
        val notificationId = json.str("notification_id")
        val record = document.issuanceRecord!!.withTrust(finalTrust).copy(notificationId = notificationId)
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
        )
        return documentStore.createDocument(
            displayName = display?.name ?: config.docType ?: config.vct ?: config.id,
            typeDisplayName = issuerDisplay?.name ?: session.issuer.credentialIssuer,
            appData = record.encode(),
        )
    }

    private fun oauthError(json: JsonObject, fallback: String): ProtocolException =
        ProtocolException(json.str("error") ?: "server_error", json.str("error_description") ?: fallback)

    companion object {
        /** Checks a URL before the wallet opens it as an authorization page. */
        fun isSafeAuthorizationUrl(url: String, allowInsecureLoopback: Boolean) = isAcceptableEndpoint(url, allowInsecureLoopback)
    }
}
