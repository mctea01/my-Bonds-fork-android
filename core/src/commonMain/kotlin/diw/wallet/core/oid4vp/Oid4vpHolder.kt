package diw.wallet.core.oid4vp

import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.oid4vp.compat.TwdiwPresentationDialect
import diw.wallet.core.profile.bonds.BondsHolderDerived
import diw.wallet.core.profile.bonds.BondsMoicaOnline
import diw.wallet.core.profile.bonds.HolderDerivedPlan
import diw.wallet.core.profile.bonds.HolderDerivedSource
import diw.wallet.core.profile.bonds.HolderHint
import diw.wallet.core.profile.bonds.HeldMoicaCard
import diw.wallet.core.profile.bonds.MoicaMatch
import diw.wallet.core.oid4vp.compat.PresentationDialect
import diw.wallet.core.oid4vp.ext.ConsentLine
import diw.wallet.core.oid4vp.ext.ExtendedOutcome
import diw.wallet.core.oid4vp.ext.ExtendedPrepared
import diw.wallet.core.oid4vp.ext.ExtendedPresenter
import diw.wallet.core.oid4vp.ext.LegacyRequestValidator
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.jose.Jws
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.forms.submitForm
import io.ktor.client.statement.bodyAsText
import io.ktor.http.encodeURLParameter
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.openid.dcql.DcqlCredentialQueryException
import org.multipaz.presentment.ConsentData
import org.multipaz.presentment.CredentialQueryResult
import org.multipaz.presentment.CredentialSelection
import org.multipaz.presentment.PresentmentSource

/** A validated request matched against the wallet, ready for the consent screen. */
sealed interface PreparedRequest {
    val request: ValidatedAuthorizationRequest
}

/** OpenID4VP 1.0 request with mdoc / SD-JWT VC DCQL queries, matched by Multipaz. */
data class PreparedPresentation(
    override val request: ValidatedAuthorizationRequest,
    val queryResult: CredentialQueryResult,
    val consentData: ConsentData,
) : PreparedRequest

/** A request matched by the wallet's own engine (W3C formats, Presentation Exchange, SIOP, pre-1.0, profiles). */
data class PreparedExtended(val prepared: ExtendedPrepared) : PreparedRequest {
    override val request: ValidatedAuthorizationRequest get() = prepared.request
    val lines: List<ConsentLine> get() = prepared.lines
}

/**
 * A Bonds self-issued card request (Presentation Exchange with the vc+moica format), answered from the cards the
 * wallet keeps outside the document store.
 */
data class PreparedMoica(override val request: ValidatedAuthorizationRequest, val matches: List<MoicaMatch>) : PreparedRequest

/**
 * A Bonds holder-derived request (DCQL dc+sd-jwt with bonds_rule): answered by a credential minted at presentation
 * time from a vault document, never by a held card. [plan] holds the computed answer shown before consent.
 */
data class PreparedDerived(override val request: ValidatedAuthorizationRequest, val plan: HolderDerivedPlan) : PreparedRequest

/** Result of a completed presentation. */
sealed class PresentationOutcome {
    /** direct_post(.jwt): the Verifier accepted; [redirectUri] should be opened if present. */
    data class Posted(val redirectUri: String?, val verifierStatus: Int) : PresentationOutcome()
    /** DC API: [data] is returned to the platform as the credential response data. */
    data class DcApi(val data: JsonObject) : PresentationOutcome()
    /** fragment / query response mode: the wallet opens [url] (the Verifier's redirect_uri with the response). */
    data class Redirect(val url: String) : PresentationOutcome()
}

/**
 * OpenID4VP 1.0 holder orchestration: resolve, validate (own layer), match DCQL, consent, build, deliver.
 */
class Oid4vpHolder(
    private val httpClient: HttpClient,
    trustRegistry: TrustRegistry,
    private val source: PresentmentSource,
    private val environment: EnvironmentPolicy,
    private val policy: PresentationPolicy = PresentationPolicy(),
    /** Wallet-level holder identities (TWDIW, Microsoft Verified ID, SIOP). */
    holderIdentities: HolderIdentities? = null,
    /** Trust for verifiers identified by a DID. */
    didTrust: DidTrust = DidTrust.NONE,
    /** Profile behaviour outside OpenID4VP 1.0; always on, used only for requests a profile owns. */
    private val dialects: List<PresentationDialect> = emptyList(),
    /** Bonds self-issued cards (vc+moica) for requests that name that format, and the key their subject DID names. */
    private val moicaCards: suspend () -> List<HeldMoicaCard> = { emptyList() },
    private val moicaHolder: suspend () -> HolderKey? = { null },
    /** Vault documents a Bonds holder-derived credential can be computed from. */
    private val derivedSources: suspend () -> List<HolderDerivedSource> = { emptyList() },
    /** Who the holder is (ID number, name), to pick the holder's own row on a household record. */
    private val derivedHolders: suspend () -> List<HolderHint> = { emptyList() },
) {
    private val resolver = RequestResolver(httpClient, policy, environment.insecureLoopbackAllowed)
    private val didResolver = DidResolver(httpClient, environment.insecureLoopbackAllowed)
    private val validator = RequestValidator(trustRegistry, didResolver, policy, environment.insecureLoopbackAllowed)
    private val legacy = LegacyRequestValidator(httpClient, trustRegistry, didResolver, didTrust, policy, environment.insecureLoopbackAllowed, dialects)
    private val builder = ResponseBuilder(source)
    private val extended = ExtendedPresenter(httpClient, source.documentStore, holderIdentities, dialects, environment.insecureLoopbackAllowed)

    /** Resolves and validates a URI request; [entryHint] names the profile whose entry point delivered it. */
    suspend fun resolveUri(uri: String, entryHint: String? = null): ValidatedAuthorizationRequest {
        val raw = resolver.fromUri(uri, entryHint)
        return if (needsLegacy(raw)) legacy.validate(raw) else validator.validate(raw)
    }

    /** True for requests outside OpenID4VP 1.0: pre-1.0 drafts, SIOPv2, OAuth response modes and profile requests. */
    private fun needsLegacy(raw: RawAuthorizationRequest): Boolean {
        val p = raw.params
        if (dialects.any { it.owns(raw, p) }) return true
        if (p.containsKey("presentation_definition") || p.containsKey("presentation_definition_uri") || p.containsKey("client_id_scheme")) return true
        if ((p["claims"] as? JsonObject)?.containsKey("vp_token") == true) return true
        if (p.str("response_type") != "vp_token") return true
        val mode = ResponseMode.fromWire(p.str("response_mode") ?: if (raw.channel == RequestChannel.DC_API) "dc_api" else "fragment")
        if (mode == null || !mode.standard) return true
        val clientId = p.str("client_id") ?: raw.outer["client_id"] ?: ""
        // Draft 22-23 prefixes that OpenID4VP 1.0 renamed or dropped.
        return clientId.startsWith("did:") || clientId.startsWith("x509_san_uri:")
    }

    suspend fun resolveDcApi(protocol: String, data: JsonObject, origin: String): ValidatedAuthorizationRequest {
        val request = resolver.fromDcApi(protocol, data, origin)
        if (request.multiSignedCandidates.isEmpty()) return validator.validate(request)
        var best: ValidatedAuthorizationRequest? = null
        var lastError: Throwable? = null
        val priority = listOf(
            diw.wallet.core.trust.TrustTier.T1,
            diw.wallet.core.trust.TrustTier.T2,
            diw.wallet.core.trust.TrustTier.T3,
            diw.wallet.core.trust.TrustTier.T4,
        )
        for (candidate in request.multiSignedCandidates) {
            try {
                val validated = validator.validate(candidate)
                if (best == null || priority.indexOf(validated.verifier.trust.tier) <
                    priority.indexOf(best.verifier.trust.tier)
                ) best = validated
            } catch (e: ProtocolException) {
                lastError = e
            }
        }
        return best?.copy(warnings = best.warnings + (
            "Multi-signed DC API: authenticated " + best.verifier.clientId.raw +
                " among " + request.multiSignedCandidates.size + " signatures"
        )) ?: throw RequestValidationException(
            "invalid_request_object",
            "No multi-signed verifier identity could be authenticated",
            cause = lastError,
        )
    }

    /**
     * Matches the request against stored credentials. Throws [ProtocolException] (access_denied) when nothing matches.
     * OpenID4VP 1.0 requests for mdoc and SD-JWT VC go through Multipaz; everything else through the wallet's own engine.
     */
    suspend fun prepare(request: ValidatedAuthorizationRequest): PreparedRequest {
        if (BondsHolderDerived.wants(request)) return PreparedDerived(request, BondsHolderDerived.prepare(request, derivedSources(), derivedHolders()))
        if (request.profile == TwdiwPresentationDialect.ID && BondsMoicaOnline.wants(request)) {
            return PreparedMoica(request, BondsMoicaOnline.match(request, moicaCards()))
        }
        if (request.isLegacy || needsOwnDcql(request)) return PreparedExtended(extended.prepare(request))
        return prepareStandard(request)
    }

    private fun needsOwnDcql(request: ValidatedAuthorizationRequest): Boolean =
        request.dcqlQuery.arr("credentials").orEmpty().any { (it as? JsonObject)?.str("format") !in MULTIPAZ_FORMATS }

    private suspend fun prepareStandard(request: ValidatedAuthorizationRequest): PreparedPresentation {
        val dcql = builder.dcqlQuery(request)
        val tx = builder.parseTransactionData(request)
        val result = try {
            dcql.execute(presentmentSource = source, transactionDataMap = tx)
        } catch (e: DcqlCredentialQueryException) {
            throw ProtocolException("access_denied", "No stored credential satisfies the request", e)
        }
        return PreparedPresentation(request, result, ConsentData.fromCredentialQueryResult(result, source))
    }

    /** Responds to a request prepared by the wallet's own engine with its chosen credentials. */
    /** Responds with the default choice: the first match of each standard query, or the engine's choice for extended requests. */
    suspend fun respondDefault(prepared: PreparedRequest): PresentationOutcome = when (prepared) {
        is PreparedExtended -> respond(prepared)
        is PreparedMoica -> respond(prepared)
        is PreparedDerived -> respond(prepared)
        is PreparedPresentation -> respond(prepared, prepared.queryResult.select(emptyList()))
    }

    suspend fun respond(prepared: PreparedMoica): PresentationOutcome {
        val holder = moicaHolder() ?: throw ProtocolException("credential_unavailable", "No holder key for self-issued cards")
        val params = BondsMoicaOnline.response(prepared.request, prepared.matches, holder)
        return when (val o = extended.deliver(prepared.request, params, null, extended.dialectOf(prepared.request))) {
            is ExtendedOutcome.Posted -> PresentationOutcome.Posted(o.redirectUri, o.status)
            is ExtendedOutcome.Redirect -> PresentationOutcome.Redirect(o.url)
            is ExtendedOutcome.DcApi -> PresentationOutcome.DcApi(o.data)
        }
    }

    suspend fun respond(prepared: PreparedDerived): PresentationOutcome {
        val params = BondsHolderDerived.response(prepared.request, prepared.plan)
        return when (val o = extended.deliver(prepared.request, params, null, extended.dialectOf(prepared.request))) {
            is ExtendedOutcome.Posted -> PresentationOutcome.Posted(o.redirectUri, o.status)
            is ExtendedOutcome.Redirect -> PresentationOutcome.Redirect(o.url)
            is ExtendedOutcome.DcApi -> PresentationOutcome.DcApi(o.data)
        }
    }

    suspend fun respond(prepared: PreparedExtended): PresentationOutcome = when (val o = extended.respond(prepared.prepared)) {
        is ExtendedOutcome.Posted -> PresentationOutcome.Posted(o.redirectUri, o.status)
        is ExtendedOutcome.Redirect -> PresentationOutcome.Redirect(o.url)
        is ExtendedOutcome.DcApi -> PresentationOutcome.DcApi(o.data)
    }

    suspend fun respond(prepared: PreparedPresentation, selection: CredentialSelection): PresentationOutcome {
        val request = prepared.request
        val built = builder.build(request, selection)
        return if (request.responseMode.dcApi) {
            PresentationOutcome.DcApi(built.payload)
        } else {
            post(request.responseUri!!, built.payload)
        }
    }

    /** Tells an authenticated Verifier that the user declined or the wallet failed. Unauthenticated Verifiers get nothing. */
    suspend fun decline(request: ValidatedAuthorizationRequest, error: String = "access_denied", description: String? = null): PresentationOutcome? {
        val payload = ResponseBuilder.errorPayload(error, description, request.state)
        if (request.responseMode.dcApi) return if (selectsByValueOrIssuer(request.dcqlQuery)) null else PresentationOutcome.DcApi(payload)
        if (request.isLegacy) {
            if (request.verifier.trust.tier == diw.wallet.core.trust.TrustTier.T4) return null
            val target = request.target ?: return null
            if (!request.responseMode.posted) {
                val q = payload.entries.joinToString("&") { (k, v) -> k + "=" + (v as JsonPrimitive).content.encodeURLParameter() }
                return PresentationOutcome.Redirect(target + (if (request.responseMode == ResponseMode.FRAGMENT) "#" else if ('?' in target) "&" else "?") + q)
            }
            return runCatching { post(target, payload) }.getOrNull()
        }
        if (request.verifier.trust.tier == diw.wallet.core.trust.TrustTier.T4 &&
            request.verifier.clientId.prefix != ClientIdPrefix.REDIRECT_URI) return null
        return post(request.responseUri!!, payload)
    }

    companion object {
        /** DCQL formats the Multipaz engine presents; requests for other formats use the wallet's own engine. */
        val MULTIPAZ_FORMATS = setOf("mso_mdoc", "mso_mdoc_zk", "dc+sd-jwt")

        /**
         * Data returned to a DC API caller whose request failed validation (OpenID4VP 1.0 A.4, e.g. invalid_request when
         * the origin is not in expected_origins), or null to cancel the flow instead. Other failures are not reported.
         */
        fun dcApiError(data: JsonObject, e: Throwable): JsonObject? {
            if (e !is RequestValidationException) return null
            val request = data["request"]
            val params = if (request == null) data else runCatching { Jws.parse((request as JsonPrimitive).content).payload }.getOrNull()
            return if (selectsByValueOrIssuer(params?.obj("dcql_query"))) null else ResponseBuilder.errorPayload(e.code, null, null)
        }

        /**
         * Value matching or issuer selection: over the DC API an error before consent would reveal that the user holds a
         * matching value or a credential from that issuer (OpenID4VP 1.0 section 15.9.2), so such flows are cancelled.
         */
        private fun selectsByValueOrIssuer(dcql: JsonObject?): Boolean =
            dcql?.arr("credentials").orEmpty().any { c ->
                val q = c as? JsonObject ?: return@any false
                "trusted_authorities" in q || q.arr("claims").orEmpty().any { (it as? JsonObject)?.containsKey("values") == true }
            }
    }

    private suspend fun post(responseUri: String, payload: JsonObject): PresentationOutcome.Posted {
        val resp = httpClient.submitForm(
            url = responseUri,
            formParameters = parameters {
                for ((k, v) in payload) {
                    append(k, if (v is JsonPrimitive && v.isString) v.content else v.toString())
                }
            }
        )
        val text = resp.bodyAsText()
        if (!resp.status.isSuccess()) {
            throw ProtocolException("verifier_error", "Verifier rejected the response: HTTP ${resp.status.value} $text")
        }
        val redirect = runCatching { (DiwJson.parseToJsonElement(text) as JsonObject).str("redirect_uri") }.getOrNull()
        val safeRedirect = redirect?.takeIf { isAcceptableEndpoint(it, environment.insecureLoopbackAllowed) }
        return PresentationOutcome.Posted(safeRedirect, resp.status.value)
    }
}
