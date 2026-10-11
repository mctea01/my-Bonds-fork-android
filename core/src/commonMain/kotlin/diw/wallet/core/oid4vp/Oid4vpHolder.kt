package diw.wallet.core.oid4vp

import diw.wallet.core.did.DidResolver
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
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.openid.dcql.DcqlCredentialQueryException
import org.multipaz.presentment.ConsentData
import org.multipaz.presentment.CredentialQueryResult
import org.multipaz.presentment.CredentialSelection
import org.multipaz.presentment.PresentmentSource

/** A validated request with the credentials that can satisfy it, ready for the consent screen. */
data class PreparedPresentation(
    val request: ValidatedAuthorizationRequest,
    val queryResult: CredentialQueryResult,
    val consentData: ConsentData,
)

/** Result of a completed presentation. */
sealed class PresentationOutcome {
    /** direct_post(.jwt): the Verifier accepted; [redirectUri] should be opened if present. */
    data class Posted(val redirectUri: String?, val verifierStatus: Int) : PresentationOutcome()
    /** DC API: [data] is returned to the platform as the credential response data. */
    data class DcApi(val data: JsonObject) : PresentationOutcome()
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
) {
    private val resolver = RequestResolver(httpClient, policy, environment.insecureLoopbackAllowed)
    private val validator = RequestValidator(
        trustRegistry,
        DidResolver(httpClient, environment.insecureLoopbackAllowed),
        policy,
        environment.insecureLoopbackAllowed
    )
    private val builder = ResponseBuilder(source)

    suspend fun resolveUri(uri: String): ValidatedAuthorizationRequest = validator.validate(resolver.fromUri(uri))

    suspend fun resolveDcApi(protocol: String, data: JsonObject, origin: String): ValidatedAuthorizationRequest =
        validator.validate(resolver.fromDcApi(protocol, data, origin))

    /** Matches the DCQL query against stored credentials. Throws [ProtocolException] (access_denied) when nothing matches. */
    suspend fun prepare(request: ValidatedAuthorizationRequest): PreparedPresentation {
        val dcql = builder.dcqlQuery(request)
        val tx = builder.parseTransactionData(request)
        val result = try {
            dcql.execute(presentmentSource = source, transactionDataMap = tx)
        } catch (e: DcqlCredentialQueryException) {
            throw ProtocolException("access_denied", "No stored credential satisfies the request", e)
        }
        return PreparedPresentation(request, result, ConsentData.fromCredentialQueryResult(result, source))
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
        if (request.verifier.trust.tier == diw.wallet.core.trust.TrustTier.T4 &&
            request.verifier.clientId.prefix != ClientIdPrefix.REDIRECT_URI) return null
        return post(request.responseUri!!, payload)
    }

    companion object {
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
