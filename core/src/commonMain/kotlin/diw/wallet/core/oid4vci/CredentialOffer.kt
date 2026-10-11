package diw.wallet.core.oid4vci

import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.int
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.obj
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.queryParameters
import diw.wallet.core.util.reqStr
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonObject

const val GRANT_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
const val GRANT_AUTHORIZATION_CODE = "authorization_code"

/** Transaction code (PIN) the user must type for a pre-authorized grant. */
data class TxCode(
    val inputMode: String = "numeric",
    val length: Int? = null,
    val description: String? = null,
)

data class PreAuthorizedGrant(
    val preAuthorizedCode: String,
    val txCode: TxCode?,
    val authorizationServer: String?,
)

data class AuthorizationCodeGrant(
    val issuerState: String?,
    val authorizationServer: String?,
)

/** OpenID4VCI 1.0 Credential Offer (Section 4.1). */
data class CredentialOffer(
    val credentialIssuer: String,
    val credentialConfigurationIds: List<String>,
    val preAuthorized: PreAuthorizedGrant?,
    val authorizationCode: AuthorizationCodeGrant?,
    val raw: JsonObject,
) {
    companion object {
        /** Schemes a wallet registers for offers. */
        val SCHEMES = setOf("openid-credential-offer", "haip-vci", "https")

        fun parse(json: JsonObject): CredentialOffer {
            val issuer = json.reqStr("credential_issuer", "invalid_credential_offer")
            val ids = json.strList("credential_configuration_ids")
            if (ids.isEmpty()) throw ProtocolException("invalid_credential_offer", "credential_configuration_ids is empty")
            val grants = json.obj("grants")
            val pre = grants?.obj(GRANT_PRE_AUTHORIZED_CODE)?.let { g ->
                PreAuthorizedGrant(
                    preAuthorizedCode = g.reqStr("pre-authorized_code", "invalid_credential_offer"),
                    txCode = g.obj("tx_code")?.let { t ->
                        TxCode(t.str("input_mode") ?: "numeric", t.int("length"), t.str("description"))
                    },
                    authorizationServer = g.str("authorization_server"),
                )
            }
            val code = grants?.obj(GRANT_AUTHORIZATION_CODE)?.let { g ->
                AuthorizationCodeGrant(g.str("issuer_state"), g.str("authorization_server"))
            }
            return CredentialOffer(issuer, ids, pre, code, json)
        }
    }
}

/** Resolves an offer given by value or by reference (credential_offer_uri). */
class CredentialOfferResolver(
    private val httpClient: HttpClient,
    private val allowInsecureLoopback: Boolean,
) {
    /** Resolves an offer; an offer in an older shape (draft 11/12 credentials array) is normalized by [compat]. */
    suspend fun resolve(uri: String, compat: diw.wallet.core.compat.DialectSet? = null): CredentialOffer {
        val scheme = uri.substringBefore(':', "").lowercase()
        if (scheme !in CredentialOffer.SCHEMES) {
            throw ProtocolException("invalid_credential_offer", "Unsupported offer scheme '$scheme'")
        }
        val q = queryParameters(uri)
        val byValue = q["credential_offer"]
        val byRef = q["credential_offer_uri"]
        if (byValue != null && byRef != null) {
            throw ProtocolException("invalid_credential_offer", "Both credential_offer and credential_offer_uri are present")
        }
        val json = when {
            byValue != null -> parseJsonObject(byValue, "invalid_credential_offer")
            byRef != null -> fetch(byRef)
            else -> throw ProtocolException("invalid_credential_offer", "No credential offer in URI")
        }
        val shaped = if (json.strList("credential_configuration_ids").isEmpty()) compat?.first { it.normalizeOffer(json) } ?: json else json
        val offer = CredentialOffer.parse(shaped)
        if (!isAcceptableEndpoint(offer.credentialIssuer, allowInsecureLoopback)) {
            throw ProtocolException("invalid_credential_offer", "credential_issuer must be an https URL")
        }
        return offer
    }

    private suspend fun fetch(url: String): JsonObject {
        if (!isAcceptableEndpoint(url, allowInsecureLoopback)) {
            throw ProtocolException("invalid_credential_offer", "credential_offer_uri must be https")
        }
        val resp = httpClient.get(url) { accept(ContentType.Application.Json) }
        if (!resp.status.isSuccess()) {
            throw ProtocolException("invalid_credential_offer", "credential_offer_uri returned ${resp.status.value}")
        }
        return parseJsonObject(resp.bodyAsText(), "invalid_credential_offer")
    }
}
