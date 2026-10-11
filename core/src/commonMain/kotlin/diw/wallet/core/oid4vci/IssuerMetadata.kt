package diw.wallet.core.oid4vci

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.bool
import diw.wallet.core.util.int
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.long
import diw.wallet.core.util.obj
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.reqStr
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import diw.wallet.core.util.wellKnownUrl
import diw.wallet.core.util.wellKnownUrlAppended
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.time.Clock

/** Display entry from metadata (Section 12.2.4). */
data class DisplayInfo(
    val name: String?,
    val locale: String?,
    val logoUri: String?,
    val description: String?,
    val backgroundColor: String?,
    val textColor: String?,
) {
    companion object {
        fun list(arr: JsonArray?): List<DisplayInfo> = arr.orEmpty().mapNotNull { e ->
            (e as? JsonObject)?.let {
                DisplayInfo(
                    name = it.str("name"),
                    locale = it.str("locale"),
                    logoUri = it.obj("logo")?.str("uri"),
                    description = it.str("description"),
                    backgroundColor = it.str("background_color"),
                    textColor = it.str("text_color"),
                )
            }
        }
    }
}

/** Picks the display entry best matching [locales] (BCP 47, most preferred first). */
fun List<DisplayInfo>.pick(locales: List<String>): DisplayInfo? {
    for (l in locales) {
        firstOrNull { it.locale.equals(l, ignoreCase = true) }?.let { return it }
        val lang = l.substringBefore('-')
        firstOrNull { it.locale?.substringBefore('-').equals(lang, ignoreCase = true) }?.let { return it }
    }
    return firstOrNull { it.locale == null } ?: firstOrNull()
}

enum class CredentialFormatId(val wire: String) {
    MSO_MDOC("mso_mdoc"),
    SD_JWT_VC("dc+sd-jwt"),
    /** Pre-1.0 media type still emitted by older issuers; handled as SD-JWT VC. */
    SD_JWT_VC_LEGACY("vc+sd-jwt"),
    /** W3C VC secured as a JWT, not using JSON-LD (Appendix A.1.1). */
    JWT_VC_JSON("jwt_vc_json"),
    /** W3C VC secured as a JWT, using JSON-LD (Appendix A.1.2). */
    JWT_VC_JSON_LD("jwt_vc_json-ld"),
    /** W3C VC secured with Data Integrity / Linked Data Proofs (Appendix A.1.3). */
    LDP_VC("ldp_vc"),
    /** Draft 11 and earlier name for jwt_vc_json. */
    JWT_VC("jwt_vc");

    val isSdJwt: Boolean get() = this == SD_JWT_VC || this == SD_JWT_VC_LEGACY
    val isW3c: Boolean get() = this == JWT_VC_JSON || this == JWT_VC_JSON_LD || this == LDP_VC || this == JWT_VC

    companion object {
        fun fromWire(s: String?): CredentialFormatId? = entries.firstOrNull { it.wire == s }
    }
}

/** Requirements on key attestation for a proof type (Appendix D). */
data class KeyAttestationRequirement(
    val keyStorage: List<String>,
    val userAuthentication: List<String>,
)

data class ProofTypeInfo(
    val signingAlgorithms: List<String>,
    val keyAttestationsRequired: KeyAttestationRequirement?,
)

data class CredentialConfiguration(
    val id: String,
    val format: CredentialFormatId,
    val docType: String?,
    val vct: String?,
    val scope: String?,
    val bindingMethods: List<String>,
    val signingAlgorithms: List<String>,
    val proofTypes: Map<String, ProofTypeInfo>,
    val display: List<DisplayInfo>,
    val claims: JsonArray?,
    val raw: JsonObject,
    /** W3C type list (credential_definition.type), most specific last; empty for other formats. */
    val types: List<String> = emptyList(),
    /** W3C @context list (credential_definition.@context) for jwt_vc_json-ld and ldp_vc. */
    val contexts: List<String> = emptyList(),
) {
    /** Credentials without cryptographic binding are issued keyless. */
    val keyBound: Boolean get() = bindingMethods.isNotEmpty() || proofTypes.isNotEmpty()

    /** DID methods the issuer binds to (did:key, did:jwk, did:web, or "did" for any); empty when keys are bound as JWK/COSE key. */
    val didMethods: List<String> get() = bindingMethods.filter { it == "did" || it.startsWith("did:") }

    /** True when the issuer binds only to DIDs, so proofs must carry a DID URL kid rather than a jwk. */
    val didBindingOnly: Boolean get() = bindingMethods.isNotEmpty() && didMethods.size == bindingMethods.size

    companion object {
        fun parse(id: String, json: JsonObject): CredentialConfiguration {
            val format = CredentialFormatId.fromWire(json.str("format"))
                ?: throw ProtocolException("unsupported_credential_format", "Unsupported format '${json.str("format")}' for $id")
            val proofs = json.obj("proof_types_supported")?.mapNotNull { (name, v) ->
                val o = v as? JsonObject ?: return@mapNotNull null
                name to ProofTypeInfo(
                    signingAlgorithms = o.strList("proof_signing_alg_values_supported"),
                    keyAttestationsRequired = o.obj("key_attestations_required")?.let {
                        KeyAttestationRequirement(it.strList("key_storage"), it.strList("user_authentication"))
                    },
                )
            }?.toMap().orEmpty()
            val credentialMetadata = json.obj("credential_metadata")
            val display = DisplayInfo.list(credentialMetadata?.arr("display") ?: json.arr("display"))
            val definition = json.obj("credential_definition")
            return CredentialConfiguration(
                id = id,
                format = format,
                docType = json.str("doctype"),
                vct = json.str("vct"),
                scope = json.str("scope"),
                bindingMethods = json.strList("cryptographic_binding_methods_supported"),
                signingAlgorithms = json.arr("credential_signing_alg_values_supported").orEmpty()
                    .map { it.toString().trim('"') },
                proofTypes = proofs,
                display = display,
                claims = credentialMetadata?.arr("claims") ?: json.arr("claims"),
                raw = json,
                types = definition?.strList("type").orEmpty(),
                contexts = definition?.strList("@context").orEmpty(),
            )
        }
    }
}

/** Issuer-side JWE parameters for credential request encryption (Section 12.2.4). */
data class RequestEncryptionInfo(
    val jwks: JsonArray,
    val encValues: List<String>,
    val zipValues: List<String>,
    val required: Boolean,
)

data class ResponseEncryptionInfo(
    val algValues: List<String>,
    val encValues: List<String>,
    val zipValues: List<String>,
    val required: Boolean,
)

/** OpenID4VCI 1.0 Credential Issuer Metadata, together with how it was authenticated. */
data class IssuerMetadata(
    val credentialIssuer: String,
    val authorizationServers: List<String>,
    val credentialEndpoint: String,
    val nonceEndpoint: String?,
    val deferredCredentialEndpoint: String?,
    val notificationEndpoint: String?,
    val requestEncryption: RequestEncryptionInfo?,
    val responseEncryption: ResponseEncryptionInfo?,
    val batchSize: Int,
    val display: List<DisplayInfo>,
    val configurations: Map<String, CredentialConfiguration>,
    val trust: TrustDecision,
    val raw: JsonObject,
    /** Configurations this wallet cannot request (unknown format, malformed entry), with the reason, for display. */
    val unsupported: Map<String, String> = emptyMap(),
) {
    /** The authorization server to use for a grant, honouring the offer's hint when it is listed. */
    fun authorizationServerFor(hint: String?): String = when {
        hint != null && hint in authorizationServers -> hint
        hint != null -> throw ProtocolException("invalid_credential_offer", "authorization_server '$hint' is not listed by the issuer")
        authorizationServers.isNotEmpty() -> authorizationServers.first()
        else -> credentialIssuer
    }

    companion object {
        fun parse(json: JsonObject, trust: TrustDecision): IssuerMetadata {
            val issuer = json.reqStr("credential_issuer", "invalid_issuer_metadata")
            val configs = json.obj("credential_configurations_supported")
                ?: throw ProtocolException("invalid_issuer_metadata", "credential_configurations_supported missing")
            val parsed = mutableMapOf<String, CredentialConfiguration>()
            val unsupported = mutableMapOf<String, String>()
            for ((id, v) in configs) {
                val o = v as? JsonObject
                if (o == null) { unsupported[id] = "Malformed configuration"; continue }
                runCatching { CredentialConfiguration.parse(id, o) }
                    .onSuccess { parsed[id] = it }
                    .onFailure { unsupported[id] = it.message ?: "Unsupported" }
            }
            return IssuerMetadata(
                credentialIssuer = issuer,
                authorizationServers = json.strList("authorization_servers"),
                credentialEndpoint = json.reqStr("credential_endpoint", "invalid_issuer_metadata"),
                nonceEndpoint = json.str("nonce_endpoint"),
                deferredCredentialEndpoint = json.str("deferred_credential_endpoint"),
                notificationEndpoint = json.str("notification_endpoint"),
                requestEncryption = json.obj("credential_request_encryption")?.let {
                    RequestEncryptionInfo(
                        jwks = it.obj("jwks")?.arr("keys") ?: JsonArray(emptyList()),
                        encValues = it.strList("enc_values_supported"),
                        zipValues = it.strList("zip_values_supported"),
                        required = it.bool("encryption_required") ?: false,
                    )
                },
                responseEncryption = json.obj("credential_response_encryption")?.let {
                    ResponseEncryptionInfo(
                        algValues = it.strList("alg_values_supported"),
                        encValues = it.strList("enc_values_supported"),
                        zipValues = it.strList("zip_values_supported"),
                        required = it.bool("encryption_required") ?: false,
                    )
                },
                batchSize = json.obj("batch_credential_issuance")?.int("batch_size")?.coerceAtLeast(1) ?: 1,
                display = DisplayInfo.list(json.arr("display")),
                configurations = parsed,
                trust = trust,
                raw = json,
                unsupported = unsupported,
            )
        }
    }
}

/** RFC 8414 Authorization Server Metadata (fields used by OpenID4VCI). */
data class AuthServerMetadata(
    val issuer: String,
    val authorizationEndpoint: String?,
    val tokenEndpoint: String,
    val parEndpoint: String?,
    val requirePar: Boolean,
    val dpopAlgorithms: List<String>,
    val codeChallengeMethods: List<String>,
    val tokenEndpointAuthMethods: List<String>,
    val challengeEndpoint: String?,
    val preAuthorizedAnonymousAccess: Boolean,
    val responseIssParameterSupported: Boolean,
    val raw: JsonObject,
) {
    val usesDpop: Boolean get() = dpopAlgorithms.isNotEmpty()
    val usesClientAttestation: Boolean get() = "attest_jwt_client_auth" in tokenEndpointAuthMethods

    companion object {
        fun parse(json: JsonObject): AuthServerMetadata = AuthServerMetadata(
            issuer = json.reqStr("issuer", "invalid_as_metadata"),
            authorizationEndpoint = json.str("authorization_endpoint"),
            tokenEndpoint = json.reqStr("token_endpoint", "invalid_as_metadata"),
            parEndpoint = json.str("pushed_authorization_request_endpoint"),
            requirePar = json.bool("require_pushed_authorization_requests") ?: false,
            dpopAlgorithms = json.strList("dpop_signing_alg_values_supported"),
            codeChallengeMethods = json.strList("code_challenge_methods_supported"),
            tokenEndpointAuthMethods = json.strList("token_endpoint_auth_methods_supported"),
            challengeEndpoint = json.str("challenge_endpoint"),
            preAuthorizedAnonymousAccess = json.bool("pre-authorized_grant_anonymous_access_supported") ?: false,
            responseIssParameterSupported = json.bool("authorization_response_iss_parameter_supported") ?: false,
            raw = json,
        )
    }
}

/**
 * Fetches and authenticates issuer and authorization server metadata.
 * Signed issuer metadata (typ openidvci-issuer-metadata+jwt) is verified against ISSUER anchors.
 */
class MetadataFetcher(
    private val httpClient: HttpClient,
    private val trustRegistry: TrustRegistry,
    private val allowInsecureLoopback: Boolean,
) {
    /** Fetches issuer metadata; metadata in an older shape is normalized by [compat] (draft 11/12 credentials_supported). */
    suspend fun issuer(credentialIssuer: String, compat: diw.wallet.core.compat.DialectSet? = null): IssuerMetadata {
        checkEndpoint(credentialIssuer, "credential_issuer")
        val lookup = getFirst(
            listOf(wellKnownUrl(credentialIssuer, "openid-credential-issuer"), wellKnownUrlAppended(credentialIssuer, "openid-credential-issuer")),
            accept = "application/jwt, application/json;q=0.9",
        )
        val resp = lookup.response
            ?: throw ProtocolException("invalid_issuer_metadata", "Issuer metadata not found for $credentialIssuer${lookup.failure}")
        val body = resp.bodyAsText()
        val isJwt = resp.contentType()?.match(ContentType("application", "jwt")) == true ||
            (!body.trimStart().startsWith("{") && body.count { it == '.' } == 2)
        val (json, trust) = if (isJwt) verifySigned(body.trim(), credentialIssuer) else {
            val obj = parseJsonObject(body, "invalid_issuer_metadata")
            val signed = obj.str("signed_metadata")
            if (signed != null) {
                val (signedClaims, t) = verifySigned(signed, credentialIssuer)
                JsonObject(obj + signedClaims) to t
            } else {
                obj to TrustDecision(
                    tier = TrustTier.T3, environment = null, official = false, anchorName = null,
                    labels = setOf(TrustLabel.UNSIGNED_METADATA),
                    reasons = listOf("Issuer metadata is not signed; issuer identity rests on TLS only"),
                )
            }
        }
        val shaped = if (json.obj("credential_configurations_supported") == null) {
            compat?.first { it.normalizeIssuerMetadata(json) } ?: json
        } else json
        val metadata = IssuerMetadata.parse(shaped, trust)
        if (metadata.credentialIssuer != credentialIssuer) {
            throw ProtocolException("invalid_issuer_metadata", "credential_issuer in metadata does not match '${credentialIssuer}'")
        }
        checkEndpoint(metadata.credentialEndpoint, "credential_endpoint")
        metadata.nonceEndpoint?.let { checkEndpoint(it, "nonce_endpoint") }
        metadata.deferredCredentialEndpoint?.let { checkEndpoint(it, "deferred_credential_endpoint") }
        metadata.notificationEndpoint?.let { checkEndpoint(it, "notification_endpoint") }
        return metadata
    }

    /** Checks authorization server metadata a dialect supplied for an issuer that publishes none. */
    fun checkFallback(meta: AuthServerMetadata): AuthServerMetadata {
        checkEndpoint(meta.tokenEndpoint, "token_endpoint")
        meta.authorizationEndpoint?.let { checkEndpoint(it, "authorization_endpoint") }
        return meta
    }

    suspend fun authorizationServer(identifier: String): AuthServerMetadata {
        checkEndpoint(identifier, "authorization_server")
        val lookup = getFirst(
            listOf(
                wellKnownUrl(identifier, "oauth-authorization-server"),
                wellKnownUrl(identifier, "openid-configuration"),
                wellKnownUrlAppended(identifier, "openid-configuration"),
            ),
            accept = "application/json",
        )
        val resp = lookup.response
            ?: throw ProtocolException("invalid_as_metadata", "Authorization server metadata not found for $identifier${lookup.failure}")
        val meta = AuthServerMetadata.parse(parseJsonObject(resp.bodyAsText(), "invalid_as_metadata"))
        if (meta.issuer.trimEnd('/') != identifier.trimEnd('/')) {
            throw ProtocolException("invalid_as_metadata", "AS issuer '${meta.issuer}' does not match '$identifier'")
        }
        checkEndpoint(meta.tokenEndpoint, "token_endpoint")
        meta.authorizationEndpoint?.let { checkEndpoint(it, "authorization_endpoint") }
        meta.parEndpoint?.let { checkEndpoint(it, "pushed_authorization_request_endpoint") }
        meta.challengeEndpoint?.let { checkEndpoint(it, "challenge_endpoint") }
        return meta
    }

    private suspend fun verifySigned(jwt: String, credentialIssuer: String): Pair<JsonObject, TrustDecision> {
        val jws = Jws.parse(jwt)
        if (jws.typ != "openidvci-issuer-metadata+jwt") {
            throw ProtocolException("invalid_issuer_metadata", "Signed metadata has typ '${jws.typ}'")
        }
        val chain = jws.x5c?.certificates
            ?: throw ProtocolException("invalid_issuer_metadata", "Signed metadata without x5c is not supported")
        X509CertChainCheck.validate(chain)
        jws.verify(VerificationKey.fromCertificate(chain.first()))
        val claims = jws.payload
        val sub = claims.str("sub")
        if (sub != null && sub != credentialIssuer) {
            throw ProtocolException("invalid_issuer_metadata", "Signed metadata sub does not match credential_issuer")
        }
        claims.long("exp")?.let {
            if (it < Clock.System.now().epochSeconds) throw ProtocolException("invalid_issuer_metadata", "Signed metadata expired")
        }
        return claims to trustRegistry.decide(TrustRole.ISSUER, chain)
    }

    private class Lookup(val response: HttpResponse?, val failure: String)

    /** First successful response; otherwise the last failure, e.g. " (HTTP 404: No test found ...)", for the error message. */
    private suspend fun getFirst(urls: List<String>, accept: String): Lookup {
        var failure = ""
        for (u in urls.distinct()) {
            val r = try {
                httpClient.get(u) { header(HttpHeaders.Accept, accept) }
            } catch (e: Exception) {
                failure = " (${e.message ?: e::class.simpleName})"
                continue
            }
            if (r.status.isSuccess()) return Lookup(r, "")
            val text = runCatching { r.bodyAsText() }.getOrDefault("")
            val detail = runCatching { Json.parseToJsonElement(text).jsonObject }.getOrNull()
                ?.let { it.str("error_description") ?: it.str("error") ?: it.str("message") }
                ?: text.replace(Regex("<[^>]*>"), " ").replace(Regex("\\s+"), " ").trim()
            failure = " (HTTP ${r.status.value}" + (if (detail.isNotEmpty()) ": ${detail.take(160)}" else "") + ")"
        }
        return Lookup(null, failure)
    }

    private fun checkEndpoint(url: String, name: String) {
        if (!isAcceptableEndpoint(url, allowInsecureLoopback)) {
            throw ProtocolException("invalid_issuer_metadata", "$name '$url' is not an acceptable https endpoint")
        }
    }
}

/** Basic X.509 chain consistency check (signatures and validity), independent of anchors. */
object X509CertChainCheck {
    suspend fun validate(chain: List<org.multipaz.crypto.X509Cert>) {
        if (chain.size > 1) {
            try {
                org.multipaz.crypto.X509CertChain(chain).validate()
            } catch (e: Exception) {
                throw ProtocolException("invalid_certificate_chain", "Certificate chain is invalid: ${e.message}", e)
            }
        }
        val now = Clock.System.now()
        val leaf = chain.first()
        if (now < leaf.validityNotBefore || now > leaf.validityNotAfter) {
            throw ProtocolException("invalid_certificate_chain", "Leaf certificate is outside its validity period")
        }
    }
}
