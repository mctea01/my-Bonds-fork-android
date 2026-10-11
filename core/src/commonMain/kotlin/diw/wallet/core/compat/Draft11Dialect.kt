package diw.wallet.core.compat

import diw.wallet.core.oid4vci.AuthServerMetadata
import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.oid4vci.GRANT_AUTHORIZATION_CODE
import diw.wallet.core.oid4vci.GRANT_PRE_AUTHORIZED_CODE
import diw.wallet.core.oid4vci.IssuerMetadata
import diw.wallet.core.util.arr
import diw.wallet.core.util.bool
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * OpenID4VCI draft 11 and 12 (still deployed by EBSI-era, Sphereon, Microsoft Entra test and many W3C issuers):
 * credentials and credentials_supported instead of configuration ids, user_pin_required, types at the top level,
 * cryptographic_suites_supported, a token_endpoint in issuer metadata, format based requests with a single proof,
 * response encryption parameters at the top level, and acceptance_token based deferred issuance.
 *
 * Offers and metadata are rewritten into the 1.0 shape once, marked with [MARKER], so the standard client
 * can process them; the request is then built in the draft shape for marked configurations only.
 */
class Draft11Dialect : IssuanceDialect {
    override val id = "draft11"
    override val spec = "OpenID4VCI draft 11/12"

    override fun claimsMetadata(issuer: IssuerMetadata): Boolean = issuer.raw.str(MARKER) != null

    override fun normalizeOffer(offer: JsonObject): JsonObject? {
        val creds = offer.arr("credentials") ?: return null
        val ids = creds.mapNotNull { e ->
            when (e) {
                is JsonPrimitive -> e.content
                is JsonObject -> syntheticId(e)
                else -> null
            }
        }
        if (ids.isEmpty()) return null
        val grants = offer.obj("grants")
        return buildJsonObject {
            put("credential_issuer", offer.str("credential_issuer"))
            putJsonArray("credential_configuration_ids") { ids.forEach { add(JsonPrimitive(it)) } }
            putJsonObject("grants") {
                grants?.obj(GRANT_PRE_AUTHORIZED_CODE)?.let { g ->
                    putJsonObject(GRANT_PRE_AUTHORIZED_CODE) {
                        put("pre-authorized_code", g.str("pre-authorized_code"))
                        val tx = g.obj("tx_code")
                        if (tx != null) put("tx_code", tx)
                        else if (g.bool("user_pin_required") == true) putJsonObject("tx_code") { put("input_mode", "numeric") }
                        g.str("authorization_server")?.let { put("authorization_server", it) }
                    }
                }
                grants?.obj(GRANT_AUTHORIZATION_CODE)?.let { put(GRANT_AUTHORIZATION_CODE, it) }
            }
            put(MARKER, "offer")
        }
    }

    override fun normalizeIssuerMetadata(metadata: JsonObject): JsonObject? {
        val supported = metadata["credentials_supported"] ?: return null
        val entries: List<Pair<String, JsonObject>> = when (supported) {
            is JsonArray -> supported.filterIsInstance<JsonObject>().map { (it.str("id") ?: syntheticId(it)) to it }
            is JsonObject -> supported.mapNotNull { (k, v) -> (v as? JsonObject)?.let { k to it } }
            else -> return null
        }
        val configs = buildJsonObject {
            for ((id, e) in entries) put(id, normalizeConfiguration(e))
        }
        val out = metadata.toMutableMap()
        out.remove("credentials_supported")
        out["credential_configurations_supported"] = configs
        if (metadata["authorization_servers"] == null) metadata.str("authorization_server")?.let {
            out["authorization_servers"] = JsonArray(listOf(JsonPrimitive(it)))
        }
        val respAlgs = metadata.strList("credential_response_encryption_alg_values_supported")
        if (metadata["credential_response_encryption"] == null && respAlgs.isNotEmpty()) {
            out["credential_response_encryption"] = buildJsonObject {
                putJsonArray("alg_values_supported") { respAlgs.forEach { add(JsonPrimitive(it)) } }
                putJsonArray("enc_values_supported") {
                    metadata.strList("credential_response_encryption_enc_values_supported").forEach { add(JsonPrimitive(it)) }
                }
                put("encryption_required", metadata.bool("require_credential_response_encryption") ?: false)
            }
        }
        out[MARKER] = JsonPrimitive("11")
        return JsonObject(out)
    }

    private fun normalizeConfiguration(e: JsonObject): JsonObject {
        val out = e.toMutableMap()
        val format = e.str("format")
        // Draft 11 jwt_vc_json carries types at the top level; ldp_vc and jwt_vc_json-ld carry @context and types.
        val types = e.strList("types").ifEmpty { e.obj("credential_definition")?.strList("types").orEmpty() }
        if (format != null && format.startsWith("jwt_vc") || format == "ldp_vc") {
            val def = (e.obj("credential_definition") ?: JsonObject(emptyMap())).toMutableMap()
            if (types.isNotEmpty() && def["type"] == null) def["type"] = JsonArray(types.map { JsonPrimitive(it) })
            val ctx = e["@context"] ?: def["@context"]
            if (ctx != null) def["@context"] = ctx
            e.obj("credentialSubject")?.let { def["credentialSubject"] = it }
            def.remove("types")
            out["credential_definition"] = JsonObject(def)
        }
        if (format == "vc+sd-jwt" && e.str("vct") == null) e.obj("credential_definition")?.str("vct")?.let { out["vct"] = JsonPrimitive(it) }
        val suites = e.strList("cryptographic_suites_supported")
        if (suites.isNotEmpty() && e["credential_signing_alg_values_supported"] == null) {
            out["credential_signing_alg_values_supported"] = JsonArray(suites.map { JsonPrimitive(it) })
        }
        val proofNames = when (val p = e["proof_types_supported"] ?: e["proof_types"]) {
            is JsonArray -> p.mapNotNull { (it as? JsonPrimitive)?.content }
            is JsonObject -> null
            else -> if (e.strList("cryptographic_binding_methods_supported").isNotEmpty()) listOf("jwt") else emptyList()
        }
        if (proofNames != null) {
            out.remove("proof_types")
            out["proof_types_supported"] = buildJsonObject {
                for (n in proofNames) putJsonObject(n) {
                    putJsonArray("proof_signing_alg_values_supported") {
                        (if (n == "jwt") suites.filter { it in JOSE_ALGS } else suites).forEach { add(JsonPrimitive(it)) }
                    }
                }
            }
        }
        out[MARKER] = JsonPrimitive("11")
        return JsonObject(out)
    }

    override fun authorizationServerFallback(issuer: IssuerMetadata): AuthServerMetadata? {
        val token = issuer.raw.str("token_endpoint") ?: return null
        return AuthServerMetadata(
            issuer = issuer.raw.str("authorization_server") ?: issuer.credentialIssuer,
            authorizationEndpoint = issuer.raw.str("authorization_endpoint"),
            tokenEndpoint = token,
            parEndpoint = issuer.raw.str("pushed_authorization_request_endpoint"),
            requirePar = false,
            dpopAlgorithms = emptyList(),
            codeChallengeMethods = emptyList(),
            tokenEndpointAuthMethods = emptyList(),
            challengeEndpoint = null,
            preAuthorizedAnonymousAccess = true,
            responseIssParameterSupported = false,
            raw = JsonObject(emptyMap()),
        )
    }

    override fun nonceWithoutEndpoint(tokenResponse: JsonObject): String? = tokenResponse.str("c_nonce")

    override fun nonceFromError(error: JsonObject): String? = error.str("c_nonce")

    override fun credentialRequest(issuer: IssuerMetadata, config: CredentialConfiguration, credentialIdentifier: String?, proofs: JsonObject?): JsonObject? {
        if (config.raw.str(MARKER) == null) return null
        return buildJsonObject {
            val format = config.raw.str("format") ?: config.format.wire
            put("format", format)
            when {
                format == "jwt_vc_json" || format == "jwt_vc" -> putJsonArray("types") { config.types.forEach { add(JsonPrimitive(it)) } }
                format == "ldp_vc" || format == "jwt_vc_json-ld" -> putJsonObject("credential_definition") {
                    config.raw.obj("credential_definition")?.get("@context")?.let { put("@context", it) }
                    putJsonArray("types") { config.types.forEach { add(JsonPrimitive(it)) } }
                }
                format == "mso_mdoc" -> config.docType?.let { put("doctype", it) }
                else -> config.vct?.let { v -> put("vct", v); putJsonObject("credential_definition") { put("vct", v) } }
            }
            singleProof(proofs)?.let { put("proof", it) }
        }
    }

    override fun adaptRequestBody(issuer: IssuerMetadata, body: JsonObject): JsonObject? {
        if (issuer.raw.str(MARKER) == null) return null
        val enc = body.obj("credential_response_encryption") ?: return null
        val out = body.toMutableMap()
        out.remove("credential_response_encryption")
        enc.obj("jwk")?.let { jwk ->
            out["credential_encryption_jwk"] = jwk
            out["credential_response_encryption_alg"] = JsonPrimitive(jwk.str("alg") ?: "ECDH-ES")
        }
        enc.str("enc")?.let { out["credential_response_encryption_enc"] = JsonPrimitive(it) }
        return JsonObject(out)
    }

    override fun credentialsFromResponse(response: JsonObject): List<String>? = response["credential"]?.let { listOf(credentialText(it)) }

    override fun deferral(response: JsonObject): Deferral? =
        if (response["credential"] == null) response.str("acceptance_token")?.let { Deferral(it, acceptanceToken = true) } else null

    override fun isIssuancePending(status: io.ktor.http.HttpStatusCode, error: JsonObject): Boolean = error.str("error") == "issuance_pending"

    companion object {
        /** Marks offers, metadata and configurations rewritten from the draft 11/12 shape. */
        const val MARKER = "x-diw-draft"

        private val JOSE_ALGS = setOf("ES256", "ES384", "ES512", "ES256K", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512")

        /** Identifier for a draft 11 configuration given by value: format and types, as in the offer. */
        fun syntheticId(e: JsonObject): String {
            val types = e.strList("types").ifEmpty { e.obj("credential_definition")?.let { it.strList("types").ifEmpty { it.strList("type") } }.orEmpty() }
            val name = types.lastOrNull { it != "VerifiableCredential" } ?: e.str("doctype") ?: e.str("vct") ?: e.obj("credential_definition")?.str("vct") ?: "credential"
            return (e.str("format") ?: "unknown") + ":" + name
        }

        /** A single draft era proof object from the 1.0 proofs object. */
        fun singleProof(proofs: JsonObject?): JsonObject? {
            val jwt = proofs?.arr("jwt")?.firstOrNull()
            val cwt = proofs?.arr("cwt")?.firstOrNull()
            val ldp = proofs?.arr("ldp_vp")?.firstOrNull() ?: proofs?.arr("di_vp")?.firstOrNull()
            val attestation = proofs?.arr("attestation")?.firstOrNull()
            return when {
                jwt != null -> buildJsonObject { put("proof_type", "jwt"); put("jwt", jwt) }
                cwt != null -> buildJsonObject { put("proof_type", "cwt"); put("cwt", cwt) }
                ldp != null -> buildJsonObject { put("proof_type", "ldp_vp"); put("ldp_vp", ldp) }
                attestation != null -> buildJsonObject { put("proof_type", "attestation"); put("attestation", attestation) }
                else -> null
            }
        }

        /** A credential from a response: a string as is, a JSON-LD object serialized. */
        fun credentialText(e: JsonElement): String = (e as? JsonPrimitive)?.takeIf { it.isString }?.content ?: e.toString()
    }
}
