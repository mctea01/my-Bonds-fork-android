package diw.wallet.core.oid4vp

import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.addCborArray
import org.multipaz.cbor.buildCborArray
import org.multipaz.credential.Credential
import org.multipaz.credential.SecureAreaBoundCredential
import kotlinx.io.bytestring.decodeToString
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.JsonWebEncryption
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.response.buildDeviceResponse
import org.multipaz.mdoc.zkp.ZkSystem
import org.multipaz.mdoc.zkp.ZkSystemSpec
import org.multipaz.openid.OpenID4VP
import org.multipaz.openid.dcql.DcqlQuery
import org.multipaz.presentment.CredentialMatchSourceOpenID4VP
import org.multipaz.presentment.CredentialPresentmentSetOptionMemberMatch
import org.multipaz.presentment.CredentialSelection
import org.multipaz.presentment.PresentmentSource
import org.multipaz.presentment.PresentmentUnlockReason
import org.multipaz.presentment.TransactionData
import org.multipaz.request.JsonRequestedClaim
import org.multipaz.request.MdocRequestedClaim
import org.multipaz.sdjwt.SdJwt
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.util.toBase64Url
import diw.wallet.core.jose.PlatformCrypto
import kotlin.time.Clock

/** The selected encryption target for an encrypted response. */
data class ResponseEncryption(val key: EcPublicKey, val kid: String?, val enc: Algorithm)

/** Output of [ResponseBuilder.build]. */
data class BuiltResponse(
    /** The vp_token object keyed by DCQL credential query id. */
    val vpToken: JsonObject,
    /** Parameters to deliver: either {vp_token, state} or {response: JWE}. */
    val payload: JsonObject,
    val encrypted: Boolean,
)

/**
 * Builds OpenID4VP 1.0 responses for a [ValidatedAuthorizationRequest]. The client_id and origin bindings
 * come from the validation layer, so every client identifier prefix is handled uniformly (the Multipaz
 * built-in generator only binds X.509 authenticated clients).
 */
class ResponseBuilder(private val source: PresentmentSource) {

    fun dcqlQuery(request: ValidatedAuthorizationRequest): DcqlQuery = try {
        DcqlQuery.fromJson(request.dcqlQuery)
    } catch (e: Exception) {
        throw ProtocolException("invalid_request", "Malformed dcql_query: ${e.message}", e)
    }

    fun parseTransactionData(request: ValidatedAuthorizationRequest): Map<String, List<TransactionData<*>>> {
        if (request.transactionData.isEmpty()) return emptyMap()
        return try {
            source.documentTypeRepository.parseJsonTransactions(request.transactionData)
        } catch (e: Exception) {
            throw ProtocolException("invalid_transaction_data", "Unsupported or malformed transaction_data: ${e.message}", e)
        }
    }

    fun selectEncryption(request: ValidatedAuthorizationRequest): ResponseEncryption? {
        if (!request.responseMode.encrypted) return null
        val meta = request.clientMetadata ?: throw ProtocolException("invalid_request", "client_metadata missing")
        val keys = meta.obj("jwks")?.arr("keys") ?: throw ProtocolException("invalid_request", "client_metadata.jwks missing")
        val candidate = keys.mapNotNull { it as? JsonObject }.firstOrNull { jwk ->
            val use = jwk.str("use")
            val alg = jwk.str("alg")
            (use == null || use == "enc") && (alg == null || alg == "ECDH-ES") && (jwk.str("kty") == "EC" || jwk.str("kty") == "OKP")
        } ?: throw ProtocolException("invalid_request", "No usable ECDH-ES encryption key in client_metadata.jwks")
        val encValues = meta.strList("encrypted_response_enc_values_supported").ifEmpty { listOf("A128GCM") }
        val enc = encValues.firstNotNullOfOrNull {
            when (it) {
                "A128GCM" -> Algorithm.A128GCM
                "A192GCM" -> Algorithm.A192GCM
                "A256GCM" -> Algorithm.A256GCM
                else -> null
            }
        } ?: throw ProtocolException("invalid_request", "No supported content encryption in $encValues")
        return ResponseEncryption(EcPublicKey.fromJwk(candidate), candidate.str("kid"), enc)
    }

    suspend fun build(request: ValidatedAuthorizationRequest, selection: CredentialSelection): BuiltResponse {
        val encryption = selectEncryption(request)
        val vpTokens = linkedMapOf<String, MutableList<String>>()
        var usingZk = false
        for (match in selection.matches) {
            val src = match.source as? CredentialMatchSourceOpenID4VP
                ?: throw ProtocolException("server_error", "Selection does not come from a DCQL query")
            val query = src.credentialQuery
            val presentation = when {
                query.mdocDocType != null -> {
                    if (query.format == "mso_mdoc_zk") usingZk = true
                    presentMdoc(request, match, encryption, query.format == "mso_mdoc_zk")
                }
                query.vctValues != null -> presentSdJwt(request, match)
                else -> throw ProtocolException("invalid_request", "Unsupported credential format ${query.format}")
            }
            vpTokens.getOrPut(query.id) { mutableListOf() }.add(presentation)
        }
        val vpToken = buildJsonObject {
            for ((id, list) in vpTokens) putJsonArray(id) { list.forEach { add(JsonPrimitive(it)) } }
        }
        val plain = buildJsonObject {
            put("vp_token", vpToken)
            request.state?.let { put("state", it) }
        }
        if (encryption == null) return BuiltResponse(vpToken, plain, false)
        val jwe = JsonWebEncryption.encrypt(
            claimsSet = plain,
            recipientPublicKey = encryption.key,
            encAlg = encryption.enc,
            // Multipaz decrypt always length-prefixes apu/apv, so both must be present.
            apu = walletNonce().encodeToByteString(),
            apv = request.nonce.encodeToByteString(),
            kid = encryption.kid,
            compressionLevel = if (usingZk) 9 else null,
        )
        return BuiltResponse(vpToken, buildJsonObject { put("response", jwe) }, true)
    }

    private suspend fun presentMdoc(
        request: ValidatedAuthorizationRequest,
        match: CredentialPresentmentSetOptionMemberMatch,
        encryption: ResponseEncryption?,
        zk: Boolean,
    ): String {
        if (match.transactionData.isNotEmpty()) {
            throw ProtocolException("invalid_transaction_data", "transaction_data for mso_mdoc is not supported")
        }
        val src = match.source as CredentialMatchSourceOpenID4VP
        val thumbprint = encryption?.key?.toJwkThumbprint(Algorithm.SHA256)?.toByteArray()
        val handoverInfo = Cbor.encode(buildCborArray {
            if (request.responseMode.dcApi) {
                add(request.origin ?: throw ProtocolException("invalid_request", "origin unknown"))
                add(request.nonce)
                if (thumbprint == null) add(Simple.NULL) else add(Bstr(thumbprint))
            } else {
                add(request.verifier.effectiveClientId)
                add(request.nonce)
                if (thumbprint == null) add(Simple.NULL) else add(Bstr(thumbprint))
                add(request.responseUri!!)
            }
        })
        val handoverName = if (request.responseMode.dcApi) "OpenID4VPDCAPIHandover" else "OpenID4VPHandover"
        val sessionTranscript = buildCborArray {
            add(Simple.NULL)
            add(Simple.NULL)
            addCborArray {
                add(handoverName)
                add(Bstr(Crypto.digest(Algorithm.SHA256, handoverInfo)))
            }
        }
        val credential = match.credential as MdocCredential
        @Suppress("UNCHECKED_CAST")
        val document = MdocDocument.fromPresentment(
            sessionTranscript = sessionTranscript,
            credential = credential,
            requestedClaims = src.credentialQuery.claims as List<MdocRequestedClaim>,
        )
        val zkSystem: Pair<ZkSystem, ZkSystemSpec>? = if (zk) findZkSystem(match) else null
        val deviceResponse = buildDeviceResponse(sessionTranscript = sessionTranscript, status = DeviceResponse.STATUS_OK) {
            if (zkSystem != null) {
                addZkDocument(zkSystem.first.generateProof(zkSystem.second, document, sessionTranscript))
            } else {
                addDocument(document)
            }
        }
        credential.increaseUsageCount()
        return Cbor.encode(deviceResponse.toDataItem()).toBase64Url()
    }

    private fun findZkSystem(match: CredentialPresentmentSetOptionMemberMatch): Pair<ZkSystem, ZkSystemSpec> {
        val query = (match.source as CredentialMatchSourceOpenID4VP).credentialQuery
        val repo = source.zkSystemRepository ?: throw ProtocolException("invalid_request", "ZK proofs are not available on this device")
        val specs = (query.meta["zk_system_type"] as? JsonArray ?: JsonArray(emptyList())).map { entry ->
            val o = entry.jsonObject
            ZkSystemSpec(o["id"]!!.jsonPrimitive.content, o["system"]!!.jsonPrimitive.content).also { spec ->
                for ((k, v) in o) if (k != "id" && k != "system") spec.addParam(k, v)
            }
        }
        for (spec in specs) {
            val sys = repo.lookup(spec.system) ?: continue
            val matching = sys.getMatchingSystemSpec(specs, query.claims) ?: continue
            return sys to matching
        }
        throw ProtocolException("invalid_request", "No matching ZK system for the request")
    }

    private suspend fun presentSdJwt(
        request: ValidatedAuthorizationRequest,
        match: CredentialPresentmentSetOptionMemberMatch,
    ): String {
        val src = match.source as CredentialMatchSourceOpenID4VP
        val credential = match.credential as SdJwtVcCredential
        @Suppress("UNCHECKED_CAST")
        val claims = src.credentialQuery.claims as List<JsonRequestedClaim>
        val base = credential as Credential
        val sdJwt = SdJwt.fromCompactSerialization(base.issuerProvidedData.decodeToString())
        val filtered = sdJwt.filter(claims.map { it.claimPath })
        base.increaseUsageCount()
        if (credential !is SecureAreaBoundCredential) {
            if (requiresHolderBinding(request, src.credentialQuery.id)) {
                throw ProtocolException("invalid_request", "Holder binding requested for a keyless credential")
            }
            return filtered.compactSerialization
        }
        val transactionResponse = OpenID4VP.processTransactions(credential, match.transactionData, match.transactionUserInput)
        val audience = if (request.responseMode.dcApi) "origin:${request.origin}" else request.verifier.effectiveClientId
        return filtered.present(
            signingKey = AsymmetricKey.anonymous(
                alias = credential.alias,
                secureArea = credential.secureArea,
                unlockReason = PresentmentUnlockReason(credential),
            ),
            nonce = request.nonce,
            audience = audience,
            creationTime = Clock.System.now(),
        ) {
            for ((k, v) in transactionResponse) put(k, v)
        }.compactSerialization
    }

    private fun requiresHolderBinding(request: ValidatedAuthorizationRequest, queryId: String): Boolean {
        val q = request.dcqlQuery.arr("credentials")?.mapNotNull { it as? JsonObject }?.firstOrNull { it.str("id") == queryId }
        return (q?.get("require_cryptographic_holder_binding") as? JsonPrimitive)?.content != "false"
    }

    companion object {
        /** Builds an OpenID4VP error response body. */
        fun errorPayload(error: String, description: String?, state: String?): JsonObject = buildJsonObject {
            put("error", error)
            description?.let { put("error_description", it) }
            state?.let { put("state", it) }
        }

        fun walletNonce(): String = PlatformCrypto.randomBytes(16).toBase64Url()
    }
}
