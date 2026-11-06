package diw.wallet.core.oid4vp.ext

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.ResponseMode
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.compat.PresentationDialect
import diw.wallet.core.oid4vp.compat.VpInput
import diw.wallet.core.oid4vp.pe.DescriptorMatch
import diw.wallet.core.oid4vp.pe.PresentationDefinition
import diw.wallet.core.oid4vp.pe.PresentationExchange
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.obj
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import diw.wallet.core.w3c.DataIntegrity
import diw.wallet.core.w3c.SdJwtDisclosures
import diw.wallet.core.w3c.W3cVc
import diw.wallet.core.w3c.W3cVcCredential
import io.ktor.client.HttpClient
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.URLBuilder
import io.ktor.http.encodeURLParameter
import io.ktor.http.parameters
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.addCborArray
import org.multipaz.cbor.buildCborArray
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.JsonWebEncryption
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.response.buildDeviceResponse
import org.multipaz.request.MdocRequestedClaim
import org.multipaz.util.toBase64Url
import kotlin.time.Clock

/** One credential chosen for an extended presentation and what it discloses. */
data class ChosenCredential(
    val credential: WalletCredential,
    /** Member paths to disclose, from the credential JSON root; an empty path means the whole credential. */
    val memberPaths: List<List<String>>,
    /** Presentation Exchange input descriptor id. */
    val descriptorId: String?,
    /** DCQL credential query id. */
    val queryId: String?,
    val intentToRetain: Boolean,
)

/** One line of the consent screen: a credential and the claims it discloses (claim paths joined with '.'). */
data class ConsentLine(val document: Document, val documentName: String, val claims: List<String>)

/**
 * An extended request matched against the wallet, ready for consent. [chosen] and [lines] are index aligned; the
 * holder may swap the credential of a line for one of its [alternatives] through [ExtendedPresenter.replace].
 */
class ExtendedPrepared internal constructor(
    val request: ValidatedAuthorizationRequest,
    val chosen: List<ChosenCredential>,
    val lines: List<ConsentLine>,
    val definition: PresentationDefinition?,
    val dcql: DcqlQueryModel?,
    internal val peMatches: List<DescriptorMatch> = emptyList(),
    internal val peCandidates: Map<String, List<DescriptorMatch>> = emptyMap(),
    internal val dcqlMatches: List<DcqlMatch> = emptyList(),
    internal val dcqlCandidates: Map<String, List<DcqlMatch>> = emptyMap(),
) {
    /**
     * Other held credentials that can answer line [index] while the submission still meets the request: candidates of
     * the same input descriptor or DCQL query, or, under a Presentation Exchange pick rule, of another descriptor of the
     * same group. Credentials already presented on another line are left out.
     */
    fun alternatives(index: Int): List<WalletCredential> = replacements(index).map { it.second }

    internal fun replacements(index: Int): List<Pair<Any, WalletCredential>> {
        val current = chosen.getOrNull(index) ?: return emptyList()
        val others = chosen.filterIndexed { i, _ -> i != index }.map { it.credential.document.identifier }.toSet()
        fun usable(c: WalletCredential) = c.document.identifier != current.credential.document.identifier && c.document.identifier !in others
        val def = definition
        if (def != null) {
            val match = peMatches.getOrNull(index) ?: return emptyList()
            val rest = peMatches.filterIndexed { i, _ -> i != index }.associateBy { it.descriptor.id }
            return def.descriptors.filter { it.id == match.descriptor.id || it.id !in rest }.flatMap { d ->
                peCandidates[d.id].orEmpty().filter { usable(it.credential) && PresentationExchange.satisfies(def, rest + (d.id to it)) }
            }.distinctBy { it.credential.document.identifier }.map { it to it.credential }
        }
        val match = dcqlMatches.getOrNull(index) ?: return emptyList()
        if (match.query.multiple) return emptyList()
        return dcqlCandidates[match.query.id].orEmpty().filter { usable(it.credential) }
            .distinctBy { it.credential.document.identifier }.map { it to it.credential }
    }
}

/** How an extended response was delivered. */
sealed class ExtendedOutcome {
    /** Posted to the Verifier; [redirectUri] should be opened when present. */
    data class Posted(val redirectUri: String?, val status: Int) : ExtendedOutcome()
    /** Fragment or query response: the wallet opens [url]. */
    data class Redirect(val url: String) : ExtendedOutcome()
    /** DC API response data. */
    data class DcApi(val data: JsonObject) : ExtendedOutcome()
}

/**
 * Builds and delivers presentations the Multipaz engine cannot: W3C credentials (jwt_vp, ldp_vp, SD-JWT wrapped),
 * Presentation Exchange submissions, SIOPv2 id_tokens, pre-1.0 response modes, the ISO 18013-7 Annex B mdoc handover,
 * and profile shapes (TWDIW, Microsoft Verified ID) through [dialects].
 */
class ExtendedPresenter(
    private val httpClient: HttpClient,
    private val store: DocumentStore,
    private val holderIdentities: HolderIdentities?,
    private val dialects: List<PresentationDialect>,
    private val allowInsecureLoopback: Boolean,
) {
    internal fun dialectOf(request: ValidatedAuthorizationRequest) = dialects.firstOrNull { it.id == request.profile }

    suspend fun prepare(request: ValidatedAuthorizationRequest): ExtendedPrepared {
        val creds = WalletCredential.load(store)
        return when {
            request.presentationDefinition != null -> {
                val def = PresentationDefinition.parse(request.presentationDefinition)
                // ISO 18013-7: an mdoc input descriptor's id is the docType.
                val candidates = PresentationExchange.match(def, creds).mapValues { (id, list) ->
                    list.filter { it.credential.family != CredentialFamily.MDOC || it.credential.docType == id }
                }
                pe(request, def, candidates, PresentationExchange.select(def, candidates))
            }
            request.dcqlQuery.isNotEmpty() -> {
                val model = DcqlQueryModel.parse(request.dcqlQuery)
                val candidates = OwnDcql.match(model, creds)
                dcql(request, model, candidates, OwnDcql.select(model, candidates))
            }
            else -> ExtendedPrepared(request, emptyList(), emptyList(), null, null)
        }
    }

    /**
     * The same request with line [index] answered by [credential], one of [ExtendedPrepared.alternatives]; the other
     * lines keep their credentials. Throws when [credential] is not an alternative of that line.
     */
    fun replace(prepared: ExtendedPrepared, index: Int, credential: WalletCredential): ExtendedPrepared {
        val (match, _) = prepared.replacements(index).firstOrNull { it.second.document.identifier == credential.document.identifier }
            ?: throw ProtocolException("access_denied", "The credential cannot answer this part of the request")
        val def = prepared.definition
        if (def != null) {
            val picked = prepared.peMatches.toMutableList().also { it[index] = match as DescriptorMatch }
            // Keep the definition's descriptor order, as the first selection has it.
            val order = def.descriptors.map { it.id }
            return pe(prepared.request, def, prepared.peCandidates, picked.sortedBy { order.indexOf(it.descriptor.id) })
        }
        val picked = prepared.dcqlMatches.toMutableList().also { it[index] = match as DcqlMatch }
        return dcql(prepared.request, prepared.dcql!!, prepared.dcqlCandidates, picked)
    }

    private fun pe(request: ValidatedAuthorizationRequest, def: PresentationDefinition, candidates: Map<String, List<DescriptorMatch>>, picked: List<DescriptorMatch>): ExtendedPrepared {
        val chosen = picked.map { it.toChosen() }
        return ExtendedPrepared(request, chosen, lines(chosen), def, null, peMatches = picked, peCandidates = candidates)
    }

    private fun dcql(request: ValidatedAuthorizationRequest, model: DcqlQueryModel, candidates: Map<String, List<DcqlMatch>>, picked: List<DcqlMatch>): ExtendedPrepared {
        val chosen = picked.map { ChosenCredential(it.credential, it.memberPaths, null, it.query.id, it.claims.any { c -> c.intentToRetain }) }
        return ExtendedPrepared(request, chosen, lines(chosen), null, model, dcqlMatches = picked, dcqlCandidates = candidates)
    }

    private fun lines(chosen: List<ChosenCredential>) = chosen.map { c ->
        // Structural members a filter matches on (the card type, schema, status) carry no personal data; they are not listed.
        val shown = c.memberPaths.filter { p -> p.dropWhile { it == "vc" }.joinToString(".") !in STRUCTURAL_MEMBERS }
        ConsentLine(c.credential.document, c.credential.displayName, shown.map { p -> label(p) }.distinct())
    }

    private fun DescriptorMatch.toChosen() = ChosenCredential(
        credential,
        fields.mapNotNull { it.memberPath }.ifEmpty { if (descriptor.fields.isEmpty()) listOf(emptyList()) else emptyList() },
        descriptor.id,
        null,
        fields.any { it.field.intentToRetain },
    )

    private fun label(path: List<String>): String = if (path.isEmpty()) "*" else
        path.joinToString(".").removePrefix("vc.").removePrefix("credentialSubject.")

    suspend fun respond(prepared: ExtendedPrepared): ExtendedOutcome {
        val request = prepared.request
        val dialect = dialectOf(request)
        val audience = if (request.responseMode.dcApi) "origin:${request.origin}" else request.verifier.effectiveClientId
        val mdocNonce = PlatformCrypto.randomBytes(16).toBase64Url()
        val holders = prepared.chosen.associateWith { holderOf(it.credential) }

        // vp_token elements and Presentation Exchange descriptor_map entries.
        val tokens = mutableListOf<JsonElement>()
        val descriptors = mutableListOf<JsonObject>()
        val dcqlTokens = linkedMapOf<String, MutableList<JsonElement>>()

        fun addPe(id: String?, format: String, path: String, nested: JsonObject? = null) {
            if (id == null) return
            descriptors += buildJsonObject {
                put("id", id); put("format", format); put("path", path)
                nested?.let { put("path_nested", it) }
            }
        }

        val mdocs = prepared.chosen.filter { it.credential.family == CredentialFamily.MDOC }
        if (mdocs.isNotEmpty()) {
            if (prepared.dcql != null) {
                for (c in mdocs) dcqlTokens.getOrPut(c.queryId!!) { mutableListOf() } += JsonPrimitive(deviceResponse(request, listOf(c), mdocNonce))
            } else {
                val idx = tokens.size
                tokens += JsonPrimitive(deviceResponse(request, mdocs, mdocNonce))
                mdocs.forEach { addPe(it.descriptorId, "mso_mdoc", "\$[$idx]") }
            }
        }
        for (c in prepared.chosen.filter { it.credential.family == CredentialFamily.SD_JWT_VC }) {
            val token = sdJwtPresentation(c, holders[c], audience, request.nonce)
            if (prepared.dcql != null) dcqlTokens.getOrPut(c.queryId!!) { mutableListOf() } += JsonPrimitive(token)
            else {
                val idx = tokens.size
                tokens += JsonPrimitive(token)
                addPe(c.descriptorId, sdJwtFormat(request, c), "\$[$idx]")
            }
        }
        val w3c = prepared.chosen.filter { it.credential.family == CredentialFamily.W3C_JWT || it.credential.family == CredentialFamily.W3C_SD_JWT || it.credential.family == CredentialFamily.W3C_LDP }
        // Keyless W3C credentials are presented as they are; key bound ones inside a presentation signed by their holder.
        for (c in w3c.filter { holders[it] == null }) {
            val token: JsonElement = if (c.credential.family == CredentialFamily.W3C_LDP) parseJsonObject(c.credential.raw) else JsonPrimitive(embedded(c))
            if (prepared.dcql != null) dcqlTokens.getOrPut(c.queryId!!) { mutableListOf() } += token
            else {
                val idx = tokens.size
                tokens += token
                addPe(c.descriptorId, if (c.credential.family == CredentialFamily.W3C_LDP) "ldp_vc" else "jwt_vc_json", "\$[$idx]")
            }
        }
        val bound = w3c.filter { holders[it] != null }
        // DCQL: one presentation per credential. Presentation Exchange: one presentation per holder and kind.
        val groups: List<List<ChosenCredential>> = if (prepared.dcql != null) bound.map { listOf(it) }
            else bound.groupBy { (it.credential.family == CredentialFamily.W3C_LDP) to holders[it]!!.alias }.values.toList()
        for (group in groups) {
            val holder = holders[group.first()]!!
            val ldp = group.first().credential.family == CredentialFamily.W3C_LDP
            val vp: JsonElement = if (ldp) ldpVp(request, holder, group, audience) else JsonPrimitive(jwtVp(request, holder, group, audience, dialect))
            if (prepared.dcql != null) dcqlTokens.getOrPut(group.first().queryId!!) { mutableListOf() } += vp
            else {
                val idx = tokens.size
                tokens += vp
                group.forEachIndexed { i, c ->
                    val vcPath = if (ldp) "\$.verifiableCredential[$i]" else dialect?.nestedPath(i) ?: "\$.vp.verifiableCredential[$i]"
                    val nestedFormat = dialect?.nestedFormat(c.credential) ?: if (ldp) "ldp_vc" else nestedJwtFormat(request, c)
                    addPe(c.descriptorId, if (ldp) "ldp_vp" else "jwt_vp", "\$[$idx]", buildJsonObject {
                        put("id", c.descriptorId); put("format", nestedFormat); put("path", vcPath)
                    })
                }
            }
        }

        // A single presentation is sent as it is with "$" paths, as every pre-1.0 verifier expects.
        val single = prepared.dcql == null && tokens.size == 1
        val finalDescriptors = if (single) descriptors.map { d -> JsonObject(d + ("path" to JsonPrimitive("\$"))) } else descriptors
        val vpToken: JsonElement? = when {
            "vp_token" !in request.responseTypes -> null
            prepared.dcql != null -> buildJsonObject {
                for ((id, list) in dcqlTokens) {
                    // OpenID4VP 1.0 uses arrays; drafts 22-27 used a single presentation per query.
                    if (request.profile == null || list.size > 1) put(id, JsonArray(list)) else put(id, list.first())
                }
            }
            single -> tokens.first()
            else -> JsonArray(tokens)
        }
        val submission = prepared.definition?.let { def ->
            buildJsonObject {
                put("id", uuid())
                put("definition_id", def.id)
                put("descriptor_map", JsonArray(finalDescriptors))
            }
        }
        val anyHolder = holders.values.filterNotNull().firstOrNull()
        val idToken = if ("id_token" in request.responseTypes) {
            val siopHolder = siopHolder(request, dialect, anyHolder)
            dialect?.idToken(request, siopHolder, submission) ?: siopIdToken(request, siopHolder, if (vpToken == null) submission else null)
        } else null

        val params = linkedMapOf<String, JsonElement>()
        vpToken?.let { params["vp_token"] = it }
        // Microsoft Verified ID carries the submission in the id_token (_vp_token); others send it as a parameter.
        if (submission != null && !(dialect != null && idToken != null && dialect.id == "msvid")) params["presentation_submission"] = submission
        idToken?.let { params["id_token"] = JsonPrimitive(it) }
        request.state?.let { params["state"] = JsonPrimitive(it) }
        dialect?.extraResponseParameters(request, anyHolder)?.forEach { (k, v) -> params[k] = JsonPrimitive(v) }
        prepared.chosen.forEach { it.credential.credential.increaseUsageCount() }
        return deliver(request, JsonObject(params), mdocNonce.takeIf { mdocs.isNotEmpty() }, dialect)
    }

    private fun sdJwtFormat(request: ValidatedAuthorizationRequest, c: ChosenCredential): String {
        val accepted = descriptorFormats(request, c)
        return if (accepted != null && "dc+sd-jwt" in accepted && "vc+sd-jwt" !in accepted) "dc+sd-jwt" else "vc+sd-jwt"
    }

    private fun nestedJwtFormat(request: ValidatedAuthorizationRequest, c: ChosenCredential): String {
        val accepted = descriptorFormats(request, c).orEmpty()
        return when {
            c.credential.family == CredentialFamily.W3C_SD_JWT && "vc+sd-jwt" in accepted -> "vc+sd-jwt"
            "jwt_vc_json" in accepted -> "jwt_vc_json"
            else -> "jwt_vc"
        }
    }

    private fun descriptorFormats(request: ValidatedAuthorizationRequest, c: ChosenCredential): Set<String>? {
        val def = request.presentationDefinition ?: return null
        val d = def.arr("input_descriptors")?.filterIsInstance<JsonObject>()?.firstOrNull { it.str("id") == c.descriptorId }
        return d?.obj("format")?.keys ?: def.obj("format")?.keys
    }

    // ---------------------------------------------------------------- holder keys

    private suspend fun holderOf(c: WalletCredential): HolderKey? = when (val cred = c.credential) {
        is W3cVcCredential -> cred.secureArea?.let { sa -> HolderKey(sa, sa.getKeyInfo(cred.alias!!), cred.sharedKey, cred.holderDid) }
        is SecureAreaBoundCredential -> HolderKey(cred.secureArea, cred.secureArea.getKeyInfo(cred.alias), false)
        else -> null
    }

    /** Key for a SIOP id_token: the profile's identity, the presented credentials' holder, or the wallet's SIOP identity. */
    private suspend fun siopHolder(request: ValidatedAuthorizationRequest, dialect: PresentationDialect?, presented: HolderKey?): HolderKey {
        val ids = holderIdentities
        dialect?.holderProfile?.let { p -> ids?.find(p)?.let { return it } }
        presented?.let { return it.withDid(it.did ?: HolderKey.didFor(it.publicKey, "did:jwk")) }
        ids?.find(HolderIdentities.SIOP)?.let { return it }
        throw ProtocolException("access_denied", "No holder identity for a self-issued id_token; receive a credential first")
    }

    // ---------------------------------------------------------------- SD-JWT

    /** The credential as embedded in a presentation: SD-JWTs reduced to the chosen disclosures, others unchanged. */
    private fun embedded(c: ChosenCredential): String {
        val parts = c.credential.sdJwt ?: return c.credential.raw.trim()
        val payload = c.credential.sdPayload!!
        val keep = if (c.memberPaths.any { it.isEmpty() }) parts.disclosures else SdJwtDisclosures.select(payload, parts.disclosures, c.memberPaths)
        return parts.withDisclosures(keep)
    }

    private suspend fun sdJwtPresentation(c: ChosenCredential, holder: HolderKey?, audience: String, nonce: String): String {
        val base = embedded(c)
        if (holder == null) return base
        val alg = joseAlg(holder.publicKey)
        val kb = signJws(
            buildJsonObject { put("alg", alg); put("typ", "kb+jwt") },
            buildJsonObject {
                put("iat", Clock.System.now().epochSeconds)
                put("aud", audience)
                put("nonce", nonce)
                put("sd_hash", PlatformCrypto.sha256(base.encodeToByteArray()).toBase64Url())
            },
            holder.signingKey(alg),
        )
        return base + kb
    }

    // ---------------------------------------------------------------- W3C presentations

    private suspend fun jwtVp(request: ValidatedAuthorizationRequest, holder: HolderKey, group: List<ChosenCredential>, audience: String, dialect: PresentationDialect?): String {
        val vcs = group.map { it.credential to embedded(it) }
        dialect?.jwtVp(VpInput(request, holder, vcs))?.let { return it }
        val did = holder.did ?: HolderKey.didFor(holder.publicKey, "did:jwk")
        val alg = joseAlg(holder.publicKey)
        val now = Clock.System.now().epochSeconds
        val v2 = group.all { (it.credential.w3c?.get("@context") as? JsonArray)?.firstOrNull()?.let { c -> (c as? JsonPrimitive)?.content } == W3cVc.CONTEXT_V2 }
        return signJws(
            buildJsonObject { put("alg", alg); put("typ", "JWT"); put("kid", DidKeys.verificationMethod(did)) },
            buildJsonObject {
                put("iss", did)
                put("aud", audience)
                put("nonce", request.nonce)
                put("iat", now)
                put("nbf", now)
                put("exp", now + 600)
                put("jti", "urn:uuid:" + uuid())
                putJsonObject("vp") {
                    putJsonArray("@context") { add(if (v2) W3cVc.CONTEXT_V2 else W3cVc.CONTEXT_V1) }
                    putJsonArray("type") { add("VerifiablePresentation") }
                    put("holder", did)
                    putJsonArray("verifiableCredential") { vcs.forEach { add(it.second) } }
                }
            },
            holder.signingKey(alg),
        )
    }

    private suspend fun ldpVp(request: ValidatedAuthorizationRequest, holder: HolderKey, group: List<ChosenCredential>, audience: String): JsonObject {
        val did = holder.did ?: HolderKey.didFor(holder.publicKey, "did:key")
        val v2 = group.all { (it.credential.json["@context"] as? JsonArray)?.firstOrNull()?.let { c -> (c as? JsonPrimitive)?.content } == W3cVc.CONTEXT_V2 }
        val vp = buildJsonObject {
            putJsonArray("@context") { add(if (v2) W3cVc.CONTEXT_V2 else W3cVc.CONTEXT_V1) }
            putJsonArray("type") { add("VerifiablePresentation") }
            put("holder", did)
            putJsonArray("verifiableCredential") { group.forEach { add(parseJsonObject(it.credential.raw)) } }
        }
        return DataIntegrity(DidResolver(httpClient, allowInsecureLoopback)).sign(
            unsecured = vp,
            key = holder.signingKey(),
            verificationMethod = DidKeys.verificationMethod(did),
            proofPurpose = "authentication",
            challenge = request.nonce,
            domain = audience,
        )
    }

    /** SIOPv2 id_token: subject is a DID (did:jwk) unless the Verifier only accepts JWK thumbprints. */
    private suspend fun siopIdToken(request: ValidatedAuthorizationRequest, holder: HolderKey, submission: JsonObject?): String {
        val syntax = request.clientMetadata?.strList("subject_syntax_types_supported").orEmpty()
        val useThumbprint = syntax.isNotEmpty() && syntax.none { it.startsWith("did") }
        val alg = joseAlg(holder.publicKey)
        val now = Clock.System.now().epochSeconds
        val jwk = holder.publicKey.toJwk()
        return if (useThumbprint) {
            val sub = holder.publicKey.toJwkThumbprint(Algorithm.SHA256).toByteArray().toBase64Url()
            signJws(
                buildJsonObject { put("alg", alg); put("typ", "JWT"); put("jwk", jwk) },
                buildJsonObject {
                    put("iss", "https://self-issued.me/v2"); put("sub", sub); put("sub_jwk", jwk)
                    put("aud", request.verifier.effectiveClientId); put("nonce", request.nonce)
                    put("iat", now); put("exp", now + 600)
                    submission?.let { putJsonObject("_vp_token") { put("presentation_submission", it) } }
                },
                holder.signingKey(alg),
            )
        } else {
            val did = holder.did ?: HolderKey.didFor(holder.publicKey, "did:jwk")
            signJws(
                buildJsonObject { put("alg", alg); put("typ", "JWT"); put("kid", DidKeys.verificationMethod(did)) },
                buildJsonObject {
                    put("iss", did); put("sub", did)
                    put("aud", request.verifier.effectiveClientId); put("nonce", request.nonce)
                    put("iat", now); put("exp", now + 600)
                    submission?.let { putJsonObject("_vp_token") { put("presentation_submission", it) } }
                },
                holder.signingKey(alg),
            )
        }
    }

    // ---------------------------------------------------------------- mdoc

    private suspend fun deviceResponse(request: ValidatedAuthorizationRequest, chosen: List<ChosenCredential>, mdocNonce: String): String {
        val transcript = if (request.profile == null) handover10(request) else handoverAnnexB(request, mdocNonce)
        val response = buildDeviceResponse(sessionTranscript = transcript, status = DeviceResponse.STATUS_OK) {
            for (c in chosen) {
                val cred = c.credential.credential as MdocCredential
                val claims = c.memberPaths.filter { it.size == 2 }.map { (ns, elem) ->
                    MdocRequestedClaim(docType = cred.docType, namespaceName = ns, dataElementName = elem, intentToRetain = c.intentToRetain)
                }.ifEmpty {
                    // The whole document was asked for.
                    c.credential.json.flatMap { (ns, v) -> (v as JsonObject).keys.map { MdocRequestedClaim(docType = cred.docType, namespaceName = ns, dataElementName = it, intentToRetain = c.intentToRetain) } }
                }
                addDocument(MdocDocument.fromPresentment(sessionTranscript = transcript, credential = cred, requestedClaims = claims))
            }
        }
        return Cbor.encode(response.toDataItem()).toBase64Url()
    }

    /** OpenID4VP 1.0 OpenID4VPHandover (redirect / direct_post flows). */
    private suspend fun handover10(request: ValidatedAuthorizationRequest) = buildCborArray {
        add(Simple.NULL)
        add(Simple.NULL)
        addCborArray {
            add("OpenID4VPHandover")
            add(Bstr(Crypto.digest(Algorithm.SHA256, Cbor.encode(buildCborArray {
                add(request.verifier.effectiveClientId)
                add(request.nonce)
                add(Simple.NULL)
                add(request.target ?: "")
            }))))
        }
    }

    /** ISO/IEC 18013-7 Annex B OID4VPHandover used with OpenID4VP drafts: hashes of client_id and response_uri with the mdoc generated nonce. */
    private suspend fun handoverAnnexB(request: ValidatedAuthorizationRequest, mdocNonce: String) = buildCborArray {
        add(Simple.NULL)
        add(Simple.NULL)
        addCborArray {
            add(Bstr(Crypto.digest(Algorithm.SHA256, Cbor.encode(buildCborArray { add(request.verifier.effectiveClientId); add(mdocNonce) }))))
            add(Bstr(Crypto.digest(Algorithm.SHA256, Cbor.encode(buildCborArray { add(request.target ?: ""); add(mdocNonce) }))))
            add(request.nonce)
        }
    }

    // ---------------------------------------------------------------- delivery

    /** Sends [params] the way the request asks (form post, redirect or DC API); [dialect] judges a posted answer. */
    internal suspend fun deliver(request: ValidatedAuthorizationRequest, params: JsonObject, mdocNonce: String?, dialect: PresentationDialect?): ExtendedOutcome {
        fun text(v: JsonElement) = if (v is JsonPrimitive && v.isString) v.content else v.toString()
        return when (request.responseMode) {
            ResponseMode.DC_API, ResponseMode.DC_API_JWT -> ExtendedOutcome.DcApi(
                if (request.responseMode.encrypted) buildJsonObject { put("response", encrypt(request, params, mdocNonce)) } else params
            )
            ResponseMode.FRAGMENT, ResponseMode.QUERY -> {
                val target = request.redirectUri ?: throw ProtocolException("invalid_request", "redirect_uri missing")
                val encoded = params.entries.joinToString("&") { (k, v) -> k.encodeURLParameter() + "=" + text(v).encodeURLParameter() }
                val sep = if (request.responseMode == ResponseMode.FRAGMENT) "#" else if ('?' in target) "&" else "?"
                ExtendedOutcome.Redirect(target + sep + encoded)
            }
            else -> {
                val target = request.target ?: throw ProtocolException("invalid_request", "No response endpoint")
                val form: Map<String, String> = if (request.responseMode == ResponseMode.DIRECT_POST_JWT) {
                    mapOf("response" to encrypt(request, params, mdocNonce))
                } else params.mapValues { (_, v) -> text(v) }
                val resp = httpClient.submitForm(url = target, formParameters = parameters { form.forEach { (k, v) -> append(k, v) } })
                val body = resp.bodyAsText()
                val ok = dialect?.accepted(resp.status.value, body) ?: (resp.status.value in 200..399)
                if (!ok) throw ProtocolException("verifier_error", "Verifier rejected the response: HTTP ${resp.status.value} ${body.take(300)}")
                val redirect = runCatching { (DiwJson.parseToJsonElement(body) as JsonObject).str("redirect_uri") }.getOrNull()
                    ?: resp.headers["Location"]
                ExtendedOutcome.Posted(redirect?.takeIf { isAcceptableEndpoint(it, allowInsecureLoopback) }, resp.status.value)
            }
        }
    }

    /** JWE (ECDH-ES) of the response to a key in client_metadata (jwks or jwks_uri), honouring pre-1.0 parameter names. */
    private suspend fun encrypt(request: ValidatedAuthorizationRequest, params: JsonObject, mdocNonce: String?): String {
        val meta = request.clientMetadata ?: throw ProtocolException("invalid_request", "client_metadata missing for an encrypted response")
        val keys = meta.obj("jwks")?.arr("keys") ?: meta.str("jwks_uri")?.let { uri ->
            if (!isAcceptableEndpoint(uri, allowInsecureLoopback)) throw ProtocolException("invalid_request", "jwks_uri must be https")
            parseJsonObject(httpClient.get(uri).bodyAsText()).arr("keys")
        } ?: throw ProtocolException("invalid_request", "No encryption keys in client_metadata")
        val jwk = keys.filterIsInstance<JsonObject>().firstOrNull {
            (it.str("use") == null || it.str("use") == "enc") && (it.str("alg") == null || it.str("alg") == "ECDH-ES") && (it.str("kty") == "EC" || it.str("kty") == "OKP")
        } ?: throw ProtocolException("invalid_request", "No usable ECDH-ES key in client_metadata")
        val encName = meta.str("authorization_encrypted_response_enc")
            ?: meta.strList("encrypted_response_enc_values_supported").firstOrNull { it in setOf("A128GCM", "A192GCM", "A256GCM") }
            ?: "A128GCM"
        return JsonWebEncryption.encrypt(
            claimsSet = params,
            recipientPublicKey = EcPublicKey.fromJwk(jwk),
            encAlg = Algorithm.fromJoseAlgorithmIdentifier(encName),
            apu = (mdocNonce ?: PlatformCrypto.randomBytes(16).toBase64Url()).encodeToByteString(),
            apv = request.nonce.encodeToByteString(),
            kid = jwk.str("kid"),
        )
    }

    companion object {
        fun joseAlg(key: EcPublicKey): String = when (key.curve) {
            EcCurve.P384 -> "ES384"
            EcCurve.P521 -> "ES512"
            EcCurve.ED25519 -> "EdDSA"
            else -> "ES256"
        }

        /** W3C credential members that identify the card rather than describe its holder. */
        private val STRUCTURAL_MEMBERS = setOf("type", "@context", "issuer", "credentialSchema", "credentialStatus", "iss", "vct")

        fun uuid(): String {
            val b = PlatformCrypto.randomBytes(16)
            b[6] = ((b[6].toInt() and 0x0f) or 0x40).toByte()
            b[8] = ((b[8].toInt() and 0x3f) or 0x80).toByte()
            val h = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
            return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
        }
    }
}
