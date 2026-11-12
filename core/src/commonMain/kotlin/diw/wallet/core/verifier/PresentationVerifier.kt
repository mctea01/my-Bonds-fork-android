package diw.wallet.core.verifier

import diw.wallet.core.i18n.ct
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.DerivedEvidence
import diw.wallet.core.document.derived.ZkPdfContext
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.obj
import diw.wallet.core.w3c.SdJwtDisclosures
import diw.wallet.core.w3c.DataIntegrity
import diw.wallet.core.w3c.W3cVc
import diw.wallet.core.w3c.bbs.Bbs2023
import diw.wallet.core.w3c.bbs.BbsProfile
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.util.bool
import org.multipaz.util.toBase64Url
import kotlinx.serialization.json.JsonElement
import org.multipaz.sdjwt.SdJwtKb
import diw.wallet.core.document.Check as DocumentCheck
import diw.wallet.core.jose.Jws
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.long
import diw.wallet.core.util.str
import org.multipaz.util.fromBase64Url
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.addCborArray
import org.multipaz.cbor.buildCborArray
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.JsonWebEncryption
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.mdoc.zkp.ZkSystemRepository
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.revocation.RevocationChecker
import org.multipaz.verification.JsonVerifiedPresentation
import org.multipaz.verification.MdocVerifiedPresentation
import org.multipaz.verification.QueryData
import org.multipaz.verification.VerificationUtil
import org.multipaz.verification.VerifiedPresentation
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** State the Verifier keeps between issuing a request and receiving the response. */
data class VerifierSession(
    val nonce: String,
    val clientId: String,
    val responseMode: String,
    val dcqlQuery: JsonObject,
    val responseUri: String? = null,
    val state: String? = null,
    val encryptionKey: EcPrivateKey? = null,
    /** Expected caller origin for DC API sessions. */
    val origin: String? = null,
)

enum class CheckStatus { PASS, FAIL, WARN, UNKNOWN }

data class Check(val name: String, val status: CheckStatus, val detail: String = "")

/** Per-credential result. A credential is only [passed] when every check passes; partial results never read as success. */
data class CredentialVerification(
    val queryId: String,
    val format: String,
    val typeName: String,
    val claims: Map<String, String>,
    val checks: List<Check>,
    val issuerTrust: TrustDecision,
    /**
     * The evidence a document-derived credential carries (signature statement, time stamp, zkPDF proof and its
     * fields). A failed entry fails the credential; one that could not be checked is shown but does not.
     */
    val evidence: List<Check> = emptyList(),
) {
    val passed: Boolean
        get() = checks.all { it.status == CheckStatus.PASS } && issuerTrust.environment != null &&
            evidence.none { it.status == CheckStatus.FAIL }
}

data class PresentationVerification(
    val credentials: List<CredentialVerification>,
    val error: String? = null,
    val errorDescription: String? = null,
    val sessionChecks: List<Check> = emptyList(),
    /** Non-standard but tolerated wallet behaviour (test Verifier only); does not change [passed]. */
    val compatibilityNotes: List<String> = emptyList(),
) {
    val passed: Boolean
        get() = error == null && credentials.isNotEmpty() && credentials.all { it.passed } &&
            sessionChecks.all { it.status == CheckStatus.PASS }
    val testEnvironmentOnly: Boolean get() = credentials.any { it.issuerTrust.environment == TrustEnvironment.TEST }
}

/**
 * Verifier-side checks on top of Multipaz VerificationUtil: KB-JWT audience and freshness, issuer trust
 * through the environment-partitioned registry, validity window and Token Status List.
 */
class PresentationVerifier(
    private val trustRegistry: TrustRegistry,
    private val documentTypeRepository: DocumentTypeRepository,
    private val revocationChecker: RevocationChecker?,
    private val zkSystemRepository: ZkSystemRepository? = null,
    private val maxKbAge: Duration = 5.minutes,
    /**
     * Accept a direct_post body sent as `response=<unsecured JWT (alg none)>` instead of form fields, as Multipaz 0.101
     * wallets do. Off by default; the test Verifier enables it and reports a compatibility note.
     */
    private val acceptUnsecuredJwtResponse: Boolean = false,
    /**
     * Resolves the issuer of an SD-JWT VC that names a DID instead of carrying x5c (document-derived credentials);
     * Multipaz takes issuer keys from x5c only, so these are checked here. Null rejects such credentials.
     */
    private val didResolver: DidResolver? = null,
    /** Checks the time stamp and the zkPDF proof of a document-derived credential; null leaves them unchecked. */
    private val documentTrust: DocumentTrustSource? = null,
    private val zkPdf: ZkPdfContext? = null,
    /** Trust for issuers of Data Integrity credentials (ldp_vc), which name a DID; unknown DIDs fail issuer trust. */
    private val didTrust: DidTrust = DidTrust.NONE,
) {
    /** Verifies a direct_post / direct_post.jwt body (form parameters). */
    suspend fun verifyDirectPost(form: Map<String, String>, session: VerifierSession): PresentationVerification {
        val notes = mutableListOf<String>()
        val payload: JsonObject = if (session.responseMode == "direct_post.jwt") {
            val jwe = form["response"] ?: return PresentationVerification(emptyList(), "invalid_response", "missing response parameter")
            decrypt(jwe, session) ?: return PresentationVerification(emptyList(), "invalid_response", "response decryption failed")
        } else if (form.containsKey("response")) {
            val unsecured = (if (acceptUnsecuredJwtResponse) unsecuredJwtPayload(form.getValue("response")) else null)
                ?: return PresentationVerification(emptyList(), "invalid_response", "unexpected encrypted response")
            notes += "direct_post sent as an unsecured JWT (alg none) in 'response' instead of form fields (OpenID4VP 1.0 section 8.2)"
            unsecured
        } else {
            JsonObject(form.mapValues { (k, v) ->
                if (k == "vp_token") DiwJson.parseToJsonElement(v) else JsonPrimitive(v)
            })
        }
        val transcript = sessionTranscript(session.clientId, session.nonce, session.encryptionKey, session.responseUri)
        return verifyPayload(payload, session, transcript, expectedAud = session.clientId).copy(compatibilityNotes = notes)
    }

    /** Payload of a `header.payload.` JWT whose header is exactly alg none; null for anything else. */
    private fun unsecuredJwtPayload(jwt: String): JsonObject? = runCatching {
        val parts = jwt.split('.')
        if (parts.size != 3 || parts[2].isNotEmpty()) return null
        val header = DiwJson.parseToJsonElement(parts[0].fromBase64Url().decodeToString()) as JsonObject
        if (header.str("alg") != "none") return null
        DiwJson.parseToJsonElement(parts[1].fromBase64Url().decodeToString()) as JsonObject
    }.getOrNull()

    /** Verifies a DC API response data object. */
    suspend fun verifyDcApi(data: JsonObject, session: VerifierSession, origin: String): PresentationVerification {
        val payload = if (session.responseMode == "dc_api.jwt") {
            val jwe = data.str("response") ?: return PresentationVerification(emptyList(), "invalid_response", "missing response")
            decrypt(jwe, session) ?: return PresentationVerification(emptyList(), "invalid_response", "response decryption failed")
        } else data
        val thumb = session.encryptionKey?.publicKey?.toJwkThumbprint(Algorithm.SHA256)?.toByteArray()
        val handover = Cbor.encode(buildCborArray {
            add(origin); add(session.nonce); if (thumb == null) add(Simple.NULL) else add(Bstr(thumb))
        })
        val transcript = buildCborArray {
            add(Simple.NULL); add(Simple.NULL)
            addCborArray { add("OpenID4VPDCAPIHandover"); add(Bstr(Crypto.digest(Algorithm.SHA256, handover))) }
        }
        return verifyPayload(payload, session, transcript, expectedAud = "origin:$origin")
    }

    private suspend fun decrypt(jwe: String, session: VerifierSession): JsonObject? {
        val key = session.encryptionKey ?: return null
        return try {
            JsonWebEncryption.decrypt(jwe, AsymmetricKey.anonymous(key, key.curve.defaultKeyAgreementAlgorithm))
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun verifyPayload(
        payload: JsonObject,
        session: VerifierSession,
        transcript: DataItem,
        expectedAud: String,
    ): PresentationVerification {
        payload.str("error")?.let { return PresentationVerification(emptyList(), it, payload.str("error_description")) }
        val sessionChecks = mutableListOf<Check>()
        sessionChecks += if (session.state == payload.str("state")) Check("state", CheckStatus.PASS)
        else Check("state", CheckStatus.FAIL, "state mismatch")
        val vpToken = payload["vp_token"] as? JsonObject
            ?: return PresentationVerification(emptyList(), "invalid_response", "vp_token missing or not an object", sessionChecks)
        // Multipaz parses the mdoc and SD-JWT VC queries; Data Integrity queries (ldp_vc) are matched here.
        val queries = (session.dcqlQuery["credentials"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
        val ldpIds = queries.filter { it.str("format") in LDP_FORMATS }.mapNotNull { it.str("id") }.toSet()
        val multipazDcql = if (ldpIds.isEmpty()) session.dcqlQuery
            else JsonObject(session.dcqlQuery - "credential_sets" + ("credentials" to JsonArray(queries.filter { it.str("id") !in ldpIds })))
        val queryData = (if (ldpIds.size == queries.size) emptyList() else QueryData.fromDcql(multipazDcql)).associateBy { it.id!! }
        val requestedIds = queryData.keys + ldpIds
        val unknown = vpToken.keys - requestedIds
        if (unknown.isNotEmpty()) sessionChecks += Check("vp_token ids", CheckStatus.FAIL, "unrequested ids $unknown")

        val now = Clock.System.now()
        // SD-JWT VCs whose issuer is a DID (no x5c) are verified here; the rest go through Multipaz.
        val didIssued = vpToken.keys.filter { id -> didIssuedSdJwt(vpToken[id]) != null }.toSet()
        // Data Integrity credentials and presentations (ldp_vc, ldp_vp) are verified here as well.
        val ldp = vpToken.keys.filter { id -> id in ldpIds && ldpEntry(vpToken[id]) != null }.toSet()
        val standard = JsonObject(vpToken.filterKeys { it !in didIssued && it !in ldp })
        val presentations: List<VerifiedPresentation> = if (standard.isEmpty()) emptyList() else try {
            VerificationUtil.verifyOpenID4VPResponse(
                now = now,
                vpToken = standard,
                sessionTranscript = transcript,
                nonce = session.nonce,
                documentTypeRepository = documentTypeRepository,
                zkSystemRepository = zkSystemRepository,
                queryData = queryData.filterKeys { it !in didIssued && it !in ldp },
            )
        } catch (e: Exception) {
            return PresentationVerification(emptyList(), "invalid_presentation", "signature/binding verification failed: ${e.message}", sessionChecks)
        }
        val results = presentations.map { vp -> evaluate(vp, vpToken, expectedAud, now) } +
            didIssued.mapNotNull { id ->
                val query = (session.dcqlQuery["credentials"] as? JsonArray)?.filterIsInstance<JsonObject>()?.firstOrNull { it.str("id") == id }
                    ?: return@mapNotNull null
                verifyDidIssued(id, didIssuedSdJwt(vpToken[id])!!, query, session.nonce, expectedAud, now)
            } +
            ldp.mapNotNull { id ->
                val query = (session.dcqlQuery["credentials"] as? JsonArray)?.filterIsInstance<JsonObject>()?.firstOrNull { it.str("id") == id }
                    ?: return@mapNotNull null
                verifyLdp(id, ldpEntry(vpToken[id])!!, query, session.nonce, expectedAud, now)
            }
        val missing = requestedIds.filter { id -> results.none { it.queryId == id } }
        if (missing.isNotEmpty()) sessionChecks += Check("requested credentials", CheckStatus.WARN, "not returned: $missing")
        return PresentationVerification(results, sessionChecks = sessionChecks)
    }

    private suspend fun evaluate(vp: VerifiedPresentation, vpToken: JsonObject, expectedAud: String, now: Instant): CredentialVerification {
        val checks = mutableListOf(Check("signature and holder binding", CheckStatus.PASS, "Multipaz VerificationUtil"))
        val id = vp.vpTokenIdentifier ?: "?"
        val chain = vp.documentSignerCertChain
        val (format, typeName, claims) = when (vp) {
            is JsonVerifiedPresentation -> {
                val token = ((vpToken[id] as? JsonArray)?.firstOrNull() ?: vpToken[id])?.jsonPrimitive?.content
                checks += kbChecks(token, expectedAud, now)
                Triple("dc+sd-jwt", vp.vct, vp.issuerSignedClaims.associate { it.claimPath.joinToString(".") { e -> e.jsonPrimitive.content } to it.value.toString() })
            }
            is MdocVerifiedPresentation -> Triple(
                if (vp.zkpUsed) "mso_mdoc_zk" else "mso_mdoc",
                vp.docType,
                vp.issuerSignedClaims.associate { "${it.namespaceName}.${it.dataElementName}" to it.value.toString() }
            )
            else -> Triple("unknown", "unknown", emptyMap())
        }
        vp.validFrom?.let { checks += if (it <= now) Check("validFrom", CheckStatus.PASS) else Check("validFrom", CheckStatus.FAIL, "not yet valid") }
        vp.validUntil?.let { checks += if (it >= now) Check("validUntil", CheckStatus.PASS) else Check("validUntil", CheckStatus.FAIL, "expired") }

        val trust = if (chain == null) {
            TrustDecision.unknown("no issuer certificate chain")
        } else {
            val docType = (vp as? MdocVerifiedPresentation)?.docType
            val m = trustRegistry.match(TrustRole.ISSUER, chain.certificates, now, docType)
            m?.let { checks += revocation(vp, it.anchor) }
            trustRegistry.decision(m)
        }
        checks += if (trust.environment != null) Check("issuer trust", CheckStatus.PASS, "${trust.anchorName} (${trust.environment.id})")
        else Check("issuer trust", CheckStatus.FAIL, "issuer chain not anchored in an enabled environment")
        return CredentialVerification(id, format, typeName, claims, checks, trust)
    }

    /** The SD-JWT VC (with KB-JWT) in [entry] when its issuer is a DID and it carries no x5c; null otherwise. */
    private fun didIssuedSdJwt(entry: JsonElement?): String? {
        if (didResolver == null) return null
        val token = ((entry as? JsonArray)?.singleOrNull() ?: entry)?.let { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            ?: return null
        if ('~' !in token) return null
        return runCatching {
            val jwt = token.substringBefore('~').split('.')
            val header = DiwJson.parseToJsonElement(jwt[0].fromBase64Url().decodeToString()) as JsonObject
            val payload = DiwJson.parseToJsonElement(jwt[1].fromBase64Url().decodeToString()) as JsonObject
            token.takeIf { "x5c" !in header && payload.str("iss")?.startsWith("did:") == true }
        }.getOrNull()
    }

    /**
     * An SD-JWT VC issued by a DID: the issuer signature with the DID's key, the KB-JWT (signature with the cnf key,
     * nonce, audience and age), the requested type and claims, the validity window, and for a document-derived
     * credential its evidence, including a zkPDF proof when the holder disclosed it.
     */
    private suspend fun verifyDidIssued(
        id: String,
        token: String,
        query: JsonObject,
        nonce: String,
        expectedAud: String,
        now: Instant,
    ): CredentialVerification {
        val checks = mutableListOf<Check>()
        fun failed(reason: String) = CredentialVerification(id, "dc+sd-jwt", "unknown", emptyMap(), checks + Check("signature and holder binding", CheckStatus.FAIL, reason),
            TrustDecision.unknown(reason))
        val kb = try {
            SdJwtKb.fromCompactSerialization(token)
        } catch (_: Exception) {
            return failed("malformed SD-JWT VC")
        }
        val sdJwt = kb.sdJwt
        val iss = sdJwt.issuer ?: return failed("no issuer")
        val issuerKey = try {
            (didResolver!!.resolveKey(iss, sdJwt.jwtHeader.str("kid")).key as? VerificationKey.Ec)?.key
        } catch (_: Exception) {
            null
        } ?: return failed("issuer DID key cannot be resolved")
        val processed = try {
            kb.verify(
                issuerKey = issuerKey,
                checkNonce = { it == nonce },
                checkAudience = { it == expectedAud },
                checkCreationTime = { kotlin.math.abs((now - it).inWholeSeconds) <= maxKbAge.inWholeSeconds },
            )
        } catch (e: Exception) {
            return failed("issuer signature or key binding invalid: ${e.message}")
        }
        checks += Check("signature and holder binding", CheckStatus.PASS, "issuer $iss; KB-JWT nonce, aud and iat")
        val vct = sdJwt.credentialType ?: ""
        val vctValues = (query.obj("meta")?.get("vct_values") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }
        checks += if (vctValues == null || vct in vctValues) Check("vct", CheckStatus.PASS, vct)
        else Check("vct", CheckStatus.FAIL, "$vct not requested")
        checks += requestedClaims(query, processed)
        sdJwt.validFrom?.let { checks += if (it <= now + 2.minutes) Check("validFrom", CheckStatus.PASS) else Check("validFrom", CheckStatus.FAIL, "not yet valid") }
        sdJwt.validUntil?.let { checks += if (it >= now) Check("validUntil", CheckStatus.PASS) else Check("validUntil", CheckStatus.FAIL, "expired") }
        val derived = vct == DerivedCredentials.VCT
        val evidence = if (derived) {
            val signed = Jws.parse(SdJwtDisclosures.parse(token.substringBeforeLast('~') + "~").issuerJwt).payload
            DerivedEvidence.verify(signed, documentTrust, disclosed = processed, zk = zkPdf, now = now).map { e ->
                Check(e.title, when (e.check) {
                    DocumentCheck.PASS -> CheckStatus.PASS
                    DocumentCheck.FAIL -> CheckStatus.FAIL
                    DocumentCheck.WARN -> CheckStatus.WARN
                    DocumentCheck.NOT_CHECKED -> CheckStatus.UNKNOWN
                }, e.detail)
            }
        } else emptyList()
        val technical = setOf("iss", "iat", "nbf", "exp", "vct", "cnf", "status", "_sd_alg", "sub")
        val claims = processed.filterKeys { k -> k !in technical && !(derived && (k == "evidence" || DerivedCredentials.isProofClaim(k))) }
            .mapValues { (_, v) -> (v as? JsonPrimitive)?.takeIf { it.isString }?.content ?: v.toString() }
        // A document-derived credential is the holder wallet's own statement (T3); its evidence is what a verifier weighs.
        val trust = if (derived) {
            TrustDecision(TrustTier.T3, TrustEnvironment.USER, official = false, anchorName = ct("core_pv_holder_wallet"), labels = setOf(TrustLabel.SELF_ISSUED))
        } else TrustDecision.unknown("issuer identified by a DID that this verifier does not trust")
        checks += if (trust.environment != null) Check("issuer trust", CheckStatus.PASS, trust.anchorName ?: iss)
        else Check("issuer trust", CheckStatus.FAIL, "DID issuer not anchored")
        return CredentialVerification(id, "dc+sd-jwt", vct, claims, checks, trust, evidence)
    }

    /** The JSON-LD credential or presentation in [entry] (a DCQL array of one, or the object itself); null otherwise. */
    private fun ldpEntry(entry: JsonElement?): JsonObject? {
        if (didResolver == null) return null
        val obj = ((entry as? JsonArray)?.singleOrNull() ?: entry) as? JsonObject ?: return null
        return obj.takeIf { "@context" in it && "proof" in it }
    }

    /**
     * A Data Integrity credential, bare or inside a presentation. A presentation's proof must name the holder, the
     * request nonce (challenge) and this verifier (domain); its credential is then bound when its subject is the
     * holder. A bare bbs-2023 derived credential is bound to the request through its presentation header, and to the
     * holder when issued with anonymous holder binding or a holder bound pseudonym. Pseudonyms are checked for this
     * verifier's nym_domain. Then the type, requested claims, validity window and issuer trust (a DID).
     */
    private suspend fun verifyLdp(
        id: String,
        entry: JsonObject,
        query: JsonObject,
        nonce: String,
        expectedAud: String,
        now: Instant,
    ): CredentialVerification {
        val checks = mutableListOf<Check>()
        val format = query.str("format") ?: "ldp_vc"
        fun failed(reason: String) = CredentialVerification(id, format, "unknown", emptyMap(), checks + Check("signature and holder binding", CheckStatus.FAIL, reason),
            TrustDecision.unknown(reason))
        val di = DataIntegrity(didResolver!!)
        val requireBinding = query.bool("require_cryptographic_holder_binding") ?: true
        val presentation = "VerifiablePresentation" in W3cVc.types(entry)
        var holder: String? = null
        val vc: JsonObject = if (presentation) {
            val proof = try {
                di.verify(entry, expectedPurpose = "authentication", challenge = nonce, domain = expectedAud)
            } catch (e: Exception) {
                return failed("presentation proof invalid: ${e.message}")
            }
            holder = entry.idOf("holder")
            if (holder == null || proof.verificationMethod.substringBefore('#') != holder) return failed("presentation is not signed by its holder")
            (entry["verifiableCredential"] as? JsonArray)?.singleOrNull() as? JsonObject
                ?: entry["verifiableCredential"] as? JsonObject
                ?: return failed("presentation must carry exactly one credential")
        } else entry
        val issuer = W3cVc.issuer(vc, null) ?: return failed("credential has no issuer")
        val proof = try {
            di.verify(vc, expectedPurpose = "assertionMethod", nymDomain = expectedAud)
        } catch (e: Exception) {
            return failed("issuer proof invalid: ${e.message}")
        }
        if (proof.verificationMethod.substringBefore('#') != issuer) return failed("credential is not signed by its issuer")
        val bbs = proof.bbs
        val expectedHeader = BbsProfile.presentationHeader(expectedAud, nonce)
        val fresh = bbs?.derived == true && bbs.presentationHeader?.contentEquals(expectedHeader) == true
        if (bbs != null && !bbs.derived) return failed("bbs-2023 base proofs are not presentations")
        if (bbs != null && !fresh && !presentation) return failed("bbs-2023 presentation header does not match this request")
        val subject = W3cVc.subject(vc, null)
        val bound = when {
            presentation -> subject != null && subject == holder && (bbs == null || fresh)
            else -> bbs?.feature?.holderBound == true && fresh
        }
        when {
            bound -> checks += Check("signature and holder binding", CheckStatus.PASS, buildString {
                append("issuer ").append(issuer).append(" (").append(proof.cryptosuite ?: proof.type).append(")")
                if (presentation) append("; presentation by ").append(holder).append(", nonce and domain")
                else append("; ").append(bbs!!.feature.id).append(" proof for this request")
            })
            requireBinding -> return failed(if (presentation) "credential subject is not the presentation holder" else "credential is not bound to a holder")
            else -> checks += Check("signature and holder binding", CheckStatus.PASS, "issuer $issuer (${proof.cryptosuite ?: proof.type}); holder binding not requested")
        }
        if (bbs != null && bbs.feature.pseudonymous) {
            val nym = bbs.pseudonym
            checks += if (nym != null && bbs.nymDomain == expectedAud) Check("pseudonym", CheckStatus.PASS, nym.toBase64Url())
            else Check("pseudonym", CheckStatus.FAIL, "pseudonym not made for this verifier")
        }
        val types = W3cVc.types(vc)
        val typeValues = (query.obj("meta")?.get("type_values") as? JsonArray)?.mapNotNull { set -> (set as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } }
        checks += if (typeValues.isNullOrEmpty() || typeValues.any { set -> set.all { want -> types.any { it == want || want.endsWith("#$it") || want.endsWith("/$it") } } })
            Check("type", CheckStatus.PASS, types.joinToString())
        else Check("type", CheckStatus.FAIL, "${types.joinToString()} not requested")
        checks += requestedClaims(query, vc)
        val (validFrom, validUntil) = W3cVc.validity(vc, null)
        validFrom?.let { checks += if (it <= now + 2.minutes) Check("validFrom", CheckStatus.PASS) else Check("validFrom", CheckStatus.FAIL, "not yet valid") }
        validUntil?.let { checks += if (it >= now) Check("validUntil", CheckStatus.PASS) else Check("validUntil", CheckStatus.FAIL, "expired") }
        val trust = didTrust.decide(issuer, TrustRole.ISSUER) ?: TrustDecision.unknown("issuer identified by a DID that this verifier does not trust")
        checks += if (trust.environment != null) Check("issuer trust", CheckStatus.PASS, trust.anchorName ?: issuer)
        else Check("issuer trust", CheckStatus.FAIL, "DID issuer not anchored")
        val skip = setOf("@context", "type", "proof", "issuer", "id", "validFrom", "validUntil", "issuanceDate", "expirationDate", "credentialStatus", "credentialSchema")
        val claims = linkedMapOf<String, String>()
        fun flatten(prefix: String, e: JsonElement) {
            when (e) {
                is JsonObject -> e.forEach { (k, v) -> if (!(prefix.isEmpty() && k in skip)) flatten(if (prefix.isEmpty()) k else "$prefix.$k", v) }
                is JsonPrimitive -> claims[prefix] = if (e.isString) e.content else e.toString()
                else -> claims[prefix] = e.toString()
            }
        }
        flatten("", vc)
        bbs?.pseudonym?.let { claims["pseudonym"] = it.toBase64Url() }
        return CredentialVerification(id, format, W3cVc.displayType(types) ?: types.lastOrNull() ?: "unknown", claims, checks, trust)
    }

    private fun JsonObject.idOf(key: String): String? = when (val v = this[key]) {
        is JsonPrimitive -> v.contentOrNull
        is JsonObject -> v.str("id")
        else -> null
    }

    /**
     * The DCQL `claims` (and `claim_sets`) of [query] against the disclosed claims [disclosed]: every path is resolved
     * in full (keys, array indices and null for all elements), a claim that selects nothing is missing, and a claim
     * with `values` passes only when a selected value equals one of them. Without `claim_sets` every claim is needed;
     * with them, one set whose claims all pass is enough.
     */
    private fun requestedClaims(query: JsonObject, disclosed: JsonObject): Check {
        val claims = (query["claims"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
        if (claims.isEmpty()) return Check("requested claims", CheckStatus.PASS)
        val failures = linkedMapOf<String, String>()
        claims.forEachIndexed { index, claim ->
            val label = (claim["id"] as? JsonPrimitive)?.contentOrNull ?: "#$index"
            val path = claim["path"] as? JsonArray
            if (path.isNullOrEmpty()) {
                failures[label] = "no path"
                return@forEachIndexed
            }
            val selected = selectClaim(disclosed, path)
            val values = (claim["values"] as? JsonArray)?.mapNotNull { it as? JsonPrimitive }
            when {
                selected.isEmpty() -> failures[label] = "missing ${pathText(path)}"
                values != null && selected.none { v -> v is JsonPrimitive && values.any { sameValue(it, v) } } ->
                    failures[label] = "${pathText(path)} not one of the requested values"
            }
        }
        val sets = (query["claim_sets"] as? JsonArray)?.mapNotNull { set -> (set as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } }
        val ids = claims.mapIndexed { i, c -> (c["id"] as? JsonPrimitive)?.contentOrNull ?: "#$i" }
        val passed = if (sets.isNullOrEmpty()) failures.isEmpty()
        else sets.any { set -> set.isNotEmpty() && set.all { it in ids && it !in failures } }
        return if (passed) Check("requested claims", CheckStatus.PASS)
        else Check("requested claims", CheckStatus.FAIL, failures.values.joinToString("; ").ifEmpty { "no claim set satisfied" })
    }

    private fun selectClaim(root: JsonElement, path: JsonArray): List<JsonElement> {
        var current = listOf(root)
        for (step in path) {
            current = current.flatMap { node ->
                when {
                    step is JsonNull -> (node as? JsonArray)?.toList().orEmpty()
                    step is JsonPrimitive && step.isString -> listOfNotNull((node as? JsonObject)?.get(step.content))
                    step is JsonPrimitive -> step.intOrNull?.let { i -> (node as? JsonArray)?.getOrNull(i) }?.let { listOf(it) }.orEmpty()
                    else -> emptyList()
                }
            }
            if (current.isEmpty()) break
        }
        return current
    }

    /** DCQL value matching: strings with strings, numbers by value, booleans with booleans. */
    private fun sameValue(wanted: JsonPrimitive, actual: JsonPrimitive): Boolean = when {
        wanted.isString || actual.isString -> wanted.isString && actual.isString && wanted.content == actual.content
        wanted.booleanOrNull != null || actual.booleanOrNull != null -> wanted.booleanOrNull == actual.booleanOrNull
        else -> wanted.doubleOrNull != null && wanted.doubleOrNull == actual.doubleOrNull
    }

    private fun pathText(path: JsonArray) = path.joinToString(".") { (it as? JsonPrimitive)?.contentOrNull ?: "*" }

    private fun kbChecks(token: String?, expectedAud: String, now: Instant): List<Check> {
        if (token == null || token.endsWith("~")) return listOf(Check("key binding", CheckStatus.FAIL, "no KB-JWT"))
        val kb = try {
            Jws.unverifiedPayload(token.substringAfterLast('~'))
        } catch (e: Exception) {
            return listOf(Check("key binding", CheckStatus.FAIL, "malformed KB-JWT"))
        }
        val out = mutableListOf<Check>()
        out += if (kb.str("aud") == expectedAud) Check("KB-JWT aud", CheckStatus.PASS)
        else Check("KB-JWT aud", CheckStatus.FAIL, "aud=${kb.str("aud")} expected $expectedAud")
        val iat = kb.long("iat")
        out += if (iat != null && kotlin.math.abs(now.epochSeconds - iat) <= maxKbAge.inWholeSeconds) Check("KB-JWT iat", CheckStatus.PASS)
        else Check("KB-JWT iat", CheckStatus.FAIL, "iat outside ${maxKbAge}")
        return out
    }

    private suspend fun revocation(vp: VerifiedPresentation, anchor: org.multipaz.crypto.X509Cert): Check {
        val status = vp.revocationStatus ?: return Check("status", CheckStatus.PASS, "credential carries no status reference")
        val checker = revocationChecker ?: return Check("status", CheckStatus.UNKNOWN, "status checking disabled")
        val r = checker.check(status, issuerCert = anchor, onlyTrusted = true)
        return when (r.state) {
            RevocationCheckState.VALID -> Check("status", CheckStatus.PASS, "valid")
            RevocationCheckState.INVALID -> Check("status", CheckStatus.FAIL, "revoked")
            RevocationCheckState.SUSPENDED -> Check("status", CheckStatus.FAIL, "suspended")
            RevocationCheckState.UNKNOWN -> Check("status", CheckStatus.UNKNOWN, r.error?.message ?: "unknown")
        }
    }

    companion object {
        /** DCQL formats of Data Integrity credentials and presentations. */
        val LDP_FORMATS = setOf("ldp_vc", "ldp_vp", "ldp", "di_vc", "di_vp")

        /** SessionTranscript for OpenID4VP redirect-based flows (OpenID4VPHandover, B.2.6.1). */
        suspend fun sessionTranscript(clientId: String, nonce: String, encKey: EcPrivateKey?, responseUri: String?): DataItem {
            val thumb = encKey?.publicKey?.toJwkThumbprint(Algorithm.SHA256)?.toByteArray()
            val info = Cbor.encode(buildCborArray {
                add(clientId); add(nonce); if (thumb == null) add(Simple.NULL) else add(Bstr(thumb)); responseUri?.let { add(it) }
            })
            return buildCborArray {
                add(Simple.NULL); add(Simple.NULL)
                addCborArray {
                    add(if (responseUri == null) "OpenID4VPDCAPIHandover" else "OpenID4VPHandover")
                    add(Bstr(Crypto.digest(Algorithm.SHA256, info)))
                }
            }
        }
    }
}
