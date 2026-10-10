package diw.wallet.core.verifier

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.Jws
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.trust.tierFor
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.long
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
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
) {
    val passed: Boolean get() = checks.all { it.status == CheckStatus.PASS } && issuerTrust.environment != null
}

data class PresentationVerification(
    val credentials: List<CredentialVerification>,
    val error: String? = null,
    val errorDescription: String? = null,
    val sessionChecks: List<Check> = emptyList(),
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
) {
    /** Verifies a direct_post / direct_post.jwt body (form parameters). */
    suspend fun verifyDirectPost(form: Map<String, String>, session: VerifierSession): PresentationVerification {
        val payload: JsonObject = if (session.responseMode == "direct_post.jwt") {
            val jwe = form["response"] ?: return PresentationVerification(emptyList(), "invalid_response", "missing response parameter")
            decrypt(jwe, session) ?: return PresentationVerification(emptyList(), "invalid_response", "response decryption failed")
        } else {
            if (form.containsKey("response")) return PresentationVerification(emptyList(), "invalid_response", "unexpected encrypted response")
            JsonObject(form.mapValues { (k, v) ->
                if (k == "vp_token") DiwJson.parseToJsonElement(v) else JsonPrimitive(v)
            })
        }
        val transcript = sessionTranscript(session.clientId, session.nonce, session.encryptionKey, session.responseUri)
        return verifyPayload(payload, session, transcript, expectedAud = session.clientId)
    }

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
        val queryData = QueryData.fromDcql(session.dcqlQuery).associateBy { it.id!! }
        val unknown = vpToken.keys - queryData.keys
        if (unknown.isNotEmpty()) sessionChecks += Check("vp_token ids", CheckStatus.FAIL, "unrequested ids $unknown")

        val now = Clock.System.now()
        val presentations: List<VerifiedPresentation> = try {
            VerificationUtil.verifyOpenID4VPResponse(
                now = now,
                vpToken = vpToken,
                sessionTranscript = transcript,
                nonce = session.nonce,
                documentTypeRepository = documentTypeRepository,
                zkSystemRepository = zkSystemRepository,
                queryData = queryData,
            )
        } catch (e: Exception) {
            return PresentationVerification(emptyList(), "invalid_presentation", "signature/binding verification failed: ${e.message}", sessionChecks)
        }
        val results = presentations.map { vp -> evaluate(vp, vpToken, expectedAud, now) }
        val missing = queryData.keys.filter { id -> results.none { it.queryId == id } }
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
            if (m == null) TrustDecision(TrustTier.T3, null, false, null, setOf(TrustLabel.UNKNOWN_ANCHOR), listOf("issuer not anchored"))
            else TrustDecision(
                tierFor(m.environment, m.official, true), m.environment, m.official, m.metadata.displayName,
                if (m.environment == TrustEnvironment.TEST) setOf(TrustLabel.TEST_ANCHOR) else emptySet()
            ).also { _ ->
                checks += revocation(vp, m.anchor)
            }
        }
        checks += if (trust.environment != null) Check("issuer trust", CheckStatus.PASS, "${trust.anchorName} (${trust.environment.id})")
        else Check("issuer trust", CheckStatus.FAIL, "issuer chain not anchored in an enabled environment")
        return CredentialVerification(id, format, typeName, claims, checks, trust)
    }

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
