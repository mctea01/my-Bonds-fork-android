package diw.wallet.core.oid4vp

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.CredentialStatusChecker
import diw.wallet.core.status.StatusFinding
import diw.wallet.core.status.StatusPolicy
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.trust.highlyTrusted
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import org.multipaz.asn1.OID
import org.multipaz.crypto.X509Cert
import org.multipaz.revocation.RevocationStatus
import kotlin.time.Clock
import kotlin.time.Instant

/** How far a verifier_info entry can be relied on. */
enum class AttestationVerdict { VALID, PARTIAL, INVALID, UNSUPPORTED }

/**
 * The result of checking one verifier_info entry (OpenID4VP 1.0 section 5.11): a registration certificate of a
 * wallet-relying party (ETSI TS 119 475, typ rc-wrp+jwt) or another signed attestation about the verifier.
 *
 * @property boundToVerifier the attestation names the verifier that sent the request (its access certificate's
 *   organisation identifier, DNS name or client_id); null when the request gives nothing to compare with.
 * @property outsideRegistration requested claims the attestation does not register ("vct or doctype: path"); null
 *   when the attestation lists no credentials or the request is not a DCQL query.
 */
data class VerifierAttestation(
    val format: String,
    val type: String?,
    val verdict: AttestationVerdict,
    val signer: String? = null,
    val trust: TrustDecision? = null,
    val name: String? = null,
    val subject: String? = null,
    val purposes: List<String> = emptyList(),
    val serviceDescription: String? = null,
    val country: String? = null,
    val publicBody: Boolean? = null,
    val entitlements: List<String> = emptyList(),
    val registryUri: String? = null,
    val privacyPolicy: String? = null,
    val supportUri: String? = null,
    val supervisoryAuthority: String? = null,
    val boundToVerifier: Boolean? = null,
    val outsideRegistration: List<String>? = null,
    val status: CredentialStatus? = null,
    val statusFinding: StatusFinding? = null,
    val issuedAt: Instant? = null,
    val expiresAt: Instant? = null,
    val credentialIds: List<String> = emptyList(),
    val problems: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
)

/**
 * Checks the verifier_info entries of a validated request before the user is asked: the signature with the x5c
 * leaf, the signer's chain against the VERIFIER anchors (the ISSUER anchors when none matches, as registrars of the
 * test ecosystems use the issuer PKI), the lifetime, the status list entry, that the attestation names the verifier,
 * and that the request stays within the registered credentials and claims. Nothing here rejects the request: the
 * results are shown, and a failed check needs the user's confirmation.
 */
class VerifierInfoChecker(
    private val trustRegistry: TrustRegistry,
    private val statusChecker: CredentialStatusChecker?,
) {
    suspend fun check(request: ValidatedAuthorizationRequest, now: Instant = Clock.System.now()): List<VerifierAttestation> =
        request.verifierInfo.map { e ->
            runCatching { check(e, request, now) }.getOrElse { ex ->
                VerifierAttestation(e.format, null, AttestationVerdict.INVALID, credentialIds = e.credentialIds,
                    problems = listOf("無法讀取這份證明：" + (ex.message ?: ex::class.simpleName)))
            }
        }

    private suspend fun check(e: VerifierInfoEntry, request: ValidatedAuthorizationRequest, now: Instant): VerifierAttestation {
        val compact = (e.data as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()
        if (compact == null || compact.count { it == '.' } != 2) {
            return VerifierAttestation(e.format, null, AttestationVerdict.UNSUPPORTED, credentialIds = e.credentialIds,
                notes = listOf("格式「${e.format}」不是已簽章的 JWT，錢包無法驗證，只列出供參考"))
        }
        val jws = Jws.parse(compact)
        val claims = jws.payload
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()

        // Signature and signer.
        val chain = runCatching { jws.x5c?.certificates }.getOrNull()
        var trust: TrustDecision? = null
        var signer: String? = null
        if (chain.isNullOrEmpty()) {
            problems.add("證明沒有附上簽署憑證（x5c），無法驗證簽章")
        } else {
            signer = commonName(chain.first())
            val signatureOk = runCatching { jws.verify(VerificationKey.fromCertificate(chain.first())) }.isSuccess
            if (!signatureOk) problems.add("證明的簽章驗證失敗")
            val t = trustRegistry.decide(TrustRole.VERIFIER, chain)
            trust = if (t.tier.highlyTrusted || t.environment != null) t else trustRegistry.decide(TrustRole.ISSUER, chain).takeIf { it.environment != null } ?: t
            if (!signatureOk) trust = trust.copy(tier = TrustTier.T4)
            if (trust.environment == null) problems.add("簽署者「${signer ?: "未知"}」沒有連到任何信任錨點")
        }

        // Lifetime.
        val issuedAt = (claims["iat"] as? JsonPrimitive)?.longOrNull?.let { Instant.fromEpochSeconds(it) }
            ?: (jws.header["iat"] as? JsonPrimitive)?.longOrNull?.let { Instant.fromEpochSeconds(it) }
        val expiresAt = (claims["exp"] as? JsonPrimitive)?.longOrNull?.let { Instant.fromEpochSeconds(it) }
        if (expiresAt != null && expiresAt < now) problems.add("證明已於 $expiresAt 到期")
        (claims["nbf"] as? JsonPrimitive)?.longOrNull?.let { if (Instant.fromEpochSeconds(it) > now) problems.add("證明尚未生效") }

        // Status list entry of the attestation itself.
        val statusRef = (claims["status"] as? JsonObject)?.get("status_list") as? JsonObject
        var status: CredentialStatus? = null
        var finding: StatusFinding? = null
        if (statusRef != null) {
            val uri = (statusRef["uri"] as? JsonPrimitive)?.contentOrNull
            val idx = (statusRef["idx"] as? JsonPrimitive)?.intOrNull
            val checker = statusChecker
            if (uri != null && idx != null && checker != null) {
                status = runCatching { checker.check(RevocationStatus.StatusList(idx, uri, null), chain) }.getOrNull()
                finding = StatusPolicy.finding(status)
                when (finding) {
                    StatusFinding.REVOKED -> problems.add("登錄證明已被撤銷")
                    StatusFinding.SUSPENDED -> problems.add("登錄證明目前暫停")
                    StatusFinding.VALID -> {}
                    else -> notes.add("無法確認登錄證明的狀態" + (status?.detail?.let { "（$it）" } ?: ""))
                }
            } else if (checker == null) notes.add("未查詢登錄證明的狀態")
        }

        // Binding to the verifier that sent the request.
        val subject = claims.str("sub")
        val bound = bound(subject, request.verifier)
        when (bound) {
            false -> problems.add("證明登錄的對象（${subject ?: "未寫明"}）不是這個查驗方")
            null -> notes.add("無法比對證明登錄的對象（${subject ?: "未寫明"}）與這個查驗方")
            true -> {}
        }

        // Registered credentials and claims.
        val registered = (claims["credentials"] as? JsonArray)?.mapNotNull { it as? JsonObject }
        val outside = if (registered != null && request.dcqlQuery.isNotEmpty()) outside(request.dcqlQuery, registered) else null
        if (!outside.isNullOrEmpty()) {
            problems.add("要求了登錄範圍以外的資料：" + outside.take(6).joinToString("、") + if (outside.size > 6) "等 ${outside.size} 項" else "")
        }
        if (registered == null && jws.typ == RC_TYP) notes.add("證明沒有列出登錄的證件與欄位")

        val verdict = when {
            problems.any { it.startsWith("證明的簽章") || it.contains("撤銷") || it.contains("到期") || it.contains("不是這個查驗方") } -> AttestationVerdict.INVALID
            problems.isNotEmpty() || trust?.tier?.highlyTrusted != true || finding != null && finding != StatusFinding.VALID -> AttestationVerdict.PARTIAL
            else -> AttestationVerdict.VALID
        }
        return VerifierAttestation(
            format = e.format,
            type = jws.typ,
            verdict = verdict,
            signer = signer,
            trust = trust,
            name = claims.str("name") ?: claims.str("sub_ln"),
            subject = subject,
            purposes = localized(claims["purpose"]),
            serviceDescription = localized(claims["srv_description"]).firstOrNull(),
            country = claims.str("country"),
            publicBody = (claims["public_body"] as? JsonPrimitive)?.booleanOrNull,
            entitlements = (claims["entitlements"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty(),
            registryUri = claims.str("registry_uri"),
            privacyPolicy = claims.str("privacy_policy"),
            supportUri = claims.str("support_uri") ?: claims.str("info_uri"),
            supervisoryAuthority = (claims["supervisory_authority"] as? JsonObject)?.let { it.str("uri") ?: it.str("email") },
            boundToVerifier = bound,
            outsideRegistration = outside,
            status = status,
            statusFinding = finding,
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            credentialIds = e.credentialIds,
            problems = problems,
            notes = notes,
        )
    }

    companion object {
        const val RC_TYP = "rc-wrp+jwt"
        private const val ORGANIZATION_IDENTIFIER = "2.5.4.97"

        private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

        private fun commonName(c: X509Cert): String? = runCatching { c.subject.components[OID.COMMON_NAME.oid]?.value }.getOrNull()

        /** Values of a [{lang, value}] list (the request's language first is left to the screen), or a plain string. */
        fun localized(e: JsonElement?): List<String> = when (e) {
            is JsonPrimitive -> listOfNotNull(e.contentOrNull)
            is JsonArray -> e.mapNotNull { (it as? JsonObject)?.str("value") ?: (it as? JsonPrimitive)?.contentOrNull }
            is JsonObject -> listOfNotNull(e.str("value"))
            else -> emptyList()
        }

        /**
         * Whether [subject] names [verifier]: the organisation identifier of its access certificate (ETSI EN 319 412-1,
         * e.g. LEIXG-...), one of its DNS names, its DID or its client_id. Null when it cannot be told: no subject, or
         * a different subject while the access certificate states no organisation identifier to compare with.
         */
        fun bound(subject: String?, verifier: VerifierIdentityInfo): Boolean? {
            subject ?: return null
            val leaf = verifier.certificateChain?.certificates?.firstOrNull()
            val orgId = leaf?.let { runCatching { it.subject.components[ORGANIZATION_IDENTIFIER]?.value }.getOrNull() }
            val names = listOfNotNull(orgId, verifier.clientId.value, verifier.effectiveClientId, verifier.did) + verifier.dnsNames
            return when {
                subject in names -> true
                orgId != null -> false
                else -> null
            }
        }

        /** Requested claims that no registered credential of the same format and type covers. */
        fun outside(dcql: JsonObject, registered: List<JsonObject>): List<String> {
            val out = ArrayList<String>()
            val queries = (dcql["credentials"] as? JsonArray)?.mapNotNull { it as? JsonObject }.orEmpty()
            for (q in queries) {
                val format = q.str("format")
                val label = typeLabel(q) ?: format ?: "證件"
                val matches = registered.filter { r -> r.str("format") == format && sameType(q, r) }
                if (matches.isEmpty()) {
                    out.add("$label（未登錄這種證件）")
                    continue
                }
                val requested = (q["claims"] as? JsonArray)?.mapNotNull { (it as? JsonObject)?.get("path") as? JsonArray }
                // Any registered entry without a claim list allows the whole credential.
                if (matches.any { claimPaths(it) == null }) continue
                val allowed = matches.flatMap { claimPaths(it).orEmpty() }
                if (requested == null) {
                    out.add("$label（整張證件）")
                    continue
                }
                for (p in requested) {
                    if (allowed.none { covers(it, p) }) out.add("$label：" + p.joinToString(".") { (it as? JsonPrimitive)?.contentOrNull ?: "*" })
                }
            }
            return out.distinct()
        }

        private fun claimPaths(r: JsonObject): List<JsonArray>? =
            ((r["claim"] ?: r["claims"]) as? JsonArray)?.mapNotNull { (it as? JsonObject)?.get("path") as? JsonArray }

        private fun typeLabel(q: JsonObject): String? {
            val meta = q["meta"] as? JsonObject ?: return null
            return meta.str("doctype_value") ?: (meta["vct_values"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }?.joinToString("、")
        }

        private fun sameType(q: JsonObject, r: JsonObject): Boolean {
            val qm = q["meta"] as? JsonObject
            val rm = r["meta"] as? JsonObject
            if (qm == null || rm == null) return true
            qm.str("doctype_value")?.let { d -> return rm.str("doctype_value") == null || rm.str("doctype_value") == d }
            val qv = (qm["vct_values"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
            val rv = (rm["vct_values"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
            return qv.isEmpty() || rv.isEmpty() || qv.any { it in rv }
        }

        /** A registered path covers a requested one when it is equal or a prefix of it; null in either is a wildcard. */
        private fun covers(registered: JsonArray, requested: JsonArray): Boolean {
            if (registered.size > requested.size) return false
            return registered.indices.all { i ->
                val a = registered[i]
                val b = requested[i]
                a is JsonNull || b is JsonNull || a == b
            }
        }
    }
}
