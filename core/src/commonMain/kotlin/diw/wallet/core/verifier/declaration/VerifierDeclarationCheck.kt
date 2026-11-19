package diw.wallet.core.verifier.declaration

import diw.wallet.core.did.DidResolver
import diw.wallet.core.i18n.ct
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.oid4vp.VerifierInfoChecker
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.trust.highlyTrusted
import diw.wallet.core.verifier.Check
import diw.wallet.core.verifier.CheckStatus
import diw.wallet.core.verifier.CredentialVerification
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.multipaz.util.fromBase64
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.asn1.OID
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import kotlin.time.Clock
import kotlin.time.Instant

/** The request a declaration must be bound to: the verifier's client identifier, the request nonce and the request key. */
data class DeclarationBinding(
    /** Effective client identifier with its prefix (x509_hash:..., decentralized_identifier:did:...). */
    val clientId: String,
    val nonce: String,
    /** Certificate chain that authenticated the request (x509 prefixes, ISO 18013-5 reader authentication). */
    val certificateChain: X509CertChain?,
    /** DID of a decentralized_identifier verifier. */
    val did: String?,
    /** How far the request signature itself was trusted. */
    val requestTrust: TrustDecision,
)

/** Verifies an evidence presentation bound to [clientId] and [nonce]; null when its format cannot be checked here. */
fun interface EvidenceVerifier {
    suspend fun verify(query: JsonObject, vpToken: JsonObject, clientId: String, nonce: String): CredentialVerification?
}

/**
 * What an OpenPGP evidence signature showed: [valid] when it verifies over the statement with a key that is usable and
 * not revoked; [trust] is the holder's own trust in that key (T2 verified or own, T3 unverified, T4 refused).
 */
data class OpenPgpEvidenceResult(
    val valid: Boolean,
    val fingerprint: String?,
    val userId: String?,
    val trust: TrustDecision?,
    val problems: List<String> = emptyList(),
)

/** Checks an OpenPGP detached [signature] over [data] against the holder's OpenPGP list and the sent [certificate]. */
fun interface OpenPgpEvidenceVerifier {
    suspend fun verify(data: ByteArray, signature: ByteArray, certificate: ByteArray?): OpenPgpEvidenceResult
}

/** The result for one piece of declared evidence. */
data class EvidenceResult(
    /** [DeclarationEvidence.ROLE_PARTY] or [DeclarationEvidence.ROLE_AGENT]; a mandate always supports the party. */
    val role: String,
    val mandate: Boolean,
    /** Credential type, or the principal of a mandate. */
    val title: String,
    /** Issuer of the credential or signer of the mandate. */
    val signer: String?,
    val trust: TrustDecision?,
    val passed: Boolean,
    val claims: Map<String, String> = emptyMap(),
    val problems: List<String> = emptyList(),
)

/**
 * What the wallet concluded about a verifier from its declaration (docs/design/p5-verifier.md section 4.2). [bound]
 * false means the declaration is not this request's (wrong key, client_id, nonce or expired) and its content is not
 * relied on. [tier] is the weakest of the request signature, the support for the party and, for a representative,
 * the support for the agent.
 */
data class VerifierIdentity(
    val bound: Boolean,
    val content: DeclarationContent?,
    val evidence: List<EvidenceResult>,
    val checks: List<Check>,
    /** Requested claims the declaration does not list; null when it lists none or the request is not a DCQL query. */
    val outsideDeclaration: List<String>?,
    val tier: TrustTier,
    val expiresAt: Instant?,
    val problems: List<String>,
    val notes: List<String>,
) {
    /** True only when everything was confirmed: bound, every evidence passed, no failed check, nothing outside. */
    val confirmed: Boolean
        get() = bound && evidence.all { it.passed } && checks.none { it.status == CheckStatus.FAIL } &&
            outsideDeclaration.isNullOrEmpty() && problems.isEmpty() && tier.highlyTrusted
}

/**
 * Checks a verifier declaration against the request it came with: binding (key, client_id, nonce, lifetime), each
 * evidence presentation and mandate, and the consistency of the party and agent with the access certificate, the
 * registration certificate and the evidence. Nothing here rejects the request.
 */
class VerifierDeclarationCheck(
    private val trustRegistry: TrustRegistry,
    private val didResolver: DidResolver,
    private val didTrust: DidTrust,
    private val evidenceVerifier: EvidenceVerifier?,
    private val openPgpVerifier: OpenPgpEvidenceVerifier? = null,
) {
    suspend fun check(
        compact: String,
        binding: DeclarationBinding,
        requestDcql: JsonObject?,
        /** Subject of a valid registration certificate sent with the same request, to compare with the party. */
        registrationSubject: String? = null,
        registrationTrust: TrustDecision? = null,
        now: Instant = Clock.System.now(),
    ): VerifierIdentity {
        val parsed = VerifierDeclaration.parse(compact)
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        val checks = ArrayList<Check>()

        // 1. Binding to this request.
        var bound = true
        val key = runCatching { requestKey(parsed.jws, binding) }.getOrNull()
        if (key == null || runCatching { parsed.jws.verify(key) }.isFailure) {
            bound = false
            problems.add(ct("core_vd_not_request_key"))
        }
        if (parsed.issuer != binding.clientId) {
            bound = false
            problems.add(ct("core_vd_other_client", parsed.issuer ?: ct("core_unstated")))
        }
        if (parsed.nonce != binding.nonce) {
            bound = false
            problems.add(ct("core_vd_other_nonce"))
        }
        val exp = parsed.expiresAt
        val iat = parsed.issuedAt
        if (exp == null || exp < now || iat == null || exp - iat > VerifierDeclaration.MAX_LIFETIME + kotlin.time.Duration.parse("1m")) {
            bound = false
            problems.add(ct("core_vd_lifetime"))
        }
        parsed.problems.forEach { problems.add(ct("core_vd_unreadable", it)) }
        val content = parsed.content
        if (!bound || content == null) {
            return VerifierIdentity(false, content, emptyList(), checks, null, TrustTier.T4, exp, problems, notes)
        }

        // 2. Evidence.
        val evidence = parsed.evidence.map { e ->
            when (e) {
                is DeclarationEvidence.Presentation -> presentation(e, binding)
                is DeclarationEvidence.Mandate -> mandate(e.jws, content, binding, requestDcql, now, checks)
                is DeclarationEvidence.OpenPgp -> openPgp(e, binding)
            }
        }

        // 3. Consistency with the access certificate, the registration certificate and the evidence.
        val partySupport = ArrayList<TrustTier>()
        val agentSupport = ArrayList<TrustTier>()
        val leaf = binding.certificateChain?.certificates?.firstOrNull()
        if (leaf != null) {
            val idMatch = content.party.id?.let { matchesId(leaf, it) }
            val nameMatch = matchesName(leaf, content.party.name)
            when {
                idMatch == true || idMatch == null && nameMatch -> {
                    checks += Check(ct("core_vd_chk_access_cert"), CheckStatus.PASS, leafName(leaf))
                    // The access certificate names the party: its chain speaks for the party.
                    partySupport += binding.requestTrust.tier
                }
                idMatch == false -> checks += Check(ct("core_vd_chk_access_cert"), CheckStatus.FAIL, ct("core_vd_cert_other_party", leafName(leaf)))
                else -> {
                    // A person's own certificate signing for a legal person proves the agent, not the party.
                    if (content.kind.representative && content.agent != null && matchesName(leaf, content.agent.name)) {
                        checks += Check(ct("core_vd_chk_access_cert"), CheckStatus.PASS, ct("core_vd_cert_is_agent", leafName(leaf)))
                        agentSupport += binding.requestTrust.tier
                    } else checks += Check(ct("core_vd_chk_access_cert"), CheckStatus.WARN, ct("core_vd_cert_not_compared", leafName(leaf)))
                }
            }
        }
        if (registrationSubject != null) {
            val id = content.party.id
            val same = id != null && (registrationSubject == id.value || registrationSubject.endsWith("-" + id.value))
            checks += Check(ct("core_vd_chk_registration"), if (same) CheckStatus.PASS else CheckStatus.FAIL,
                if (same) registrationSubject else ct("core_vd_registration_other", registrationSubject))
            if (same) registrationTrust?.let { partySupport += it.tier }
        }
        for ((e, r) in parsed.evidence.zip(evidence)) {
            if (!r.passed) {
                problems.add(ct("core_vd_evidence_failed", r.title))
                continue
            }
            val tier = r.trust?.tier ?: TrustTier.T3
            when {
                e is DeclarationEvidence.Mandate -> partySupport += tier
                r.role == DeclarationEvidence.ROLE_PARTY -> {
                    val c = partyEvidenceCheck(content.party, r)
                    checks += c
                    if (c.status != CheckStatus.FAIL) partySupport += tier
                }
                else -> {
                    val agent = content.agent
                    if (agent == null) {
                        notes.add(ct("core_vd_agent_unused", r.title))
                    } else {
                        val c = agentEvidenceCheck(agent, r)
                        checks += c
                        if (c.status != CheckStatus.FAIL) agentSupport += tier
                    }
                }
            }
        }
        if (content.kind.representative && parsed.evidence.none { it is DeclarationEvidence.Mandate } &&
            checks.none { it.name == ct("core_vd_chk_registration") && it.status == CheckStatus.PASS }) {
            notes.add(ct("core_vd_no_mandate"))
        }

        // 4. Scope of the request.
        val declared = content.credentials
        val outside = if (declared != null && requestDcql != null && requestDcql.isNotEmpty()) {
            VerifierInfoChecker.outside(requestDcql, declared.mapNotNull { it as? JsonObject })
        } else null
        if (declared == null) notes.add(ct("core_vd_no_scope"))
        if (!outside.isNullOrEmpty()) problems.add(ct("core_vd_outside") + outside.take(6).joinToString(ct("core_sep_list")))

        // 5. Overall tier: the weakest of the request, the party support and (for a representative) the agent support.
        val partyTier = partySupport.minByOrNull { it.ordinal } ?: TrustTier.T3
        if (partySupport.isEmpty()) notes.add(ct("core_vd_party_self_stated"))
        val agentTier = if (content.kind.representative) {
            agentSupport.minByOrNull { it.ordinal } ?: TrustTier.T3.also { notes.add(ct("core_vd_agent_self_stated")) }
        } else TrustTier.T1
        val failed = checks.any { it.status == CheckStatus.FAIL } || evidence.any { !it.passed }
        val tier = listOf(binding.requestTrust.tier, partyTier, agentTier, if (failed) TrustTier.T3 else TrustTier.T1).maxBy { it.ordinal }
        return VerifierIdentity(true, content, evidence, checks, outside, tier, exp, problems, notes)
    }

    /** The key that signed the request: the access certificate's, or the DID key named by the declaration's kid. */
    private suspend fun requestKey(jws: Jws, binding: DeclarationBinding): VerificationKey? {
        binding.certificateChain?.certificates?.firstOrNull()?.let { leaf ->
            val own = jws.x5c?.certificates?.firstOrNull()
            if (own != null && own.encoded != leaf.encoded) return null
            return VerificationKey.fromCertificate(leaf)
        }
        val did = binding.did ?: return null
        val kid = jws.kid ?: return null
        if (!kid.startsWith("#") && kid.substringBefore('#') != did) return null
        return didResolver.resolveKey(did, kid).key
    }

    private suspend fun presentation(e: DeclarationEvidence.Presentation, binding: DeclarationBinding): EvidenceResult {
        val title = typeOf(e.query)
        val verifier = evidenceVerifier
            ?: return EvidenceResult(e.role, false, title, null, null, false, problems = listOf(ct("core_vd_evidence_unchecked")))
        val v = runCatching { verifier.verify(e.query, e.vpToken, binding.clientId, binding.nonce) }.getOrElse { ex ->
            return EvidenceResult(e.role, false, title, null, null, false, problems = listOf(ex.message ?: ex::class.simpleName.orEmpty()))
        } ?: return EvidenceResult(e.role, false, title, null, null, false, problems = listOf(ct("core_vd_evidence_unsupported")))
        val failedChecks = (v.checks + v.evidence).filter { it.status == CheckStatus.FAIL }.map { it.name + (if (it.detail.isNotEmpty()) ": " + it.detail else "") }
        return EvidenceResult(
            role = e.role,
            mandate = false,
            title = v.typeName.takeIf { it != "unknown" } ?: title,
            signer = v.issuerTrust.anchorName,
            trust = v.issuerTrust,
            passed = v.passed,
            claims = v.claims,
            problems = failedChecks + if (v.issuerTrust.environment == null) listOf(ct("core_vd_issuer_untrusted")) else emptyList(),
        )
    }

    private suspend fun openPgp(e: DeclarationEvidence.OpenPgp, binding: DeclarationBinding): EvidenceResult {
        val title = ct("core_vd_openpgp")
        val verifier = openPgpVerifier
            ?: return EvidenceResult(e.role, false, title, null, null, false, problems = listOf(ct("core_vd_evidence_unchecked")))
        val certificate = e.certificate?.let { runCatching { it.fromBase64() }.getOrNull() }
        val r = runCatching { verifier.verify(DeclarationEvidence.openPgpStatement(binding.clientId, binding.nonce), e.signature.encodeToByteArray(), certificate) }
            .getOrElse { ex -> return EvidenceResult(e.role, false, title, null, null, false, problems = listOf(ex.message ?: ex::class.simpleName.orEmpty())) }
        val uid = r.userId
        val name = uid?.substringBefore('<')?.substringBefore('(')?.trim()?.takeIf { it.isNotEmpty() }
        val email = uid?.substringAfter('<', "")?.substringBefore('>')?.takeIf { it.isNotEmpty() }
        return EvidenceResult(
            role = e.role,
            mandate = false,
            title = title,
            signer = listOfNotNull(uid, r.fingerprint).joinToString(" ").ifEmpty { null },
            trust = r.trust,
            passed = r.valid && r.trust != null && r.trust.tier != TrustTier.T4,
            claims = buildMap {
                name?.let { put("name", it) }
                email?.let { put("email", it) }
                r.fingerprint?.let { put("fingerprint", it) }
            },
            problems = r.problems + if (r.trust == null) listOf(ct("core_vd_openpgp_unknown")) else emptyList(),
        )
    }

    private suspend fun mandate(
        compact: String,
        declared: DeclarationContent,
        binding: DeclarationBinding,
        requestDcql: JsonObject?,
        now: Instant,
        checks: MutableList<Check>,
    ): EvidenceResult {
        val parsed = runCatching { VerifierMandate.parse(compact) }.getOrElse { ex ->
            return EvidenceResult(DeclarationEvidence.ROLE_PARTY, true, ct("core_vd_mandate"), null, null, false, problems = listOf(ex.message.orEmpty()))
        }
        val m = parsed.content
            ?: return EvidenceResult(DeclarationEvidence.ROLE_PARTY, true, ct("core_vd_mandate"), null, null, false, problems = listOf(ct("core_vd_mandate_unreadable")))
        val problems = ArrayList<String>()
        val title = ct("core_vd_mandate_of", m.principal.name)

        // Signature and signer.
        var trust: TrustDecision? = null
        var signer: String? = null
        val chain = runCatching { parsed.jws.x5c?.certificates }.getOrNull()
        if (!chain.isNullOrEmpty()) {
            val leaf = chain.first()
            signer = leafName(leaf)
            if (runCatching { parsed.jws.verify(VerificationKey.fromCertificate(leaf)) }.isFailure) problems.add(ct("core_vd_mandate_sig"))
            trust = listOf(TrustRole.VERIFIER, TrustRole.DOCUMENT, TrustRole.ISSUER)
                .map { trustRegistry.decide(it, chain, now) }
                .minByOrNull { if (it.environment == null) 10 else it.tier.ordinal }
            if (trust?.environment == null) problems.add(ct("core_vd_mandate_untrusted", signer))
            val idMatch = m.principal.id?.let { matchesId(leaf, it) }
            if (idMatch == false || idMatch == null && !matchesName(leaf, m.principal.name)) problems.add(ct("core_vd_mandate_signer_other", signer))
        } else {
            val did = parsed.issuer?.takeIf { it.startsWith("did:") }
            val kid = parsed.jws.kid
            if (did == null || kid == null || (!kid.startsWith("#") && kid.substringBefore('#') != did)) {
                problems.add(ct("core_vd_mandate_no_key"))
            } else {
                signer = did
                val ok = runCatching { parsed.jws.verify(didResolver.resolveKey(did, kid).key) }.isSuccess
                if (!ok) problems.add(ct("core_vd_mandate_sig"))
                trust = didTrust.decideOrDefault(did, TrustRole.VERIFIER, ct("core_vd_mandate_did_unknown"))
            }
        }

        // Lifetime, agent key and scope.
        if (now < m.notBefore || now > m.expiresAt) problems.add(ct("core_vd_mandate_period"))
        if (binding.clientId !in m.agentClientIds) problems.add(ct("core_vd_mandate_other_key"))
        if (!sameParty(m.principal, declared.party)) problems.add(ct("core_vd_mandate_other_party", m.principal.name))
        val agent = declared.agent
        if (agent != null && normalize(agent.name) != normalize(m.agent.name)) problems.add(ct("core_vd_mandate_other_agent", m.agent.name))
        if (!VerifierMandate.coversPurpose(m.purposes, declared.purpose?.text)) problems.add(ct("core_vd_mandate_purpose"))
        val scope = m.credentials
        if (scope != null && requestDcql != null && requestDcql.isNotEmpty()) {
            val outside = VerifierInfoChecker.outside(requestDcql, scope.mapNotNull { it as? JsonObject })
            if (outside.isNotEmpty()) problems.add(ct("core_vd_mandate_outside") + outside.take(6).joinToString(ct("core_sep_list")))
        }
        checks += Check(ct("core_vd_chk_mandate"), if (problems.isEmpty()) CheckStatus.PASS else CheckStatus.FAIL, title)
        return EvidenceResult(DeclarationEvidence.ROLE_PARTY, true, title, signer, trust, problems.isEmpty() && trust?.environment != null,
            claims = buildMap {
                put(ct("core_vd_mandate_valid"), "${m.notBefore} - ${m.expiresAt}")
                if (m.purposes.isNotEmpty()) put(ct("core_vd_mandate_purposes"), m.purposes.joinToString(ct("core_sep_list")))
            }, problems = problems)
    }

    companion object {
        private const val ORGANIZATION_IDENTIFIER = "2.5.4.97"
        private const val SERIAL_NUMBER = "2.5.4.5"

        /** Claim names whose value names a person or organisation. */
        internal val NAME_CLAIMS = setOf("name", "full_name", "legal_name", "legal_person_name", "organization_name", "姓名", "name_zh", "chinese_name")
        internal val GIVEN_CLAIMS = setOf("given_name", "first_name")
        internal val FAMILY_CLAIMS = setOf("family_name", "last_name", "surname")
        /** Claim names whose value identifies an organisation (unified business number, EUID, LEI). */
        internal val ID_CLAIMS = setOf("legal_person_id", "legal_person_identifier", "organization_identifier", "euid", "lei", "ubn",
            "unified_business_number", "統一編號")

        fun normalize(s: String): String = s.filterNot { it.isWhitespace() || it == '·' || it == '.' }.lowercase()

        private fun component(c: X509Cert, oid: String): String? = runCatching { c.subject.components[oid]?.value }.getOrNull()

        fun leafName(c: X509Cert): String = component(c, OID.ORGANIZATION_NAME.oid) ?: component(c, OID.COMMON_NAME.oid) ?: c.subject.name

        /** Whether the certificate names identifier [id] (organizationIdentifier with a scheme prefix, or serialNumber). */
        fun matchesId(c: X509Cert, id: PartyId): Boolean? {
            val values = listOfNotNull(component(c, ORGANIZATION_IDENTIFIER), component(c, SERIAL_NUMBER))
            if (values.isEmpty()) return null
            return values.any { v -> v == id.value || v.endsWith("-" + id.value) }
        }

        fun matchesName(c: X509Cert, name: String): Boolean {
            val n = normalize(name)
            return listOfNotNull(component(c, OID.ORGANIZATION_NAME.oid), component(c, OID.COMMON_NAME.oid)).any { normalize(it) == n }
        }

        fun sameParty(a: VerifierParty, b: VerifierParty): Boolean {
            if (a.legal != b.legal) return false
            if (a.id != null && b.id != null) return a.id.scheme == b.id.scheme && a.id.value == b.id.value
            return normalize(a.name) == normalize(b.name)
        }

        private fun leafKey(path: String): String = path.substringAfterLast('.')

        /** The party evidence must disclose the party's identifier or name (a person's name may come as given and family names). */
        fun partyEvidenceCheck(party: VerifierParty, r: EvidenceResult): Check {
            val values = r.claims.values.map { it.trim('"') }
            val id = party.id
            val names = namesIn(r)
            return when {
                id != null && values.any { it == id.value || it.endsWith("-" + id.value) } -> Check(ct("core_vd_chk_party"), CheckStatus.PASS, r.title)
                normalize(party.name) in names -> Check(ct("core_vd_chk_party"), CheckStatus.PASS, r.title)
                names.isNotEmpty() -> Check(ct("core_vd_chk_party"), CheckStatus.FAIL, ct("core_vd_party_other", r.title))
                else -> Check(ct("core_vd_chk_party"), CheckStatus.WARN, ct("core_vd_party_not_disclosed", r.title))
            }
        }

        /** The names [r] discloses, normalized: full names, and given and family names joined in either order. */
        private fun namesIn(r: EvidenceResult): List<String> {
            val byLeaf = r.claims.entries.associate { (k, v) -> leafKey(k) to v.trim('"') }
            val full = byLeaf.filterKeys { it in NAME_CLAIMS }.values
            val given = byLeaf.filterKeys { it in GIVEN_CLAIMS }.values.firstOrNull()
            val family = byLeaf.filterKeys { it in FAMILY_CLAIMS }.values.firstOrNull()
            return full.map { normalize(it) } + listOfNotNull(
                if (given != null && family != null) normalize(family + given) else null,
                if (given != null && family != null) normalize(given + family) else null,
            )
        }

        /** The agent evidence must disclose the agent's name (full name, or given and family names). */
        fun agentEvidenceCheck(agent: VerifierAgent, r: EvidenceResult): Check {
            val n = normalize(agent.name)
            val candidates = namesIn(r)
            return when {
                candidates.isEmpty() -> Check(ct("core_vd_chk_agent"), CheckStatus.WARN, ct("core_vd_agent_not_disclosed", r.title))
                n in candidates -> Check(ct("core_vd_chk_agent"), CheckStatus.PASS, r.title)
                else -> Check(ct("core_vd_chk_agent"), CheckStatus.FAIL, ct("core_vd_agent_other", r.title))
            }
        }

        /** Credential type named by a DCQL query (doctype or vct), or its format. */
        fun typeOf(query: JsonObject): String {
            val meta = query["meta"] as? JsonObject
            val doctype = (meta?.get("doctype_value") as? kotlinx.serialization.json.JsonPrimitive)?.content
            val vct = (meta?.get("vct_values") as? JsonArray)?.firstOrNull()?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
            return doctype ?: vct ?: (query["format"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: ct("core_credential_word")
        }

        /** A one-query DCQL object for [query], as evidence presentations are verified. */
        fun dcqlOf(query: JsonObject): JsonObject = buildJsonObject { put("credentials", buildJsonArray { add(query) }) }
    }
}
