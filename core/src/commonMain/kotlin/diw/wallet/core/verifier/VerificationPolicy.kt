package diw.wallet.core.verifier

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.i18n.ct
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.highlyTrusted

/**
 * Assurance of a presented credential (docs/design/p5-verifier.md section 8), from the strongest. A verifier picks the
 * levels it accepts; the result's business rule field follows from it.
 */
enum class AssuranceLevel(val key: String) {
    /** Issued by an issuer anchored in a trust list or root (T1, T2). */
    TRUSTED_ISSUER("core_assurance_trusted_issuer"),
    /** Derived by the holder's wallet from a signed document, with a zkPDF proof of the authority's signature. */
    DOCUMENT_DERIVED("core_assurance_document_derived"),
    /** Derived or self-signed by the holder's wallet; the evidence can be re-checked but no authority signs it. */
    HOLDER_DERIVED("core_assurance_holder_derived"),
    /** Verifiable, but the issuer is not anchored (T3: user trusted DID, custom PKI). */
    OTHER_ISSUER("core_assurance_other_issuer"),
    /** An issuer of the test environment. */
    SANDBOX("core_assurance_sandbox");

    val title: String get() = ct(key)
}

/** What a verifier accepts: the assurance levels, and whether a zero-knowledge proof must back the values. */
data class VerificationPolicy(
    val accepted: Set<AssuranceLevel> = DEFAULT,
    val requireZeroKnowledge: Boolean = false,
) {
    companion object {
        val DEFAULT = setOf(AssuranceLevel.TRUSTED_ISSUER, AssuranceLevel.DOCUMENT_DERIVED)

        /** The assurance of [c]; null when its issuer could not be judged (verification failed). */
        fun assurance(c: CredentialVerification): AssuranceLevel? {
            val t = c.issuerTrust
            return when {
                t.environment == TrustEnvironment.TEST -> AssuranceLevel.SANDBOX
                c.derived && c.zkProof && c.format == "dc+sd-jwt" -> AssuranceLevel.DOCUMENT_DERIVED
                c.derived || TrustLabel.SELF_ISSUED in t.labels -> AssuranceLevel.HOLDER_DERIVED
                t.environment == null -> null
                t.tier.highlyTrusted -> AssuranceLevel.TRUSTED_ISSUER
                else -> AssuranceLevel.OTHER_ISSUER
            }
        }
    }

    /** The business rule check of [c] under this policy (never PASS for a credential that failed its own checks). */
    fun evaluate(c: CredentialVerification): Check {
        val level = assurance(c) ?: return Check(ct("core_policy_rule"), CheckStatus.FAIL, ct("core_policy_unjudged"))
        return when {
            level !in accepted -> Check(ct("core_policy_rule"), CheckStatus.FAIL, ct("core_policy_not_accepted", level.title))
            requireZeroKnowledge && !c.zkProof -> Check(ct("core_policy_rule"), CheckStatus.FAIL, ct("core_policy_no_zk"))
            !c.passed -> Check(ct("core_policy_rule"), CheckStatus.UNKNOWN, ct("core_policy_checks_failed", level.title))
            else -> Check(ct("core_policy_rule"), CheckStatus.PASS, level.title)
        }
    }
}
