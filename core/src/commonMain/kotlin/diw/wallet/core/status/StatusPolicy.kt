package diw.wallet.core.status

import diw.wallet.core.env.TrustEnvironment
import org.multipaz.revocation.RevocationCheckState
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Risk of what a credential is used for. The higher the risk, the less an unconfirmed status is accepted and the
 * fresher a status result has to be. [maxStatusAge] is how old a status result may be before it counts as stale.
 */
enum class RiskLevel(val maxStatusAge: Duration) {
    /** Membership, attendance, discounts: a wrong answer costs little. */
    LOW(6.days),

    /** Government cards, counter services, age checks. */
    MEDIUM(1.days),

    /** Identity documents, finance, access to places or records. */
    HIGH(1.hours);

    companion object {
        fun max(a: RiskLevel, b: RiskLevel): RiskLevel = if (a.ordinal >= b.ordinal) a else b
    }
}

/** Whether a credential may be relied on for a use of a given risk. */
enum class StatusVerdict {
    ACCEPT,

    /** Usable, but the user or verifier should know why it is not a plain pass. */
    CAUTION,

    REJECT,
}

/** What a status result says, before the risk is applied. */
enum class StatusFinding {
    /** Valid, and the list is signed by a key tied to the issuer or to a trust anchor. */
    VALID,

    /** Valid by a list whose key rests on TLS only (a jku the issuer cannot be tied to). */
    VALID_TLS_ONLY,

    /** Valid by a list whose signature could not be verified. */
    VALID_UNVERIFIED,

    REVOKED,
    SUSPENDED,

    /** The issuer gives no status for this credential. */
    NO_STATUS,

    /** The list could not be read, or its value has no defined meaning. */
    UNKNOWN,

    /** No status query has been made. */
    NOT_CHECKED,
}

data class StatusDecision(
    val verdict: StatusVerdict,
    val finding: StatusFinding,
    val risk: RiskLevel,
    /** The result is older than [RiskLevel.maxStatusAge]; a stale pass is lowered to caution. */
    val stale: Boolean,
    /** The list is trusted only in the test environment; a test pass is lowered to caution and never looks official. */
    val test: Boolean = false,
)

/**
 * Accepting a credential status by the risk of the use. A revoked credential is never accepted. A list that could
 * not be read, or whose signature could not be verified, is accepted for low risk, needs attention for medium risk
 * and is refused for high risk. A list verified over TLS only is enough up to medium risk.
 *
 * | finding          | LOW     | MEDIUM  | HIGH    |
 * |------------------|---------|---------|---------|
 * | VALID            | ACCEPT  | ACCEPT  | ACCEPT  |
 * | VALID_TLS_ONLY   | ACCEPT  | ACCEPT  | CAUTION |
 * | VALID_UNVERIFIED | ACCEPT  | CAUTION | REJECT  |
 * | NO_STATUS        | ACCEPT  | ACCEPT  | CAUTION |
 * | UNKNOWN          | ACCEPT  | CAUTION | REJECT  |
 * | NOT_CHECKED      | CAUTION | CAUTION | REJECT  |
 * | SUSPENDED        | CAUTION | REJECT  | REJECT  |
 * | REVOKED          | REJECT  | REJECT  | REJECT  |
 */
object StatusPolicy {
    fun finding(status: CredentialStatus?): StatusFinding = when {
        status == null -> StatusFinding.NOT_CHECKED
        status.state == RevocationCheckState.INVALID -> StatusFinding.REVOKED
        status.state == RevocationCheckState.SUSPENDED -> StatusFinding.SUSPENDED
        status.state == RevocationCheckState.VALID -> when (status.assurance) {
            StatusAssurance.TRUSTED -> StatusFinding.VALID
            StatusAssurance.TLS_ONLY -> StatusFinding.VALID_TLS_ONLY
            StatusAssurance.UNVERIFIED -> StatusFinding.VALID_UNVERIFIED
        }
        !status.referenced -> StatusFinding.NO_STATUS
        else -> StatusFinding.UNKNOWN
    }

    fun verdict(finding: StatusFinding, risk: RiskLevel): StatusVerdict {
        val (low, medium, high) = when (finding) {
            StatusFinding.VALID -> Triple(StatusVerdict.ACCEPT, StatusVerdict.ACCEPT, StatusVerdict.ACCEPT)
            StatusFinding.VALID_TLS_ONLY -> Triple(StatusVerdict.ACCEPT, StatusVerdict.ACCEPT, StatusVerdict.CAUTION)
            StatusFinding.VALID_UNVERIFIED -> Triple(StatusVerdict.ACCEPT, StatusVerdict.CAUTION, StatusVerdict.REJECT)
            StatusFinding.NO_STATUS -> Triple(StatusVerdict.ACCEPT, StatusVerdict.ACCEPT, StatusVerdict.CAUTION)
            StatusFinding.UNKNOWN -> Triple(StatusVerdict.ACCEPT, StatusVerdict.CAUTION, StatusVerdict.REJECT)
            StatusFinding.NOT_CHECKED -> Triple(StatusVerdict.CAUTION, StatusVerdict.CAUTION, StatusVerdict.REJECT)
            StatusFinding.SUSPENDED -> Triple(StatusVerdict.CAUTION, StatusVerdict.REJECT, StatusVerdict.REJECT)
            StatusFinding.REVOKED -> Triple(StatusVerdict.REJECT, StatusVerdict.REJECT, StatusVerdict.REJECT)
        }
        return when (risk) {
            RiskLevel.LOW -> low
            RiskLevel.MEDIUM -> medium
            RiskLevel.HIGH -> high
        }
    }

    /**
     * The decision for [status] at [risk]. A pass older than the risk allows becomes caution, and so does a pass
     * from a list trusted only in the test environment.
     */
    fun decide(status: CredentialStatus?, risk: RiskLevel, now: Instant = Clock.System.now()): StatusDecision {
        val finding = finding(status)
        val stale = status != null && now - status.checkedAt > risk.maxStatusAge
        val test = status?.environment == TrustEnvironment.TEST
        var verdict = verdict(finding, risk)
        if ((stale || test) && verdict == StatusVerdict.ACCEPT && finding != StatusFinding.NO_STATUS) verdict = StatusVerdict.CAUTION
        return StatusDecision(verdict, finding, risk, stale, test)
    }

    /** How long a status result is kept before a background refresh: half the age the risk allows, at least 10 minutes. */
    fun refreshAfter(risk: RiskLevel): Duration = maxOf(risk.maxStatusAge / 2, 10.minutes)
}
