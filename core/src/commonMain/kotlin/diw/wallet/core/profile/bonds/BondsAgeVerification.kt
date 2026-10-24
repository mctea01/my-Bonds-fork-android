package diw.wallet.core.profile.bonds

import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.zk.OpenAcAgeCheck
import diw.wallet.core.zk.OpenAcAgeVerifier
import diw.wallet.core.zk.ZkResult
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.util.toBase64Url
import kotlin.time.TimeSource

/**
 * The outcome of checking a posted age package. [proofValid] is the cryptography alone (both proofs, their link, the
 * nonce, the cutoff and the issuer key); [accepted] adds the issuer: a government card must come from an issuer at T2
 * or better, a self-issued card is always self-asserted.
 */
data class BondsAgeVerification(
    val request: BondsAgeRequest,
    val proofValid: Boolean,
    val accepted: Boolean,
    /** Why the package was not accepted, or what an acceptance below T2 rests on; null for a plain acceptance. */
    val reason: String?,
    val issuerDid: String,
    val claimName: String,
    val issuerTrust: TrustDecision?,
    val verifyMs: Long,
    val prepareMs: Long,
    val showMs: Long,
) {
    val selfIssued: Boolean get() = request.source == BondsCredentialSource.SELF_ISSUED

    /** The answer for the holder, in Bonds' verdict shape. */
    fun verdict(): BondsAgeVerdict =
        BondsAgeVerdict(if (accepted) "accepted" else "rejected", accepted, reason, request.minimumAge, verifyMs)
}

object BondsAgeVerifier {
    /**
     * Checks [pkg] against its request: the issuer DID must be a P-256 did:key, the proofs are verified against that
     * key, and for a government card the issuer must be at [minimumTier] or better. A failure of the engine itself (missing
     * assets, out of memory) is thrown, never reported as a rejected proof.
     */
    suspend fun verify(
        pkg: BondsAgePackage,
        engine: OpenAcAgeVerifier,
        resolver: DidResolver,
        didTrust: DidTrust,
        minimumTier: TrustTier = TrustTier.T2,
    ): BondsAgeVerification {
        val request = pkg.request
        fun result(valid: Boolean, accepted: Boolean, reason: String?, trust: TrustDecision?, ms: Long) =
            BondsAgeVerification(request, valid, accepted, reason, pkg.issuerDid, pkg.claimName, trust, ms, pkg.prepareMs, pkg.showMs)

        val key = runCatching { (resolver.resolve(pkg.issuerDid).methods.singleOrNull()?.key as? VerificationKey.Ec)?.key }
            .getOrNull() as? EcPublicKeyDoubleCoordinate
        if (key == null || key.curve != EcCurve.P256) return result(false, false, ISSUER_KEY, null, 0)
        val started = TimeSource.Monotonic.markNow()
        val check = OpenAcAgeCheck(pkg.prepareProof, pkg.showProof, request.nonce, pkg.claimName, pkg.claimFormat,
            request.cutoffValue(pkg.claimFormat), key.x.toBase64Url(), key.y.toBase64Url())
        val valid = when (val r = engine.verify(check)) {
            is ZkResult.Ok -> r.value
            is ZkResult.Failed -> throw IllegalStateException(r.reason)
            ZkResult.Cancelled -> throw kotlinx.coroutines.CancellationException("Verification cancelled")
        }
        val ms = started.elapsedNow().inWholeMilliseconds
        if (!valid) return result(false, false, PROOF_INVALID, null, ms)
        if (request.source == BondsCredentialSource.SELF_ISSUED) return result(true, true, null, null, ms)
        val trust = didTrust.decideOrDefault(pkg.issuerDid, TrustRole.ISSUER, "Issuer ${pkg.issuerDid} is in no trust list")
        return when {
            trust.tier <= TrustTier.T2 -> result(true, true, null, trust, ms)
            trust.tier <= minimumTier -> result(true, true, "$ACCEPTED_UNLISTED（${trust.tier}）", trust, ms)
            else -> result(true, false, UNTRUSTED_ISSUER, trust, ms)
        }
    }

    const val ISSUER_KEY = "發卡者 DID 不是 P-256 的 did:key"
    const val PROOF_INVALID = "零知識證明沒有通過驗證"
    const val ACCEPTED_UNLISTED = "發卡者不在信任清單，依查驗方設定接受"
    const val UNTRUSTED_ISSUER = "證明有效，但發卡者不在政府皮夾的信任清單"
}
