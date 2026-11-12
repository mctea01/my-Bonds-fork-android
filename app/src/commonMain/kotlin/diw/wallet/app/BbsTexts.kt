package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.w3c.bbs.BbsFeature

/** Names and consent notes of the bbs-2023 features (selective disclosure, holder binding, pseudonyms). */
internal object BbsTexts {
    fun name(feature: BbsFeature): String = tr(
        when (feature) {
            BbsFeature.BASELINE -> Res.string.bbs_feature_baseline
            BbsFeature.ANONYMOUS_HOLDER_BINDING -> Res.string.bbs_feature_anonymous_holder_binding
            BbsFeature.PSEUDONYM -> Res.string.bbs_feature_pseudonym
            BbsFeature.HOLDER_BINDING_PSEUDONYM -> Res.string.bbs_feature_holder_binding_pseudonym
        }
    )

    /** What the verifier learns beyond the listed claims, shown on the consent screen. */
    fun consent(feature: BbsFeature): String = tr(
        when (feature) {
            BbsFeature.BASELINE -> Res.string.consent_bbs_baseline
            BbsFeature.ANONYMOUS_HOLDER_BINDING -> Res.string.consent_bbs_anonymous_holder_binding
            BbsFeature.PSEUDONYM -> Res.string.consent_bbs_pseudonym
            BbsFeature.HOLDER_BINDING_PSEUDONYM -> Res.string.consent_bbs_holder_binding_pseudonym
        }
    )
}
