package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import diw.wallet.app.WalletModel
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.oid4vp.AttestationVerdict
import diw.wallet.core.oid4vp.VerifierAttestation
import diw.wallet.core.oid4vp.VerifierInfoChecker

fun tierColor(t: TrustTier): Color = when (t) {
    TrustTier.T1 -> Color(0xFF1B7F3B)
    TrustTier.T2 -> Color(0xFF1565C0)
    TrustTier.T3 -> Color(0xFFB26A00)
    TrustTier.T4 -> Color(0xFFB3261E)
}

@Composable
fun labelText(l: TrustLabel): String = when (l) {
    TrustLabel.TEST_ANCHOR -> stringResource(Res.string.trust_label_test)
    TrustLabel.USER_ANCHOR -> stringResource(Res.string.trust_label_user)
    TrustLabel.UNKNOWN_ANCHOR -> stringResource(Res.string.trust_label_chain_unlisted)
    TrustLabel.UNSIGNED_REQUEST -> stringResource(Res.string.trust_label_unsigned)
    TrustLabel.VIA_INTERMEDIARY -> stringResource(Res.string.trust_label_intermediary)
    TrustLabel.RETAINS_DATA -> stringResource(Res.string.trust_label_retains)
    TrustLabel.HAS_TRANSACTION_DATA -> stringResource(Res.string.trust_label_transaction)
    TrustLabel.SOFTWARE_KEY -> stringResource(Res.string.trust_label_software_key)
    TrustLabel.TIME_NOT_VERIFIED -> stringResource(Res.string.trust_label_time_unverified)
    TrustLabel.UNSIGNED_METADATA -> stringResource(Res.string.trust_label_metadata_unsigned)
    TrustLabel.KEY_NOT_ATTESTED -> stringResource(Res.string.trust_label_key_unattested)
    TrustLabel.LINKED_DOMAIN -> stringResource(Res.string.trust_label_linked_domain)
    TrustLabel.SYSTEM_ANCHOR -> stringResource(Res.string.trust_label_system)
    TrustLabel.IDENTITY_VERIFIED -> stringResource(Res.string.trust_label_gpki)
    TrustLabel.MAINLAND_CHINA_CA -> stringResource(Res.string.trust_label_china)
    TrustLabel.SELF_ISSUED -> stringResource(Res.string.trust_label_self)
    TrustLabel.AATL -> stringResource(Res.string.trust_label_aatl)
    TrustLabel.EUTL -> stringResource(Res.string.trust_label_eutl)
    TrustLabel.EU_QUALIFIED -> stringResource(Res.string.trust_label_eu_qualified)
    TrustLabel.OPENID_FEDERATION -> stringResource(Res.string.trust_label_federation)
}

/** The clause added for an EU trusted list service the list names as qualified. */
@Composable
private fun qualified(t: TrustDecision): String = if (TrustLabel.EU_QUALIFIED in t.labels) stringResource(Res.string.trust_qualified_suffix) else ""

private val SELF_ISSUED_TEXT: String
    @Composable get() = stringResource(Res.string.trust_self_issued_text)

/** A TWDIW-listed party whose on-chain registration or role could not be confirmed (T2 from the national list). */
private fun twdiwListed(t: TrustDecision): Boolean = t.reasons.any { "TWDIW trust list" in it }

/** One-line advice per tier; official or anchored parties get the short form. */
@Composable
fun tierAdvice(t: TrustDecision): String = when {
    t.environment == TrustEnvironment.TEST -> stringResource(Res.string.trust_advice_test)
    t.tier == TrustTier.T1 -> stringResource(Res.string.trust_advice_t1)
    TrustLabel.SELF_ISSUED in t.labels -> SELF_ISSUED_TEXT
    t.tier == TrustTier.T4 -> stringResource(Res.string.trust_advice_t4)
    t.tier == TrustTier.T3 -> stringResource(Res.string.trust_advice_t3)
    TrustLabel.IDENTITY_VERIFIED in t.labels -> stringResource(Res.string.trust_advice_gpki, t.anchorName ?: "")
    twdiwListed(t) -> stringResource(Res.string.trust_advice_twdiw_partial)
    TrustLabel.LINKED_DOMAIN in t.labels -> stringResource(Res.string.trust_advice_linked_domain, t.anchorName ?: "")
    TrustLabel.MAINLAND_CHINA_CA in t.labels -> stringResource(Res.string.trust_advice_china, t.anchorName ?: "")
    TrustLabel.AATL in t.labels -> stringResource(Res.string.trust_advice_aatl, t.anchorName ?: "")
    TrustLabel.EUTL in t.labels -> stringResource(Res.string.trust_advice_eutl, t.anchorName ?: "", qualified(t))
    TrustLabel.SYSTEM_ANCHOR in t.labels -> stringResource(Res.string.trust_advice_system, t.anchorName ?: "")
    t.environment == TrustEnvironment.USER -> stringResource(Res.string.trust_advice_user)
    t.anchorName != null -> stringResource(Res.string.trust_advice_builtin_issuer, t.anchorName.toString())
    else -> stringResource(Res.string.trust_advice_t2)
}

/**
 * Who a document signer or time-stamp authority is, by the trust of its certificate chain. It says nothing about the
 * signature itself, whose integrity and validity are shown beside it (an invalid signature must not read as valid).
 */
@Composable
fun signerTrustLine(t: TrustDecision): String = when {
    t.environment == TrustEnvironment.TEST -> stringResource(Res.string.signer_trust_test)
    t.tier == TrustTier.T1 -> stringResource(Res.string.signer_trust_t1)
    t.tier == TrustTier.T4 -> stringResource(Res.string.signer_trust_failed)
    t.tier == TrustTier.T3 -> stringResource(Res.string.signer_trust_t3)
    TrustLabel.IDENTITY_VERIFIED in t.labels -> stringResource(Res.string.signer_trust_gpki, t.anchorName ?: "")
    TrustLabel.MAINLAND_CHINA_CA in t.labels -> stringResource(Res.string.signer_trust_china, t.anchorName ?: "")
    TrustLabel.AATL in t.labels -> stringResource(Res.string.signer_trust_aatl, t.anchorName ?: "")
    TrustLabel.EUTL in t.labels -> stringResource(Res.string.signer_trust_eutl, t.anchorName ?: "", qualified(t))
    TrustLabel.SYSTEM_ANCHOR in t.labels -> stringResource(Res.string.signer_trust_public, t.anchorName ?: "")
    t.environment == TrustEnvironment.USER -> stringResource(Res.string.signer_trust_user, t.anchorName ?: "")
    else -> stringResource(Res.string.signer_trust_t2, t.anchorName ?: "")
}

/** What the trust says about the issuer of a document being verified, one sentence for a verdict card. */
@Composable
fun issuerTrustLine(t: TrustDecision?): String = when {
    t == null -> stringResource(Res.string.issuer_trust_none)
    t.environment == TrustEnvironment.TEST -> stringResource(Res.string.issuer_trust_test)
    t.tier == TrustTier.T1 -> stringResource(Res.string.issuer_trust_t1)
    TrustLabel.SELF_ISSUED in t.labels -> SELF_ISSUED_TEXT
    t.tier == TrustTier.T4 -> stringResource(Res.string.issuer_trust_failed)
    t.tier == TrustTier.T3 -> stringResource(Res.string.issuer_trust_t3)
    TrustLabel.IDENTITY_VERIFIED in t.labels -> stringResource(Res.string.issuer_trust_gpki, t.anchorName ?: "")
    twdiwListed(t) -> stringResource(Res.string.issuer_trust_twdiw_partial)
    TrustLabel.LINKED_DOMAIN in t.labels -> stringResource(Res.string.issuer_trust_linked_domain, t.anchorName ?: "")
    TrustLabel.MAINLAND_CHINA_CA in t.labels -> stringResource(Res.string.issuer_trust_china, t.anchorName ?: "")
    t.environment == TrustEnvironment.SYSTEM -> stringResource(Res.string.issuer_trust_public, t.anchorName ?: "")
    t.environment == TrustEnvironment.USER -> stringResource(Res.string.issuer_trust_user)
    else -> stringResource(Res.string.issuer_trust_builtin, t.anchorName ?: "")
}

/** The four trust tiers as the wallet assigns them, each with the sources that lead to it. */
@Composable
fun TierLegend() {
    val rows = listOf(
        TrustTier.T1 to stringResource(Res.string.tier_legend_t1),
        TrustTier.T2 to stringResource(Res.string.tier_legend_t2),
        TrustTier.T3 to stringResource(Res.string.tier_legend_t3),
        TrustTier.T4 to stringResource(Res.string.tier_legend_t4),
    )
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        // The badge sits above its text, so the text keeps the full width on a narrow phone.
        rows.forEach { (tier, text) ->
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Box(
                    Modifier.background(tierColor(tier), RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(WalletModel.tierTitle(tier), color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                }
                Text(text, style = MaterialTheme.typography.bodySmall)
            }
        }
        Text(stringResource(Res.string.tier_legend_note), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
fun TierBadge(trust: TrustDecision, modifier: Modifier = Modifier) {
    Box(
        modifier
            .background(tierColor(trust.tier), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(WalletModel.tierTitle(trust.tier), color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun TrustCard(title: String, subject: String, trust: TrustDecision, extra: List<String> = emptyList(), onClick: (() -> Unit)? = null) {
    Card(
        modifier = Modifier.fillMaxWidth().then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
        colors = CardDefaults.cardColors(containerColor = tierColor(trust.tier).copy(alpha = 0.08f)),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(title, style = MaterialTheme.typography.labelLarge)
                TierBadge(trust)
            }
            Text(subject, style = MaterialTheme.typography.titleMedium)
            trust.anchorName?.let { Text(stringResource(Res.string.trust_anchor_line, it), style = MaterialTheme.typography.bodySmall) }
            Text(tierAdvice(trust), style = MaterialTheme.typography.bodyMedium)
            if (trust.labels.isNotEmpty()) {
                Text(trust.labels.map { labelText(it) }.joinToString(stringResource(Res.string.sep_list)), style = MaterialTheme.typography.bodySmall, color = tierColor(trust.tier))
            }
            extra.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/**
 * One verifier_info entry as checked: who registered the verifier, for what purpose, which signer vouches for it,
 * and every failed check. A test registrar never reads as official.
 */
@Composable
fun VerifierAttestationCard(a: VerifierAttestation) {
    val (verdict, title) = when (a.verdict) {
        AttestationVerdict.VALID -> Verdict.PASS to stringResource(Res.string.attestation_valid)
        AttestationVerdict.PARTIAL -> Verdict.CAUTION to stringResource(Res.string.attestation_partial)
        AttestationVerdict.INVALID -> Verdict.FAIL to stringResource(Res.string.attestation_invalid)
        AttestationVerdict.UNSUPPORTED -> Verdict.CAUTION to stringResource(Res.string.attestation_unverifiable)
    }
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = verdict.color.copy(alpha = 0.10f))) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (a.type == VerifierInfoChecker.RC_TYP) stringResource(Res.string.attestation_registration) else stringResource(Res.string.attestation_attached), style = MaterialTheme.typography.labelLarge)
                VerdictPill(verdict, title)
            }
            a.name?.let { Text(it, style = MaterialTheme.typography.titleSmall) }
            a.purposes.takeIf { it.isNotEmpty() }?.let { Text(stringResource(Res.string.attestation_purpose) + it.joinToString(stringResource(Res.string.sep_semicolon)), style = MaterialTheme.typography.bodyMedium) }
            a.serviceDescription?.let { Text(stringResource(Res.string.attestation_service, it), style = MaterialTheme.typography.bodySmall) }
            a.subject?.let { Text(stringResource(Res.string.attestation_subject, it) + when (a.boundToVerifier) {
                true -> stringResource(Res.string.attestation_subject_match)
                false -> stringResource(Res.string.attestation_subject_mismatch)
                null -> ""
            }, style = MaterialTheme.typography.bodySmall) }
            a.outsideRegistration?.let { if (it.isEmpty()) Text(stringResource(Res.string.attestation_in_scope), style = MaterialTheme.typography.bodySmall) }
            if (a.entitlements.isNotEmpty()) Text(stringResource(Res.string.attestation_entitlements) + a.entitlements.joinToString(stringResource(Res.string.sep_list)) { it.substringAfterLast('/').replace('_', ' ') }, style = MaterialTheme.typography.bodySmall)
            a.publicBody?.let { if (it) Text(stringResource(Res.string.attestation_public_body), style = MaterialTheme.typography.bodySmall) }
            a.country?.let { Text(stringResource(Res.string.attestation_country, it), style = MaterialTheme.typography.bodySmall) }
            a.signer?.let { signer ->
                val t = a.trust
                Text(stringResource(Res.string.attestation_signer, signer) + (t?.let { stringResource(Res.string.sep_space) + WalletModel.tierTitle(it.tier) + (it.anchorName?.let { n -> stringResource(Res.string.parenthesized, n) } ?: "") } ?: ""),
                    style = MaterialTheme.typography.bodySmall)
                if (t?.environment == TrustEnvironment.TEST) Text(stringResource(Res.string.attestation_test_signer), style = MaterialTheme.typography.bodySmall, color = tierColor(TrustTier.T3))
            }
            a.statusFinding?.let { Text(stringResource(Res.string.attestation_status) + diw.wallet.app.StatusTexts.finding(it), style = MaterialTheme.typography.bodySmall) }
            a.expiresAt?.let { Text(stringResource(Res.string.attestation_valid_until) + localTime(it), style = MaterialTheme.typography.bodySmall) }
            a.registryUri?.let { Text(stringResource(Res.string.attestation_registrar, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
            a.privacyPolicy?.let { Text(stringResource(Res.string.attestation_privacy, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
            a.supervisoryAuthority?.let { Text(stringResource(Res.string.attestation_supervisor, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline) }
            if (a.credentialIds.isNotEmpty()) Text(stringResource(Res.string.attestation_applies) + a.credentialIds.joinToString(stringResource(Res.string.sep_list)), style = MaterialTheme.typography.bodySmall)
            a.problems.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            a.notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/** Banner shown on every screen while a custom test server is in use. */
@Composable
fun TestEnvironmentBanner() {
    Box(
        Modifier.fillMaxWidth().background(Color(0xFFB3261E)).padding(vertical = 4.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(stringResource(Res.string.test_server_banner), color = Color.White, fontSize = 12.sp)
    }
}

/** Diagonal watermark text for documents issued in the TEST environment. */
@Composable
fun TestWatermark(modifier: Modifier = Modifier, fontSize: Int = 28) {
    Text(
        stringResource(Res.string.test_watermark),
        modifier = modifier,
        color = Color(0x55B3261E),
        fontSize = fontSize.sp,
        fontWeight = FontWeight.Bold,
    )
}
