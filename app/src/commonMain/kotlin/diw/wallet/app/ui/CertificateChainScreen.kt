package diw.wallet.app.ui

import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import diw.wallet.app.CredentialDetails
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.trust.PathSource
import diw.wallet.core.trust.PathStep
import diw.wallet.core.trust.RootListing
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustPath
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.x509.displaySubject
import org.jetbrains.compose.resources.stringResource
import org.multipaz.crypto.X509Cert
import kotlin.time.Clock

/** The uses offered when the user trusts a root from a chain; wallet providers and list signers stay in Trust anchors. */
private val REVIEW_ROLES = listOf(
    TrustRole.ISSUER, TrustRole.STATUS_LIST, TrustRole.VERIFIER, TrustRole.DOCUMENT, TrustRole.TSA, TrustRole.CONTENT, TrustRole.TRAVEL_DOCUMENT,
)

/**
 * A certificate chain shown up to its root (see [diw.wallet.core.trust.TrustRegistry.path]): the trust result for the
 * use it was checked for, every certificate from the root down to the leaf with where it came from and whether its
 * signature verifies, the root's review details, and the selected certificate's contents. A chain that leads to no
 * anchor (T3) can have its root trusted from here after the user reviewed and confirmed it.
 */
@Composable
fun CertificateScreen(model: WalletModel, screen: Screen.Certificate) {
    var version by remember(screen) { mutableIntStateOf(0) }
    val path by produceState<TrustPath?>(null, screen, version) {
        value = runCatching { model.trustPath(screen.chain, screen.role, screen.docType) }.getOrNull()
            ?: TrustPath(screen.chain.map { PathStep(it, PathSource.PRESENTED, null, false) }, emptyList(), null, emptyList())
    }
    var selected by remember(screen) { mutableStateOf(screen.chain.getOrNull(screen.index) ?: screen.chain.first()) }
    var focused by remember(screen) { mutableStateOf(!screen.focusRoot) }
    LaunchedEffect(path) {
        val p = path
        if (!focused && p != null) {
            p.top?.let { selected = it }
            focused = true
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(selected.displaySubject(), style = MaterialTheme.typography.titleMedium)
        val p = path
        if (p == null) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                Text(stringResource(Res.string.chain_loading), style = MaterialTheme.typography.bodySmall)
            }
        } else {
            p.decision?.let { d -> ChainTrustSummary(d, screen.role) }
            SectionTitle(stringResource(Res.string.chain_title))
            ChainList(p, selected) { selected = it }
            if (!p.rootReached) MissingRoot(model, p)
            if (p.extras.isNotEmpty()) {
                Text(stringResource(Res.string.chain_extras), style = MaterialTheme.typography.titleSmall)
                p.extras.forEach { c -> LabelValue(stringResource(Res.string.chain_extra_cert), c.displaySubject(), small = true) { selected = c } }
            }
            val root = p.top
            if (root != null && p.rootReached) RootReview(model, p, root, screen.role) { version++ }
        }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        SectionTitle(stringResource(Res.string.chain_selected, selected.displaySubject()))
        DetailSections(model, CredentialDetails.certificate(selected))
    }
}

@Composable
private fun ChainTrustSummary(d: TrustDecision, role: TrustRole?) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TierBadge(d)
            role?.let { Text(stringResource(Res.string.chain_trust_for, roleName(it)), style = MaterialTheme.typography.bodyMedium) }
        }
        d.anchorName?.let { Text(stringResource(Res.string.chain_anchor_name, it), style = MaterialTheme.typography.bodySmall) }
        Text(tierAdvice(d), style = MaterialTheme.typography.bodySmall)
        if (TrustLabel.UNKNOWN_ANCHOR in d.labels) {
            Text(stringResource(Res.string.chain_t3_hint), style = MaterialTheme.typography.bodySmall, color = tierColor(TrustTier.T3))
        }
    }
}

/** The chain from the root (or the highest certificate found) down to the leaf, indented by depth. */
@Composable
private fun ChainList(p: TrustPath, selected: X509Cert, onSelect: (X509Cert) -> Unit) {
    val now = Clock.System.now()
    val last = p.steps.lastIndex
    p.steps.indices.reversed().forEachIndexed { depth, i ->
        val step = p.steps[i]
        val c = step.certificate
        val selfIssued = c.subject == c.issuer
        val position = when {
            i == last && selfIssued -> stringResource(Res.string.certificate_trust_root_label)
            i == last && last > 0 -> stringResource(Res.string.chain_pos_top)
            i == 0 -> stringResource(Res.string.chain_pos_leaf)
            else -> stringResource(Res.string.chain_pos_intermediate)
        }
        val source = when (step.source) {
            PathSource.PRESENTED -> stringResource(Res.string.chain_src_presented)
            PathSource.BUILT_IN_INTERMEDIATE -> stringResource(Res.string.chain_src_builtin_mid)
            PathSource.USER_INTERMEDIATE -> stringResource(Res.string.chain_src_user_mid)
            PathSource.TRUST_SOURCE -> stringResource(Res.string.chain_src_trust)
            PathSource.AIA -> stringResource(Res.string.chain_src_aia)
        }
        val signature = when {
            step.signatureValid == null -> null
            i == last && selfIssued -> if (step.signatureValid == true) stringResource(Res.string.chain_self_ok) else stringResource(Res.string.chain_self_bad)
            else -> if (step.signatureValid == true) stringResource(Res.string.chain_sig_ok) else stringResource(Res.string.chain_sig_bad)
        }
        val validity = when {
            now < c.validityNotBefore -> stringResource(Res.string.chain_not_yet, localTime(c.validityNotBefore))
            now > c.validityNotAfter -> stringResource(Res.string.chain_expired, localTime(c.validityNotAfter))
            else -> stringResource(Res.string.chain_valid_until, localTime(c.validityNotAfter))
        }
        val problem = step.signatureValid == false || now !in c.validityNotBefore..c.validityNotAfter
        val isSelected = c == selected
        Column(
            Modifier.fillMaxWidth().padding(start = (minOf(depth, 4) * 12).dp)
                .border(if (isSelected) 2.dp else 1.dp, if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(8.dp))
                .clickable { onSelect(c) }
                .padding(10.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(position, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                if (step.anchor) Text(stringResource(Res.string.chain_anchor_mark), style = MaterialTheme.typography.labelMedium, color = tierColor(TrustTier.T2))
            }
            Text(c.displaySubject(), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Text(listOfNotNull(source, signature, validity).joinToString(stringResource(Res.string.sep_list)), style = MaterialTheme.typography.bodySmall,
                color = if (problem) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** The issuer of the highest certificate could not be found anywhere: what is missing and where to add it. */
@Composable
private fun MissingRoot(model: WalletModel, p: TrustPath) {
    val top = p.top ?: return
    val broken = p.steps.lastOrNull()?.signatureValid == false || p.steps.any { it.signatureValid == false }
    val lines = buildList {
        add(stringResource(Res.string.chain_missing_text, top.issuer.name))
        runCatching { top.authorityKeyIdentifier }.getOrNull()?.let { add(stringResource(Res.string.chain_missing_key, groupedFingerprint(DocCryptoUtil.hex(it).uppercase()))) }
        if (broken) add(stringResource(Res.string.chain_broken_link))
    }
    VerdictCard(Verdict.CAUTION, stringResource(Res.string.chain_missing_title), lines)
    TextButton(onClick = { model.screen.value = Screen.TrustAnchors }) { Text(stringResource(Res.string.chain_open_anchors)) }
}

@Composable
private fun listingText(l: RootListing): String = when (l.kind) {
    RootListing.Kind.STORED_ANCHOR -> stringResource(
        Res.string.root_listed_anchor,
        l.role?.let { roleName(it) } ?: "",
        l.environment?.let { environmentTitle(it) } ?: "",
        l.name,
    ) + if (l.official) stringResource(Res.string.root_listed_official) else ""
    RootListing.Kind.BUILT_IN_CSCA -> stringResource(Res.string.root_listed_csca, l.name)
    RootListing.Kind.BUILT_IN_PUBLIC -> stringResource(Res.string.root_listed_public, l.name)
    RootListing.Kind.PLATFORM_STORE -> stringResource(Res.string.root_listed_platform)
    RootListing.Kind.IMPORTABLE -> stringResource(Res.string.root_listed_importable, l.name)
    RootListing.Kind.TRUST_LIST -> stringResource(Res.string.root_listed_list, l.name)
}

/**
 * The root's identity, fingerprint and where the wallet already holds it; for a chain that leads to no anchor, the
 * checks to make and the uses to trust it for, confirmed in a risk dialog that repeats the fingerprint.
 */
@Composable
private fun RootReview(model: WalletModel, p: TrustPath, root: X509Cert, role: TrustRole?, onTrusted: () -> Unit) {
    val fingerprint = remember(root) { groupedFingerprint(DocCryptoUtil.hex(PlatformCrypto.sha256(root.encoded.toByteArray())).uppercase()) }
    val defaultName = remember(root) { root.subject.components[OID_CN]?.value ?: root.displaySubject() }
    SectionTitle(stringResource(Res.string.root_review_title))
    LabelValue(stringResource(Res.string.cert_subject), root.subject.name, small = true)
    root.subject.components[OID_O]?.value?.let { LabelValue(stringResource(Res.string.root_field_org), it, small = true) }
    root.subject.components[OID_C]?.value?.let { LabelValue(stringResource(Res.string.root_field_country), it, small = true) }
    LabelValue(stringResource(Res.string.root_field_validity), localTime(root.validityNotBefore) + stringResource(Res.string.range_to) + localTime(root.validityNotAfter), small = true)
    LabelValue(stringResource(Res.string.root_field_sha256), fingerprint, small = true)
    Text(stringResource(Res.string.root_listed_title), style = MaterialTheme.typography.titleSmall)
    if (p.rootListings.isEmpty()) Text(stringResource(Res.string.root_listed_none), style = MaterialTheme.typography.bodySmall, color = tierColor(TrustTier.T3))
    p.rootListings.forEach { Text(listingText(it), style = MaterialTheme.typography.bodySmall) }

    val needsReview = p.decision?.let { TrustLabel.UNKNOWN_ANCHOR in it.labels } ?: !p.rootKnown
    if (!needsReview) {
        if (role != null && p.anchoredFor(role)) Text(stringResource(Res.string.root_review_already, roleName(role)), style = MaterialTheme.typography.bodySmall)
        return
    }
    var roles by remember(root, role) {
        val r = role
        mutableStateOf(when {
            r == null -> setOf(TrustRole.DOCUMENT)
            r == TrustRole.DOCUMENT -> setOf(TrustRole.DOCUMENT, TrustRole.TSA)
            r in REVIEW_ROLES -> setOf(r)
            else -> emptySet()
        })
    }
    var name by remember(root) { mutableStateOf(defaultName) }
    var confirming by remember(root) { mutableStateOf(false) }
    Text(stringResource(Res.string.root_review_steps_title), style = MaterialTheme.typography.titleSmall)
    Text(stringResource(Res.string.root_review_step_fp), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(Res.string.root_review_step_name), style = MaterialTheme.typography.bodySmall)
    if (role == TrustRole.TRAVEL_DOCUMENT || TrustRole.TRAVEL_DOCUMENT in roles) Text(stringResource(Res.string.root_review_step_csca), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(Res.string.root_review_step_scope), style = MaterialTheme.typography.bodySmall)
    if (Clock.System.now() > root.validityNotAfter) {
        Text(stringResource(Res.string.root_review_expired), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        return
    }
    Text(stringResource(Res.string.root_review_uses), style = MaterialTheme.typography.bodyMedium)
    RoleChips(REVIEW_ROLES, roles) { roles = it }
    OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text(stringResource(Res.string.root_review_name)) }, singleLine = true,
        modifier = Modifier.fillMaxWidth())
    Button(onClick = { confirming = true }, enabled = roles.isNotEmpty()) { Text(stringResource(Res.string.root_review_add)) }
    if (confirming) {
        val uses = REVIEW_ROLES.filter { it in roles }.map { roleName(it) }.joinToString(stringResource(Res.string.sep_list))
        RiskConfirmDialog(
            title = stringResource(Res.string.platform_trust_title, name.ifBlank { defaultName }),
            lines = listOf(
                stringResource(Res.string.files_root_unknown),
                stringResource(Res.string.root_review_confirm_fp, fingerprint),
                stringResource(Res.string.root_review_confirm_uses, uses),
                stringResource(Res.string.files_root_check),
                stringResource(Res.string.root_review_effect),
            ),
            confirm = stringResource(Res.string.zk_server_trust),
            onConfirm = {
                confirming = false
                model.trustRootCertificate(root.encoded.toByteArray(), roles, name, onTrusted)
            },
            onDismiss = { confirming = false },
        )
    }
}

private const val OID_CN = "2.5.4.3"
private const val OID_O = "2.5.4.10"
private const val OID_C = "2.5.4.6"
