package diw.wallet.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import diw.wallet.app.LegalConsent
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import diw.wallet.app.legal.Integration
import diw.wallet.app.legal.LegalBlock
import diw.wallet.app.legal.LegalDocument
import diw.wallet.app.legal.LegalStrings
import diw.wallet.app.legal.LegalTexts
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

internal val Integration.icon: ImageVector
    get() = when (this) {
        Integration.TWDIW -> WalletIcons.Government
        Integration.MS_VERIFIED_ID -> WalletIcons.Organization
        Integration.MOBILE_MOICA -> WalletIcons.Phone
        Integration.MYDATA -> WalletIcons.Document
        Integration.ZKPASSPORT -> WalletIcons.Pass
    }

/** The holder's decision on [i] in one line. */
private fun statusLine(c: LegalConsent, i: Integration): String {
    val r = c.record(i)
    return when {
        c.enabled(i) -> LegalStrings.enabledLine(r!!.version, r.date)
        r == null || r.version != LegalTexts.statement(i).document.version -> LegalStrings.PENDING_LINE
        else -> LegalStrings.DISABLED_LINE
    }
}

/**
 * The legal texts mark emphasis with **bold** and names such as hosts with `code`, the same marks the published Markdown
 * uses; this renders both and leaves any other character as it is.
 */
internal fun legalAnnotated(text: String): AnnotatedString = buildAnnotatedString {
    var i = 0
    while (i < text.length) {
        val bold = text.startsWith("**", i)
        val mark = if (bold) "**" else if (text[i] == '`') "`" else null
        val end = mark?.let { text.indexOf(it, i + it.length) } ?: -1
        if (mark == null || end < 0) {
            append(text[i])
            i++
            continue
        }
        val inner = text.substring(i + mark.length, end)
        if (bold) {
            withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { append(legalAnnotated(inner)) }
        } else {
            withStyle(SpanStyle(fontFamily = FontFamily.Monospace)) { append(inner) }
        }
        i = end + mark.length
    }
}

/** A legal text: version line, summary and the numbered sections. */
@Composable
fun LegalDocumentView(doc: LegalDocument, withSummary: Boolean = true) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(LegalStrings.versionLine(doc.version, doc.effectiveDate), style = MaterialTheme.typography.bodySmall)
        if (withSummary) SummaryCard(doc.summary)
        doc.sections.forEachIndexed { i, s ->
            Text("${i + 1}. ${s.heading}", style = MaterialTheme.typography.titleSmall)
            s.blocks.forEach { b ->
                when (b) {
                    is LegalBlock.Paragraph -> Text(legalAnnotated(b.text), style = MaterialTheme.typography.bodyMedium)
                    is LegalBlock.Bullets -> Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        b.items.forEach { Text(legalAnnotated("・$it"), style = MaterialTheme.typography.bodyMedium) }
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryCard(points: List<String>) {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(LegalStrings.SUMMARY, style = MaterialTheme.typography.titleSmall)
            points.forEach { Text(legalAnnotated("・$it"), style = MaterialTheme.typography.bodyMedium) }
        }
    }
}

@Composable
private fun PageColumn(content: @Composable () -> Unit) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            Modifier.widthIn(max = 720.dp).fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) { content() }
    }
}

@Composable
private fun CheckRow(text: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().clickable { onChange(!checked) }, verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

private enum class OnboardingStep { WELCOME, BASICS, STATEMENTS, DONE }

/**
 * The first-start pages: welcome, the terms and the privacy policy (required), each integration statement (agree to
 * enable or decline to switch it off), and a summary. After an update only the texts with a new version are asked.
 */
@Composable
fun OnboardingScreen(model: WalletModel, onDone: () -> Unit) {
    val consent by model.legal.consent.collectAsState()
    val firstStart = remember { consent.terms == null && consent.privacy == null }
    val total = remember { consent.undecided.size }
    var welcomed by rememberSaveable { mutableStateOf(!firstStart) }
    val step = when {
        !welcomed -> OnboardingStep.WELCOME
        !consent.basicsAccepted -> OnboardingStep.BASICS
        consent.undecided.isNotEmpty() -> OnboardingStep.STATEMENTS
        else -> OnboardingStep.DONE
    }
    PageColumn {
        when (step) {
            OnboardingStep.WELCOME -> WelcomePage { welcomed = true }
            OnboardingStep.BASICS -> BasicsPage(updated = !firstStart) { model.legal.acceptBasics() }
            OnboardingStep.STATEMENTS -> {
                val i = consent.undecided.first()
                val index = (total - consent.undecided.size + 1).coerceAtLeast(1)
                StatementPage(
                    model, i, LegalStrings.statementProgress(index, maxOf(total, index)),
                    updated = consent.record(i) != null,
                )
            }
            OnboardingStep.DONE -> DonePage(consent, onDone)
        }
    }
}

@Composable
private fun WelcomePage(onStart: () -> Unit) {
    Icon(WalletIcons.Wallet, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(48.dp))
    Text(LegalStrings.WELCOME_TITLE, style = MaterialTheme.typography.headlineSmall)
    Text(LegalStrings.WELCOME_TEXT, style = MaterialTheme.typography.bodyMedium)
    LegalStrings.WELCOME_POINTS.forEach { (title, text) ->
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(text, style = MaterialTheme.typography.bodyMedium)
        }
    }
    Button(onClick = onStart, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.WELCOME_START) }
}

@Composable
private fun BasicsPage(updated: Boolean, onAccept: () -> Unit) {
    var terms by rememberSaveable { mutableStateOf(false) }
    var privacy by rememberSaveable { mutableStateOf(false) }
    var refused by remember { mutableStateOf(false) }
    Text(LegalStrings.BASICS_TITLE, style = MaterialTheme.typography.headlineSmall)
    Text(if (updated) LegalStrings.BASICS_UPDATED else LegalStrings.BASICS_TEXT, style = MaterialTheme.typography.bodyMedium)
    listOf(LegalTexts.terms, LegalTexts.privacy).forEach { doc ->
        HorizontalDivider()
        Text(doc.title, style = MaterialTheme.typography.titleMedium)
        Text(LegalStrings.versionLine(doc.version, doc.effectiveDate), style = MaterialTheme.typography.bodySmall)
        SummaryCard(doc.summary)
        CollapsibleSection(doc.title + LegalStrings.FULL_TEXT, key = "onboarding-" + doc.id) {
            LegalDocumentView(doc, withSummary = false)
        }
    }
    HorizontalDivider()
    CheckRow(LegalStrings.AGREE_TERMS, terms) { terms = it }
    CheckRow(LegalStrings.AGREE_PRIVACY, privacy) { privacy = it }
    Button(onClick = onAccept, enabled = terms && privacy, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.AGREE_CONTINUE) }
    OutlinedButton(onClick = { refused = true }, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.DISAGREE) }
    if (refused) {
        AlertDialog(
            onDismissRequest = { refused = false },
            title = { Text(LegalStrings.DISAGREE_TITLE) },
            text = { Text(LegalStrings.DISAGREE_TEXT) },
            confirmButton = { TextButton(onClick = { refused = false }) { Text(LegalStrings.BACK_TO_READING) } },
        )
    }
}

/** One statement with its two choices; used on the first-start pages. */
@Composable
private fun StatementPage(model: WalletModel, i: Integration, progress: String, updated: Boolean) {
    val st = LegalTexts.statement(i)
    Text(progress, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
    Text(LegalStrings.STATEMENTS_INTRO, style = MaterialTheme.typography.bodySmall)
    if (updated) Text(LegalStrings.STATEMENTS_UPDATED, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    StatementHeader(i)
    LegalDocumentView(st.document)
    Button(onClick = { model.legal.decide(i, true) }, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.ACCEPT_ENABLE) }
    OutlinedButton(onClick = { model.legal.decide(i, false) }, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.DECLINE_DISABLE) }
}

@Composable
private fun StatementHeader(i: Integration) {
    val st = LegalTexts.statement(i)
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Icon(i.icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(36.dp))
        Column {
            Text(st.document.title, style = MaterialTheme.typography.titleLarge)
            Text(LegalStrings.operatorLine(st.operator), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun DonePage(consent: LegalConsent, onDone: () -> Unit) {
    Text(LegalStrings.DONE_TITLE, style = MaterialTheme.typography.headlineSmall)
    Integration.entries.filter { it.available }.forEach { i ->
        LabelValue(LegalTexts.statement(i).name, statusLine(consent, i))
    }
    Text(LegalStrings.DONE_TEXT, style = MaterialTheme.typography.bodySmall)
    Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.DONE_START) }
}

/** The legal settings page: the accepted texts and every statement with its state. */
@Composable
fun LegalSettingsPage(model: WalletModel) {
    val consent by model.legal.consent.collectAsState()
    SectionTitle(LegalStrings.SETTINGS_BASICS)
    listOf(LegalTexts.terms to consent.terms, LegalTexts.privacy to consent.privacy).forEach { (doc, r) ->
        ActionRow(WalletIcons.Document, doc.title, r?.let { LegalStrings.acceptedLine(it.version, it.date) } ?: LegalStrings.PENDING_LINE) {
            model.screen.value = Screen.LegalText(doc.id)
        }
    }
    HorizontalDivider()
    SectionTitle(LegalStrings.STATEMENTS_TITLE)
    Text(LegalStrings.SETTINGS_STATEMENTS_TEXT, style = MaterialTheme.typography.bodySmall)
    Integration.entries.filter { it.available }.forEach { i ->
        ActionRow(i.icon, LegalTexts.statement(i).name, statusLine(consent, i)) { model.screen.value = Screen.IntegrationStatement(i) }
    }
    // Reserved statements are only previewed: nothing can be agreed to until the feature ships.
    Integration.entries.filterNot { it.available }.forEach { i ->
        val st = LegalTexts.statement(i)
        ActionRow(i.icon, st.name, LegalStrings.notAvailableLine(st.name)) { model.screen.value = Screen.LegalText(st.document.id) }
    }
    HorizontalDivider()
    SectionTitle(LegalStrings.SETTINGS_ONLINE)
    LabelValue("GitHub", LegalTexts.PUBLISHED_URL, small = true) { model.platform.openBrowser(LegalTexts.PUBLISHED_URL) }
}

/** The settings summary line of the legal page. */
fun legalSummary(model: WalletModel): String {
    val c = model.legal.consent.value
    val shipped = Integration.entries.filter { it.available }
    return LegalStrings.settingsSummary(shipped.count { c.enabled(it) }, shipped.size)
}

/** The terms, the privacy policy or a statement, read from the settings. */
@Composable
fun LegalTextScreen(model: WalletModel, screen: Screen.LegalText) {
    val doc = LegalTexts.byId(screen.documentId) ?: return
    PageColumn {
        Text(doc.title, style = MaterialTheme.typography.headlineSmall)
        LegalDocumentView(doc)
        OutlinedButton(onClick = { model.platform.openBrowser(LegalTexts.PUBLISHED_URL + "/" + doc.id + ".md") }) { Text(LegalStrings.OPEN_ONLINE) }
    }
}

/**
 * A statement with the holder's decision, opened from the settings or by a link that needs it ([Screen.IntegrationStatement.pendingUri],
 * opened once the holder agrees).
 */
@Composable
fun IntegrationStatementScreen(model: WalletModel, screen: Screen.IntegrationStatement) {
    val consent by model.legal.consent.collectAsState()
    val i = screen.integration
    val st = LegalTexts.statement(i)
    var confirmWithdraw by remember { mutableStateOf(false) }
    PageColumn {
        screen.pendingUri?.let {
            Text(LegalStrings.pendingLink(st.name), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
        }
        StatementHeader(i)
        Text(statusLine(consent, i), style = MaterialTheme.typography.titleSmall)
        LegalDocumentView(st.document)
        if (consent.enabled(i)) {
            OutlinedButton(onClick = { confirmWithdraw = true }, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.WITHDRAW) }
        } else {
            Button(onClick = {
                model.legal.decide(i, true)
                val pending = screen.pendingUri
                if (pending != null) {
                    model.screen.value = Screen.Home
                    model.scope.launch {
                        model.legal.consent.first { it.enabled(i) }
                        model.handleUri(pending)
                    }
                }
            }, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.ACCEPT_ENABLE) }
            if (consent.record(i)?.version != st.document.version) {
                OutlinedButton(onClick = { model.legal.decide(i, false); model.back() }, modifier = Modifier.fillMaxWidth()) {
                    Text(LegalStrings.DECLINE_DISABLE)
                }
            }
        }
        OutlinedButton(onClick = { model.platform.openBrowser(LegalTexts.PUBLISHED_URL + "/" + st.document.id + ".md") }) { Text(LegalStrings.OPEN_ONLINE) }
    }
    if (confirmWithdraw) {
        AlertDialog(
            onDismissRequest = { confirmWithdraw = false },
            title = { Text(LegalStrings.WITHDRAW_TITLE) },
            text = { Text(LegalStrings.withdrawText(st.name)) },
            confirmButton = { TextButton(onClick = { confirmWithdraw = false; model.legal.decide(i, false) }) { Text(LegalStrings.WITHDRAW) } },
            dismissButton = { TextButton(onClick = { confirmWithdraw = false }) { Text(LegalStrings.CANCEL) } },
        )
    }
}

/** Where a feature of a switched-off integration would be: says why and opens its statement. */
@Composable
fun IntegrationOffRow(model: WalletModel, i: Integration, title: String = LegalTexts.statement(i).name) {
    ActionRow(i.icon, title, LegalStrings.disabledRow(LegalTexts.statement(i).name)) { model.screen.value = Screen.IntegrationStatement(i) }
}
