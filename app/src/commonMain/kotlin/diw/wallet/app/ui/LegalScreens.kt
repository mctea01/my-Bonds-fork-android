package diw.wallet.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
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
import androidx.compose.material3.Surface
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
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
@Composable
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
        TranslationNote()
        if (withSummary) SummaryCard(doc.summary)
        doc.sections.forEachIndexed { i, s ->
            Text("${i + 1}. ${s.heading}", style = MaterialTheme.typography.titleSmall)
            s.blocks.forEach { b ->
                when (b) {
                    is LegalBlock.Paragraph -> Text(legalAnnotated(b.text), style = MaterialTheme.typography.bodyMedium)
                    is LegalBlock.Bullets -> Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        b.items.forEach { Text(legalAnnotated((if (doc.language == "zh") "・" else "• ") + it), style = MaterialTheme.typography.bodyMedium) }
                    }
                }
            }
        }
    }
}

/** The legal texts are Chinese only; outside Chinese the reader is told which text they accept. */
@Composable
private fun TranslationNote() {
    LegalStrings.TRANSLATION_NOTE.takeIf { it.isNotBlank() }?.let {
        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
    }
}

@Composable
private fun SummaryCard(points: List<String>, title: String? = null) {
    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title?.let { "$it・" + LegalStrings.SUMMARY } ?: LegalStrings.SUMMARY, style = MaterialTheme.typography.titleSmall)
            points.forEach { Text(legalAnnotated("・$it"), style = MaterialTheme.typography.bodyMedium) }
        }
    }
}

/** A scrolling page; a new [page] (the next step or statement) starts at the top. */
@Composable
private fun PageColumn(page: Any? = null, content: @Composable () -> Unit) {
    val scroll = rememberScrollState()
    androidx.compose.runtime.LaunchedEffect(page) { scroll.scrollTo(0) }
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            Modifier.widthIn(max = 720.dp).fillMaxSize().verticalScroll(scroll).padding(horizontal = 20.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) { content() }
        VerticalScrollIndicator(scroll, Modifier.align(Alignment.CenterEnd).fillMaxHeight())
    }
}

internal enum class OnboardingStep { WELCOME, CONSENT, DONE }

/** The first-start page to show: welcome, then one page with every text still to decide, then the summary. */
internal fun onboardingStep(consent: LegalConsent, welcomed: Boolean): OnboardingStep = when {
    !welcomed -> OnboardingStep.WELCOME
    !consent.complete -> OnboardingStep.CONSENT
    else -> OnboardingStep.DONE
}

/**
 * The first-start pages: welcome with what will be asked, one page of check boxes (the terms and the privacy policy,
 * required; each integration statement, optional) whose document names open the full texts, and a summary. After an
 * update only the texts with a new version are asked.
 */
@Composable
fun OnboardingScreen(model: WalletModel, onDone: () -> Unit) {
    val consent by model.legal.consent.collectAsState()
    val firstStart = remember { consent.terms == null && consent.privacy == null }
    var welcomed by rememberSaveable { mutableStateOf(!firstStart) }
    var reading by rememberSaveable { mutableStateOf<String?>(null) }
    val step = onboardingStep(consent, welcomed)
    val doc = reading?.let { LegalTexts.byId(it) }
    // A document opened from the consent page covers it, so the page keeps its check boxes and scroll position.
    Box(Modifier.fillMaxSize()) {
        PageColumn(page = step) {
            when (step) {
                OnboardingStep.WELCOME -> WelcomePage(model, consent.undecided.size) { welcomed = true }
                OnboardingStep.CONSENT -> ConsentPage(model, consent, updated = !firstStart) { reading = it.id }
                OnboardingStep.DONE -> DonePage(consent, onDone) { model.platform.openBrowser(USER_GUIDE_URL) }
            }
        }
        if (doc != null) {
            Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                PageColumn(page = doc.id) { DocumentReader(doc) { reading = null } }
            }
        }
    }
}

/** Tells whether a text must be accepted (the terms and the privacy policy) or is optional (a service statement). */
@Composable
private fun KindPill(required: Boolean) {
    val c = MaterialTheme.colorScheme
    Text(
        if (required) LegalStrings.REQUIRED else LegalStrings.OPTIONAL,
        Modifier.background(if (required) c.primaryContainer else c.secondaryContainer, RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        style = MaterialTheme.typography.labelMedium,
        color = if (required) c.onPrimaryContainer else c.onSecondaryContainer,
    )
}

@Composable
private fun KindLine(required: Boolean, text: String) {
    Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        KindPill(required)
        Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 2.dp))
    }
}

/**
 * [template] with its %1$s, %2$s ... placeholders replaced by [links], each shown as an underlined link that calls its
 * action; the rest is plain text.
 */
internal fun linkedText(template: String, links: List<Pair<String, () -> Unit>>, color: Color): AnnotatedString = buildAnnotatedString {
    var at = 0
    for (m in Regex("%(\\d+)\\\$s").findAll(template)) {
        append(template.substring(at, m.range.first))
        val link = links.getOrNull(m.groupValues[1].toInt() - 1)
        if (link == null) {
            append(m.value)
        } else {
            val style = TextLinkStyles(SpanStyle(color = color, fontWeight = FontWeight.Medium, textDecoration = TextDecoration.Underline))
            withLink(LinkAnnotation.Clickable(link.first, style) { link.second() }) { append(link.first) }
        }
        at = m.range.last + 1
    }
    append(template.substring(at))
}

/** A check box whose label holds links; tapping the label outside a link toggles the box. */
@Composable
private fun LinkedCheckRow(text: AnnotatedString, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().clickable { onChange(!checked) }, verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(vertical = 8.dp))
    }
}

@Composable
private fun WelcomePage(model: WalletModel, optionalCount: Int, onStart: () -> Unit) {
    Icon(WalletIcons.Wallet, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(48.dp))
    LanguageChooser(model)
    Text(LegalStrings.WELCOME_TITLE, style = MaterialTheme.typography.headlineSmall)
    Text(LegalStrings.WELCOME_TEXT, style = MaterialTheme.typography.bodyMedium)
    LegalStrings.WELCOME_POINTS.forEach { (title, text) ->
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(text, style = MaterialTheme.typography.bodyMedium)
        }
    }
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(LegalStrings.STEPS_TITLE, style = MaterialTheme.typography.titleSmall)
            KindLine(true, LegalStrings.STEPS_REQUIRED)
            if (optionalCount > 0) KindLine(false, LegalStrings.stepsOptional(optionalCount))
        }
    }
    Button(onClick = onStart, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.WELCOME_START) }
}

/**
 * Every text still to decide on one page. The terms and the privacy policy share one required check box; each
 * integration has its own optional one, unticked by default, and its key points open when it is ticked. A name in a
 * label opens the full text ([onRead]). Continuing records all choices at once; an unticked integration is declined.
 */
@Composable
private fun ConsentPage(model: WalletModel, consent: LegalConsent, updated: Boolean, onRead: (LegalDocument) -> Unit) {
    val link = MaterialTheme.colorScheme.primary
    val basicsNeeded = !consent.basicsAccepted
    val services = remember(consent.undecided) { consent.undecided }
    var basics by rememberSaveable { mutableStateOf(false) }
    var chosen by rememberSaveable { mutableStateOf(emptyList<String>()) }
    var refused by remember { mutableStateOf(false) }
    Text(LegalStrings.CONSENT_TITLE, style = MaterialTheme.typography.headlineSmall)
    if (basicsNeeded) Text(LegalStrings.CONSENT_TEXT, style = MaterialTheme.typography.bodyMedium)
    TranslationNote()
    if (basicsNeeded) {
        HorizontalDivider()
        KindTitle(LegalStrings.BASICS_TITLE, required = true)
        if (updated) Text(LegalStrings.BASICS_UPDATED, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        listOf(LegalTexts.terms, LegalTexts.privacy).forEach { doc -> SummaryCard(doc.summary, doc.title) }
        LinkedCheckRow(
            linkedText(
                LegalStrings.AGREE_BASICS,
                listOf(LegalStrings.LINK_TERMS to { onRead(LegalTexts.terms) }, LegalStrings.LINK_PRIVACY to { onRead(LegalTexts.privacy) }),
                link,
            ),
            basics,
        ) { basics = it }
    }
    if (services.isNotEmpty()) {
        HorizontalDivider()
        KindTitle(LegalStrings.OPTIONAL_TITLE, required = false)
        Text(LegalStrings.OPTIONAL_HINT, style = MaterialTheme.typography.bodySmall)
        services.forEach { i ->
            val st = LegalTexts.statement(i)
            val on = i.id in chosen
            var points by rememberSaveable(i.id) { mutableStateOf(false) }
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(Tokens.CardRadius)) {
                Column(Modifier.padding(start = 4.dp, end = 14.dp, top = 4.dp, bottom = 4.dp)) {
                    LinkedCheckRow(
                        linkedText(LegalStrings.AGREE_STATEMENT, listOf(st.document.title to { onRead(st.document) }), link),
                        on,
                    ) { chosen = if (it) chosen + i.id else chosen - i.id }
                    Column(Modifier.padding(start = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Icon(i.icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                            Text(LegalStrings.purpose(i), style = MaterialTheme.typography.bodyMedium)
                        }
                        Text(LegalStrings.operatorLine(st.operator), style = MaterialTheme.typography.bodySmall)
                        if (consent.record(i) != null) {
                            Text(LegalStrings.STATEMENTS_UPDATED, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                        }
                        if (on || points) SummaryCard(st.document.summary)
                        if (!on) {
                            TextButton(onClick = { points = !points }) { Text(if (points) LegalStrings.HIDE_POINTS else LegalStrings.SHOW_POINTS) }
                        }
                    }
                }
            }
        }
    }
    HorizontalDivider()
    Button(
        onClick = { model.legal.decideAll(basicsNeeded, services.associateWith { it.id in chosen }) },
        enabled = basics || !basicsNeeded,
        modifier = Modifier.fillMaxWidth(),
    ) { Text(LegalStrings.AGREE_CONTINUE) }
    if (basicsNeeded) {
        OutlinedButton(onClick = { refused = true }, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.DISAGREE) }
    }
    if (refused) {
        AlertDialog(
            onDismissRequest = { refused = false },
            title = { Text(LegalStrings.DISAGREE_TITLE) },
            text = { Text(LegalStrings.DISAGREE_TEXT) },
            confirmButton = { TextButton(onClick = { refused = false }) { Text(LegalStrings.BACK_TO_READING) } },
        )
    }
}

/** The full text of a document opened from a link on the consent page. */
@Composable
private fun DocumentReader(doc: LegalDocument, onBack: () -> Unit) {
    TextButton(onClick = onBack) { Text(LegalStrings.BACK) }
    Text(doc.title, style = MaterialTheme.typography.headlineSmall)
    LegalDocumentView(doc)
    Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.BACK) }
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
private fun DonePage(consent: LegalConsent, onDone: () -> Unit, onGuide: () -> Unit) {
    Text(LegalStrings.DONE_TITLE, style = MaterialTheme.typography.headlineSmall)
    SectionTitle(LegalStrings.DONE_REQUIRED)
    LabelValue(LegalStrings.BASICS_TITLE, LegalStrings.DONE_ACCEPTED)
    SectionTitle(LegalStrings.DONE_OPTIONAL)
    Integration.entries.filter { it.available }.forEach { i ->
        LabelValue(LegalTexts.statement(i).name, statusLine(consent, i))
    }
    Text(LegalStrings.DONE_TEXT, style = MaterialTheme.typography.bodySmall)
    Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.DONE_START) }
    TextButton(onClick = onGuide, modifier = Modifier.fillMaxWidth()) { Text(LegalStrings.DONE_GUIDE) }
}

/** The legal settings page: the accepted texts and every statement with its state. */
@Composable
fun LegalSettingsPage(model: WalletModel) {
    val consent by model.legal.consent.collectAsState()
    KindTitle(LegalStrings.SETTINGS_BASICS, required = true)
    listOf(LegalTexts.terms to consent.terms, LegalTexts.privacy to consent.privacy).forEach { (doc, r) ->
        ActionRow(WalletIcons.Document, doc.title, r?.let { LegalStrings.acceptedLine(it.version, it.date) } ?: LegalStrings.PENDING_LINE) {
            model.screen.value = Screen.LegalText(doc.id)
        }
    }
    HorizontalDivider()
    KindTitle(LegalStrings.STATEMENTS_TITLE, required = false)
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
    LabelValue("GitHub", LegalTexts.onlineFolder, small = true) { model.platform.openBrowser(LegalTexts.onlineFolder) }
}

@Composable
private fun KindTitle(text: String, required: Boolean) {
    Row(verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        SectionTitle(text)
        KindPill(required)
    }
}

/** The settings summary line of the legal page. */
@Composable
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
        OutlinedButton(onClick = { model.platform.openBrowser(LegalTexts.onlineUrl(doc)) }) { Text(LegalStrings.OPEN_ONLINE) }
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
        OutlinedButton(onClick = { model.platform.openBrowser(LegalTexts.onlineUrl(st.document)) }) { Text(LegalStrings.OPEN_ONLINE) }
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
