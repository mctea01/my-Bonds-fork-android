package diw.wallet.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import diw.wallet.app.Screen
import diw.wallet.app.SettingsSection
import diw.wallet.app.ThirdParty
import diw.wallet.app.ThirdPartyCatalog
import diw.wallet.app.ThirdPartyComponent
import diw.wallet.app.ThirdPartyKind
import diw.wallet.app.WalletModel
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource

/** The list's search, group and scroll position, kept while the holder looks at an entry and comes back. */
private object ThirdPartyListState {
    var query by mutableStateOf("")
    var kind by mutableStateOf<ThirdPartyKind?>(null)
    var licenses by mutableStateOf(false)
    val scroll = LazyListState()
}

/** The catalog once read; [loaded] stays false while it is being read. */
private class Loaded(val loaded: Boolean, val catalog: ThirdPartyCatalog?)

@Composable
private fun rememberCatalog(): Loaded =
    produceState(Loaded(false, null)) { value = Loaded(true, ThirdParty.catalog()) }.value

@Composable
private fun language() = stringResource(Res.string.third_party_language)

private val ThirdPartyKind.title: StringResource
    get() = when (this) {
        ThirdPartyKind.LIBRARY -> Res.string.third_party_kind_library
        ThirdPartyKind.CRATE -> Res.string.third_party_kind_crate
        ThirdPartyKind.NATIVE -> Res.string.third_party_kind_native
        ThirdPartyKind.MODEL -> Res.string.third_party_kind_model
        ThirdPartyKind.CIRCUIT -> Res.string.third_party_kind_circuit
        ThirdPartyKind.DATA -> Res.string.third_party_kind_data
        ThirdPartyKind.DOWNLOADED -> Res.string.third_party_kind_downloaded
        ThirdPartyKind.RUNTIME -> Res.string.third_party_kind_runtime
    }

/** The license names of [c], as the list shows them. */
private fun licenseLine(catalog: ThirdPartyCatalog, c: ThirdPartyComponent): String =
    c.licenses.joinToString(", ") { catalog.license(it)?.name ?: it }

/** On the About page: how many components and licenses this build lists, and the way to the list and the texts. */
@Composable
fun ThirdPartySummary(model: WalletModel) {
    val state = rememberCatalog()
    val catalog = state.catalog
    when {
        !state.loaded -> Unit
        catalog == null -> Text(stringResource(Res.string.third_party_none), style = MaterialTheme.typography.bodySmall)
        else -> Text(stringResource(Res.string.third_party_summary, catalog.components.size, catalog.licenses.size), style = MaterialTheme.typography.bodySmall)
    }
    ActionRow(WalletIcons.Document, stringResource(Res.string.third_party_open), stringResource(Res.string.third_party_open_text), enabled = catalog != null || !state.loaded) {
        model.screen.value = Screen.ThirdPartyList
    }
    WrapRow {
        OutlinedButton(onClick = { model.screen.value = Screen.ThirdPartyDocument("LICENSE") }) { Text(stringResource(Res.string.settings_license_full)) }
        OutlinedButton(onClick = { model.screen.value = Screen.ThirdPartyDocument("NOTICE") }) { Text(stringResource(Res.string.settings_notice)) }
    }
}

/** Every third-party component of this build, by group, with a search; or the licenses with how many use each. */
@Composable
fun ThirdPartyListScreen(model: WalletModel) {
    val state = rememberCatalog()
    val catalog = state.catalog
    val lang = language()
    val s = ThirdPartyListState
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            Modifier.widthIn(max = ContentMaxWidth).fillMaxSize(),
            state = s.scroll,
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (!state.loaded) return@LazyColumn
            if (catalog == null) {
                item(key = "none") { Text(stringResource(Res.string.third_party_none), style = MaterialTheme.typography.bodyMedium) }
                return@LazyColumn
            }
            item(key = "intro") {
                Text(stringResource(Res.string.third_party_intro, catalog.components.size, catalog.licenses.size), style = MaterialTheme.typography.bodySmall)
            }
            item(key = "search") {
                OutlinedTextField(
                    value = s.query,
                    onValueChange = { s.query = it },
                    leadingIcon = { Icon(WalletIcons.Search, contentDescription = null) },
                    placeholder = { Text(stringResource(Res.string.third_party_search)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            val present = ThirdPartyKind.entries.filter { k -> catalog.components.any { it.kind == k.id } }
            item(key = "filters") {
                WrapRow {
                    FilterChip(selected = !s.licenses && s.kind == null, onClick = { s.licenses = false; s.kind = null }, label = { Text(stringResource(Res.string.filter_all)) })
                    present.forEach { k ->
                        FilterChip(selected = !s.licenses && s.kind == k, onClick = { s.licenses = false; s.kind = if (s.kind == k) null else k }, label = { Text(stringResource(k.title)) })
                    }
                    FilterChip(selected = s.licenses, onClick = { s.licenses = !s.licenses }, label = { Text(stringResource(Res.string.third_party_licenses)) })
                }
            }
            if (s.licenses) {
                val q = s.query.trim()
                val shown = catalog.licenses.filter { l -> q.isEmpty() || l.id.contains(q, ignoreCase = true) || l.name?.contains(q, ignoreCase = true) == true }
                items(shown, key = { "l-" + it.id }) { l ->
                    ListRow(l.name ?: l.id, l.id + " · " + stringResource(Res.string.third_party_license_count, catalog.usersOf(l.id).size)) {
                        model.screen.value = Screen.ThirdPartyLicenseText(l.id, Screen.ThirdPartyList)
                    }
                }
                if (shown.isEmpty()) item(key = "no-match") { NoMatch() }
                return@LazyColumn
            }
            val shown = catalog.search(s.query, s.kind, lang)
            val groups = shown.groupBy { it.kind }
            for (k in present) {
                val list = groups[k.id] ?: continue
                item(key = "h-" + k.id) { SectionTitle(stringResource(k.title) + stringResource(Res.string.parenthesized, list.size)) }
                items(list, key = { it.id }) { c ->
                    val detail = listOfNotNull(c.version, licenseLine(catalog, c)).joinToString(" · ")
                    ListRow(c.name, detail) { model.screen.value = Screen.ThirdPartyEntry(c.id) }
                }
            }
            if (shown.isEmpty()) item(key = "no-match") { NoMatch() }
        }
    }
}

@Composable
private fun NoMatch() {
    Text(stringResource(Res.string.third_party_no_match), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 16.dp))
}

@Composable
private fun ListRow(title: String, detail: String, onClick: () -> Unit) {
    Column(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 6.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall)
        Text(detail, style = MaterialTheme.typography.bodySmall)
    }
    HorizontalDivider()
}

/** A license or notice text, selectable, in a fixed-width font so ASCII layouts in notices stay aligned. */
@Composable
private fun LicenseText(text: String) {
    SelectionContainer {
        Text(text.trimEnd(), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
    }
}

/** One component: what it is, where it is, its license and the texts that come with it. */
@Composable
fun ThirdPartyEntryScreen(model: WalletModel, screen: Screen.ThirdPartyEntry) {
    val catalog = rememberCatalog().catalog ?: return
    val c = catalog.component(screen.id) ?: return
    val lang = language()
    ScreenColumn(spacing = 12.dp) {
        Text(c.name, style = MaterialTheme.typography.headlineSmall)
        ThirdPartyKind.of(c.kind)?.let { Text(stringResource(it.title), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary) }
        c.description(lang)?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        c.version?.let { LabelValue(stringResource(Res.string.settings_version), it, small = true) }
        c.coordinates?.let { LabelValue(stringResource(Res.string.third_party_coordinates), it, small = true) }
        // License names, with the published expression where it says how they combine (OR, AND, WITH).
        val expression = c.license.takeIf { Regex("\\b(OR|AND|WITH)\\b").containsMatchIn(it) }
        LabelValue(stringResource(Res.string.third_party_license), licenseLine(catalog, c) + (expression?.let { "\n$it" } ?: ""), small = true)
        c.copyright?.let { LabelValue(stringResource(Res.string.third_party_copyright), it, small = true) }
        c.scope(lang)?.let { LabelValue(stringResource(Res.string.third_party_scope), it, small = true) }
        c.url?.let { url -> LabelValue(stringResource(Res.string.third_party_website), url, small = true) { model.platform.openBrowser(url) } }
        val own = c.texts.mapNotNull { catalog.texts[it] }
        if (own.isNotEmpty()) {
            HorizontalDivider()
            SectionTitle(stringResource(Res.string.third_party_files))
            own.forEachIndexed { i, text ->
                if (i > 0) HorizontalDivider()
                LicenseText(text)
            }
        }
        HorizontalDivider()
        SectionTitle(stringResource(Res.string.third_party_license_texts))
        if (own.isEmpty()) Text(stringResource(Res.string.third_party_standard_text), style = MaterialTheme.typography.bodySmall)
        c.licenses.mapNotNull { catalog.license(it) }.forEach { l ->
            CollapsibleSection(l.name ?: l.id, initiallyExpanded = own.isEmpty() && c.licenses.size == 1, key = "tp-" + c.id + "-" + l.id) {
                l.url?.let { url -> LabelValue(stringResource(Res.string.third_party_website), url, small = true) { model.platform.openBrowser(url) } }
                catalog.texts[l.text]?.let { LicenseText(it) }
            }
        }
    }
}

/** One license: its full text and the components under it. */
@Composable
fun ThirdPartyLicenseScreen(model: WalletModel, screen: Screen.ThirdPartyLicenseText) {
    val catalog = rememberCatalog().catalog ?: return
    val l = catalog.license(screen.id) ?: return
    val users = catalog.usersOf(l.id)
    ScreenColumn(spacing = 12.dp) {
        Text(l.name ?: l.id, style = MaterialTheme.typography.headlineSmall)
        LabelValue("SPDX", l.id, small = true)
        l.url?.let { url -> LabelValue(stringResource(Res.string.third_party_website), url, small = true) { model.platform.openBrowser(url) } }
        CollapsibleSection(stringResource(Res.string.third_party_used_by), count = users.size, key = "tp-users-" + l.id) {
            users.forEach { c -> ListRow(c.name, c.version ?: "") { model.screen.value = Screen.ThirdPartyEntry(c.id, screen) } }
        }
        HorizontalDivider()
        catalog.texts[l.text]?.let { LicenseText(it) }
    }
}

/** NOTICE or LICENSE of this repository, as the build packaged it. */
@Composable
fun ThirdPartyDocumentScreen(model: WalletModel, screen: Screen.ThirdPartyDocument) {
    val text = produceState<String?>(null, screen.name) { value = ThirdParty.document(screen.name) }.value
    ScreenColumn(spacing = 12.dp) {
        if (text == null) {
            Text(stringResource(Res.string.third_party_none), style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = { model.platform.openBrowser("${diw.wallet.app.legal.LegalTexts.SOURCE_URL}/blob/main/${screen.name}") }) {
                Text(stringResource(Res.string.third_party_online))
            }
        } else {
            LicenseText(text)
        }
    }
}

/** The title bar text of the third-party screens. */
@Composable
fun thirdPartyTitle(s: Screen): String = when (s) {
    is Screen.ThirdPartyDocument -> if (s.name == "LICENSE") stringResource(Res.string.settings_license_full) else stringResource(Res.string.settings_notice)
    is Screen.ThirdPartyLicenseText -> stringResource(Res.string.third_party_license)
    else -> stringResource(Res.string.settings_third_party)
}

internal fun thirdPartyBack(s: Screen): Screen = when (s) {
    is Screen.ThirdPartyEntry -> s.from
    is Screen.ThirdPartyLicenseText -> s.from
    else -> Screen.SettingsPage(SettingsSection.ABOUT)
}
