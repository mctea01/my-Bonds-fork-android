package diw.wallet.app.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ProvidedValue
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import diw.wallet.app.AppLanguageStore

/** The locale the interface strings are read in; providing a tag overrides the system locale, null restores it. */
expect object LocalAppLocale {
    val current: String @Composable get

    @Composable
    infix fun provides(value: String?): ProvidedValue<*>
}

/** Shows [content] in the language chosen in [store], redrawing it when the choice changes. */
@Composable
fun AppLocaleScope(store: AppLanguageStore, content: @Composable () -> Unit) {
    val tag by store.tag.collectAsState()
    val override = if (store.systemManaged) null else tag
    CompositionLocalProvider(LocalAppLocale provides override) {
        key(override) { content() }
    }
}
