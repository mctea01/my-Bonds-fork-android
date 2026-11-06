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

/**
 * Shows [content] in the language chosen in [store], redrawing it when the choice changes. Where the platform applies
 * the choice itself ([AppLanguageStore.systemManaged], the per-app language of Android 13 and later), the configuration
 * it gave the activity already holds the language and is left as it is: overriding it would fall back to the system
 * language of the phone.
 */
@Composable
fun AppLocaleScope(store: AppLanguageStore, content: @Composable () -> Unit) {
    val tag by store.tag.collectAsState()
    if (store.systemManaged) {
        key(tag) { content() }
        return
    }
    CompositionLocalProvider(LocalAppLocale provides tag) {
        key(tag) { content() }
    }
}
