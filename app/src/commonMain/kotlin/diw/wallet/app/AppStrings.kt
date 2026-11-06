package diw.wallet.app

import androidx.compose.ui.text.intl.Locale
import org.jetbrains.compose.resources.ResourceEnvironment
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.getString
import org.jetbrains.compose.resources.getSystemResourceEnvironment

/**
 * A resource environment for [language] and [region] built without the system environment, which follows only the
 * system language (Android ignores the per-app language there) and needs a display on desktop. Null when the
 * resources library no longer allows it.
 */
internal expect fun languageEnvironment(language: String, region: String): ResourceEnvironment?

/** The environment strings outside composition are read in: the language chosen in the app, otherwise the current locale. */
fun resourceEnvironment(tag: String?): ResourceEnvironment {
    val locale = tag?.let { Locale(it) } ?: Locale.current
    return languageEnvironment(locale.language, locale.region) ?: getSystemResourceEnvironment()
}

/** [resource] in the language chosen in this store, with [args] in its %n$s placeholders. */
suspend fun AppLanguageStore.text(resource: StringResource, vararg args: Any): String =
    getString(resourceEnvironment(tag.value), resource, *args)
