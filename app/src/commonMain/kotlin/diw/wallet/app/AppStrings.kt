package diw.wallet.app

import androidx.compose.ui.text.intl.Locale
import diw.wallet.app.res.Res
import diw.wallet.app.res.allStringResources
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

/**
 * Strings for code outside composition that cannot suspend, such as model messages and detail rows: every string
 * resource of the app language is read once into memory and read again when the language changes.
 */
object AppText {
    private var loaded: Pair<String?, Map<String, String>>? = null

    /** Reads every string of [tag] (null: the current locale) unless it is the language already loaded. */
    suspend fun load(tag: String?) {
        if (loaded?.first == tag && loaded != null) return
        val env = resourceEnvironment(tag)
        val all = Res.allStringResources
        loaded = tag to all.mapValues { (_, r) -> getString(env, r) }
    }

    /** [resource] in the loaded language with [args] in its %n$s placeholders; the key when nothing is loaded yet. */
    fun get(resource: StringResource, vararg args: Any?): String {
        var text = loaded?.second?.get(resource.key) ?: resource.key
        args.forEachIndexed { i, a -> text = text.replace("%${i + 1}\$s", a.toString()).replace("%${i + 1}\$d", a.toString()) }
        return text
    }
}

/** Short form of [AppText.get] for model code. */
fun tr(resource: StringResource, vararg args: Any?): String = AppText.get(resource, *args)
