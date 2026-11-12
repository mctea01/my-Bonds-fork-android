package diw.wallet.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * A language of the interface: [tag] (BCP 47) and [name], the language's name in itself; [tag] is null for
 * [SYSTEM], which follows the system language. The offered languages ([all]) come from the translation files
 * (language_tag and language_self in each strings.xml), so adding a language changes no code.
 */
data class AppLanguage(val tag: String?, val name: String) {
    companion object {
        val SYSTEM = AppLanguage(null, "")

        /** The languages translation files provide, in the order of their resource directories. */
        val all: List<AppLanguage> get() = AppLanguages.all

        /**
         * The offered language for [tag]: the same tag, else the same language and script or region, else the same
         * language; [SYSTEM] for null or a language no translation file provides.
         */
        fun of(tag: String?): AppLanguage {
            if (tag == null) return SYSTEM
            val parts = tag.replace('_', '-').lowercase().split('-')
            val offered = all.map { it to it.tag!!.lowercase().split('-') }
            offered.firstOrNull { it.second == parts }?.let { return it.first }
            val same = offered.filter { it.second.first() == parts.first() }
            // zh-Hant-TW and zh-TW share a region or script with zh-TW; the first file of the language otherwise.
            return same.firstOrNull { (_, p) -> p.drop(1).any { it in parts.drop(1) } }?.first ?: same.firstOrNull()?.first ?: SYSTEM
        }
    }
}

/**
 * Where the language chosen in the app is kept. [systemManaged] is true where the platform applies the choice itself
 * (the Android 13 per-app language), so the interface follows the system locale and never overrides it.
 */
abstract class AppLanguageStore {
    open val systemManaged: Boolean get() = false

    protected abstract fun read(): String?

    protected abstract fun write(tag: String?)

    private val state by lazy { MutableStateFlow(read()) }

    /** The chosen language tag; null follows the system. */
    val tag: StateFlow<String?> get() = state.asStateFlow()

    fun set(language: AppLanguage) {
        write(language.tag)
        state.value = if (systemManaged) read() else language.tag
    }
}

/** A store that lives only while the process runs (tests, platforms without settings). */
class MemoryLanguageStore(private var saved: String? = null) : AppLanguageStore() {
    override fun read() = saved

    override fun write(tag: String?) {
        saved = tag
    }
}
