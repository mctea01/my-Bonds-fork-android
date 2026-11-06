package diw.wallet.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Languages of the interface; [tag] (BCP 47) is null when the app follows the system language. */
enum class AppLanguage(val tag: String?) {
    SYSTEM(null),
    TRADITIONAL_CHINESE("zh-TW"),
    ENGLISH("en"),
    ;

    companion object {
        fun of(tag: String?): AppLanguage = when {
            tag == null -> SYSTEM
            tag.startsWith("zh", ignoreCase = true) -> TRADITIONAL_CHINESE
            tag.startsWith("en", ignoreCase = true) -> ENGLISH
            else -> SYSTEM
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
