package diw.wallet.app.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.ProvidedValue
import androidx.compose.runtime.staticCompositionLocalOf
import java.util.Locale

actual object LocalAppLocale {
    /** The JVM locale at start, before the app replaced it. */
    private val system: Locale = Locale.getDefault()
    private val local = staticCompositionLocalOf { Locale.getDefault().toLanguageTag() }

    actual val current: String
        @Composable get() = local.current

    @Composable
    actual infix fun provides(value: String?): ProvidedValue<*> {
        val locale = value?.let { Locale.forLanguageTag(it) } ?: system
        Locale.setDefault(locale)
        return local.provides(locale.toLanguageTag())
    }
}
