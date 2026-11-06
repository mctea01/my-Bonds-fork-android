package diw.wallet.app.ui

import android.content.res.Configuration
import android.content.res.Resources
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ProvidedValue
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import java.util.Locale

actual object LocalAppLocale {
    actual val current: String
        @Composable get() = LocalConfiguration.current.locales[0].toLanguageTag()

    @Composable
    @Suppress("DEPRECATION")
    actual infix fun provides(value: String?): ProvidedValue<*> {
        val base = LocalConfiguration.current
        val locale = value?.let { Locale.forLanguageTag(it) } ?: Resources.getSystem().configuration.locales[0]
        Locale.setDefault(locale)
        val configuration = Configuration(base).apply { setLocale(locale) }
        val resources = LocalContext.current.resources
        resources.updateConfiguration(configuration, resources.displayMetrics)
        return LocalConfiguration.provides(configuration)
    }
}
