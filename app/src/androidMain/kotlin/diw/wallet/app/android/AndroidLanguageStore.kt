package diw.wallet.app.android

import android.app.LocaleManager
import android.content.Context
import android.os.Build
import android.os.LocaleList
import diw.wallet.app.AppLanguageStore

/**
 * Android 13 and later keep the choice as the system per-app language (also changed from the system settings);
 * older versions keep it in the app's preferences and the interface overrides the locale.
 */
class AndroidLanguageStore(private val context: Context) : AppLanguageStore() {
    private val prefs = context.getSharedPreferences("diw-language", Context.MODE_PRIVATE)

    override val systemManaged: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU

    override fun read(): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.getSystemService(LocaleManager::class.java).applicationLocales.takeIf { !it.isEmpty }?.get(0)?.toLanguageTag()
        } else {
            prefs.getString(KEY, null)
        }

    override fun write(tag: String?) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.getSystemService(LocaleManager::class.java).applicationLocales =
                if (tag == null) LocaleList.getEmptyLocaleList() else LocaleList.forLanguageTags(tag)
        } else {
            prefs.edit().apply { if (tag == null) remove(KEY) else putString(KEY, tag) }.apply()
        }
    }

    private companion object {
        const val KEY = "tag"
    }
}
