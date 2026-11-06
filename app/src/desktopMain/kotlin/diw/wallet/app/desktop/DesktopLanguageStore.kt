package diw.wallet.app.desktop

import diw.wallet.app.AppLanguageStore
import java.util.prefs.Preferences

/** The language chosen in the app, kept in the user's Java preferences so it applies before the storage is unlocked. */
class DesktopLanguageStore : AppLanguageStore() {
    private val prefs = Preferences.userRoot().node("diw/wallet/app")

    override fun read(): String? = prefs.get(KEY, null)

    override fun write(tag: String?) {
        if (tag == null) prefs.remove(KEY) else prefs.put(KEY, tag)
        runCatching { prefs.flush() }
    }

    private companion object {
        const val KEY = "language"
    }
}
