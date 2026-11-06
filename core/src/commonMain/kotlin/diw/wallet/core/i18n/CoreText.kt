package diw.wallet.core.i18n

/**
 * User-facing text of core: every message is a key with arguments. The app installs [resolver], which looks the key
 * up in its string resources in the language it shows; without one (core used on its own, tests, the server) the
 * Traditional Chinese text of [CoreStrings] is used. Placeholders are %1$s, %2$s and so on.
 */
object CoreText {
    @Volatile
    var resolver: ((String) -> String?)? = null

    fun get(key: String, vararg args: Any?): String {
        var text = resolver?.invoke(key) ?: CoreStrings.ZH[key] ?: key
        args.forEachIndexed { i, a -> text = text.replace("%${i + 1}\$s", a.toString()).replace("%${i + 1}\$d", a.toString()) }
        return text
    }

    /** The text of [key] before its first placeholder, for recognising a message that was already formatted. */
    fun prefix(key: String): String = get(key).substringBefore("%1\$s").substringBefore("%1\$d")

    /** The Traditional Chinese text of [key], which reports saved before translation (and core alone) use. */
    fun chinese(key: String): String = CoreStrings.ZH[key] ?: key
}

/** The text of core message [key] with [args] in the app's language. */
fun ct(key: String, vararg args: Any?): String = CoreText.get(key, *args)
