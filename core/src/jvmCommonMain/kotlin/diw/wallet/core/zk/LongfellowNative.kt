package diw.wallet.core.zk

import diw.wallet.core.i18n.ct

internal actual object LongfellowNative {
    private val reason: String? by lazy {
        try {
            // Initializing the natives class loads libzkp: Android arm64-v8a and x86_64, desktop Linux x86_64 and
            // macOS arm64 only.
            Class.forName("org.multipaz.mdoc.zkp.longfellow.LongfellowNatives", true, LongfellowNative::class.java.classLoader)
            null
        } catch (_: LinkageError) {
            ct("core_lf_no_arch")
        } catch (_: ClassNotFoundException) {
            ct("core_lf_missing")
        }
    }

    actual fun unavailableReason(): String? = reason
}
