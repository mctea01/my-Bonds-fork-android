package diw.wallet.core.zk

internal actual object LongfellowNative {
    private val reason: String? by lazy {
        try {
            // Initializing the natives class loads libzkp: Android arm64-v8a and x86_64, desktop Linux x86_64 and
            // macOS arm64 only.
            Class.forName("org.multipaz.mdoc.zkp.longfellow.LongfellowNatives", true, LongfellowNative::class.java.classLoader)
            null
        } catch (_: LinkageError) {
            "此處理器架構沒有 Longfellow 原生函式庫"
        } catch (_: ClassNotFoundException) {
            "Longfellow 未包含在此版本"
        }
    }

    actual fun unavailableReason(): String? = reason
}
