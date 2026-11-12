package diw.wallet.core.zk.native

import diw.wallet.core.zk.ZkComponent
import java.io.File

/**
 * A native component that comes with the package itself: in the desktop resources (unpacked under [dataDirectory]
 * like diw_zk), or among an APK's own libraries. [base] is the library name without prefix or suffix.
 */
class BundledZkComponent(private val dataDirectory: File, private val base: String) : ZkComponent {
    override val installable: Boolean get() = false

    override fun present(): Boolean = if (ZkNative.android) load() != null else ZkNative.bundled(base)

    override suspend fun install(progress: (Float) -> Unit): String? = if (present()) null else "not_installable"

    override fun load(): String? = try {
        if (ZkNative.android) {
            System.loadLibrary(base)
            "lib$base.so"
        } else {
            ZkNative.unpack(dataDirectory, base)?.absolutePath
        }
    } catch (_: LinkageError) {
        null
    } catch (_: Exception) {
        null
    }
}
