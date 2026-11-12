package diw.wallet.app.android

import android.app.Activity
import android.content.Context
import com.google.android.play.core.splitcompat.SplitCompat
import com.google.android.play.core.splitinstall.SplitInstallException
import com.google.android.play.core.splitinstall.SplitInstallHelper
import com.google.android.play.core.splitinstall.SplitInstallManagerFactory
import com.google.android.play.core.splitinstall.SplitInstallRequest
import com.google.android.play.core.splitinstall.SplitInstallStateUpdatedListener
import com.google.android.play.core.splitinstall.model.SplitInstallSessionStatus
import diw.wallet.core.zk.ZkComponent
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * A native library in an on-demand feature module ([module], under features/). Google Play installs it when asked;
 * APKs made with every module (the GitHub release) already carry it among their own libraries, so loading is tried
 * first in every case. [activity] shows Play's confirmation when a download needs one.
 */
class PlayFeatureComponent(
    private val context: Context,
    private val module: String,
    private val library: String,
    private val activity: () -> Activity?,
) : ZkComponent {
    private val manager by lazy { SplitInstallManagerFactory.create(context) }

    @Volatile private var loaded = false

    /** Only Google Play delivers feature modules; another installer cannot add one to this app. */
    override val installable: Boolean
        get() = runCatching {
            context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName == PLAY_STORE
        }.getOrDefault(false)

    override fun present(): Boolean = loaded || module in runCatching { manager.installedModules }.getOrDefault(emptySet()) || load() != null

    override fun load(): String? {
        if (loaded) return "lib$library.so"
        val ok = try {
            System.loadLibrary(library)
            true
        } catch (_: UnsatisfiedLinkError) {
            // A module installed in this process is not yet on the class loader's library path.
            try {
                SplitCompat.install(context)
                SplitInstallHelper.loadLibrary(context, library)
                true
            } catch (_: Throwable) {
                false
            }
        } catch (_: Throwable) {
            false
        }
        loaded = ok
        return if (ok) "lib$library.so" else null
    }

    override suspend fun install(progress: (Float) -> Unit): String? {
        if (load() != null) return null
        if (!installable) return "not_installable"
        return suspendCancellableCoroutine { continuation ->
            var session = -1
            lateinit var listener: SplitInstallStateUpdatedListener
            fun finish(result: String?) {
                manager.unregisterListener(listener)
                if (continuation.isActive) continuation.resume(result)
            }
            listener = SplitInstallStateUpdatedListener { state ->
                if (state.sessionId() != session) return@SplitInstallStateUpdatedListener
                when (state.status()) {
                    SplitInstallSessionStatus.DOWNLOADING -> {
                        val total = state.totalBytesToDownload()
                        if (total > 0) progress((state.bytesDownloaded().toFloat() / total).coerceIn(0f, 1f))
                    }
                    SplitInstallSessionStatus.REQUIRES_USER_CONFIRMATION -> {
                        val a = activity()
                        if (a == null) finish("install_confirmation") else runCatching {
                            manager.startConfirmationDialogForResult(state, a, CONFIRMATION_REQUEST)
                        }.onFailure { finish("install_confirmation") }
                    }
                    SplitInstallSessionStatus.INSTALLED -> finish(if (load() != null) null else "install_load")
                    SplitInstallSessionStatus.FAILED -> finish("install_failed:${state.errorCode()}")
                    SplitInstallSessionStatus.CANCELED -> finish("install_cancelled")
                    else -> {}
                }
            }
            manager.registerListener(listener)
            continuation.invokeOnCancellation {
                manager.unregisterListener(listener)
                if (session > 0) manager.cancelInstall(session)
            }
            manager.startInstall(SplitInstallRequest.newBuilder().addModule(module).build())
                .addOnSuccessListener { id ->
                    session = id
                    // 0: already installed.
                    if (id == 0) finish(if (load() != null) null else "install_load")
                }
                .addOnFailureListener { e -> finish("install_failed:${(e as? SplitInstallException)?.errorCode ?: 0}") }
        }
    }

    companion object {
        private const val PLAY_STORE = "com.android.vending"
        private const val CONFIRMATION_REQUEST = 7301
    }
}
