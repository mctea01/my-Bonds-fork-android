package diw.wallet.core.zk.native

import diw.wallet.core.zk.ZkAsset
import diw.wallet.core.zk.ZkAssetStore
import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.LongfellowNative
import diw.wallet.core.zk.OpenAcAgeProver
import diw.wallet.core.zk.ZkEnvironment
import diw.wallet.core.zk.ZkNativeStatus
import diw.wallet.core.zk.ZkPlatformInfo
import diw.wallet.core.zk.ZkResult
import io.ktor.client.HttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Android and desktop share this: the library is unpacked under [dataDirectory], assets are kept in its
 * zk-assets folder and fetched with [http] (the store disables redirects on its own copy). Nothing is loaded or
 * hashed until first asked, because hashing installed proving keys reads hundreds of megabytes.
 */
class JvmZkEnvironment(
    private val dataDirectory: File,
    private val http: HttpClient,
    private val info: () -> ZkPlatformInfo,
) : ZkEnvironment, AutoCloseable {
    private val opened = lazy { runCatching { FileZkAssetStore.bundled(File(dataDirectory, "zk-assets"), http) }.getOrNull() }
    private val store: FileZkAssetStore? by opened

    override suspend fun platformInfo(): ZkPlatformInfo = withContext(Dispatchers.IO) { info() }

    /** The Rust engines plus Longfellow, which Multipaz ships as its own library. */
    override suspend fun loadNative(): ZkResult<ZkNativeStatus> = withContext(Dispatchers.IO) {
        val longfellow = if (LongfellowNative.unavailableReason() == null) setOf(ZkBackend.LONGFELLOW) else emptySet()
        when (val rust = ZkNative.load(dataDirectory)) {
            is ZkResult.Ok -> ZkResult.Ok(rust.value.copy(backends = rust.value.backends + longfellow))
            else -> if (longfellow.isNotEmpty()) ZkResult.Ok(ZkNativeStatus(longfellow, "")) else rust
        }
    }

    override val catalog: List<ZkAsset> get() = store?.assets.orEmpty()

    override val assets: ZkAssetStore? get() = store

    override val ageProver: OpenAcAgeProver? by lazy { store?.let { OpenAcAgeNativeProver(it, File(dataDirectory, "zk-work")) } }

    override fun close() {
        if (opened.isInitialized()) store?.close()
    }
}
