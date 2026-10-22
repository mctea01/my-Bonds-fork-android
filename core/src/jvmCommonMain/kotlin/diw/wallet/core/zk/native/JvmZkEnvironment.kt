package diw.wallet.core.zk.native

import diw.wallet.core.zk.ZkAsset
import diw.wallet.core.zk.ZkAssetStore
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

    override suspend fun loadNative(): ZkResult<ZkNativeStatus> = withContext(Dispatchers.IO) { ZkNative.load(dataDirectory) }

    override val catalog: List<ZkAsset> get() = store?.assets.orEmpty()

    override val assets: ZkAssetStore? get() = store

    override fun close() {
        if (opened.isInitialized()) store?.close()
    }
}
