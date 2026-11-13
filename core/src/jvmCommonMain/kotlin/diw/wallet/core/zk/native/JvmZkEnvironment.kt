package diw.wallet.core.zk.native

import diw.wallet.core.zk.ZkAsset
import diw.wallet.core.zk.ZkAssetStore
import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.ZkComponent
import diw.wallet.core.zk.native.bindings.zkpassportLegacyBackend
import diw.wallet.core.zk.LongfellowNative
import diw.wallet.core.zk.OpenAcAgeProver
import diw.wallet.core.zk.OpenAcAgeVerifier
import diw.wallet.core.zk.ZkEnvironment
import diw.wallet.core.zk.ZkNativeStatus
import diw.wallet.core.zk.ZkPdfAssets
import diw.wallet.core.zk.ZkPdfEngine
import diw.wallet.core.zk.ZkPlatformInfo
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.profile.bonds.SocketBondsLanLink
import diw.wallet.core.zkpassport.JvmZkPassportVerifier
import diw.wallet.core.zkpassport.ZkPassportProver
import diw.wallet.core.zkpassport.ZkPassportVerifier
import diw.wallet.core.zktls.NativeZkTlsEngine
import diw.wallet.core.zktls.ZkTlsEngine
import io.ktor.client.HttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.net.SocketFactory

/**
 * Android and desktop share this: the library is unpacked under [dataDirectory], assets are kept in its
 * zk-assets folder and fetched with [http] (the store disables redirects on its own copy). Nothing is loaded or
 * hashed until first asked, because hashing installed proving keys reads hundreds of megabytes.
 */
class JvmZkEnvironment(
    private val dataDirectory: File,
    private val http: HttpClient,
    /** The local network for zkTLS between devices: listening addresses, subnet order and per-address sockets. */
    private val lan: SocketBondsLanLink = SocketBondsLanLink(),
    private val socketFactoryFor: (String) -> SocketFactory? = { null },
    /** Barretenberg 5 for zkPassport circuits before 0.22.0: in the package itself unless the platform delivers it apart. */
    private val legacy: ZkComponent? = BundledZkComponent(dataDirectory, "diw_bb5"),
    private val info: () -> ZkPlatformInfo,
) : ZkEnvironment, AutoCloseable {
    init { ZkNative.directory = dataDirectory }

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

    override val ageProver: OpenAcAgeProver? by lazy { store?.let { OpenAcAgeNativeProver(it, File(dataDirectory, "zk-work"), File(dataDirectory, "zk-cache")) } }

    override val ageVerifier: OpenAcAgeVerifier? by lazy { store?.let { OpenAcAgeNativeVerifier(it, File(dataDirectory, "zk-verify")) } }

    override val pdf: ZkPdfEngine? by lazy { store?.let { ZkPdfNativeEngine(it) } }

    /** The folder of the installed zkPDF CRS, shared with zkPassport; null until both files are installed. */
    private fun crsDirectory(): File? =
        store?.let { s -> ZkPdfAssets.CRS.map { s.installedFile(it) ?: return@let null }.first().parentFile }

    private suspend fun ultraHonkReady(): Boolean =
        (loadNative() as? ZkResult.Ok)?.value?.backends?.contains(ZkBackend.NOIR_ULTRAHONK) == true

    override val zkPassportLegacy: ZkComponent? get() = legacy

    @Volatile private var legacyOpened = false

    /** Whether Barretenberg 5 is open in the native library; checked again after the component is installed. */
    private suspend fun legacyReady(): Boolean = withContext(Dispatchers.IO) {
        if (legacyOpened) return@withContext true
        if (!ultraHonkReady()) return@withContext false
        val library = legacy?.load() ?: return@withContext false
        legacyOpened = runCatching { zkpassportLegacyBackend(library) }.isSuccess
        legacyOpened
    }

    override val zkPassport: ZkPassportVerifier by lazy {
        JvmZkPassportVerifier(
            http, File(dataDirectory, "zkpassport-cache"), crsDirectory = ::crsDirectory, nativeReady = ::ultraHonkReady,
            legacyReady = ::legacyReady,
        )
    }

    /** zkPassport proofs made on this device from a passport's chip files, with the same CRS and cache. */
    val zkPassportProver: ZkPassportProver by lazy {
        ZkPassportProver(http, File(dataDirectory, "zkpassport-cache"), crsDirectory = ::crsDirectory, nativeReady = ::ultraHonkReady)
    }

    override val zkPassportHolder: diw.wallet.core.zkpassport.ZkPassportHolder by lazy {
        diw.wallet.core.zkpassport.JvmZkPassportHolder(http, zkPassportProver, network = socketFactoryFor)
    }

    override val tls: ZkTlsEngine by lazy {
        NativeZkTlsEngine(http, lan::localAddresses, lan::preferred, socketFactoryFor) {
            (loadNative() as? ZkResult.Ok)?.value?.backends?.contains(ZkBackend.TLSN) == true
        }
    }

    /** VmRSS from /proc (Linux and Android); other systems report none. */
    override fun residentMemoryMb(): Long? = runCatching {
        File("/proc/self/status").useLines { lines ->
            lines.firstOrNull { it.startsWith("VmRSS:") }?.substringAfter(':')?.trim()?.substringBefore(' ')?.toLongOrNull()?.div(1024)
        }
    }.getOrNull()

    override fun close() {
        if (opened.isInitialized()) store?.close()
    }
}
