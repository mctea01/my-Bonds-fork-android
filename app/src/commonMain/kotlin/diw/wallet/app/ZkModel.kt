package diw.wallet.app

import diw.wallet.core.zk.ZkAsset
import diw.wallet.core.zk.ZkAssetStatus
import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.ZkCapabilities
import diw.wallet.core.zk.ZkCapability
import diw.wallet.core.zk.ZkEnvironment
import diw.wallet.core.zk.ZkErrors
import diw.wallet.core.zk.ZkNativeStatus
import diw.wallet.core.zk.ZkPlatformInfo
import diw.wallet.core.zk.ZkResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** The proofs the wallet produces, with the engine each needs, its default time limit and its measured memory peak. */
enum class ZkProofKind(val backend: ZkBackend, val label: String, val timeout: Duration, val peakMemoryMb: Long?) {
    PDF(ZkBackend.NOIR_ULTRAHONK, "PDF 簽章零知識證明", 10.minutes, null),
    AGE(ZkBackend.OPENAC_SPARTAN2, "年齡零知識證明", 5.minutes, 2325),
    TLS(ZkBackend.TLSN, "網站查驗證明", 2.minutes, null),
    MDOC_AGE(ZkBackend.LONGFELLOW, "mdoc 年齡零知識證明", 3.minutes, null);

    /** Answers a verifier's request, so it cannot be produced elsewhere and imported later. */
    val answersVerifier: Boolean get() = this == AGE || this == MDOC_AGE
}

/** Whether a proof can be produced here and what it still needs; the low-compute choice screen is built from it. */
data class ZkReadiness(
    val kind: ZkProofKind,
    /** False only when the engine cannot run on this device at all (no library, unsupported architecture, not in this build). */
    val canRunHere: Boolean,
    /** Why producing the proof here is not recommended, or impossible; null when nothing stands against it. */
    val advice: String?,
    /** Prover assets that are not installed yet. */
    val missing: List<ZkAsset>,
    val platform: ZkPlatformInfo?,
) {
    val downloadBytes: Long get() = missing.sumOf { it.gzipBytes }
    val installedBytes: Long get() = missing.sumOf { it.installedBytes }
    val recommended: Boolean get() = canRunHere && advice == null
}

enum class ZkJobPhase { QUEUED, RUNNING, DONE, FAILED, CANCELLED, TIMED_OUT }

/** A proof in the background; [message] is what the user is told, never backend detail (it may hold private input). */
data class ZkJob(
    val id: String,
    val kind: ZkProofKind,
    val phase: ZkJobPhase,
    val step: String? = null,
    val message: String? = null,
    val retryable: Boolean = false,
    val startedAt: Instant? = null,
    val timeout: Duration,
) {
    val active: Boolean get() = phase == ZkJobPhase.QUEUED || phase == ZkJobPhase.RUNNING
}

data class ZkDownload(val id: String, val received: Long, val total: Long, val error: String? = null)

/**
 * Zero-knowledge state for the screens: what this device can prove ([capability]), which circuit assets are
 * installed, downloads with progress, and proofs running in the background one at a time (each holds gigabytes of
 * native memory), with a time limit, cancellation and a retryable state when they stop. Nothing is loaded or hashed
 * until [refresh] or a proof asks, since checking installed keys reads hundreds of megabytes.
 */
class ZkModel(
    private val scope: CoroutineScope,
    private val environment: ZkEnvironment?,
    /** Long native calls block their thread, so they stay off the shared default pool. */
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(2),
    private val timeoutFor: (ZkProofKind, Boolean) -> Duration = { kind, extended -> if (extended) EXTENDED_TIMEOUT else kind.timeout },
    private val clock: Clock = Clock.System,
) {
    val capability = MutableStateFlow<ZkCapability?>(null)
    val native = MutableStateFlow<ZkNativeStatus?>(null)
    /** Why the native library is not available; null when it loaded or has not been tried. */
    val nativeProblem = MutableStateFlow<String?>(if (environment == null) NO_RUNTIME else null)
    val platformInfo = MutableStateFlow<ZkPlatformInfo?>(null)
    val assetStatus = MutableStateFlow<Map<String, ZkAssetStatus>>(emptyMap())
    val downloads = MutableStateFlow<Map<String, ZkDownload>>(emptyMap())
    private val _jobs = MutableStateFlow<Map<String, ZkJob>>(emptyMap())
    val jobs: StateFlow<Map<String, ZkJob>> = _jobs
    val refreshing = MutableStateFlow(false)

    private val nativeLock = Mutex()
    private var nativeTried = false
    private val proving = Mutex()
    private val running = MutableStateFlow<Map<String, Job>>(emptyMap())
    private var downloadJob: Job? = null

    val catalog: List<ZkAsset> get() = environment?.catalog.orEmpty()

    /** Evaluates the device and loads the library if needed, without checking assets; cheap enough for a summary. */
    fun probe(): Job = scope.launch(dispatcher) { evaluate() }

    /** Re-reads resources, loads the library if it has not been, and re-checks every installed asset. */
    fun refresh(): Job = scope.launch(dispatcher) {
        refreshing.value = true
        try {
            evaluate()
            val store = environment?.assets ?: return@launch
            assetStatus.value = catalog.associate { it.id to runCatching { store.status(it.id) }.getOrDefault(ZkAssetStatus.CORRUPT) }
        } finally {
            refreshing.value = false
        }
    }

    private suspend fun evaluate(): ZkCapability {
        val loaded = loadNative()
        val info = environment?.let { runCatching { it.platformInfo() }.getOrNull() }
        platformInfo.value = info
        val result = ZkCapabilities.evaluate(info ?: UNKNOWN_PLATFORM, loaded)
        capability.value = result
        return result
    }

    private suspend fun loadNative(): ZkNativeStatus? = nativeLock.withLock {
        if (nativeTried) return native.value
        nativeTried = true
        val env = environment ?: return null
        when (val result = runCatching { env.loadNative() }.getOrElse { ZkErrors.internal }) {
            is ZkResult.Ok -> native.value = result.value
            is ZkResult.Failed -> nativeProblem.value = result.reason
            ZkResult.Cancelled -> nativeTried = false
        }
        native.value
    }

    private fun proverAssets(backend: ZkBackend) = catalog.filter { it.backend == backend && "prover" in it.role }

    /** What producing [kind] here needs; evaluates the device first if that has not been done. */
    suspend fun readiness(kind: ZkProofKind): ZkReadiness = withContext(dispatcher) {
        val capable = capability.value ?: evaluate()
        val store = environment?.assets
        val missing = proverAssets(kind.backend).filter { asset ->
            val status = assetStatus.value[asset.id] ?: store?.status(asset.id)?.also { s -> assetStatus.update { it + (asset.id to s) } }
            status != ZkAssetStatus.READY
        }
        val info = platformInfo.value
        val canRun = kind.backend in capable.backends
        val advice = when {
            !canRun -> nativeProblem.value ?: capable.reasons[kind.backend] ?: "此版本尚未包含此證明後端"
            capable.reasons[kind.backend] != null -> capable.reasons[kind.backend]
            info != null && kind.peakMemoryMb != null && info.availableRamMb < kind.peakMemoryMb ->
                "可用記憶體約 ${info.availableRamMb} MB，低於預估峰值 ${kind.peakMemoryMb} MB，可能被系統中止"
            info != null && missing.sumOf { it.installedBytes } / MIB > info.freeDiskMb ->
                "可用儲存空間不足以安裝所需的證明資產"
            else -> null
        }
        ZkReadiness(kind, canRun, advice, missing, info)
    }

    /** Downloads [ids] one after another with progress; stops at the first failure, which stays in [downloads]. */
    fun download(ids: List<String>): Job {
        downloadJob?.cancel()
        return scope.launch(dispatcher) {
            val store = environment?.assets ?: return@launch
            for (id in ids) {
                val asset = catalog.firstOrNull { it.id == id } ?: continue
                downloads.update { it + (id to ZkDownload(id, 0, asset.gzipBytes)) }
                val result = try {
                    store.download(id) { received, total -> downloads.update { it + (id to ZkDownload(id, received, total)) } }
                } catch (e: CancellationException) {
                    downloads.update { it - id }
                    assetStatus.update { it + (id to ZkAssetStatus.MISSING) }
                    throw e
                } catch (_: Exception) {
                    ZkResult.Failed("無法下載證明資產，請重試", true)
                }
                assetStatus.update { it + (id to runCatching { store.status(id) }.getOrDefault(ZkAssetStatus.CORRUPT)) }
                if (result is ZkResult.Failed) {
                    downloads.update { it + (id to ZkDownload(id, 0, asset.gzipBytes, result.reason)) }
                    return@launch
                }
                downloads.update { it - id }
            }
        }.also { downloadJob = it }
    }

    fun cancelDownload() {
        downloadJob?.cancel()
    }

    suspend fun delete(id: String) = withContext(dispatcher) {
        val store = environment?.assets ?: return@withContext
        store.delete(id)
        assetStatus.update { it + (id to ZkAssetStatus.MISSING) }
    }

    /**
     * Runs [prove] in the background after any proof already running. [extended] is the user's choice to produce it
     * here anyway, which lengthens the limit. [prove] reports steps through its argument and must verify its own
     * proof before returning it. Exceptions become a generic failure so no backend text reaches the screen.
     */
    fun <T> prove(
        id: String,
        kind: ZkProofKind,
        extended: Boolean = false,
        prove: suspend (step: (String) -> Unit) -> ZkResult<T>,
    ): Deferred<ZkResult<T>> {
        val limit = timeoutFor(kind, extended)
        set(ZkJob(id, kind, ZkJobPhase.QUEUED, timeout = limit))
        val task = scope.async(dispatcher, start = CoroutineStart.LAZY) {
            try {
                proving.withLock {
                    val capable = capability.value ?: evaluate()
                    if (kind.backend !in capable.backends) return@withLock finish(id, ZkErrors.unsupported)
                    set(ZkJob(id, kind, ZkJobPhase.RUNNING, startedAt = clock.now(), timeout = limit))
                    val result = withTimeoutOrNull(limit) {
                        try {
                            prove { step -> _jobs.update { jobs -> jobs[id]?.let { jobs + (id to it.copy(step = step)) } ?: jobs } }
                        } catch (e: CancellationException) {
                            throw e
                        } catch (_: Exception) {
                            ZkErrors.internal
                        }
                    }
                    if (result == null) {
                        set(ZkJob(id, kind, ZkJobPhase.TIMED_OUT, message = TIMED_OUT, retryable = true, timeout = limit))
                        ZkResult.Failed(TIMED_OUT, true)
                    } else finish(id, result)
                }
            } catch (e: CancellationException) {
                set(ZkJob(id, kind, ZkJobPhase.CANCELLED, message = "已取消", retryable = true, timeout = limit))
                throw e
            } finally {
                running.update { it - id }
            }
        }
        running.update { it + (id to task) }
        task.start()
        return task
    }

    private fun <T> finish(id: String, result: ZkResult<T>): ZkResult<T> {
        _jobs.update { jobs ->
            val job = jobs[id] ?: return@update jobs
            jobs + (id to when (result) {
                is ZkResult.Ok -> job.copy(phase = ZkJobPhase.DONE, step = null, message = null)
                is ZkResult.Failed -> job.copy(phase = ZkJobPhase.FAILED, step = null, message = result.reason, retryable = result.retryable)
                ZkResult.Cancelled -> job.copy(phase = ZkJobPhase.CANCELLED, step = null, message = "已取消", retryable = true)
            })
        }
        return result
    }

    private fun set(job: ZkJob) = _jobs.update { it + (job.id to job) }

    /** Stops a queued or running proof; the native call sees the cancellation through its token. */
    fun cancel(id: String) {
        running.value[id]?.cancel()
    }

    /** Forgets a finished proof's state. */
    fun clear(id: String) = _jobs.update { jobs -> if (jobs[id]?.active == true) jobs else jobs - id }

    companion object {
        val EXTENDED_TIMEOUT = 30.minutes
        const val TIMED_OUT = "證明逾時，已停止，可重試"
        const val NO_RUNTIME = "此平台沒有零知識執行環境"
        private const val MIB = 1024L * 1024L
        private val UNKNOWN_PLATFORM = ZkPlatformInfo("unknown", 0, 0, 0, false)
    }
}
