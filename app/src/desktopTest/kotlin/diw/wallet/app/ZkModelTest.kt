package diw.wallet.app

import diw.wallet.core.zk.ZkAsset
import diw.wallet.core.zk.ZkAssetStatus
import diw.wallet.core.zk.ZkAssetStore
import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.ZkEnvironment
import diw.wallet.core.zk.ZkErrors
import diw.wallet.core.zk.ZkNativeStatus
import diw.wallet.core.zk.ZkPlatformInfo
import diw.wallet.core.zk.ZkResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** ZkModel against a synthetic environment: no native library, no network, no real assets. */
class ZkModelTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @AfterTest
    fun stop() = scope.cancel()

    private fun asset(id: String, role: Set<String> = setOf("prover"), backend: ZkBackend = ZkBackend.OPENAC_SPARTAN2) =
        ZkAsset(id, backend, role, listOf("https://example.invalid/$id"), "0".repeat(64), 1000, "1".repeat(64), 4000, "MIT")

    private class FakeStore(val states: MutableMap<String, ZkAssetStatus>, val fail: Set<String> = emptySet()) : ZkAssetStore {
        val downloaded = mutableListOf<String>()
        override suspend fun status(id: String) = states[id] ?: ZkAssetStatus.MISSING
        override suspend fun download(id: String, onProgress: (Long, Long) -> Unit): ZkResult<Unit> {
            downloaded += id
            onProgress(500, 1000)
            if (id in fail) return ZkResult.Failed("證明資產完整性檢查失敗，已刪除下載內容", true)
            onProgress(1000, 1000)
            states[id] = ZkAssetStatus.READY
            return ZkResult.Ok(Unit)
        }
        override fun path(id: String): String? = null
        override suspend fun delete(id: String) { states.remove(id) }
    }

    private class FakeEnvironment(
        override val catalog: List<ZkAsset>,
        override val assets: ZkAssetStore?,
        val info: ZkPlatformInfo,
        val native: ZkResult<ZkNativeStatus>,
    ) : ZkEnvironment {
        var loads = 0
        override suspend fun platformInfo() = info
        override suspend fun loadNative(): ZkResult<ZkNativeStatus> { loads++; return native }
    }

    private val desktop = ZkPlatformInfo("linux-x86_64", 16384, 12000, 50000, true)
    private val openac = ZkResult.Ok(ZkNativeStatus(setOf(ZkBackend.OPENAC_SPARTAN2), "0.1.0"))

    private fun model(env: ZkEnvironment?, timeoutMs: Long = 5000) =
        ZkModel(scope, env, Dispatchers.IO, { _, _ -> timeoutMs.milliseconds })

    @Test
    fun readinessListsMissingProverAssetsOnly() = runBlocking {
        val catalog = listOf(asset("a"), asset("b"), asset("vk", setOf("verifier")), asset("pdf", backend = ZkBackend.NOIR_ULTRAHONK))
        val store = FakeStore(mutableMapOf("a" to ZkAssetStatus.READY, "b" to ZkAssetStatus.PARTIAL))
        val env = FakeEnvironment(catalog, store, desktop, openac)
        val zk = model(env)
        val ready = zk.readiness(ZkProofKind.AGE)
        assertTrue(ready.canRunHere)
        assertNull(ready.advice)
        assertEquals(listOf("b"), ready.missing.map { it.id })
        assertEquals(1000, ready.downloadBytes)
        assertTrue(ready.recommended)
        val pdf = zk.readiness(ZkProofKind.PDF)
        assertFalse(pdf.canRunHere)
        assertNotNull(pdf.advice)
        zk.readiness(ZkProofKind.TLS)
        assertEquals(1, env.loads, "the native library is loaded once")
    }

    @Test
    fun lowMemoryAdvisesButStillAllows() = runBlocking {
        val env = FakeEnvironment(emptyList(), FakeStore(mutableMapOf()), ZkPlatformInfo("arm64-v8a", 8192, 1500, 50000, false), openac)
        val ready = model(env).readiness(ZkProofKind.AGE)
        assertTrue(ready.canRunHere)
        assertNotNull(ready.advice)
        assertFalse(ready.recommended)
    }

    @Test
    fun missingRuntimeExplainsWhy() = runBlocking {
        val zk = model(null)
        assertEquals(ZkModel.NO_RUNTIME, zk.nativeProblem.value)
        val ready = zk.readiness(ZkProofKind.AGE)
        assertFalse(ready.canRunHere)
        assertEquals(ZkModel.NO_RUNTIME, ready.advice)
        val failed = FakeEnvironment(emptyList(), null, desktop, ZkErrors.unsupported)
        val other = model(failed)
        assertFalse(other.readiness(ZkProofKind.AGE).canRunHere)
        assertEquals(ZkErrors.unsupported.reason, other.nativeProblem.value)
    }

    @Test
    fun downloadStopsAtFirstFailureAndKeepsTheReason() = runBlocking {
        val store = FakeStore(mutableMapOf(), fail = setOf("b"))
        val zk = model(FakeEnvironment(listOf(asset("a"), asset("b"), asset("c")), store, desktop, openac))
        zk.download(listOf("a", "b", "c")).join()
        assertEquals(listOf("a", "b"), store.downloaded)
        assertEquals(ZkAssetStatus.READY, zk.assetStatus.value["a"])
        assertNull(zk.downloads.value["a"])
        assertNotNull(zk.downloads.value["b"]?.error)
        zk.refresh().join()
        assertEquals(ZkAssetStatus.MISSING, zk.assetStatus.value["c"])
    }

    @Test
    fun proofSucceedsWithSteps() = runBlocking {
        val zk = model(FakeEnvironment(emptyList(), null, desktop, openac))
        val result = zk.prove("p1", ZkProofKind.AGE) { step -> step("prepare"); ZkResult.Ok(42) }.await()
        assertEquals(ZkResult.Ok(42), result)
        assertEquals(ZkJobPhase.DONE, zk.jobs.value["p1"]?.phase)
        zk.clear("p1")
        assertNull(zk.jobs.value["p1"])
    }

    @Test
    fun unsupportedBackendIsNotRun() = runBlocking {
        val zk = model(FakeEnvironment(emptyList(), null, desktop, openac))
        var ran = false
        val result = zk.prove("p", ZkProofKind.PDF) { ran = true; ZkResult.Ok(Unit) }.await()
        assertFalse(ran)
        assertEquals(ZkErrors.unsupported, result)
        assertEquals(ZkJobPhase.FAILED, zk.jobs.value["p"]?.phase)
    }

    @Test
    fun timeoutStopsAndIsRetryable() = runBlocking {
        val zk = model(FakeEnvironment(emptyList(), null, desktop, openac), timeoutMs = 100)
        val result = zk.prove<Unit>("slow", ZkProofKind.AGE) { awaitCancellation() }.await()
        assertEquals(ZkResult.Failed(ZkModel.TIMED_OUT, true), result)
        assertEquals(ZkJobPhase.TIMED_OUT, zk.jobs.value["slow"]?.phase)
    }

    @Test
    fun exceptionTextNeverReachesTheScreen() = runBlocking {
        val zk = model(FakeEnvironment(emptyList(), null, desktop, openac))
        val result = zk.prove<Unit>("boom", ZkProofKind.AGE) { error("birth date 1990-01-01") }.await()
        assertEquals(ZkErrors.internal, result)
        assertFalse(zk.jobs.value["boom"]?.message.orEmpty().contains("1990"))
    }

    @Test
    fun proofsRunOneAtATimeAndQueuedOnesCanBeCancelled() = runBlocking {
        val zk = model(FakeEnvironment(emptyList(), null, desktop, openac))
        val release = CompletableDeferred<Unit>()
        val started = CompletableDeferred<Unit>()
        val first = zk.prove("first", ZkProofKind.AGE) { started.complete(Unit); release.await(); ZkResult.Ok(1) }
        started.await()
        val second = zk.prove("second", ZkProofKind.AGE) { ZkResult.Ok(2) }
        withTimeout(5.seconds) { while (zk.jobs.value["second"]?.phase != ZkJobPhase.QUEUED) kotlinx.coroutines.delay(10) }
        zk.cancel("second")
        runCatching { second.await() }
        assertEquals(ZkJobPhase.CANCELLED, zk.jobs.value["second"]?.phase)
        assertEquals(ZkJobPhase.RUNNING, zk.jobs.value["first"]?.phase)
        release.complete(Unit)
        assertEquals(ZkResult.Ok(1), first.await())
    }

    @Test
    fun desktopEnvironmentUsesTheBundledCatalog() = runBlocking {
        val dir = kotlin.io.path.createTempDirectory("zk-env").toFile()
        try {
            val env = diw.wallet.core.zk.native.JvmZkEnvironment(dir, io.ktor.client.HttpClient()) { diw.wallet.app.desktop.desktopZkInfo(dir) }
            assertTrue(env.catalog.any { it.id == "jwt_2k.r1cs" && it.backend == ZkBackend.OPENAC_SPARTAN2 })
            val info = env.platformInfo()
            assertTrue(info.isDesktop && info.totalRamMb > 0 && info.freeDiskMb > 0)
            if (System.getProperty("os.name").lowercase().contains("linux")) assertEquals("linux-x86_64".takeIf { System.getProperty("os.arch") in setOf("amd64", "x86_64") } ?: info.abi, info.abi)
            assertEquals(ZkAssetStatus.MISSING, env.assets?.status("show.graph"))
            env.close()
        } finally {
            dir.deleteRecursively()
        }
    }
}
