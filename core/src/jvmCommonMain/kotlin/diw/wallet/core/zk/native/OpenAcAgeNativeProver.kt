package diw.wallet.core.zk.native

import diw.wallet.core.zk.OpenAcAgeInput
import diw.wallet.core.zk.OpenAcAgeProof
import diw.wallet.core.zk.OpenAcAgeProver
import diw.wallet.core.zk.ZkErrors
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.bindings.ZkCancelToken
import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.createAgePrepareInput
import diw.wallet.core.zk.native.bindings.createAgeShowInput
import diw.wallet.core.zk.native.bindings.generateSharedBlinds
import diw.wallet.core.zk.native.bindings.proveJwt
import diw.wallet.core.zk.native.bindings.proveShow
import diw.wallet.core.zk.native.bindings.reblindJwt
import diw.wallet.core.zk.native.bindings.reblindShow
import diw.wallet.core.zk.native.bindings.verifyAgePresentation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.MessageDigest
import java.util.UUID

/**
 * OpenAC age proofs as Bonds makes them: Prepare over the SD-JWT, Show over the nonce signature and cutoff, fresh
 * shared blinds and both reblinds, then a mandatory check against the expected issuer key before anything is
 * returned. Each proof runs in its own scratch tree under [workDirectory] that links the installed assets into the
 * layout the native code reads, and is deleted afterwards.
 *
 * With a cache key the Prepare proof, instance and witness are kept in [cacheDirectory] before any reblind, so a later
 * proof of the same card only reblinds and runs Show; every presentation still carries fresh blinds. The witness holds
 * the birth date, so the cache stays in private app storage and unused entries are dropped after [CACHE_DAYS] days.
 */
class OpenAcAgeNativeProver(
    private val store: FileZkAssetStore,
    private val workDirectory: File,
    private val cacheDirectory: File,
) : OpenAcAgeProver {
    override suspend fun prove(input: OpenAcAgeInput, step: (String) -> Unit): ZkResult<OpenAcAgeProof> = withContext(Dispatchers.IO) {
        val sources = LAYOUT.mapValues { (id, _) -> store.installedFile(id) ?: return@withContext MISSING_ASSETS }
        // Proofs run one at a time, so anything left here is from a run the system stopped.
        workDirectory.listFiles()?.forEach { it.deleteRecursively() }
        val root = File(workDirectory, UUID.randomUUID().toString())
        val documents = File(root, "circom")
        try {
            sources.forEach { (id, file) -> link(file, File(documents, LAYOUT.getValue(id))) }
            ZkCancelToken().use { token ->
                coroutineScope {
                    // Cancelling this coroutine (the user, or the time limit) stops the native call through the token.
                    val watcher = launch { try { awaitCancellation() } finally { token.cancel() } }
                    try {
                        proveIn(documents.absolutePath, input, token, step)
                    } finally {
                        watcher.cancel()
                    }
                }
            }
        } catch (e: ZkException) {
            ZkNative.failure(e)
        } catch (_: IOException) {
            ZkErrors.resources
        } finally {
            root.deleteRecursively()
        }
    }

    private fun proveIn(path: String, input: OpenAcAgeInput, token: ZkCancelToken, step: (String) -> Unit): ZkResult<OpenAcAgeProof> {
        val keys = File(path, "keys")
        val entry = input.cacheKey?.let { File(cacheDirectory, sha256(it)) }
        val cached = entry?.let { restore(it, keys) }
        step("準備憑證")
        var started = System.nanoTime()
        val (claimName, format) = cached ?: run {
            val prepared = createAgePrepareInput(path, input.sdJwt, input.issuerKeyX, input.issuerKeyY)
            proveJwt(path, token)
            val claim = prepared.claimName to prepared.claimFormat.toInt()
            entry?.let { save(it, keys, claim) }
            claim
        }
        var prepareMs = elapsed(started)
        val cutoff = input.cutoff(format).toULong()

        step("產生年齡證明")
        started = System.nanoTime()
        createAgeShowInput(path, input.nonce, input.deviceSignature, claimName, format.toUByte(), cutoff)
        proveShow(path, token)
        var showMs = elapsed(started)

        step("重新隨機化證明")
        started = System.nanoTime()
        generateSharedBlinds(path, token)
        reblindJwt(path, token)
        prepareMs += elapsed(started)
        started = System.nanoTime()
        reblindShow(path, token)
        showMs += elapsed(started)

        step("在這台裝置驗證證明")
        val accepted = verifyAgePresentation(path, input.nonce, claimName, format.toUByte(), cutoff,
            input.issuerKeyX, input.issuerKeyY, token)
        if (!accepted) {
            // A proof built on a cached base that this device rejects means the base is stale: rebuild it once.
            if (cached == null) return SELF_CHECK_FAILED
            entry?.deleteRecursively()
            return proveIn(path, input, token, step)
        }
        return ZkResult.Ok(
            OpenAcAgeProof(claimName, format, File(keys, "prepare_proof.bin").readBytes(),
                File(keys, "show_proof.bin").readBytes(), prepareMs, showMs),
        )
    }

    /** The cached claim name and format after copying the Prepare state into [keys], or null when there is none. */
    private fun restore(entry: File, keys: File): Pair<String, Int>? = runCatching {
        val (name, format) = File(entry, CLAIM).readText().lines()
        CACHED.forEach { File(entry, it).copyTo(File(keys, it), overwrite = true) }
        entry.setLastModified(System.currentTimeMillis())
        name to format.toInt()
    }.getOrNull()

    private fun save(entry: File, keys: File, claim: Pair<String, Int>) {
        runCatching {
            cacheDirectory.listFiles()?.filter { System.currentTimeMillis() - it.lastModified() > CACHE_DAYS * DAY_MS }
                ?.forEach { it.deleteRecursively() }
            val staging = File(cacheDirectory, entry.name + ".part").apply { deleteRecursively(); mkdirs() }
            CACHED.forEach { File(keys, it).copyTo(File(staging, it)) }
            File(staging, CLAIM).writeText("${claim.first}\n${claim.second}")
            entry.deleteRecursively()
            if (!staging.renameTo(entry)) staging.deleteRecursively()
        }
    }

    private fun sha256(text: String) =
        MessageDigest.getInstance("SHA-256").digest(text.encodeToByteArray()).joinToString("") { "%02x".format(it.toInt() and 255) }

    override fun clearCache() {
        cacheDirectory.deleteRecursively()
    }

    private fun elapsed(since: Long) = (System.nanoTime() - since) / 1_000_000

    companion object {
        /** Asset id to the path the native code reads under its documents directory. */
        val LAYOUT = mapOf(
            "jwt_2k.r1cs" to "build/jwt/jwt_js/jwt.r1cs",
            "show.r1cs" to "build/show/show_js/show.r1cs",
            "prepare_proving.key" to "keys/prepare_proving.key",
            "prepare_verifying.key" to "keys/prepare_verifying.key",
            "show_proving.key" to "keys/show_proving.key",
            "show_verifying.key" to "keys/show_verifying.key",
            "jwt_2k.graph" to "graphs/jwt_2k.graph",
            "show.graph" to "graphs/show.graph",
        )
        private val CACHED = listOf("prepare_proof.bin", "prepare_instance.bin", "prepare_witness.bin")
        private const val CLAIM = "claim.txt"
        const val CACHE_DAYS = 30L
        private const val DAY_MS = 86_400_000L
        val MISSING_ASSETS = ZkResult.Failed("年齡證明的電路檔尚未下載完成", false)
        val SELF_CHECK_FAILED = ZkResult.Failed("產生的證明沒有通過這台裝置的驗證，未送出", true)
    }
}

/** A symbolic link where the platform allows one, else a hard link, else a copy. */
internal fun link(source: File, target: File) {
    target.parentFile.mkdirs()
    runCatching { Files.createSymbolicLink(target.toPath(), source.toPath()) }
        .recoverCatching { Files.createLink(target.toPath(), source.toPath()) }
        .getOrElse { source.copyTo(target) }
}
