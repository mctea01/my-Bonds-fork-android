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
import java.util.UUID

/**
 * OpenAC age proofs as Bonds makes them: Prepare over the SD-JWT, Show over the nonce signature and cutoff, fresh
 * shared blinds and both reblinds, then a mandatory check against the expected issuer key before anything is
 * returned. Each proof runs in its own scratch tree under [workDirectory] that links the installed assets into the
 * layout the native code reads, and is deleted afterwards.
 */
class OpenAcAgeNativeProver(
    private val store: FileZkAssetStore,
    private val workDirectory: File,
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
                        run(documents.absolutePath, input, token, step)
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

    private fun run(path: String, input: OpenAcAgeInput, token: ZkCancelToken, step: (String) -> Unit): ZkResult<OpenAcAgeProof> {
        step("準備憑證")
        var started = System.nanoTime()
        val prepared = createAgePrepareInput(path, input.sdJwt, input.issuerKeyX, input.issuerKeyY)
        proveJwt(path, token)
        var prepareMs = elapsed(started)
        val format = prepared.claimFormat.toInt()
        val cutoff = input.cutoff(format).toULong()

        step("產生年齡證明")
        started = System.nanoTime()
        createAgeShowInput(path, input.nonce, input.deviceSignature, prepared.claimName, prepared.claimFormat, cutoff)
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
        val accepted = verifyAgePresentation(path, input.nonce, prepared.claimName, prepared.claimFormat, cutoff,
            input.issuerKeyX, input.issuerKeyY, token)
        if (!accepted) return SELF_CHECK_FAILED
        val keys = File(path, "keys")
        return ZkResult.Ok(
            OpenAcAgeProof(prepared.claimName, format, File(keys, "prepare_proof.bin").readBytes(),
                File(keys, "show_proof.bin").readBytes(), prepareMs, showMs),
        )
    }

    private fun elapsed(since: Long) = (System.nanoTime() - since) / 1_000_000

    /** A symbolic link where the platform allows one, else a hard link, else a copy. */
    private fun link(source: File, target: File) {
        target.parentFile.mkdirs()
        runCatching { Files.createSymbolicLink(target.toPath(), source.toPath()) }
            .recoverCatching { Files.createLink(target.toPath(), source.toPath()) }
            .getOrElse { source.copyTo(target) }
    }

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
        val MISSING_ASSETS = ZkResult.Failed("年齡證明的電路檔尚未下載完成", false)
        val SELF_CHECK_FAILED = ZkResult.Failed("產生的證明沒有通過這台裝置的驗證，未送出", true)
    }
}
