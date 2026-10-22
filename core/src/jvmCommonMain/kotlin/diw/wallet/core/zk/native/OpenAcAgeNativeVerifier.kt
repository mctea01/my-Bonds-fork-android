package diw.wallet.core.zk.native

import diw.wallet.core.zk.OpenAcAgeCheck
import diw.wallet.core.zk.OpenAcAgeVerifier
import diw.wallet.core.zk.ZkErrors
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.bindings.ZkCancelToken
import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.verifyAgePresentation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.util.UUID

/**
 * Checks posted OpenAC age presentations as Bonds' web verifier does: only the two verifying keys are linked into a
 * scratch tree under [workDirectory], with the posted proofs beside them. One check at a time, since each loads the
 * 432 MB Prepare verifying key.
 */
class OpenAcAgeNativeVerifier(
    private val store: FileZkAssetStore,
    private val workDirectory: File,
) : OpenAcAgeVerifier {
    private val lock = Mutex()

    override suspend fun verify(check: OpenAcAgeCheck): ZkResult<Boolean> = lock.withLock {
        withContext(Dispatchers.IO) {
            val keys = KEYS.associateWith { store.installedFile(it) ?: return@withContext OpenAcAgeNativeProver.MISSING_ASSETS }
            workDirectory.listFiles()?.forEach { it.deleteRecursively() }
            val documents = File(File(workDirectory, UUID.randomUUID().toString()), "circom")
            try {
                keys.forEach { (id, file) -> link(file, File(documents, "keys/$id")) }
                File(documents, "keys/prepare_proof.bin").writeBytes(check.prepareProof)
                File(documents, "keys/show_proof.bin").writeBytes(check.showProof)
                ZkCancelToken().use { token ->
                    coroutineScope {
                        val watcher = launch { try { awaitCancellation() } finally { token.cancel() } }
                        try {
                            ZkResult.Ok(
                                verifyAgePresentation(documents.absolutePath, check.nonce, check.claimName, check.claimFormat.toUByte(),
                                    check.cutoff.toULong(), check.issuerKeyX, check.issuerKeyY, token),
                            )
                        } finally {
                            watcher.cancel()
                        }
                    }
                }
            } catch (e: ZkException) {
                // A malformed proof is a rejection, not an engine failure.
                if (e is ZkException.InvalidInput) ZkResult.Ok(false) else ZkNative.failure(e)
            } catch (_: IOException) {
                ZkErrors.resources
            } finally {
                documents.parentFile.deleteRecursively()
            }
        }
    }

    companion object {
        val KEYS = listOf("prepare_verifying.key", "show_verifying.key")
    }
}
