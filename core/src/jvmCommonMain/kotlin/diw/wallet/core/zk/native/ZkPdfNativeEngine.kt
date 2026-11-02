package diw.wallet.core.zk.native

import diw.wallet.core.zk.ZkErrors
import diw.wallet.core.zk.ZkPdfAssets
import diw.wallet.core.zk.ZkPdfCost
import diw.wallet.core.zk.ZkPdfEngine
import diw.wallet.core.zk.ZkPdfProofOutput
import diw.wallet.core.zk.ZkPdfSegment
import diw.wallet.core.zk.ZkPdfStatement
import diw.wallet.core.zk.ZkPdfVerifiedOutput
import diw.wallet.core.zk.ZkPdfWitness
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.bindings.ZkCancelToken
import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.ZkPdfAnchorInput
import diw.wallet.core.zk.native.bindings.ZkPdfAnchorPublic
import diw.wallet.core.zk.native.bindings.ZkPdfBundle
import diw.wallet.core.zk.native.bindings.ZkPdfDigitTable
import diw.wallet.core.zk.native.bindings.ZkPdfPredicateInput
import diw.wallet.core.zk.native.bindings.ZkPdfProveInput
import diw.wallet.core.zk.native.bindings.ZkPdfRecord
import diw.wallet.core.zk.native.bindings.ZkPdfSegmentProof
import diw.wallet.core.zk.native.bindings.ZkPdfSlotInput
import diw.wallet.core.zk.native.bindings.ZkPdfSlotPublic
import diw.wallet.core.zk.native.bindings.ZkPdfVerifierSpec
import diw.wallet.core.zk.native.bindings.ZkPdfWindowInput
import diw.wallet.core.zk.native.bindings.ZkPdfWindowPublic
import diw.wallet.core.zk.native.bindings.ZkProgress
import diw.wallet.core.zk.native.bindings.zkpdfCheck
import diw.wallet.core.zk.native.bindings.zkpdfProve
import diw.wallet.core.zk.native.bindings.zkpdfVerify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * zkPDF through the Rust prover (native/zkpdf-prover). The native code reads the flat asset directory and checks
 * every circuit, verification key and CRS file against its own pinned SHA-256, so only presence and size are checked
 * here. One proof or check at a time: a proof holds about 2 GB at its peak.
 */
class ZkPdfNativeEngine(private val store: FileZkAssetStore) : ZkPdfEngine {
    private val lock = Mutex()

    override fun ready(composition: String, prover: Boolean): Boolean =
        ZkPdfAssets.required(composition, prover).all { store.installedFile(it) != null }

    private fun directory(composition: String, prover: Boolean): String? {
        val files = ZkPdfAssets.required(composition, prover).map { store.installedFile(it) ?: return null }
        return files.first().parentFile.absolutePath
    }

    override suspend fun check(statement: ZkPdfStatement, witness: ZkPdfWitness): ZkResult<ZkPdfCost> = native {
        val plan = zkpdfCheck(input(statement, witness, ""))
        ZkResult.Ok(ZkPdfCost(plan.totalSegments.toInt(), plan.estimatedProofBytes.toLong()))
    }

    override suspend fun prove(
        statement: ZkPdfStatement,
        witness: ZkPdfWitness,
        progress: (String, Int, Int) -> Unit,
    ): ZkResult<ZkPdfProofOutput> = native {
        val assets = directory(statement.composition, true) ?: return@native MISSING_ASSETS
        cancellable { token ->
            val result = zkpdfProve(input(statement, witness, assets), token, object : ZkProgress {
                override fun onProgress(kind: String, index: UInt, total: UInt) = progress(kind, index.toInt(), total.toInt())
            })
            // The Rust prover verifies every segment before it returns; check the whole bundle against the policy too.
            try {
                zkpdfVerify(spec(statement), result.bundle, assets)
            } catch (_: ZkException.InvalidInput) {
                return@cancellable SELF_CHECK_FAILED
            }
            ZkResult.Ok(
                ZkPdfProofOutput(
                    result.bundle.segments.map { ZkPdfSegment(it.kind, it.index.toInt(), it.proof, it.publicInputs) },
                    result.midOuts, result.claimRecords, result.claimDigests, result.proveMs.toLong(),
                ),
            )
        }
    }

    override suspend fun verify(statement: ZkPdfStatement, segments: List<ZkPdfSegment>): ZkResult<ZkPdfVerifiedOutput?> = native {
        val assets = directory(statement.composition, false) ?: return@native MISSING_ASSETS
        val bundle = ZkPdfBundle(statement.composition, segments.map {
            require(it.index >= 0)
            ZkPdfSegmentProof(it.kind, it.index.toUInt(), it.proof, it.publicInputs)
        })
        try {
            val verified = zkpdfVerify(spec(statement), bundle, assets)
            ZkResult.Ok(ZkPdfVerifiedOutput(verified.midOuts, verified.claimDigests))
        } catch (e: ZkException.InvalidInput) {
            // A malformed or non-matching bundle is a rejection, not an engine failure.
            ZkResult.Ok(null)
        }
    }

    private suspend fun <T> native(block: suspend () -> ZkResult<T>): ZkResult<T> = lock.withLock {
        withContext(Dispatchers.IO) {
            try {
                block()
            } catch (e: ZkException) {
                ZkNative.failure(e)
            } catch (_: IllegalArgumentException) {
                ZkErrors.invalidInput
            } catch (_: OutOfMemoryError) {
                ZkErrors.resources
            }
        }
    }

    /** Cancelling the calling coroutine stops the native call through the token. */
    private suspend fun <T> cancellable(block: (ZkCancelToken) -> T): T = ZkCancelToken().use { token ->
        coroutineScope {
            val watcher = launch { try { awaitCancellation() } finally { token.cancel() } }
            try {
                block(token)
            } finally {
                watcher.cancel()
            }
        }
    }

    companion object {
        val MISSING_ASSETS = ZkResult.Failed("zkPDF 的電路檔尚未下載完成", false)
        val SELF_CHECK_FAILED = ZkResult.Failed("產生的證明沒有通過這台裝置的驗證，未寫入憑證", true)

        private fun record(r: diw.wallet.core.document.zkpdf.ZkPdfTextRecord) = ZkPdfRecord(r.font, r.kind.toUByte(), r.strings)

        private fun tables(s: ZkPdfStatement) = s.digitTables.map { ZkPdfDigitTable(it.font, it.width.toUByte(), it.codes.map(Int::toUInt)) }

        private fun predicates(s: ZkPdfStatement) = s.predicates.map {
            ZkPdfPredicateInput(it.kind.toUByte(), it.slot.toUInt(), it.format.toUByte(), it.cutoff.toUInt())
        }

        internal fun input(s: ZkPdfStatement, w: ZkPdfWitness, assets: String): ZkPdfProveInput {
            require(w.privateData.size == s.windows.size && w.salts.size == s.slots.size && w.salts.all { it.size == 16 })
            return ZkPdfProveInput(
                s.composition, s.binding,
                s.windows.mapIndexed { i, x -> ZkPdfWindowInput(x.role, x.midIn, x.head, w.privateData[i], x.tail, x.keyStream) },
                s.anchors.map { ZkPdfAnchorInput(record(it.record), it.ordinal.toUInt()) },
                s.slots.mapIndexed { i, x -> ZkPdfSlotInput(x.slot.toUInt(), x.beforeAnchor.toUInt(), x.afterAnchor.toUInt(), w.salts[i]) },
                tables(s), predicates(s), assets,
            )
        }

        internal fun spec(s: ZkPdfStatement) = ZkPdfVerifierSpec(
            s.composition, s.binding,
            s.windows.map { ZkPdfWindowPublic(it.role, it.midIn, it.blocks.toUInt(), it.head, it.tail, it.keyStream) },
            s.anchors.map { ZkPdfAnchorPublic(record(it.record), it.ordinal.toUInt(), it.total.toUInt()) },
            s.slots.map { ZkPdfSlotPublic(it.slot.toUInt(), it.beforeAnchor.toUInt(), it.afterAnchor.toUInt()) },
            tables(s), predicates(s),
        )
    }
}
