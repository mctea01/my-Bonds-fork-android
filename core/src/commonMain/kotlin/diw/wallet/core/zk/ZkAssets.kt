package diw.wallet.core.zk

import kotlinx.serialization.Serializable

@Serializable
data class ZkAsset(
    val id: String,
    val backend: ZkBackend,
    val role: Set<String>,
    val urls: List<String>,
    val gzipSha256: String,
    val gzipBytes: Long,
    val installedSha256: String,
    val installedBytes: Long,
    val license: String,
)

enum class ZkAssetStatus { MISSING, PARTIAL, READY, CORRUPT }

interface ZkAssetStore {
    suspend fun status(id: String): ZkAssetStatus
    suspend fun download(id: String, onProgress: (Long, Long) -> Unit): ZkResult<Unit>
    fun path(id: String): String?
    suspend fun delete(id: String)
}

/** What a platform supplies for zero-knowledge proofs: its resources, the native engines and the verified assets. */
interface ZkEnvironment {
    suspend fun platformInfo(): ZkPlatformInfo

    /** Loads the native library once; later calls return the same result. */
    suspend fun loadNative(): ZkResult<ZkNativeStatus>

    /** The hash-pinned asset catalog; empty when the manifest is not bundled. */
    val catalog: List<ZkAsset>

    /** Null when the manifest is not bundled. */
    val assets: ZkAssetStore?

    /** The OpenAC age prover over [assets]; null where the platform has none. */
    val ageProver: OpenAcAgeProver? get() = null

    /** Checks posted OpenAC age presentations with the verifying keys in [assets]; null where the platform has none. */
    val ageVerifier: OpenAcAgeVerifier? get() = null

    /** TLSNotary proofs (zkTLS); null where the platform has none. Calls report Unsupported when the library lacks tlsn. */
    val tls: diw.wallet.core.zktls.ZkTlsEngine? get() = null
}
