package diw.wallet.core.zk

import kotlinx.serialization.Serializable

enum class ZkTier { A, B, C }

@Serializable
enum class ZkBackend { NOIR_ULTRAHONK, TLSN, OPENAC_SPARTAN2, LONGFELLOW }

data class ZkPlatformInfo(
    val abi: String,
    val totalRamMb: Long,
    val availableRamMb: Long,
    val freeDiskMb: Long,
    val isDesktop: Boolean,
)

data class ZkCapability(val tier: ZkTier, val backends: Set<ZkBackend>, val reasons: Map<ZkBackend, String>)

/** Reports actual loaded engines, including engines supplied outside the Rust library. */
data class ZkNativeStatus(val backends: Set<ZkBackend>, val version: String)

/** Initial advisory limits; WP1 replaces these with measured limits. Units are MiB. */
object ZkThresholds {
    const val TIER_A_RAM_MB = 8192L
    const val TIER_B_RAM_MB = 6144L
    const val PROVER_AVAILABLE_RAM_MB = 3072L
    const val PROVER_FREE_DISK_MB = 2048L
}

object ZkCapabilities {
    fun evaluate(platform: ZkPlatformInfo, native: ZkNativeStatus?): ZkCapability {
        val abi = platform.abi.lowercase()
        val arm64 = abi in setOf("arm64-v8a", "aarch64", "arm64", "macos-aarch64")
        val supported = arm64 || abi in setOf("x86_64", "amd64", "linux-x86_64", "windows-x86_64")
        val tier = when {
            arm64 && platform.totalRamMb >= ZkThresholds.TIER_A_RAM_MB -> ZkTier.A
            supported && platform.totalRamMb >= ZkThresholds.TIER_B_RAM_MB -> ZkTier.B
            else -> ZkTier.C
        }
        val backends = if (supported) native?.backends.orEmpty().toMutableSet() else mutableSetOf()
        if (abi == "windows-x86_64") backends.remove(ZkBackend.LONGFELLOW)
        val reasons = ZkBackend.entries.associateWith { backend ->
            when {
                !supported -> "此處理器架構沒有可用的零知識原生程式庫"
                abi == "windows-x86_64" && backend == ZkBackend.LONGFELLOW -> "Windows 尚無 Longfellow 原生程式庫"
                native == null -> "零知識原生程式庫無法載入"
                backend !in backends -> "此版本尚未包含此證明後端"
                platform.freeDiskMb < ZkThresholds.PROVER_FREE_DISK_MB -> "可用儲存空間偏低，建議先釋放空間或使用電腦版"
                tier == ZkTier.C || platform.availableRamMb < ZkThresholds.PROVER_AVAILABLE_RAM_MB ->
                    "可用記憶體偏低，仍可嘗試產生，或改用電腦版"
                backend == ZkBackend.NOIR_ULTRAHONK && tier == ZkTier.B -> "建議使用電腦版，手機效能仍待量測"
                else -> ""
            }
        }.filterValues { it.isNotEmpty() }
        return ZkCapability(tier, backends.toSet(), reasons)
    }
}

sealed interface ZkResult<out T> {
    data class Ok<T>(val value: T) : ZkResult<T>
    data class Failed(val reason: String, val retryable: Boolean) : ZkResult<Nothing>
    data object Cancelled : ZkResult<Nothing>
}

/** Backend error details are deliberately not echoed: they may contain private input. */
object ZkErrors {
    val invalidInput = ZkResult.Failed("證明輸入不符合要求", false)
    val unsupported = ZkResult.Failed("目前裝置或版本不支援此操作", false)
    val resources = ZkResult.Failed("可用資源不足，請稍後重試或使用電腦版", true)
    val internal = ZkResult.Failed("零知識作業失敗，請重試", true)
}
