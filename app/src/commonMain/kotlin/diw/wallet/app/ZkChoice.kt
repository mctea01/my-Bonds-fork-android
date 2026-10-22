package diw.wallet.app

/** Where a proof is produced when this device is short of resources (p4-zkp.md section 8). */
enum class ZkChoiceKind { ON_DEVICE, DESKTOP, SELF_HOSTED, WITHOUT_ZK }

data class ZkChoiceOption(
    val kind: ZkChoiceKind,
    val title: String,
    val detail: String,
    val enabled: Boolean,
    val recommended: Boolean,
)

/** What the caller offers besides producing the proof here. */
data class ZkChoiceContext(
    /** A self-hosted prover was added in the settings (zkPDF only). */
    val selfHostConfigured: Boolean = false,
    /** What happens when the user goes on without a proof, e.g. "衍生憑證照一般方式產生"; null when there is no such path. */
    val withoutZk: String? = null,
)

private fun mb(bytes: Long) = "${bytes / (1024L * 1024L)} MB"

/**
 * The options of the choice screen. Low compute never blocks: producing the proof here stays available whenever the
 * engine can run at all, with its estimate and risks; only a missing library or architecture disables it.
 */
fun zkChoiceOptions(readiness: ZkReadiness, context: ZkChoiceContext = ZkChoiceContext()): List<ZkChoiceOption> {
    val info = readiness.platform
    val desktop = info?.isDesktop == true
    val here = buildList {
        readiness.kind.peakMemoryMb?.let { peak ->
            add("預估記憶體峰值 $peak MB" + (info?.let { "（目前可用 ${it.availableRamMb} MB）" } ?: ""))
        }
        if (readiness.missing.isNotEmpty()) add("需先下載 ${mb(readiness.downloadBytes)}，安裝後佔用 ${mb(readiness.installedBytes)}")
        if (!readiness.recommended) add("可能被系統中止；可隨時取消，最長執行 ${ZkModel.EXTENDED_TIMEOUT.inWholeMinutes} 分鐘")
    }
    val onDevice = ZkChoiceOption(
        ZkChoiceKind.ON_DEVICE,
        if (readiness.recommended) "在這台裝置產生" else "仍在這台裝置產生",
        if (readiness.canRunHere) here.joinToString("。").ifEmpty { "在背景產生，可隨時取消" }
        else readiness.advice ?: "這台裝置無法產生此證明",
        enabled = readiness.canRunHere,
        recommended = readiness.recommended,
    )
    return buildList {
        add(onDevice)
        if (!desktop) add(
            ZkChoiceOption(
                ZkChoiceKind.DESKTOP,
                if (readiness.kind.answersVerifier) "改用電腦版回應" else "在電腦版產生後匯入",
                if (readiness.kind.answersVerifier) "在電腦版錢包加入同一張卡片後，掃描查驗方的 QR Code 回應"
                else "在電腦版開啟同一份文件產生證據檔，再匯入這台裝置；以文件的 SHA-256 確認是同一份",
                enabled = true,
                recommended = !readiness.recommended,
            ),
        )
        if (readiness.kind == ZkProofKind.PDF) add(
            ZkChoiceOption(
                ZkChoiceKind.SELF_HOSTED,
                "送到自架主機產生",
                if (context.selfHostConfigured) "主機會看到整份文件；回傳的證明會先在這台裝置驗證再使用"
                else "需先在設定的「零知識證明」頁加入自架主機",
                enabled = context.selfHostConfigured,
                recommended = false,
            ),
        )
        context.withoutZk?.let {
            add(ZkChoiceOption(ZkChoiceKind.WITHOUT_ZK, "不加零知識證據", "$it；隱私較低", enabled = true, recommended = false))
        }
    }
}
