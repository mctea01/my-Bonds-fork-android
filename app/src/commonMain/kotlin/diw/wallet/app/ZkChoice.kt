package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res

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
    /** Whether a proof made by the desktop wallet can be imported here yet. */
    val desktopImport: Boolean = true,
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
            add(tr(Res.string.zkc_peak, peak) + (info?.let { tr(Res.string.zkc_available, it.availableRamMb) } ?: ""))
        }
        if (readiness.missing.isNotEmpty()) add(tr(Res.string.zkc_download, mb(readiness.downloadBytes), mb(readiness.installedBytes)))
        if (!readiness.recommended) add(tr(Res.string.zkc_may_stop, readiness.kind.extendedTimeout.inWholeMinutes))
    }
    val onDevice = ZkChoiceOption(
        ZkChoiceKind.ON_DEVICE,
        if (readiness.recommended) tr(Res.string.zkc_on_device) else tr(Res.string.zkc_on_device_anyway),
        if (readiness.canRunHere) here.joinToString(tr(Res.string.sentence_end)).ifEmpty { tr(Res.string.zkc_background) }
        else readiness.advice ?: tr(Res.string.zkc_cannot_here),
        enabled = readiness.canRunHere,
        recommended = readiness.recommended,
    )
    return buildList {
        add(onDevice)
        if (!desktop) add(
            ZkChoiceOption(
                ZkChoiceKind.DESKTOP,
                if (readiness.kind.answersVerifier) tr(Res.string.zkc_desktop_answer) else tr(Res.string.zkc_desktop_import),
                when {
                    readiness.kind.answersVerifier -> tr(Res.string.zkc_desktop_answer_text)
                    context.desktopImport -> tr(Res.string.zkc_desktop_import_text)
                    else -> tr(Res.string.zkc_desktop_import_missing)
                },
                enabled = readiness.kind.answersVerifier || context.desktopImport,
                recommended = !readiness.recommended && (readiness.kind.answersVerifier || context.desktopImport),
            ),
        )
        if (readiness.kind == ZkProofKind.PDF) add(
            ZkChoiceOption(
                ZkChoiceKind.SELF_HOSTED,
                tr(Res.string.zkc_self_hosted),
                if (context.selfHostConfigured) tr(Res.string.zkc_self_hosted_text)
                else tr(Res.string.zkc_self_hosted_missing),
                enabled = context.selfHostConfigured,
                recommended = false,
            ),
        )
        context.withoutZk?.let {
            add(ZkChoiceOption(ZkChoiceKind.WITHOUT_ZK, tr(Res.string.zkc_without), tr(Res.string.zkc_without_text, it), enabled = true, recommended = false))
        }
    }
}
