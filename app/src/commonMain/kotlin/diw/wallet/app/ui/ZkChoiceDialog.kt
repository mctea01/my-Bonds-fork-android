package diw.wallet.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import diw.wallet.app.ZkChoiceContext
import diw.wallet.app.ZkChoiceKind
import diw.wallet.app.ZkChoiceOption
import diw.wallet.app.ZkModel
import diw.wallet.app.ZkProofKind
import diw.wallet.app.ZkReadiness
import diw.wallet.app.zkChoiceOptions
import diw.wallet.core.zk.ZkAssetStatus
import kotlinx.coroutines.launch

/** The options as cards; disabled ones stay visible with their reason, the recommended one says so. */
@Composable
fun ZkChoicePanel(readiness: ZkReadiness, options: List<ZkChoiceOption>, onPick: (ZkChoiceOption) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            readiness.advice?.let { "這台裝置產生「${readiness.kind.label}」可能不順利：$it" }
                ?: "產生「${readiness.kind.label}」前需要你確認。",
            style = MaterialTheme.typography.bodyMedium,
        )
        options.forEach { option ->
            Card(
                Modifier.fillMaxWidth().then(if (option.enabled) Modifier.clickable { onPick(option) } else Modifier),
                shape = RoundedCornerShape(Tokens.CardRadius),
                colors = CardDefaults.cardColors(
                    containerColor = if (option.enabled) MaterialTheme.colorScheme.surfaceContainerLow
                    else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                ),
            ) {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                    Text(
                        option.title + if (option.recommended) "（建議）" else "",
                        style = MaterialTheme.typography.titleSmall,
                        color = if (option.enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.outline,
                    )
                    Text(option.detail, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

private sealed interface GateState {
    data object Checking : GateState
    data class Choose(val readiness: ZkReadiness) : GateState
    /** [choice] is what runs once the download completes: this device, or the self-hosted prover (verification keys only). */
    data class ConfirmDownload(val readiness: ZkReadiness, val extended: Boolean, val choice: ZkChoiceKind = ZkChoiceKind.ON_DEVICE) : GateState
    data class Downloading(val readiness: ZkReadiness, val extended: Boolean, val choice: ZkChoiceKind) : GateState
    data class SelfHostRisk(val readiness: ZkReadiness) : GateState
    data class DesktopRisk(val readiness: ZkReadiness) : GateState
}

/**
 * Runs before a proof: when this device suits it and the assets are installed it decides at once (ON_DEVICE, normal
 * limit); otherwise it asks, downloads what is missing after the user agrees to the size, and reports the choice.
 * extended is true when the user chose to produce the proof here against the advice, which lengthens the limit.
 */
@Composable
fun ZkProofGate(
    zk: ZkModel,
    kind: ZkProofKind,
    context: ZkChoiceContext = ZkChoiceContext(),
    /** The prover assets this proof needs, when it needs only some of the backend's (a zkPDF composition). */
    assets: Collection<String>? = null,
    /** The assets checking a proof made elsewhere (self-hosted prover, desktop wallet) needs: verification keys and CRS. */
    verifyAssets: Collection<String>? = null,
    onDecision: (choice: ZkChoiceKind, extended: Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    var state by remember(kind) { mutableStateOf<GateState>(GateState.Checking) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(kind) {
        val readiness = zk.readiness(kind, assets)
        state = when {
            // With a self-hosted prover the holder always picks where the proof is made.
            !readiness.recommended || context.selfHostConfigured && kind == ZkProofKind.PDF -> GateState.Choose(readiness)
            readiness.missing.isNotEmpty() -> GateState.ConfirmDownload(readiness, extended = false)
            else -> { onDecision(ZkChoiceKind.ON_DEVICE, false); return@LaunchedEffect }
        }
    }
    when (val s = state) {
        GateState.Checking -> Unit
        is GateState.Choose -> AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text("選擇產生方式") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    ZkChoicePanel(s.readiness, zkChoiceOptions(s.readiness, context)) { option ->
                        when (option.kind) {
                            ZkChoiceKind.ON_DEVICE ->
                                if (s.readiness.missing.isEmpty()) onDecision(ZkChoiceKind.ON_DEVICE, true)
                                else state = GateState.ConfirmDownload(s.readiness, extended = true)
                            ZkChoiceKind.SELF_HOSTED -> state = GateState.SelfHostRisk(s.readiness)
                            ZkChoiceKind.DESKTOP -> if (s.readiness.kind.answersVerifier) onDecision(ZkChoiceKind.DESKTOP, false)
                                else state = GateState.DesktopRisk(s.readiness)
                            else -> onDecision(option.kind, false)
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
        )
        is GateState.ConfirmDownload -> AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text("下載電路檔？") },
            text = {
                Text(
                    (if (s.choice != ZkChoiceKind.ON_DEVICE) "驗證在其他裝置產生的「${kind.label}」" else "產生「${kind.label}」") + "需要先下載 ${sizeText(s.readiness.downloadBytes)}，安裝後佔用 ${sizeText(s.readiness.installedBytes)}。" +
                        "建議使用 Wi-Fi；可隨時停止，下次會從中斷處續傳。每個檔案都會比對清單上的 SHA-256。",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    state = GateState.Downloading(s.readiness, s.extended, s.choice)
                    scope.launch {
                        zk.download(s.readiness.missing.map { it.id }).join()
                        val statuses = zk.assetStatus.value
                        if (s.readiness.missing.all { statuses[it.id] == ZkAssetStatus.READY }) onDecision(s.choice, s.extended)
                    }
                }) { Text("下載") }
            },
            dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
        )
        is GateState.Downloading -> {
            val downloads by zk.downloads.collectAsState()
            val failed = s.readiness.missing.firstNotNullOfOrNull { downloads[it.id]?.error }
            AlertDialog(
                onDismissRequest = {},
                title = { Text(if (failed != null) "下載未完成" else "正在下載電路檔") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        val received = s.readiness.missing.sumOf { a ->
                            val d = downloads[a.id]
                            when {
                                d != null && d.error == null -> d.received
                                zk.assetStatus.value[a.id] == ZkAssetStatus.READY -> a.gzipBytes
                                else -> 0L
                            }
                        }
                        val total = s.readiness.downloadBytes
                        Text("${sizeText(received)} / ${sizeText(total)}", style = MaterialTheme.typography.bodyMedium)
                        LinearProgressIndicator(progress = { if (total <= 0) 0f else received.toFloat() / total }, modifier = Modifier.fillMaxWidth())
                        failed?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                    }
                },
                confirmButton = {
                    if (failed != null) TextButton(onClick = { state = GateState.ConfirmDownload(s.readiness, s.extended, s.choice) }) { Text("重試") }
                },
                dismissButton = {
                    TextButton(onClick = { zk.cancelDownload(); onDismiss() }) { Text(if (failed != null) "關閉" else "停止下載") }
                },
            )
        }
        is GateState.SelfHostRisk -> RiskConfirmDialog(
            title = "把文件送到自架主機？",
            lines = listOf(
                "主機會收到 PDF 第 1 頁的內容（含不打算揭露的欄位）與證明需要的私密資料，但不是整份文件。",
                "請只使用你自己管理、信任的主機；傳輸與保存由主機負責，結果最多保留一小時。",
                "回傳的證明會先在這台裝置驗證，不通過就不使用；驗證需要電路的驗證金鑰。",
            ),
            confirm = "送出",
            onConfirm = {
                scope.launch { state = verifyFirst(zk, kind, verifyAssets, ZkChoiceKind.SELF_HOSTED, onDecision) }
            },
            onDismiss = { state = GateState.Choose(s.readiness) },
        )
        is GateState.DesktopRisk -> RiskConfirmDialog(
            title = "匯出證明請求檔？",
            lines = listOf(
                "請求檔含 PDF 第 1 頁的內容（含不打算揭露的欄位）與證明需要的私密資料，但不是整份文件。",
                "請只在你自己的電腦版錢包開啟，傳送後刪除；證明產生前請求一直保留在這台裝置等待。",
                "匯入的證明會先在這台裝置驗證，不通過就不使用；驗證需要電路的驗證金鑰。",
            ),
            confirm = "匯出",
            onConfirm = {
                scope.launch { state = verifyFirst(zk, kind, verifyAssets, ZkChoiceKind.DESKTOP, onDecision) }
            },
            onDismiss = { state = GateState.Choose(s.readiness) },
        )
    }
}

/** Decides [choice] once the verification assets are installed; otherwise asks to download them first. */
private suspend fun verifyFirst(
    zk: ZkModel,
    kind: ZkProofKind,
    assets: Collection<String>?,
    choice: ZkChoiceKind,
    onDecision: (ZkChoiceKind, Boolean) -> Unit,
): GateState {
    val verifying = zk.readiness(kind, assets)
    if (verifying.missing.isNotEmpty()) return GateState.ConfirmDownload(verifying, extended = false, choice = choice)
    onDecision(choice, false)
    return GateState.Checking
}
