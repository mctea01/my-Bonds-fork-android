package diw.wallet.app.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.unit.sp
import org.multipaz.compose.prompt.FaceMatcherLivenessPromptDialog
import org.multipaz.compose.prompt.FaceMatcherPromptDialog
import org.multipaz.compose.prompt.PromptDialogs
import org.multipaz.compose.prompt.defaultToHumanReadable
import org.multipaz.prompt.AndroidPromptModel
import org.multipaz.prompt.FaceMatcherLivenessPromptDialogModel
import org.multipaz.prompt.FaceMatcherPromptDialogModel
import org.multipaz.prompt.getFaceMatcherDialogModel
import org.multipaz.prompt.getFaceMatcherLivenessDialogModel

/**
 * Multipaz's prompts, with the face match screens in larger type: the holder may have to take off glasses for the
 * camera and still read the instructions (docs/design/zkpassport.md 5.6).
 */
@Composable
internal fun WalletPromptDialogs(promptModel: AndroidPromptModel) {
    PromptDialogs(
        promptModel,
        excludeTypes = listOf(FaceMatcherPromptDialogModel.DialogType, FaceMatcherLivenessPromptDialogModel.DialogType),
    )
    val base = MaterialTheme.typography
    val large = remember(base) {
        base.copy(
            headlineSmall = base.headlineSmall.copy(fontSize = 30.sp, lineHeight = 38.sp),
            titleMedium = base.titleMedium.copy(fontSize = 30.sp, lineHeight = 38.sp),
            bodyLarge = base.bodyLarge.copy(fontSize = 21.sp, lineHeight = 28.sp),
        )
    }
    MaterialTheme(colorScheme = MaterialTheme.colorScheme, shapes = MaterialTheme.shapes, typography = large) {
        FaceMatcherPromptDialog(promptModel.getFaceMatcherDialogModel(), ::defaultToHumanReadable)
        FaceMatcherLivenessPromptDialog(promptModel.getFaceMatcherLivenessDialogModel(), ::defaultToHumanReadable)
    }
}
