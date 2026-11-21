package diw.wallet.app

import diw.wallet.app.res.Res
import diw.wallet.app.res.zkp_answer_err_facematch_mismatch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The English messages of the Multipaz FaceNet camera screen (0.102.0) shown in the app's language. */
class FaceMatchTextTest {
    @Test
    fun cameraMessagesFollowTheLoadedLanguage() = runBlocking<Unit> {
        try {
            AppText.load("zh-TW")
            assertEquals("與護照照片不符", FaceMatchText.localize("Face does not match reference portrait"))
            assertEquals("請把頭轉向左邊（第 2 步，共 3 步）", FaceMatchText.localize("Turn your head left (Step 2 of 3)"))
            assertEquals("請保持不動…（第 1 步，共 3 步）", FaceMatchText.localize("Hold still... (Step 1 of 3)"))
            // A message the library adds later is shown as it is.
            assertEquals("Something new", FaceMatchText.localize("Something new"))
            assertEquals("Something new (Step 1 of 2)", FaceMatchText.localize("Something new (Step 1 of 2)"))
            assertTrue(FaceMatchText.isReferenceFailure("Could not extract face from reference photo"))
            assertTrue(!FaceMatchText.isReferenceFailure("No face detected"))
            assertEquals(
                "人臉比對沒有通過：與護照照片的相似度最高 0.52，未達門檻 0.63。請求方沒有收到任何資料。",
                tr(Res.string.zkp_answer_err_facematch_mismatch, FaceMatchText.score(0.5249f), FaceMatchText.score(0.63f)),
            )
            AppText.load("en")
            assertEquals("Look straight ahead", FaceMatchText.localize("Look straight ahead"))
            assertEquals("Turn your head to the right (step 3 of 3)", FaceMatchText.localize("Turn your head right (Step 3 of 3)"))
        } finally {
            AppText.load(null)
        }
    }

    @Test
    fun scoresHaveTwoDecimals() {
        assertEquals("0.63", FaceMatchText.score(0.63f))
        assertEquals("0.50", FaceMatchText.score(0.5f))
        assertEquals("0.05", FaceMatchText.score(0.049f))
        assertEquals("1.00", FaceMatchText.score(1f))
        assertEquals("-0.12", FaceMatchText.score(-0.12f))
    }
}
