package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.StringResource
import kotlin.math.abs
import kotlin.math.roundToInt

/**
 * The camera screen of Multipaz FaceNet shows the session's own messages, which the library writes in English only.
 * They are matched here word for word and shown in the app's language; a message the library adds later stays as
 * it is.
 */
object FaceMatchText {
    private val messages: Map<String, StringResource> = mapOf(
        "Position your face and look at the camera" to Res.string.face_msg_position,
        "Could not extract face from reference photo" to Res.string.face_msg_reference,
        "Missing reference face embedding" to Res.string.face_msg_reference,
        "Could not start camera pipeline" to Res.string.face_msg_start_failed,
        "Face verification timed out" to Res.string.face_msg_timeout,
        "No face detected" to Res.string.face_msg_no_face,
        "Ensure only one person is in the frame" to Res.string.face_msg_one_person,
        "Identity verified" to Res.string.face_msg_verified,
        "Hold still..." to Res.string.face_msg_hold_still,
        "Hold still and look directly at the camera..." to Res.string.face_msg_hold_look,
        "Liveness check failed - ensure you are not using a photo or screen" to Res.string.face_msg_liveness_failed,
        "Unable to confirm match - please hold still and look directly at the camera" to Res.string.face_msg_unconfirmed,
        "Face does not match reference portrait" to Res.string.face_msg_mismatch,
        "Turn your head slightly to the right" to Res.string.face_msg_slight_right,
        "Turn your head slightly to the left" to Res.string.face_msg_slight_left,
        "Tilt your head slightly down" to Res.string.face_msg_slight_down,
        "Tilt your head slightly up" to Res.string.face_msg_slight_up,
        "Keep your head level" to Res.string.face_msg_level,
        "Look directly at the camera" to Res.string.face_msg_look,
        "Portrait captured" to Res.string.face_msg_captured,
        "Liveness check timed out - please try again" to Res.string.face_msg_liveness_timeout,
        "Could not capture portrait photo" to Res.string.face_msg_capture_failed,
        "Turn your head left" to Res.string.face_msg_turn_left,
        "Turn your head right" to Res.string.face_msg_turn_right,
        "Tilt your head up" to Res.string.face_msg_tilt_up,
        "Tilt your head down" to Res.string.face_msg_tilt_down,
        "Look straight ahead" to Res.string.face_msg_straight,
    )

    private val step = Regex("""^(.*) \(Step (\d+) of (\d+)\)$""")

    fun localize(message: String): String {
        step.matchEntire(message)?.let { m ->
            val base = messages[m.groupValues[1]] ?: return message
            return tr(Res.string.face_msg_step, tr(base), m.groupValues[2].toInt(), m.groupValues[3].toInt())
        }
        return messages[message]?.let { tr(it) } ?: message
    }

    /** Whether [message] is the library's report that the document's photo gave no face. */
    fun isReferenceFailure(message: String?): Boolean = messages[message] == Res.string.face_msg_reference

    /** A similarity score with two decimals, as shown to the holder. */
    fun score(value: Float): String {
        val c = (value * 100).roundToInt().coerceIn(-100, 100)
        val a = abs(c)
        return (if (c < 0) "-" else "") + "${a / 100}." + (a % 100).toString().padStart(2, '0')
    }
}
