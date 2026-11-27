package diw.wallet.app.android

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import java.util.Locale

/**
 * Reads the face match instructions aloud (the zkPassport setting "read the face match instructions aloud"), so the
 * holder can take off glasses and still follow the camera screen. Speaks [intro] first, then each new instruction as
 * it appears; an instruction that stays on screen is repeated every [REPEAT_MS]. Uses the phone's own text-to-speech
 * engine; the texts are the app's fixed instructions, never personal data. Everything runs on the main thread.
 */
internal class FaceVoice(context: Context, languageTag: String, private val intro: String) {
    private val main = Handler(Looper.getMainLooper())
    private var tts: TextToSpeech? = null
    private var ready = false
    private var introDone = false
    private var closed = false
    private var last: String? = null
    private var lastAt = 0L
    private var pending: String? = null

    init {
        main.post {
            if (closed) return@post
            tts = TextToSpeech(context.applicationContext) { status -> main.post { started(status, languageTag) } }
        }
    }

    private fun started(status: Int, languageTag: String) {
        val engine = tts ?: return
        if (closed) return
        if (status != TextToSpeech.SUCCESS) {
            runCatching { engine.shutdown() }
            tts = null
            return
        }
        val locale = Locale.forLanguageTag(languageTag)
        if (engine.isLanguageAvailable(locale) >= TextToSpeech.LANG_AVAILABLE) engine.language = locale
        engine.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
            override fun onStart(utteranceId: String?) {}

            override fun onDone(utteranceId: String?) {
                if (utteranceId == INTRO) main.post { finishIntro() }
            }

            @Deprecated("Deprecated in Java")
            override fun onError(utteranceId: String?) {
                if (utteranceId == INTRO) main.post { finishIntro() }
            }
        })
        ready = true
        engine.speak(intro, TextToSpeech.QUEUE_FLUSH, null, INTRO)
        // An engine that never reports the end of the intro must not keep the instructions quiet.
        main.postDelayed({ finishIntro() }, INTRO_MAX_MS)
    }

    private fun finishIntro() {
        if (introDone) return
        introDone = true
        pending?.let { say(it) }
    }

    /** The message now on screen; called after every frame, so most calls repeat the last one and say nothing. */
    fun update(message: String?) {
        if (message.isNullOrBlank()) return
        main.post { say(message) }
    }

    private fun say(message: String) {
        if (closed) return
        val engine = tts
        if (engine == null || !ready || !introDone) {
            pending = message
            return
        }
        pending = null
        val now = SystemClock.elapsedRealtime()
        if (message == last && now - lastAt < REPEAT_MS) return
        last = message
        lastAt = now
        engine.speak(message, TextToSpeech.QUEUE_FLUSH, null, FACE)
    }

    /** Stops once the last message had time to be heard. */
    fun close() {
        main.postDelayed({
            closed = true
            main.removeCallbacksAndMessages(null)
            tts?.let { runCatching { it.shutdown() } }
            tts = null
        }, CLOSE_DELAY_MS)
    }

    private companion object {
        const val INTRO = "intro"
        const val FACE = "face"
        const val REPEAT_MS = 5000L
        const val INTRO_MAX_MS = 8000L
        const val CLOSE_DELAY_MS = 4000L
    }
}
