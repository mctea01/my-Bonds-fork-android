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
 * it appears; an instruction that stays on screen is repeated [REPEAT_MS] after it was last heard in full. Uses the
 * phone's own text-to-speech engine; the texts are the app's fixed instructions, never personal data. Everything runs
 * on the main thread.
 */
internal class FaceVoice(context: Context, languageTag: String, private val intro: String) {
    private val main = Handler(Looper.getMainLooper())
    private var tts: TextToSpeech? = null
    private var ready = false
    private var introDone = false
    private var closing = false
    private var closed = false
    private var last: String? = null
    private var lastAt = 0L
    private var speaking: String? = null
    private var count = 0
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
                main.post { ended(utteranceId) }
            }

            override fun onStop(utteranceId: String?, interrupted: Boolean) {
                main.post { ended(utteranceId) }
            }

            @Deprecated("Deprecated in Java")
            override fun onError(utteranceId: String?) {
                main.post { ended(utteranceId) }
            }
        })
        ready = true
        engine.speak(intro, TextToSpeech.QUEUE_FLUSH, null, INTRO)
        // An engine that never reports the end of the intro must not keep the instructions quiet.
        main.postDelayed({ finishIntro() }, INTRO_MAX_MS)
    }

    private fun ended(utteranceId: String?) {
        if (utteranceId == INTRO) return finishIntro()
        if (utteranceId == null || utteranceId != speaking) return
        speaking = null
        lastAt = SystemClock.elapsedRealtime()
        if (closing) shutdown()
    }

    private fun finishIntro() {
        if (introDone) return
        introDone = true
        pending?.let { say(it) }
    }

    /** The message now on screen; called after every frame, so most calls repeat the last one and say nothing. */
    fun update(message: String?) {
        if (message.isNullOrBlank()) return
        main.post { if (!closing) say(message) }
    }

    private fun say(message: String) {
        if (closed) return
        val engine = tts
        if (engine == null || !ready || !introDone) {
            pending = message
            return
        }
        pending = null
        // The same instruction waits until it was heard in full, however slow the holder's speech rate is.
        if (message == last && (speaking != null || SystemClock.elapsedRealtime() - lastAt < REPEAT_MS)) return
        last = message
        val id = FACE + (++count)
        speaking = id
        if (engine.speak(message, TextToSpeech.QUEUE_FLUSH, null, id) != TextToSpeech.SUCCESS) ended(id)
    }

    /**
     * Takes no further messages and stops once the last one was heard in full, however slow the speech rate; a message
     * still held behind the intro is spoken first.
     */
    fun close() {
        main.post {
            if (closing) return@post
            closing = true
            val held = pending
            if (held != null && ready && tts != null) {
                introDone = true
                say(held)
            }
            if (speaking == null) shutdown() else main.postDelayed({ shutdown() }, CLOSE_MAX_MS)
        }
    }

    private fun shutdown() {
        if (closed) return
        closed = true
        main.removeCallbacksAndMessages(null)
        tts?.let { runCatching { it.shutdown() } }
        tts = null
    }

    private companion object {
        const val INTRO = "intro"
        const val FACE = "face"
        const val REPEAT_MS = 5000L
        const val INTRO_MAX_MS = 8000L
        /** An engine that never reports the end of the last message is released after this long. */
        const val CLOSE_MAX_MS = 30000L
    }
}
