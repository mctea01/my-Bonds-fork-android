package diw.wallet.app.android

import android.content.Context
import android.graphics.Bitmap
import com.googlecode.tesseract.android.TessBaseAPI
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Machine readable zone OCR with Tesseract and tessdata_fast's English model (both Apache-2.0), limited to the
 * zone's characters. Everything runs on this device; the model is copied from the app assets once.
 */
internal class TesseractMrzReader(context: Context) : MrzTextReader {
    private val api = TessBaseAPI()
    private val lock = Mutex()
    private var ready = false

    init {
        val dir = File(context.filesDir, "ocr")
        val model = File(dir, "tessdata/eng.traineddata")
        if (!model.isFile || model.length() == 0L) {
            model.parentFile?.mkdirs()
            val partial = File(model.path + ".part")
            context.assets.open("tessdata/eng.traineddata").use { input -> partial.outputStream().use { input.copyTo(it) } }
            partial.renameTo(model)
        }
        ready = api.init(dir.absolutePath, "eng", TessBaseAPI.OEM_LSTM_ONLY)
        if (ready) {
            api.setVariable(TessBaseAPI.VAR_CHAR_WHITELIST, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<")
            api.setVariable("load_system_dawg", "0")
            api.setVariable("load_freq_dawg", "0")
            api.pageSegMode = TessBaseAPI.PageSegMode.PSM_SINGLE_BLOCK
        }
    }

    override suspend fun read(bitmap: Bitmap): String = withContext(Dispatchers.Default) {
        lock.withLock {
            if (!ready) return@withLock ""
            api.setImage(bitmap)
            try { api.getUTF8Text().orEmpty() } finally { api.clear() }
        }
    }

    /** Frees the engine once a read in progress has finished. */
    override fun close() {
        CoroutineScope(Dispatchers.Default).launch {
            lock.withLock {
                if (ready) api.recycle()
                ready = false
            }
        }
    }
}

/** The OCR engine this build ships for the zone. */
internal fun mrzTextReader(context: Context): MrzTextReader = TesseractMrzReader(context.applicationContext)
