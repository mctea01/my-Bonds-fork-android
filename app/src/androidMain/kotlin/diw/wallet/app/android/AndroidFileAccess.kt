package diw.wallet.app.android

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import diw.wallet.app.PickedFile
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The storage access framework for the vault: OpenDocument to pick a file, CreateDocument to save one. The
 * launchers are registered when the activity is created, as the result API requires.
 */
class AndroidFileAccess(private val activity: ComponentActivity) {
    private var pendingOpen: CompletableDeferred<Uri?>? = null
    private var pendingCreate: CompletableDeferred<Uri?>? = null
    private var createType = "application/octet-stream"

    private val open: ActivityResultLauncher<Array<String>> =
        activity.registerForActivityResult(ActivityResultContracts.OpenDocument()) { pendingOpen?.complete(it) }

    private val create: ActivityResultLauncher<String> =
        activity.registerForActivityResult(object : ActivityResultContracts.CreateDocument("application/octet-stream") {
            override fun createIntent(context: Context, input: String): Intent = super.createIntent(context, input).setType(createType)
        }) { pendingCreate?.complete(it) }

    suspend fun pick(): PickedFile? {
        val d = CompletableDeferred<Uri?>()
        pendingOpen?.complete(null)
        pendingOpen = d
        withContext(Dispatchers.Main) { open.launch(arrayOf("*/*")) }
        val uri = d.await() ?: return null
        return read(activity, uri)
    }

    suspend fun save(name: String, mediaType: String, bytes: ByteArray): Boolean {
        val d = CompletableDeferred<Uri?>()
        pendingCreate?.complete(null)
        pendingCreate = d
        createType = mediaType.takeIf { '*' !in it } ?: "application/octet-stream"
        withContext(Dispatchers.Main) { create.launch(name) }
        val uri = d.await() ?: return false
        return withContext(Dispatchers.IO) {
            activity.contentResolver.openOutputStream(uri, "w")?.use { it.write(bytes); true } ?: false
        }
    }

    companion object {
        private const val MAX_BYTES = 64 * 1024 * 1024

        /** Reads a content or file URI handed to the app (picker result, share or open-with). */
        suspend fun read(context: Context, uri: Uri): PickedFile? = withContext(Dispatchers.IO) {
            val resolver = context.contentResolver
            val name = runCatching {
                resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                    if (c.moveToFirst()) c.getString(0) else null
                }
            }.getOrNull() ?: uri.lastPathSegment?.substringAfterLast('/') ?: "document"
            val bytes = resolver.openInputStream(uri)?.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > MAX_BYTES) throw IllegalStateException("檔案超過 64 MB")
                }
                out.toByteArray()
            } ?: return@withContext null
            PickedFile(name, bytes, resolver.getType(uri))
        }
    }
}
