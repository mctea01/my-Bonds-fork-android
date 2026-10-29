package diw.wallet.app.android

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.FileProvider
import diw.wallet.app.PickedFile
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

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

    private var pendingOpenMany: CompletableDeferred<List<Uri>>? = null

    private val openMany: ActivityResultLauncher<Array<String>> =
        activity.registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { pendingOpenMany?.complete(it) }

    private val create: ActivityResultLauncher<String> =
        activity.registerForActivityResult(object : ActivityResultContracts.CreateDocument("application/octet-stream") {
            override fun createIntent(context: Context, input: String): Intent = super.createIntent(context, input).setType(createType)
        }) { pendingCreate?.complete(it) }

    suspend fun pick(types: Array<String> = arrayOf("*/*")): PickedFile? {
        val d = CompletableDeferred<Uri?>()
        pendingOpen?.complete(null)
        pendingOpen = d
        withContext(Dispatchers.Main) { open.launch(types) }
        val uri = d.await() ?: return null
        return read(activity, uri)
    }

    /** Several files at once; files that cannot be read are left out. */
    suspend fun pickMany(): List<PickedFile> {
        val d = CompletableDeferred<List<Uri>>()
        pendingOpenMany?.complete(emptyList())
        pendingOpenMany = d
        withContext(Dispatchers.Main) { openMany.launch(arrayOf("*/*")) }
        return d.await().mapNotNull { read(activity, it) }
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

    private var pendingShare: CompletableDeferred<Unit>? = null

    private val shareSheet: ActivityResultLauncher<Intent> =
        activity.registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { pendingShare?.complete(Unit) }

    /**
     * Hands a copy of [bytes] to another app through the share sheet. The copy lives under cache/share and is
     * removed by [clearShared]: copies older than [SHARE_KEEP_MS] when the app returns to the foreground (the
     * receiving app may still be reading it when the sheet closes), and all of them when the app starts or closes.
     */
    suspend fun share(name: String, mediaType: String, bytes: ByteArray): Boolean {
        val file = withContext(Dispatchers.IO) {
            clearShared(activity, SHARE_KEEP_MS)
            val dir = File(shareRoot(activity), UUID.randomUUID().toString()).apply { mkdirs() }
            File(dir, safeName(name)).apply { writeBytes(bytes) }
        }
        val uri = FileProvider.getUriForFile(activity, activity.packageName + ".share", file)
        val type = mediaType.takeIf { '*' !in it && '/' in it } ?: "application/octet-stream"
        val send = Intent(Intent.ACTION_SEND)
            .setType(type)
            .putExtra(Intent.EXTRA_STREAM, uri)
            .putExtra(Intent.EXTRA_TITLE, file.name)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        send.clipData = ClipData.newUri(activity.contentResolver, file.name, uri)
        val chooser = Intent.createChooser(send, file.name).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        val d = CompletableDeferred<Unit>()
        pendingShare?.complete(Unit)
        pendingShare = d
        return try {
            withContext(Dispatchers.Main) { shareSheet.launch(chooser) }
            d.await()
            true
        } catch (e: android.content.ActivityNotFoundException) {
            false
        }
    }

    companion object {
        private const val MAX_BYTES = 64 * 1024 * 1024
        /** How long a shared copy is kept for the receiving app once the wallet is back in the foreground. */
        private const val SHARE_KEEP_MS = 10 * 60 * 1000L

        private fun shareRoot(context: Context) = File(context.cacheDir, "share")

        /** The file name as given, with only path separators and control characters replaced; Chinese names stay as they are. */
        private fun safeName(name: String): String =
            name.map { if (it == '/' || it == '\\' || it.code < 0x20) '_' else it }.joinToString("").trim().ifEmpty { "document" }.take(200)

        /** Removes shared copies older than [olderThanMs]; 0 removes all of them. */
        fun clearShared(context: Context, olderThanMs: Long = 0) {
            val now = System.currentTimeMillis()
            shareRoot(context).listFiles()?.forEach { dir ->
                if (olderThanMs == 0L || now - dir.lastModified() > olderThanMs) dir.deleteRecursively()
            }
        }

        /** Removes shared copies older than the keep time, for when the app returns to the foreground. */
        fun clearStaleShared(context: Context) = clearShared(context, SHARE_KEEP_MS)

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
