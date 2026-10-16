package diw.wallet.app.desktop

import com.sun.net.httpserver.HttpServer
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import diw.wallet.app.ExternalKeys
import diw.wallet.app.KeyBackend
import diw.wallet.app.NfcReaderList
import diw.wallet.app.PickedFile
import diw.wallet.app.PinOrPlatformUnlock
import diw.wallet.app.PlatformServices
import diw.wallet.app.softwareBackend
import diw.wallet.core.storage.EncryptedStorage
import diw.wallet.core.storage.ValueCipher
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.apache.pdfbox.Loader
import org.apache.pdfbox.rendering.ImageType
import org.apache.pdfbox.rendering.PDFRenderer
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.storage.Storage
import org.multipaz.storage.jdbc.JdbcStorage
import java.awt.Desktop
import java.awt.EventQueue
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** AES-256-GCM with a key derived from the App PIN; output is iv(12) || ciphertext || tag. */
class PinValueCipher(private val key: SecretKey) : ValueCipher {
    private val random = SecureRandom()

    override suspend fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        c.updateAAD(aad)
        return iv + c.doFinal(plaintext)
    }

    override suspend fun decrypt(ciphertext: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, ciphertext, 0, 12))
        c.updateAAD(aad)
        return c.doFinal(ciphertext, 12, ciphertext.size - 12)
    }

    companion object {
        private const val ITERATIONS = 600_000
        private val CHECK_AAD = "diw-wallet-pin-check".encodeToByteArray()

        /**
         * Derives the storage key with PBKDF2-HMAC-SHA256. The first call creates the salt and a check value;
         * later calls return null when the PIN does not open the check value.
         */
        suspend fun unlock(dir: File, pin: String): PinValueCipher? {
            dir.mkdirs()
            val saltFile = File(dir, "salt.bin")
            val checkFile = File(dir, "pin-check.bin")
            val salt = if (saltFile.exists()) saltFile.readBytes() else ByteArray(16).also { SecureRandom().nextBytes(it); saltFile.writeBytes(it) }
            val spec = PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, 256)
            val raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            spec.clearPassword()
            val cipher = PinValueCipher(SecretKeySpec(raw, "AES"))
            if (!checkFile.exists()) {
                checkFile.writeBytes(cipher.encrypt(salt, CHECK_AAD))
                return cipher
            }
            return try {
                if (cipher.decrypt(checkFile.readBytes(), CHECK_AAD).contentEquals(salt)) cipher else null
            } catch (_: AEADBadTagException) {
                null
            }
        }

        fun isInitialized(dir: File) = File(dir, "pin-check.bin").exists()
    }
}

/**
 * Pure software platform for PC and Linux. Credential keys live in the Software Secure Area sealed by the App PIN,
 * storage values are encrypted with a PIN-derived key, and the OID4VCI redirect uses a loopback listener (RFC 8252).
 */
class DesktopPlatform(
    private val dataDir: File,
    private val cipher: ValueCipher,
    private val onRedirect: (String) -> Unit,
) : PlatformServices {
    override val platformName = "${System.getProperty("os.name")} ${System.getProperty("os.version")} (JVM ${System.getProperty("java.version")})"

    private val server: HttpServer = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0).apply {
        createContext("/oid4vci/callback") { ex ->
            val query = ex.requestURI.rawQuery
            onRedirect(oid4vciRedirectUri + if (query != null) "?$query" else "")
            val body = "<html><head><meta charset=\"utf-8\"></head><body>授權完成，請回到 DIW MY WALLET。</body></html>".encodeToByteArray()
            ex.responseHeaders.add("Content-Type", "text/html; charset=utf-8")
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        start()
    }

    override val oid4vciRedirectUri: String = "http://127.0.0.1:${server.address.port}/oid4vci/callback"

    override suspend fun openStorage(): Storage =
        EncryptedStorage(JdbcStorage("jdbc:sqlite:" + File(dataDir, "diw-wallet-v1.db").absolutePath), cipher)

    override suspend fun keyBackends(storage: Storage, pinPrompt: suspend (String) -> String?): List<KeyBackend> =
        listOf(softwareBackend(storage, pinPrompt))

    override fun keyUnlockProvider(pinPrompt: suspend () -> String?): KeyUnlockDataProvider = PinOrPlatformUnlock(pinPrompt, null)

    override fun httpClient(): HttpClient = HttpClient(Java) { followRedirects = false }

    override fun openBrowser(url: String) {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(URI(url))
        } else {
            ProcessBuilder("xdg-open", url).start()
        }
    }

    override suspend fun renderPdf(bytes: ByteArray, maxPages: Int, widthPx: Int): List<ImageBitmap> = withContext(Dispatchers.IO) {
        runCatching {
            Loader.loadPDF(bytes).use { doc ->
                val renderer = PDFRenderer(doc)
                (0 until minOf(maxPages, doc.numberOfPages)).map { i ->
                    val widthPt = doc.getPage(i).cropBox.width.coerceAtLeast(1f)
                    renderer.renderImage(i, widthPx / widthPt, ImageType.RGB).toComposeImageBitmap()
                }
            }
        }.getOrDefault(emptyList())
    }

    /** PC/SC readers poll for cards and cannot emulate one, so a computer reads wallets but does not present by NFC. */
    override fun nfcPresentationUnavailableReason(): String = "電腦的 PC/SC 讀卡機只能讀取，不能模擬卡片；感應出示請使用手機"

    override suspend fun nfcReaders(): NfcReaderList = withContext(Dispatchers.IO) { PcscReaders.list() }

    override suspend fun pickFile(): PickedFile? = withContext(Dispatchers.IO) {
        val chosen = dialog("匯入文件", FileDialog.LOAD, null) ?: return@withContext null
        if (chosen.length() > MAX_FILE_BYTES) throw IllegalStateException("檔案超過 64 MB")
        PickedFile(chosen.name, chosen.readBytes())
    }

    override suspend fun pickFiles(): List<PickedFile> = withContext(Dispatchers.IO) {
        var chosen: List<File> = emptyList()
        EventQueue.invokeAndWait {
            val d = FileDialog(null as Frame?, "匯入文件（可選多個）", FileDialog.LOAD)
            d.isMultipleMode = true
            d.isVisible = true
            chosen = d.files.toList()
        }
        chosen.map { f ->
            if (f.length() > MAX_FILE_BYTES) throw IllegalStateException("${f.name} 超過 64 MB")
            PickedFile(f.name, f.readBytes())
        }
    }

    override suspend fun saveFile(name: String, mediaType: String, bytes: ByteArray): Boolean = withContext(Dispatchers.IO) {
        val chosen = dialog("另存文件", FileDialog.SAVE, name) ?: return@withContext false
        chosen.writeBytes(bytes)
        true
    }

    override fun openExternal(url: String): Boolean = runCatching { openBrowser(url) }.isSuccess

    override val externalKeys: ExternalKeys get() = DesktopKeys

    /** A native file dialog on the AWT event thread; null when cancelled. */
    private fun dialog(title: String, mode: Int, name: String?): File? {
        var result: File? = null
        EventQueue.invokeAndWait {
            val d = FileDialog(null as Frame?, title, mode)
            name?.let { d.file = it }
            d.isVisible = true
            if (d.file != null) result = File(d.directory, d.file)
        }
        return result
    }

    fun close() = server.stop(0)

    private companion object {
        const val MAX_FILE_BYTES = 64L * 1024 * 1024
    }
}
