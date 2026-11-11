package diw.wallet.core.zk.native

import diw.wallet.core.zk.*
import diw.wallet.core.zk.native.bindings.*
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/** Invoke before using generated bindings. The app supplies its private data directory. */
object ZkNative {
    private var loaded: ZkNativeStatus? = null

    @Synchronized
    fun load(dataDirectory: File): ZkResult<ZkNativeStatus> {
        loaded?.let { return ZkResult.Ok(it) }
        return try {
            if (!android) {
                val target = unpack(dataDirectory, "diw_zk") ?: return ZkErrors.unsupported
                System.setProperty("uniffi.component.diw_zk.libraryOverride", target.absolutePath)
            }
            if (!selfTest()) return ZkErrors.internal
            val info = nativeInfo()
            val backends = info.features.mapNotNull { feature ->
                when (feature) {
                    "zkpdf" -> ZkBackend.NOIR_ULTRAHONK
                    "tlsn" -> ZkBackend.TLSN
                    "openac" -> ZkBackend.OPENAC_SPARTAN2
                    else -> null
                }
            }.toSet()
            val status = ZkNativeStatus(backends, info.crateVersion)
            loaded = status
            ZkResult.Ok(status)
        } catch (_: LinkageError) {
            ZkErrors.unsupported
        } catch (_: Exception) {
            ZkErrors.internal
        }
    }

    val android: Boolean get() = System.getProperty("java.vm.name", "").orEmpty().contains("Dalvik", ignoreCase = true)

    /** This desktop's directory under /zk/native in the resources; null on other systems. */
    private fun platform(): String? {
        val os = System.getProperty("os.name", "").orEmpty().lowercase()
        val arch = System.getProperty("os.arch", "").orEmpty().lowercase()
        return when {
            os.contains("linux") && arch in setOf("amd64", "x86_64") -> "linux-x86_64"
            os.contains("windows") && arch in setOf("amd64", "x86_64") -> "windows-x86_64"
            os.contains("mac") && arch in setOf("aarch64", "arm64") -> "macos-aarch64"
            else -> null
        }
    }

    private fun fileName(platform: String, base: String) = when (platform) {
        "windows-x86_64" -> "$base.dll"
        "macos-aarch64" -> "lib$base.dylib"
        else -> "lib$base.so"
    }

    /** Whether the desktop resources carry library [base] (diw_zk, diw_bb5) with its digest. */
    fun bundled(base: String): Boolean = platform()?.let {
        ZkNative::class.java.getResource("/zk/native/$it/${fileName(it, base)}.sha256") != null
    } == true

    /**
     * Copies the desktop library [base] from the resources under [dataDirectory], in a folder named by its pinned
     * SHA-256, and returns it; null when this system has none.
     */
    @Synchronized
    fun unpack(dataDirectory: File, base: String): File? {
        val platform = platform() ?: return null
        val name = fileName(platform, base)
        val resource = "/zk/native/$platform/$name"
        val expected = ZkNative::class.java.getResourceAsStream("$resource.sha256")?.use {
            it.readBytes().decodeToString().trim()
        } ?: return null
        require(Regex("[a-f0-9]{64}").matches(expected))
        val directory = File(dataDirectory, "zk-native/$expected").apply { mkdirs() }
        val target = File(directory, name)
        fun hash(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(65536)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
        }
        if (!target.isFile || hash(target) != expected) {
            val temporary = Files.createTempFile(directory.toPath(), "library-", ".part").toFile()
            try {
                val source = ZkNative::class.java.getResourceAsStream(resource) ?: return null
                source.use { input -> temporary.outputStream().use { input.copyTo(it) } }
                require(hash(temporary) == expected)
                Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } finally { temporary.delete() }
        }
        return target
    }

    fun failure(error: ZkException): ZkResult<Nothing> = when (error) {
        is ZkException.InvalidInput -> ZkErrors.invalidInput
        is ZkException.Unsupported -> ZkErrors.unsupported
        is ZkException.ResourceExhausted -> ZkErrors.resources
        is ZkException.Cancelled -> ZkResult.Cancelled
        is ZkException.Internal -> ZkErrors.internal
    }
}
