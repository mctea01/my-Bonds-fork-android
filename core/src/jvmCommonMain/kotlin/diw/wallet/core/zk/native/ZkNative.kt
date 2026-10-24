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
            if (!System.getProperty("java.vm.name", "").orEmpty().contains("Dalvik", ignoreCase = true)) {
                val os = System.getProperty("os.name", "").orEmpty().lowercase()
                val arch = System.getProperty("os.arch", "").orEmpty().lowercase()
                val platform = when {
                    os.contains("linux") && arch in setOf("amd64", "x86_64") -> "linux-x86_64"
                    os.contains("windows") && arch in setOf("amd64", "x86_64") -> "windows-x86_64"
                    os.contains("mac") && arch in setOf("aarch64", "arm64") -> "macos-aarch64"
                    else -> return ZkErrors.unsupported
                }
                val name = when (platform) {
                    "windows-x86_64" -> "diw_zk.dll"
                    "macos-aarch64" -> "libdiw_zk.dylib"
                    else -> "libdiw_zk.so"
                }
                val resource = "/zk/native/$platform/$name"
                val expected = ZkNative::class.java.getResourceAsStream("$resource.sha256")?.use {
                    it.readBytes().decodeToString().trim()
                } ?: return ZkErrors.unsupported
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
                        val source = ZkNative::class.java.getResourceAsStream(resource) ?: return ZkErrors.unsupported
                        source.use { input -> temporary.outputStream().use { input.copyTo(it) } }
                        require(hash(temporary) == expected)
                        Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE,
                            StandardCopyOption.REPLACE_EXISTING)
                    } finally { temporary.delete() }
                }
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

    fun failure(error: ZkException): ZkResult<Nothing> = when (error) {
        is ZkException.InvalidInput -> ZkErrors.invalidInput
        is ZkException.Unsupported -> ZkErrors.unsupported
        is ZkException.ResourceExhausted -> ZkErrors.resources
        is ZkException.Cancelled -> ZkResult.Cancelled
        is ZkException.Internal -> ZkErrors.internal
    }
}
