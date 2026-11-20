package diw.wallet.core.zk.native

import com.sun.jna.NativeLibrary
import diw.wallet.core.zk.*
import diw.wallet.core.zk.native.bindings.*
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/** Invoke before using generated bindings. The app supplies its private data directory. */
object ZkNative {
    private var loaded: ZkNativeStatus? = null

    /** Where [ensureLoaded] unpacks the library; [JvmZkEnvironment] sets the app's private data directory. */
    @Volatile
    var directory: File? = null

    /**
     * The resource directory under /zk/native the loaded library came from (linux-x86_64, linux-x86_64-compat, ...),
     * or "external" for [LIBRARY_PROPERTY]; null before a desktop load succeeds. Companion libraries (diw_bb5) are
     * taken from the same directory only, so a compatibility build never pairs with a library this host cannot run.
     */
    @Volatile
    var variant: String? = null
        private set

    /** Why the last desktop load failed, one entry per variant tried; null after a success or before any attempt. */
    @Volatile
    var loadFailure: String? = null
        private set

    /**
     * System property (or environment variable [LIBRARY_ENV]) naming a diw_zk library file to load instead of the
     * bundled ones, for a library built or downloaded separately for this host.
     */
    const val LIBRARY_PROPERTY = "diw.zk.native.library"
    const val LIBRARY_ENV = "DIW_ZK_NATIVE_LIBRARY"

    /** Loads the library on first use (for callers such as bbs-2023 that do not go through a ZkEnvironment). */
    fun ensureLoaded(): Boolean {
        if (loaded != null) return true
        // Without the app's private directory, a fresh owner-only temporary directory (never a shared, predictable one).
        val dir = directory ?: Files.createTempDirectory("diw-wallet-native").toFile().also { directory = it }
        return load(dir) is ZkResult.Ok
    }

    @Synchronized
    fun load(dataDirectory: File): ZkResult<ZkNativeStatus> {
        loaded?.let { return ZkResult.Ok(it) }
        return try {
            if (!android) {
                val target = select(dataDirectory) ?: return ZkErrors.unsupported
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
        } catch (e: LinkageError) {
            loadFailure = loadFailure ?: (e.message ?: e.javaClass.simpleName)
            ZkErrors.unsupported
        } catch (_: Exception) {
            ZkErrors.internal
        }
    }

    /**
     * Picks the first diw_zk this host can run and opens it once, so a library that needs a newer C library fails
     * here with a LinkageError instead of inside the generated bindings (which cannot try another file). A variant
     * whose processor requirement this CPU lacks is never opened: its code would stop the process with SIGILL.
     */
    private fun select(dataDirectory: File): File? {
        val reasons = mutableListOf<String>()
        val external = System.getProperty(LIBRARY_PROPERTY)?.takeIf { it.isNotBlank() }
            ?: System.getenv(LIBRARY_ENV)?.takeIf { it.isNotBlank() }
        val choices: List<Pair<String, () -> File?>> = if (external != null) {
            listOf("external" to { File(external).takeIf { it.isFile } })
        } else {
            candidates().map { platform -> platform to { unpack(dataDirectory, "diw_zk", platform) } }
        }
        for ((name, file) in choices) {
            val missing = cpuMissing(name)
            if (missing.isNotEmpty()) {
                reasons += "$name: CPU lacks ${missing.joinToString(" ")}"
                continue
            }
            val target = file()
            if (target == null) {
                if (name == "external") reasons += "external: $external is not a file"
                continue
            }
            try {
                NativeLibrary.getInstance(target.absolutePath)
            } catch (e: UnsatisfiedLinkError) {
                reasons += "$name: " + openError(e)
                continue
            }
            variant = name
            loadFailure = null
            return target
        }
        loadFailure = reasons.joinToString("; ").ifEmpty { "no library for this system" }
        return null
    }

    /**
     * The dynamic loader's own words (for example "version `GLIBC_2.38' not found"): JNA puts them after a first
     * "Unable to load library" line, once for each way it tried, so repeated lines are dropped.
     */
    private fun openError(e: UnsatisfiedLinkError): String {
        // JNA also reports that the path is not in the resource path, which says nothing about this host.
        val lines = (e.message ?: "").lineSequence().map { it.trim() }
            .filter { it.isNotEmpty() && !it.contains("not found in resource path") }.distinct().toList()
        val detail = lines.drop(1).ifEmpty { lines }
        return detail.joinToString(" | ").ifEmpty { "cannot be opened" }.take(400)
    }

    val android: Boolean get() = System.getProperty("java.vm.name", "").orEmpty().contains("Dalvik", ignoreCase = true)

    /** This desktop's directory under /zk/native in the resources; null on other systems. */
    private fun platform(): String? {
        val os = System.getProperty("os.name", "").orEmpty().lowercase()
        val arch = System.getProperty("os.arch", "").orEmpty().lowercase()
        return when {
            os.contains("linux") && arch in setOf("amd64", "x86_64") -> "linux-x86_64"
            os.contains("linux") && arch in setOf("aarch64", "arm64") -> "linux-aarch64"
            os.contains("windows") && arch in setOf("amd64", "x86_64") -> "windows-x86_64"
            os.contains("mac") && arch in setOf("aarch64", "arm64") -> "macos-aarch64"
            else -> null
        }
    }

    /**
     * Resource directories to try, best first. Linux builds also carry "-compat" libraries: no Barretenberg (so no
     * zkPDF or zkPassport), baseline instruction set, an old C library floor and no C++ runtime.
     */
    private fun candidates(): List<String> = when (val p = platform()) {
        null -> emptyList()
        "linux-x86_64", "linux-aarch64" -> listOf(p, "$p-compat")
        else -> listOf(p)
    }

    /**
     * CPU flags the variant's code needs that this host lacks (Linux reads them from /proc/cpuinfo; elsewhere, or
     * when it cannot be read, nothing is missing). Barretenberg in linux-x86_64 is built for x86-64-v2.
     */
    private fun cpuMissing(variant: String): List<String> {
        if (variant != "linux-x86_64") return emptyList()
        val flags = cpuFlags ?: return emptyList()
        return X86_64_V2.filter { it !in flags }
    }

    private val X86_64_V2 = listOf("cx16", "lahf_lm", "popcnt", "sse4_1", "sse4_2", "ssse3")

    private val cpuFlags: Set<String>? by lazy {
        try {
            File("/proc/cpuinfo").useLines { lines ->
                lines.firstOrNull { it.startsWith("flags") }?.substringAfter(':')?.trim()?.split(Regex("\\s+"))?.toSet()
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun fileName(platform: String, base: String) = when (platform) {
        "windows-x86_64" -> "$base.dll"
        "macos-aarch64" -> "lib$base.dylib"
        else -> "lib$base.so"
    }

    /** Whether the desktop resources carry library [base] (diw_zk, diw_bb5) with its digest, in any variant. */
    fun bundled(base: String): Boolean = candidates().any {
        ZkNative::class.java.getResource("/zk/native/$it/${fileName(it, base)}.sha256") != null
    }

    /**
     * Copies the desktop library [base] from the resources under [dataDirectory], in a folder named by its pinned
     * SHA-256, and returns it; null when this system has none. Companion libraries come from the directory diw_zk
     * was loaded from (an external diw_zk has no companions).
     */
    @Synchronized
    fun unpack(dataDirectory: File, base: String): File? {
        val from = variant ?: candidates().firstOrNull { cpuMissing(it).isEmpty() } ?: return null
        if (from == "external") return null
        return unpack(dataDirectory, base, from)
    }

    @Synchronized
    private fun unpack(dataDirectory: File, base: String, platform: String): File? {
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
