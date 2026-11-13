package diw.wallet.app.desktop

import diw.wallet.app.AppText
import diw.wallet.app.WalletModel
import diw.wallet.app.res.Res
import diw.wallet.app.res.unlock_enter_pin
import diw.wallet.app.tr
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.ZkNative
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * `--self-check [file]`: exercises what a native executable most often loses (the ZK library through JNA, SQLite,
 * Bouncy Castle, Skia, string resources, PC/SC and the wallet's own start-up) without a window, prints one line per
 * check and, with [file], writes the same lines there (a Windows GUI executable has no console). Returns the exit
 * code: 0 when every required check passed. tools/desktop-native.sh runs it under the tracing agent and against the
 * native executable.
 */
object SelfCheck {
    private val lines = mutableListOf<String>()
    // UTF-8 whatever the console's code page, so the lines read the same in CI logs.
    private val out = java.io.PrintStream(java.io.FileOutputStream(java.io.FileDescriptor.out), true, Charsets.UTF_8)
    private var failed = false

    val nativeImage: Boolean get() = System.getProperty("org.graalvm.nativeimage.imagecode") != null

    fun run(file: File?): Int {
        Security.addProvider(BouncyCastleProvider())
        val work = Files.createTempDirectory("diw-self-check").toFile()
        try {
            val rt = Runtime.getRuntime()
            report("runtime", true, buildString {
                append(if (nativeImage) "native-image" else "jvm ${System.getProperty("java.vm.name")} ${System.getProperty("java.version")}")
                append(", ${System.getProperty("os.name")} ${System.getProperty("os.arch")}")
                append(", cores=${rt.availableProcessors()}, maxHeapMiB=${rt.maxMemory() shr 20}")
                physicalMiB()?.let { append(", physicalMiB=$it") }
                append(", java.home=${System.getProperty("java.home")}")
            })
            check("bouncycastle") {
                val generator = KeyPairGenerator.getInstance("EC", "BC").apply { initialize(ECGenParameterSpec("secp256r1")) }
                val pair = generator.generateKeyPair()
                val data = "diw".encodeToByteArray()
                val signature = Signature.getInstance("SHA256withECDSA", "BC").run { initSign(pair.private); update(data); sign() }
                val ok = Signature.getInstance("SHA256withECDSA", "BC").run { initVerify(pair.public); update(data); verify(signature) }
                require(ok) { "signature did not verify" }
                "P-256 signature"
            }
            check("resources") {
                runBlocking { AppText.load("en"); AppText.load("zh") }
                val text = tr(Res.string.unlock_enter_pin)
                require(text != Res.string.unlock_enter_pin.key) { "strings not loaded" }
                text
            }
            check("skia") {
                org.jetbrains.skia.Surface.makeRasterN32Premul(16, 16).use { surface ->
                    surface.canvas.clear(0xFF336699.toInt())
                    surface.makeImageSnapshot().use { "raster ${it.width}x${it.height}" }
                }
            }
            check("zk") {
                if (!ZkNative.bundled("diw_zk")) return@check "not bundled in this build"
                when (val r = ZkNative.load(work)) {
                    is ZkResult.Ok -> {
                        if (ZkNative.bundled("diw_bb5")) requireNotNull(ZkNative.unpack(work, "diw_bb5")) { "diw_bb5 not unpacked" }
                        "${r.value.version} ${r.value.backends.sorted().joinToString(",")}"
                    }
                    else -> {
                        // ZkNative reports only the category; the binding itself names the cause.
                        val cause = runCatching { diw.wallet.core.zk.native.bindings.nativeInfo() }.exceptionOrNull()
                        throw IllegalStateException("$r ${cause?.let { it::class.java.name + ": " + it.message }.orEmpty()}")
                    }
                }
            }
            check("wallet") {
                val dir = File(work, "wallet")
                runBlocking {
                    withTimeout(180_000) {
                        val cipher = requireNotNull(PinValueCipher.unlock(dir, "000000")) { "PIN cipher" }
                        val platform = DesktopPlatform(dir, cipher, DesktopLanguageStore()) { }
                        val model = WalletModel(platform)
                        model.init()
                    }
                }
                require(File(dir, "diw-wallet-v1.db").isFile) { "no database" }
                "storage, keys, trust anchors and settings"
            }
            // Optional: a CI runner has no PC/SC service or reader; the call itself must not crash.
            val readers = runCatching { PcscReaders.list() }
            report("pcsc", true, readers.fold({ r -> "${r.readers.size} readers" + (r.problem?.let { ", $it" } ?: "") }, { "unavailable: ${it::class.java.name}: ${it.message}" }))
        } catch (e: Throwable) {
            report("self-check", false, "${e::class.java.name}: ${e.message}")
        } finally {
            work.deleteRecursively()
        }
        report("result", !failed, if (failed) "failed" else "passed")
        file?.let { runCatching { it.writeText(lines.joinToString("\n", postfix = "\n"), Charsets.UTF_8) } }
        return if (failed) 1 else 0
    }

    private inline fun check(name: String, block: () -> String) {
        try {
            report(name, true, block())
        } catch (e: Throwable) {
            if (e is VirtualMachineError && e !is OutOfMemoryError) throw e
            report(name, false, "${e::class.java.name}: ${e.message}")
        }
    }

    private fun report(name: String, ok: Boolean, detail: String) {
        if (!ok) failed = true
        val line = "self-check $name ${if (ok) "ok" else "FAILED"}: $detail"
        lines += line
        out.println(line)
    }

    private fun physicalMiB(): Long? = runCatching {
        (java.lang.management.ManagementFactory.getOperatingSystemMXBean() as com.sun.management.OperatingSystemMXBean).totalMemorySize shr 20
    }.getOrNull()
}
