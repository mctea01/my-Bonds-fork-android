package diw.wallet.app.desktop

import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/**
 * Writes errors that end the app to <data folder>/logs/ (the Windows executable is a GUI program without a console,
 * so a stack trace printed there is lost). The newest 20 files are kept.
 */
internal object ErrorLog {
    @Volatile var dir: File? = null

    private val stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")

    /** Saves [error] with the runtime it happened in; returns the file, or null when it could not be written. */
    fun write(error: Throwable, thread: String = Thread.currentThread().name): File? = runCatching {
        val logs = File(dir ?: return null, "logs").apply { mkdirs() }
        val trace = StringWriter().also { error.printStackTrace(PrintWriter(it)) }.toString()
        val text = buildString {
            append("time: ").append(LocalDateTime.now()).append('\n')
            append("thread: ").append(thread).append('\n')
            append("runtime: ").append(if (SelfCheck.nativeImage) "native-image" else "jvm ${System.getProperty("java.version")}")
            append(", ").append(System.getProperty("os.name")).append(' ').append(System.getProperty("os.arch")).append('\n')
            append('\n').append(trace)
        }
        val file = File(logs, "error-${LocalDateTime.now().format(stamp)}.txt")
        file.writeText(text, Charsets.UTF_8)
        logs.listFiles { f -> f.name.startsWith("error-") && f.name.endsWith(".txt") }
            ?.sortedByDescending { it.name }?.drop(20)?.forEach { it.delete() }
        file
    }.getOrNull()
}
