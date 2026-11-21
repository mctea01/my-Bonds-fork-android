package diw.wallet.app.desktop

import java.io.File
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.StandardOpenOption

/**
 * One running app per data folder. A second one (another window, or the JVM and native editions side by side) would
 * open the same SQLite database, and a write then fails with SQLITE_BUSY while the other holds it. The lock is an OS
 * file lock on [FILE] in the folder, so it ends with the process that holds it, however that process ends.
 */
internal object DataDirLock {
    const val FILE = "app.lock"

    /**
     * The lock on [dir], held until it is released or the process ends; null when another process holds it. Throws
     * when the lock file cannot be opened or locked at all (the caller then starts without it).
     */
    fun acquire(dir: File): FileLock? {
        dir.mkdirs()
        val channel = FileChannel.open(File(dir, FILE).toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        val lock = try {
            channel.tryLock()
        } catch (e: Throwable) {
            channel.close()
            throw e
        }
        if (lock == null) channel.close()
        return lock
    }
}
