package diw.wallet.app.desktop

import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A file lock only excludes other processes, so the second app is a child JVM running [DataDirLockHolder]. */
class DataDirLockTest {
    private class Holder(val process: Process, val state: String?) {
        fun stop() {
            process.outputStream.close()
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "holder did not exit")
        }
    }

    private fun holder(dir: File): Holder {
        val java = File(System.getProperty("java.home"), "bin/java").path
        // Standard error stays apart: a JVM may print notes there (such as JAVA_TOOL_OPTIONS) before the state line.
        val builder = ProcessBuilder(java, DataDirLockHolder::class.java.name, dir.path)
            .redirectError(ProcessBuilder.Redirect.INHERIT)
        // The class path goes through the environment: a command line that long fails on Windows.
        builder.environment()["CLASSPATH"] = System.getProperty("java.class.path")
        val process = builder.start()
        return Holder(process, process.inputStream.bufferedReader().readLine())
    }

    @Test
    fun secondProcessIsRefusedUntilTheFirstEnds() {
        val root = Files.createTempDirectory("diw-lock").toFile()
        try {
            val same = File(root, "wallet")
            val other = File(root, "other")

            val first = holder(same)
            assertEquals("locked", first.state)
            // The same folder is refused while the first app runs; another folder is not affected.
            assertNull(DataDirLock.acquire(same))
            assertNotNull(DataDirLock.acquire(other)).channel().close()

            // After the first app ends, the folder can be taken again, and then it refuses the next process.
            first.stop()
            val lock = assertNotNull(DataDirLock.acquire(same))
            val second = holder(same)
            assertEquals("busy", second.state)
            second.stop()
            lock.channel().close()
        } finally {
            root.deleteRecursively()
        }
    }
}

/** Takes the lock on args[0], prints "locked" or "busy", and keeps it until its standard input closes. */
object DataDirLockHolder {
    @JvmStatic
    fun main(args: Array<String>) {
        val lock = DataDirLock.acquire(File(args[0]))
        println(if (lock != null) "locked" else "busy")
        System.out.flush()
        while (System.`in`.read() >= 0) Unit
        lock?.release()
    }
}
