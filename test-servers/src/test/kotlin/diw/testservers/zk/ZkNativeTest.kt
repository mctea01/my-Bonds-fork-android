package diw.testservers.zk

import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.bindings.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.nio.file.Files
import kotlin.test.*

class ZkNativeTest {
    @Test fun loadsPackagedRuntime() = runBlocking<Unit> {
        // Without Rust the build leaves the library out (diw.zkNative=auto); CI sets require so it is always tested there.
        val packaged = ZkNative::class.java.getResource("/zk/native") != null
        assumeTrue(packaged || System.getProperty("diw.zkNative") == "require", "ZK native library not built")
        val directory = Files.createTempDirectory("diw-zk-native").toFile()
        try {
            assertIs<ZkResult.Ok<*>>(ZkNative.load(directory))
            assertEquals("0.1.0", nativeInfo().crateVersion)
            assertEquals(listOf("runtime"), nativeInfo().features)
            assertTrue(selfTest())
            ZkCancelToken().use { it.cancel() }
            assertNull(nativeInfo().zkid)
        } finally { directory.deleteRecursively() }
    }
}
