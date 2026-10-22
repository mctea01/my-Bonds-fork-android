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
            val info = nativeInfo()
            // A requested backend must not silently fall back to the runtime-only library.
            if (System.getProperty("diw.zkFeatures") == "openac") assertTrue("openac" in info.features)
            assertTrue(selfTest())
            ZkCancelToken().use { it.cancel() }
            if ("openac" in info.features) {
                assertEquals(listOf("runtime", "openac"), info.features)
                assertEquals("b395e09c225ff45b003f0087c28e2e208e22f944", info.zkid)
            } else {
                // The OpenAC exports stay in every build and report a left-out backend as unsupported.
                assertEquals(listOf("runtime"), info.features)
                assertNull(info.zkid)
                ZkCancelToken().use { token ->
                    assertFailsWith<ZkException.Unsupported> { proveJwt(directory.path, token) }
                }
            }
        } finally { directory.deleteRecursively() }
    }
}
