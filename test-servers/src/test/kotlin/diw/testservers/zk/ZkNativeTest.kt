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
            val requested = System.getProperty("diw.zkFeatures").orEmpty().split(',').filter { it.isNotEmpty() }
            requested.forEach { assertTrue(it in info.features, "$it requested but not built") }
            assertTrue(selfTest())
            ZkCancelToken().use { it.cancel() }
            assertEquals(listOf("runtime") + listOf("openac", "tlsn").filter { it in info.features }, info.features)
            if ("openac" in info.features) {
                assertEquals("b395e09c225ff45b003f0087c28e2e208e22f944", info.zkid)
            } else {
                // The OpenAC exports stay in every build and report a left-out backend as unsupported.
                assertNull(info.zkid)
                ZkCancelToken().use { token ->
                    assertFailsWith<ZkException.Unsupported> { proveJwt(directory.path, token) }
                }
            }
            if ("tlsn" in info.features) {
                assertEquals("47aee45b53e06648c1b2ad3689b367b8c923fdec", info.tlsn)
            } else {
                assertNull(info.tlsn)
                ZkCancelToken().use { token ->
                    assertFailsWith<ZkException.Unsupported> {
                        zktlsVerify(ClosedChannel, "example.com", 443u, 4096u, 1024u, "proxy", token, ByteArray(32), ByteArray(32), emptyList())
                    }
                }
            }
        } finally { directory.deleteRecursively() }
    }

    private object ClosedChannel : ZkTlsChannel {
        override fun send(data: ByteArray) = throw ZkException.Internal(999u)
        override fun receive(): ByteArray = throw ZkException.Internal(999u)
        override fun close() {}
    }
}
