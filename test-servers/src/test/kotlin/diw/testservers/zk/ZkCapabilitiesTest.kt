package diw.testservers.zk

import diw.wallet.core.zk.*
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class ZkCapabilitiesTest {
    private val engines = ZkNativeStatus(ZkBackend.entries.toSet(), "synthetic")

    @Test fun tiersAreAdvisory() = runBlocking<Unit> {
        val a = ZkPlatformInfo("arm64-v8a", 8192, 4096, 4096, false)
        assertEquals(ZkTier.A, ZkCapabilities.evaluate(a, engines).tier)
        assertEquals(ZkTier.B, ZkCapabilities.evaluate(a.copy(totalRamMb = 6144), engines).tier)
        val c = ZkCapabilities.evaluate(a.copy(totalRamMb = 4096, availableRamMb = 256), engines)
        assertEquals(ZkTier.C, c.tier)
        assertEquals(engines.backends, c.backends)
        assertTrue(c.reasons.values.all { it.isNotBlank() })
        assertEquals(ZkTier.B, ZkCapabilities.evaluate(a.copy(abi = "x86_64"), engines).tier)
    }

    @Test fun missingLibrariesAndUnsupportedPlatforms() = runBlocking<Unit> {
        val platform = ZkPlatformInfo("arm64-v8a", 8192, 4096, 4096, false)
        assertTrue(ZkCapabilities.evaluate(platform, null).backends.isEmpty())
        assertTrue(ZkCapabilities.evaluate(platform.copy(abi = "armeabi-v7a"), engines).backends.isEmpty())
        val windows = ZkCapabilities.evaluate(platform.copy(abi = "windows-x86_64", isDesktop = true), engines)
        assertFalse(ZkBackend.LONGFELLOW in windows.backends)
        assertTrue(windows.reasons.getValue(ZkBackend.LONGFELLOW).contains("Windows"))
    }
}
