package diw.testservers.zkpassport

import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.BundledZkComponent
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.zkpassportLegacyBackend
import diw.wallet.core.zk.native.bindings.zkpassportVerifyLegacy
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Barretenberg 5 from the desktop resources, opened beside the Barretenberg 6 of diw_zk. Skipped without them, unless
 * DIW_REQUIRE_BB5 is set (CI builds both).
 */
class ZkPassportLegacyTest {
    @Test
    fun bundledBarretenbergFiveOpensBesideTheMainLibrary() {
        val dir = Files.createTempDirectory("zk-legacy").toFile()
        try {
            val required = System.getenv("DIW_REQUIRE_BB5") != null
            if (ZkNative.load(dir) !is ZkResult.Ok) if (required) error("diw_zk did not load") else return
            val component = BundledZkComponent(dir, "diw_bb5")
            if (!component.present()) if (required) error("diw_bb5 is not in the resources") else return
            val library = component.load()!!
            assertTrue(library.endsWith(".so") || library.endsWith(".dylib"), library)
            val revision = zkpassportLegacyBackend(library)
            assertTrue(revision.startsWith("5.0.0+"), revision)
            assertEquals(revision, zkpassportLegacyBackend(library))
            assertFailsWith<ZkException> { zkpassportVerifyLegacy("{") }
        } finally {
            dir.deleteRecursively()
        }
    }
}
