package diw.wallet.app

import diw.wallet.core.zk.ZkAsset
import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.ZkPlatformInfo
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The low-compute choice screen's options (p4-zkp.md section 8): low compute advises, it never blocks. */
class ZkChoiceTest {
    private val phone = ZkPlatformInfo("arm64-v8a", 6144, 1500, 20000, false)
    private val desktop = ZkPlatformInfo("linux-x86_64", 16384, 12000, 50000, true)
    private val asset = ZkAsset("jwt_2k.r1cs", ZkBackend.OPENAC_SPARTAN2, setOf("prover"), listOf("https://example.invalid/a"),
        "0".repeat(64), 28 * 1024 * 1024, "1".repeat(64), 357 * 1024 * 1024, "GPL-3.0-or-later")

    private fun options(r: ZkReadiness, c: ZkChoiceContext = ZkChoiceContext()) = zkChoiceOptions(r, c).associateBy { it.kind }

    @Test
    fun lowMemoryKeepsOnDeviceAndRecommendsDesktop() {
        val r = ZkReadiness(ZkProofKind.AGE, true, "可用記憶體偏低", listOf(asset), phone)
        val o = options(r)
        val here = o.getValue(ZkChoiceKind.ON_DEVICE)
        assertTrue(here.enabled)
        assertFalse(here.recommended)
        assertEquals("仍在這台裝置產生", here.title)
        assertTrue("2325 MB" in here.detail && "1500 MB" in here.detail && "28 MB" in here.detail && "30 分鐘" in here.detail)
        assertTrue(o.getValue(ZkChoiceKind.DESKTOP).recommended)
        assertFalse(ZkChoiceKind.SELF_HOSTED in o, "self-hosting is offered for zkPDF only")
        assertFalse(ZkChoiceKind.WITHOUT_ZK in o)
    }

    @Test
    fun missingEngineDisablesOnlyOnDevice() {
        val r = ZkReadiness(ZkProofKind.PDF, false, "此版本尚未包含此證明後端", emptyList(), phone)
        val o = options(r, ZkChoiceContext(withoutZk = "衍生憑證照一般方式產生"))
        assertFalse(o.getValue(ZkChoiceKind.ON_DEVICE).enabled)
        assertEquals("此版本尚未包含此證明後端", o.getValue(ZkChoiceKind.ON_DEVICE).detail)
        assertTrue(o.getValue(ZkChoiceKind.DESKTOP).enabled)
        assertFalse(o.getValue(ZkChoiceKind.SELF_HOSTED).enabled)
        assertTrue(o.getValue(ZkChoiceKind.WITHOUT_ZK).detail.endsWith("隱私較低"))
        assertTrue(options(r, ZkChoiceContext(selfHostConfigured = true)).getValue(ZkChoiceKind.SELF_HOSTED).enabled)
    }

    @Test
    fun desktopHasNoDesktopImportOption() {
        val r = ZkReadiness(ZkProofKind.AGE, true, null, emptyList(), desktop)
        val o = options(r)
        assertFalse(ZkChoiceKind.DESKTOP in o)
        assertTrue(o.getValue(ZkChoiceKind.ON_DEVICE).recommended)
        assertEquals("在這台裝置產生", o.getValue(ZkChoiceKind.ON_DEVICE).title)
    }
}
