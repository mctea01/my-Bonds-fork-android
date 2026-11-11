package diw.wallet.app

import diw.wallet.core.document.image.Jpeg2000
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.ZkResult
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ImageDecodingTest {
    @Test fun jpeg2000PortraitsAreDecodedNatively() {
        if (ZkNative.load(Files.createTempDirectory("zk").toFile()) !is ZkResult.Ok) return
        val jp2 = ImageDecodingTest::class.java.getResourceAsStream("/images/two-colors.jp2")!!.readBytes()
        val p = assertNotNull(Jpeg2000.decode(jp2))
        assertEquals(16, p.width)
        assertEquals(8, p.height)
        assertEquals(0xFFFF0000.toInt(), p.argb[0])
        assertEquals(0xFF0000FF.toInt(), p.argb[15])
        val image = assertNotNull(decodeImageBytes(jp2))
        assertEquals(16, image.width)
        assertNull(Jpeg2000.decode(byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte())))
    }
}
