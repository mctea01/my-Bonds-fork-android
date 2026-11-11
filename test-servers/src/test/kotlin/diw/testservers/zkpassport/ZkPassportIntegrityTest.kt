package diw.testservers.zkpassport

import diw.wallet.core.zkpassport.ZkPassportIntegrity
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ZkPassportIntegrityTest {
    private val name = "data_check_integrity_sa_sha256_dg_sha256"
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun tlv(tag: Int, v: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + (if (v.size < 128) byteArrayOf(v.size.toByte()) else byteArrayOf(0x82.toByte(), (v.size shr 8).toByte(), v.size.toByte())) + v
    private fun group(n: Int, hash: ByteArray) = tlv(0x30, tlv(0x02, byteArrayOf(n.toByte())) + tlv(0x04, hash))
    private fun pad(b: ByteArray, n: Int) = b.copyOf(maxOf(n, b.size))
    private fun array(b: ByteArray) = JsonArray(b.map { JsonPrimitive(it.toInt() and 0xFF) })

    // A fictional passport: MRZ of filler characters only.
    private val dg1 = byteArrayOf(0x61, 0x5B, 0x5F, 0x1F, 0x58) + ByteArray(88) { '<'.code.toByte() }
    private val sha256 = tlv(0x30, tlv(0x06, byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)))

    private fun eContent(withDg2: Boolean = true, dg1Hash: ByteArray = sha(dg1)) = tlv(0x30, tlv(0x02, byteArrayOf(0)) + sha256 +
        tlv(0x30, group(1, dg1Hash) + (if (withDg2) group(2, sha("photo".encodeToByteArray())) else ByteArray(0)) + group(14, sha("ca".encodeToByteArray()))))

    private fun inputs(e: ByteArray, signed: ByteArray = tlv(0x31, tlv(0x30, tlv(0x04, sha(e)))), d: ByteArray = dg1) = JsonObject(mapOf(
        "salted_dg1" to JsonObject(mapOf("value" to array(pad(d, 95)))),
        "e_content" to array(pad(e, 700)),
        "signed_attributes" to array(pad(signed, 256)),
    ))

    @Test fun theFailedCheckIsNamed() {
        val e = eContent()
        assertNull(ZkPassportIntegrity.diagnose(name, inputs(e)))
        assertNull(ZkPassportIntegrity.diagnose("disclose_bytes", inputs(e)))
        assertEquals("dg1_hash", ZkPassportIntegrity.diagnose(name, inputs(eContent(dg1Hash = ByteArray(32)))))
        assertEquals("e_content_hash", ZkPassportIntegrity.diagnose(name, inputs(e, signed = tlv(0x31, tlv(0x04, ByteArray(32))))))
        assertEquals("dg2_hash", ZkPassportIntegrity.diagnose(name, inputs(eContent(withDg2 = false))))
        assertEquals("e_content_padding", ZkPassportIntegrity.diagnose(name, inputs(e + byteArrayOf(1))))
        assertEquals("e_content_length", ZkPassportIntegrity.diagnose(name, inputs(byteArrayOf(0x30, 0x80.toByte()) + e.copyOfRange(2, e.size))))
        val oneByte = dg1.copyOf(95).also { it[93] = 0x3C }
        assertEquals("dg1_padding", ZkPassportIntegrity.diagnose(name, inputs(e, d = oneByte)))
    }
}
