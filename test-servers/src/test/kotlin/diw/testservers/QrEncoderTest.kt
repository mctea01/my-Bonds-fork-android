package diw.testservers

import diw.wallet.core.util.QrEncoder
import diw.wallet.core.util.QrMatrix
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Matrices are compared with an independent encoder (Nayuki qrcodegen 1.8.0) for fixed version, level and mask. */
class QrEncoderTest {
    private fun hash(m: QrMatrix): String {
        val bits = buildString { for (y in 0 until m.size) for (x in 0 until m.size) append(if (m[x, y]) '1' else '0') }
        return MessageDigest.getInstance("SHA-256").digest(bits.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    @Test
    fun matchesReferenceEncoder() {
        val cases = listOf(
            Triple("HELLO WORLD", Triple(1, QrEncoder.Ecc.M, 0), "9f15327b648fdbb6e3878c9a72183cc1f76f880c1b3e4f53fd7859bb5b4f2421"),
            Triple("https://example.com/a?b=1", Triple(3, QrEncoder.Ecc.L, 5), "10e7465c537df45435c393ae5b8e4cbe774b924aa43b35a78911ba55b1c8bb7b"),
            Triple("BTWVP1:Z:0A1B2C3D4E:01:02:" + "0123456789ABCDEF $%*+-./:".repeat(20), Triple(15, QrEncoder.Ecc.M, 2),
                "f299b379f002a6f97ba60991e0263bd79a23f5b15808dcc70e4caa8f3e0c92e3"),
            Triple("x".repeat(600), Triple(23, QrEncoder.Ecc.Q, 7), "23e549ec308565d55f5cef5e98496cfcf6bf6920644e734ced8cfee5577711cf"),
            Triple("A".repeat(3000), Triple(40, QrEncoder.Ecc.L, 3), "82d26ed2e19263b18252cc10ad605f8ca8fbd24e82689c28842fa3fd0e6a4244"),
            Triple("\u6578\u4f4d\u6191\u8b49 data", Triple(2, QrEncoder.Ecc.M, 1), "c4c239060e0c3cc74463b2adae2dca051d71024baaea333d28f527abc50ff3e6"),
        )
        for ((text, params, expected) in cases) {
            val (v, ecc, mask) = params
            val m = QrEncoder.encode(text, ecc, forceVersion = v, forceMask = mask)
            assertEquals(v * 4 + 17, m.size)
            assertEquals(expected, hash(m), "version $v $ecc mask $mask")
        }
    }

    @Test
    fun picksSmallestVersion() {
        assertEquals(1, QrEncoder.encode("HELLO WORLD").version)
        val frame = "BTWVP1:Z:0A1B2C3D4E:01:01:" + "A".repeat(546)
        assertTrue(QrEncoder.encode(frame).version <= 20)
    }
}
