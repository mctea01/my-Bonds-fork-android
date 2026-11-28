package diw.wallet.core.document.c2pa

import org.brotli.dec.BrotliInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

internal actual object C2paBrotli {
    actual fun decode(data: ByteArray, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        BrotliInputStream(ByteArrayInputStream(data)).use { input ->
            val buf = ByteArray(16384)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                if (out.size() + n > limit) throw IllegalArgumentException("brob content larger than $limit bytes")
                out.write(buf, 0, n)
            }
        }
        return out.toByteArray()
    }
}
