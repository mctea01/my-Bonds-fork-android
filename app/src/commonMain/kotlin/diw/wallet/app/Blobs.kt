package diw.wallet.app

import kotlinx.io.bytestring.ByteString
import org.multipaz.storage.StorageTable

/**
 * Large values in a storage table, split into chunks. Multipaz's Android storage reads a row through a 5 MB cursor
 * window, so a larger value could be written but never read back; values above [CHUNK] are stored as a header row
 * under the key and chunk rows under "key#i". A value stored whole before chunking was introduced reads as it was.
 */
object Blobs {
    const val CHUNK = 1024 * 1024
    private val MAGIC = "DIW-CHUNKED-1:".encodeToByteArray()

    suspend fun put(table: StorageTable, key: String, value: ByteArray) {
        delete(table, key)
        if (value.size <= CHUNK && !startsWithMagic(value)) {
            table.insert(key, ByteString(value))
            return
        }
        val count = (value.size + CHUNK - 1) / CHUNK
        for (i in 0 until count) {
            val from = i * CHUNK
            table.insert(chunkKey(key, i), ByteString(value.copyOfRange(from, minOf(value.size, from + CHUNK))))
        }
        table.insert(key, ByteString(MAGIC + "$count:${value.size}".encodeToByteArray()))
    }

    suspend fun get(table: StorageTable, key: String): ByteArray? {
        val head = table.get(key)?.toByteArray() ?: return null
        val (count, size) = header(head) ?: return head
        val out = ByteArray(size)
        var at = 0
        for (i in 0 until count) {
            val part = table.get(chunkKey(key, i))?.toByteArray() ?: return null
            if (at + part.size > size) return null
            part.copyInto(out, at)
            at += part.size
        }
        return if (at == size) out else null
    }

    suspend fun delete(table: StorageTable, key: String) {
        val head = table.get(key)?.toByteArray() ?: return
        header(head)?.let { (count, _) -> for (i in 0 until count) table.delete(chunkKey(key, i)) }
        table.delete(key)
    }

    private fun chunkKey(key: String, i: Int) = "$key#$i"

    private fun startsWithMagic(b: ByteArray): Boolean =
        b.size >= MAGIC.size && MAGIC.indices.all { b[it] == MAGIC[it] }

    private fun header(b: ByteArray): Pair<Int, Int>? {
        if (!startsWithMagic(b) || b.size > MAGIC.size + 32) return null
        val parts = b.copyOfRange(MAGIC.size, b.size).decodeToString().split(':')
        val count = parts.getOrNull(0)?.toIntOrNull() ?: return null
        val size = parts.getOrNull(1)?.toIntOrNull() ?: return null
        return (count to size).takeIf { count >= 0 && size >= 0 }
    }
}
