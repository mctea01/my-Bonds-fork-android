package diw.wallet.app

import kotlinx.coroutines.runBlocking
import org.multipaz.storage.StorageTableSpec
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNull

class BlobsTest {
    private val spec = StorageTableSpec(name = "BlobsTest", supportPartitions = false, supportExpiration = false)

    @Test
    fun largeValuesAreChunkedAndReadBack() = runBlocking<Unit> {
        val t = EphemeralStorage().getTable(spec)
        val small = Random.nextBytes(1000)
        val large = Random.nextBytes(Blobs.CHUNK * 3 + 17)
        Blobs.put(t, "s", small)
        Blobs.put(t, "l", large)
        assertContentEquals(small, Blobs.get(t, "s"))
        assertContentEquals(large, Blobs.get(t, "l"))
        // Replacing a chunked value with a small one drops its chunks.
        Blobs.put(t, "l", small)
        assertContentEquals(small, Blobs.get(t, "l"))
        assertNull(t.get("l#0"))
        // A value that happens to look like a chunk header is stored as one chunk, not read as a header.
        val lookalike = "DIW-CHUNKED-1:3:9".encodeToByteArray()
        Blobs.put(t, "x", lookalike)
        assertContentEquals(lookalike, Blobs.get(t, "x"))
        Blobs.delete(t, "x")
        assertNull(Blobs.get(t, "x"))
        assertNull(t.get("x#0"))
        // A value written whole before chunking existed reads as it was.
        t.insert("old", kotlinx.io.bytestring.ByteString(small))
        assertContentEquals(small, Blobs.get(t, "old"))
    }
}
