package diw.testservers.zk

import diw.wallet.core.zk.*
import diw.wallet.core.zk.native.FileZkAssetStore
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.GZIPOutputStream
import kotlin.test.*

/** Every fixture is generated locally and contains no credential or document data. */
class ZkAssetStoreTest {
    private val plain = ByteArray(1024) { (it * 37).toByte() }
    private val compressed = ByteArrayOutputStream().also { buffer ->
        GZIPOutputStream(buffer).use { it.write(plain) }
    }.toByteArray()
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private val asset = ZkAsset("synthetic.key", ZkBackend.OPENAC_SPARTAN2, setOf("prover"),
        listOf("https://assets.example.test/key.gz"), hash(compressed), compressed.size.toLong(),
        hash(plain), plain.size.toLong(), "Apache-2.0")

    private suspend fun fixture(
        entry: ZkAsset = asset,
        handler: MockRequestHandler = { respond(compressed) },
        test: suspend (FileZkAssetStore, File) -> Unit,
    ) {
        val directory = Files.createTempDirectory("diw-zk-assets").toFile()
        val client = HttpClient(MockEngine(handler))
        try { FileZkAssetStore(directory, client, listOf(entry)).use { test(it, directory) } }
        finally { client.close(); directory.deleteRecursively() }
    }

    @Test fun installVerifyTamperAndDelete() = runBlocking<Unit> {
        fixture { store, directory ->
            assertEquals(ZkAssetStatus.MISSING, store.status(asset.id))
            assertNull(store.path(asset.id))
            var progress = 0L
            assertIs<ZkResult.Ok<Unit>>(store.download(asset.id) { done, total ->
                assertEquals(asset.gzipBytes, total); assertTrue(done >= progress); progress = done
            })
            assertEquals(asset.gzipBytes, progress)
            assertEquals(ZkAssetStatus.READY, store.status(asset.id))
            val installed = File(assertNotNull(store.path(asset.id)))
            assertContentEquals(plain, installed.readBytes())
            installed.writeBytes(ByteArray(plain.size))
            assertEquals(ZkAssetStatus.CORRUPT, store.status(asset.id))
            assertNull(store.path(asset.id))
            store.delete(asset.id)
            assertTrue(directory.listFiles()!!.isEmpty())
        }
    }

    @Test fun resumesAtVerifiedRangeBoundary() = runBlocking<Unit> {
        val prefix = compressed.size / 2
        fixture(handler = { request ->
            assertEquals("bytes=$prefix-", request.headers[HttpHeaders.Range])
            respond(compressed.copyOfRange(prefix, compressed.size), HttpStatusCode.PartialContent,
                headersOf(HttpHeaders.ContentRange, "bytes $prefix-${compressed.size - 1}/${compressed.size}"))
        }) { store, directory ->
            File(directory, asset.id + ".gz.part").writeBytes(compressed.copyOf(prefix))
            assertEquals(ZkAssetStatus.PARTIAL, store.status(asset.id))
            assertIs<ZkResult.Ok<Unit>>(store.download(asset.id) { _, _ -> })
            assertContentEquals(plain, File(assertNotNull(store.path(asset.id))).readBytes())
        }
    }

    @Test fun ignoredRangeRestartsDownload() = runBlocking<Unit> {
        fixture { store, directory ->
            File(directory, asset.id + ".gz.part").writeBytes(compressed.copyOf(12))
            assertIs<ZkResult.Ok<Unit>>(store.download(asset.id) { _, _ -> })
            assertEquals(ZkAssetStatus.READY, store.status(asset.id))
        }
    }

    @Test fun interruptedTransferCanResume() = runBlocking<Unit> {
        var requests = 0
        val prefix = 23
        fixture(handler = { request ->
            if (requests++ == 0) respond(compressed.copyOf(prefix))
            else {
                assertEquals("bytes=$prefix-", request.headers[HttpHeaders.Range])
                respond(compressed.copyOfRange(prefix, compressed.size), HttpStatusCode.PartialContent,
                    headersOf(HttpHeaders.ContentRange, "bytes $prefix-${compressed.size - 1}/${compressed.size}"))
            }
        }) { store, _ ->
            assertIs<ZkResult.Failed>(store.download(asset.id) { _, _ -> })
            assertEquals(ZkAssetStatus.PARTIAL, store.status(asset.id))
            assertNull(store.path(asset.id))
            assertIs<ZkResult.Ok<Unit>>(store.download(asset.id) { _, _ -> })
            assertEquals(2, requests)
            assertEquals(ZkAssetStatus.READY, store.status(asset.id))
        }
    }

    @Test fun rejectsRedirectToCleartext() = runBlocking<Unit> {
        fixture(handler = { respond("", HttpStatusCode.Found,
            headersOf(HttpHeaders.Location, "http://assets.example.test/key.gz")) }) { store, directory ->
            assertIs<ZkResult.Failed>(store.download(asset.id) { _, _ -> })
            assertTrue(directory.listFiles()!!.isEmpty())
        }
    }

    @Test fun rejectsBothHashesAndDeletesInvalidData() = runBlocking<Unit> {
        for (entry in listOf(asset.copy(gzipSha256 = "0".repeat(64)), asset.copy(installedSha256 = "0".repeat(64)),
            asset.copy(installedBytes = 10))) {
            fixture(entry) { store, directory ->
                assertIs<ZkResult.Failed>(store.download(entry.id) { _, _ -> })
                assertNull(store.path(entry.id))
                assertTrue(directory.listFiles()!!.isEmpty())
            }
        }
    }

    @Test fun rejectsWrongResumeRange() = runBlocking<Unit> {
        fixture(handler = { respond(compressed, HttpStatusCode.PartialContent,
            headersOf(HttpHeaders.ContentRange, "bytes 0-${compressed.size - 1}/${compressed.size}")) }) { store, directory ->
            File(directory, asset.id + ".gz.part").writeBytes(compressed.copyOf(12))
            assertIs<ZkResult.Failed>(store.download(asset.id) { _, _ -> })
            assertTrue(directory.listFiles()!!.isEmpty())
        }
    }

    @Test fun cancellationRemovesAllTemporaryData() = runBlocking<Unit> {
        fixture { store, directory ->
            assertFailsWith<CancellationException> {
                store.download(asset.id) { done, _ -> if (done > 0) throw CancellationException() }
            }
            assertTrue(directory.listFiles()!!.isEmpty())
            assertNull(store.path(asset.id))
        }
    }

    @Test fun bundledManifestIsPinned() = runBlocking<Unit> {
        val directory = Files.createTempDirectory("diw-zk-catalog").toFile()
        val client = HttpClient(MockEngine { error("No network expected") })
        try {
            FileZkAssetStore.bundled(directory, client).use { store ->
                assertEquals(ZkAssetStatus.MISSING, store.status("jwt_2k.r1cs"))
                assertFailsWith<IllegalArgumentException> { store.path("../unlisted") }
            }
        } finally { client.close(); directory.deleteRecursively() }
    }
}
