package diw.wallet.core.zk.native

import diw.wallet.core.zk.*
import io.ktor.client.HttpClient
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.utils.io.*
import kotlinx.coroutines.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.zip.GZIPInputStream

/** The caller owns the HTTP client; this store owns only its redirect-disabled child. */
class FileZkAssetStore(
    private val directory: File,
    client: HttpClient,
    val assets: List<ZkAsset>,
) : ZkAssetStore, AutoCloseable {
    private val http = client.config { followRedirects = false; expectSuccess = false }
    private val catalog = assets.associateBy { it.id }
    private val locks = catalog.keys.associateWith { Mutex() }

    init {
        require(catalog.size == assets.size) { "Duplicate asset identifier" }
        assets.forEach { asset ->
            require(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,95}").matches(asset.id)) { "Invalid asset identifier" }
            require(!asset.id.endsWith(".gz.part") && !asset.id.endsWith(".installing")) { "Reserved asset identifier" }
            require(asset.gzipBytes > 0 && asset.installedBytes > 0) { "Invalid asset size" }
            require(listOf(asset.gzipSha256, asset.installedSha256).all { Regex("[a-f0-9]{64}").matches(it) }) {
                "Invalid asset hash"
            }
            require(asset.role.isNotEmpty() && asset.role.all { it in setOf("prover", "verifier") }) { "Invalid asset role" }
            require(asset.urls.isNotEmpty() && asset.urls.all(::httpsUrl)) { "Invalid asset URL" }
        }
        require(directory.isDirectory || directory.mkdirs()) { "Asset directory unavailable" }
    }

    companion object {
        /** Production uses only the hash-pinned resource; the constructor also supports synthetic test catalogs. */
        fun bundled(directory: File, client: HttpClient): FileZkAssetStore {
            val bytes = FileZkAssetStore::class.java.getResourceAsStream("/zk/assets.json")?.use { it.readBytes() }
                ?: error("Asset manifest unavailable")
            require(sha256(bytes) == ZkAssetManifest.SHA256) { "Asset manifest integrity check failed" }
            return FileZkAssetStore(directory, client, Json.decodeFromString<List<ZkAsset>>(bytes.decodeToString()))
        }

        private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).hex()
        private fun ByteArray.hex() = joinToString("") { "%02x".format(it.toInt() and 255) }
        private fun httpsUrl(value: String): Boolean = runCatching {
            val url = Url(value)
            url.protocol == URLProtocol.HTTPS && url.host.isNotBlank() && url.user == null &&
                url.password == null && url.fragment.isEmpty()
        }.getOrDefault(false)
    }

    private fun asset(id: String) = catalog[id] ?: throw IllegalArgumentException("Unknown asset identifier")
    private fun installed(asset: ZkAsset) = File(directory, asset.id)
    private fun partial(asset: ZkAsset) = File(directory, asset.id + ".gz.part")
    private fun staging(asset: ZkAsset) = File(directory, asset.id + ".installing")

    private fun matches(file: File, size: Long, hash: String): Boolean {
        if (!file.isFile || file.length() != size) return false
        return runCatching {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().buffered().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            digest.digest().hex() == hash
        }.getOrDefault(false)
    }

    override suspend fun status(id: String): ZkAssetStatus = withContext(Dispatchers.IO) {
        val asset = asset(id)
        locks.getValue(id).withLock { state(asset) }
    }

    private fun state(asset: ZkAsset): ZkAssetStatus = when {
        installed(asset).exists() -> if (matches(installed(asset), asset.installedBytes, asset.installedSha256))
            ZkAssetStatus.READY else ZkAssetStatus.CORRUPT
        partial(asset).exists() -> if (partial(asset).length() in 1..asset.gzipBytes)
            ZkAssetStatus.PARTIAL else ZkAssetStatus.CORRUPT
        else -> ZkAssetStatus.MISSING
    }

    override fun path(id: String): String? {
        val asset = asset(id)
        return installed(asset).takeIf { matches(it, asset.installedBytes, asset.installedSha256) }?.absolutePath
    }

    override suspend fun delete(id: String) = withContext(Dispatchers.IO) {
        val asset = asset(id)
        locks.getValue(id).withLock { erase(asset) }
    }

    private fun erase(asset: ZkAsset) {
        listOf(installed(asset), partial(asset), staging(asset)).forEach { Files.deleteIfExists(it.toPath()) }
    }

    override suspend fun download(id: String, onProgress: (Long, Long) -> Unit): ZkResult<Unit> =
        withContext(Dispatchers.IO) {
            val asset = asset(id)
            locks.getValue(id).withLock {
                try {
                    if (state(asset) == ZkAssetStatus.READY) return@withLock ZkResult.Ok(Unit)
                    Files.deleteIfExists(installed(asset).toPath())
                    Files.deleteIfExists(staging(asset).toPath())
                    if (partial(asset).length() > asset.gzipBytes) Files.deleteIfExists(partial(asset).toPath())
                    var downloaded = partial(asset).length() == asset.gzipBytes
                    for (url in asset.urls) {
                        if (downloaded) break
                        try {
                            fetch(asset, url, onProgress)
                            downloaded = true
                        } catch (e: CancellationException) {
                            throw e
                        } catch (_: IOException) {
                            // A transport interruption retains a prefix for a later Range request.
                        }
                    }
                    if (!downloaded) return@withLock ZkResult.Failed("下載中斷，可稍後續傳", true)
                    if (!matches(partial(asset), asset.gzipBytes, asset.gzipSha256)) throw IntegrityFailure()
                    var written = 0L
                    val digest = MessageDigest.getInstance("SHA-256")
                    GZIPInputStream(partial(asset).inputStream().buffered()).use { input ->
                        staging(asset).outputStream().buffered().use { output ->
                            val buffer = ByteArray(64 * 1024)
                            while (true) {
                                currentCoroutineContext().ensureActive()
                                val count = input.read(buffer)
                                if (count < 0) break
                                if (count.toLong() > asset.installedBytes - written) throw IntegrityFailure()
                                output.write(buffer, 0, count)
                                digest.update(buffer, 0, count)
                                written += count
                            }
                        }
                    }
                    if (written != asset.installedBytes || digest.digest().hex() != asset.installedSha256) throw IntegrityFailure()
                    currentCoroutineContext().ensureActive()
                    // Same-filesystem atomic replacement prevents partially installed keys from being used.
                    Files.move(staging(asset).toPath(), installed(asset).toPath(), StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING)
                    Files.deleteIfExists(partial(asset).toPath())
                    ZkResult.Ok(Unit)
                } catch (e: CancellationException) {
                    erase(asset)
                    throw e
                } catch (_: IntegrityFailure) {
                    erase(asset)
                    ZkResult.Failed("證明資產完整性檢查失敗，已刪除下載內容", true)
                } catch (_: Exception) {
                    erase(asset)
                    ZkResult.Failed("無法安裝證明資產，請重試", true)
                }
            }
        }

    private suspend fun fetch(asset: ZkAsset, initialUrl: String, progress: (Long, Long) -> Unit) {
        val part = partial(asset)
        var url = initialUrl
        repeat(6) { redirect ->
            var next: String? = null
            http.prepareGet(url) {
                header(HttpHeaders.AcceptEncoding, "identity")
                if (part.length() > 0) header(HttpHeaders.Range, "bytes=${part.length()}-")
            }.execute { response ->
                if (response.status.value in setOf(301, 302, 303, 307, 308)) {
                    val location = response.headers[HttpHeaders.Location] ?: throw IntegrityFailure()
                    val resolved = java.net.URI(url).resolve(location).toString()
                    if (!httpsUrl(resolved) || redirect == 5) throw IntegrityFailure()
                    next = resolved
                    return@execute
                }
                if (response.headers[HttpHeaders.ContentEncoding]?.let { it != "identity" } == true) throw IntegrityFailure()
                var offset = part.length()
                when (response.status) {
                    HttpStatusCode.OK -> offset = 0L
                    HttpStatusCode.PartialContent -> {
                        val range = response.headers[HttpHeaders.ContentRange]
                        if (range != "bytes $offset-${asset.gzipBytes - 1}/${asset.gzipBytes}") throw IntegrityFailure()
                    }
                    else -> throw IOException("Asset transport failure")
                }
                val length = response.headers[HttpHeaders.ContentLength]?.toLongOrNull()
                if (length != null && length != asset.gzipBytes - offset) throw IntegrityFailure()
                java.io.FileOutputStream(part, offset > 0).buffered().use { output ->
                    progress(offset, asset.gzipBytes)
                    val channel = response.bodyAsChannel()
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = channel.readAvailable(buffer)
                        if (count < 0) break
                        if (count.toLong() > asset.gzipBytes - offset) throw IntegrityFailure()
                        output.write(buffer, 0, count)
                        offset += count
                        progress(offset, asset.gzipBytes)
                    }
                }
                if (offset != asset.gzipBytes) throw IOException("Incomplete asset transfer")
            }
            if (next == null) return
            url = next!!
        }
        throw IntegrityFailure()
    }

    override fun close() = http.close()
    private class IntegrityFailure : Exception()
}
