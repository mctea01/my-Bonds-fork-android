package diw.wallet.core.document

import java.io.ByteArrayInputStream
import diw.wallet.core.util.TextEncodings
import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import java.util.Base64
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlin.time.Instant

/** ZIP reading and writing with limits (entries, sizes, path traversal). */
object Zip {
    const val MAX_ENTRIES = 5000
    const val MAX_TOTAL = 256L * 1024 * 1024

    fun isZip(b: ByteArray) = b.size > 4 && b[0] == 'P'.code.toByte() && b[1] == 'K'.code.toByte() && b[2] == 3.toByte() && b[3] == 4.toByte()

    /**
     * The files of a ZIP archive by normalized path (directories omitted). Names are read from the central directory
     * with their own encoding: UTF-8 when flagged or valid, the Info-ZIP Unicode path field when present, otherwise
     * the legacy encoding Windows wrote (Big5 in Taiwan, GBK in mainland China), so Chinese names never become "?".
     */
    fun read(bytes: ByteArray): Map<String, ByteArray> =
        runCatching { readCentral(bytes) }.getOrNull() ?: readStream(bytes)

    private fun u16(b: ByteArray, p: Int) = (b[p].toInt() and 0xFF) or ((b[p + 1].toInt() and 0xFF) shl 8)
    private fun u32(b: ByteArray, p: Int) = u16(b, p).toLong() or (u16(b, p + 2).toLong() shl 16)
    private fun u64(b: ByteArray, p: Int) = u32(b, p) or (u32(b, p + 4) shl 32)

    private fun readCentral(bytes: ByteArray): Map<String, ByteArray> {
        // End of central directory: the last "PK\u0005\u0006" within the trailing comment's reach.
        var eocd = -1
        for (p in bytes.size - 22 downTo maxOf(0, bytes.size - 22 - 65535)) {
            if (bytes[p] == 0x50.toByte() && bytes[p + 1] == 0x4B.toByte() && bytes[p + 2] == 5.toByte() && bytes[p + 3] == 6.toByte()) { eocd = p; break }
        }
        if (eocd < 0) throw IllegalArgumentException("no central directory")
        var count = u16(bytes, eocd + 10).toLong()
        var cdOffset = u32(bytes, eocd + 16)
        if (cdOffset == 0xFFFFFFFFL || count == 0xFFFFL) {
            // ZIP64 end of central directory locator, just before the EOCD.
            val loc = eocd - 20
            if (loc < 0 || u32(bytes, loc) != 0x07064b50L) throw IllegalArgumentException("bad zip64")
            val z64 = u64(bytes, loc + 8).toInt()
            count = u64(bytes, z64 + 32)
            cdOffset = u64(bytes, z64 + 48)
        }
        if (count > MAX_ENTRIES) throw IllegalArgumentException("壓縮檔內的檔案太多")
        val out = LinkedHashMap<String, ByteArray>()
        var total = 0L
        var p = cdOffset.toInt()
        repeat(count.toInt()) {
            if (u32(bytes, p) != 0x02014b50L) throw IllegalArgumentException("bad central directory")
            val flags = u16(bytes, p + 8)
            val method = u16(bytes, p + 10)
            var compressed = u32(bytes, p + 20)
            var size = u32(bytes, p + 24)
            val nameLen = u16(bytes, p + 28)
            val extraLen = u16(bytes, p + 30)
            val commentLen = u16(bytes, p + 32)
            var local = u32(bytes, p + 42)
            val rawName = bytes.copyOfRange(p + 46, p + 46 + nameLen)
            var unicodeName: String? = null
            var e = p + 46 + nameLen
            val extraEnd = e + extraLen
            while (e + 4 <= extraEnd) {
                val id = u16(bytes, e)
                val len = u16(bytes, e + 2)
                if (id == 0x0001) {
                    var q = e + 4
                    if (size == 0xFFFFFFFFL) { size = u64(bytes, q); q += 8 }
                    if (compressed == 0xFFFFFFFFL) { compressed = u64(bytes, q); q += 8 }
                    if (local == 0xFFFFFFFFL) { local = u64(bytes, q) }
                } else if (id == 0x7075 && len > 5 && bytes[e + 4].toInt() == 1) {
                    unicodeName = bytes.copyOfRange(e + 9, e + 4 + len).toString(Charsets.UTF_8)
                }
                e += 4 + len
            }
            p = extraEnd + commentLen
            val name = (unicodeName ?: TextEncodings.decode(rawName, flags and 0x800 != 0)).replace('\\', '/').trimStart('/')
            if (name.isEmpty() || name.endsWith("/") || name.split('/').any { it == ".." }) return@repeat
            if (flags and 1 != 0) throw IllegalArgumentException("壓縮檔「$name」有密碼保護，無法解開")
            total += size
            if (total > MAX_TOTAL) throw IllegalArgumentException("壓縮檔解開後超過 256 MB")
            val lh = local.toInt()
            if (u32(bytes, lh) != 0x04034b50L) throw IllegalArgumentException("bad local header")
            val dataStart = lh + 30 + u16(bytes, lh + 26) + u16(bytes, lh + 28)
            val data = bytes.copyOfRange(dataStart, dataStart + compressed.toInt())
            out[name] = when (method) {
                0 -> data
                8 -> {
                    val inf = java.util.zip.Inflater(true)
                    try {
                        inf.setInput(data)
                        val buf = ByteArray(size.toInt())
                        var n = 0
                        while (n < buf.size && !inf.finished()) {
                            val r = inf.inflate(buf, n, buf.size - n)
                            if (r == 0 && (inf.needsInput() || inf.needsDictionary())) break
                            n += r
                        }
                        if (n != buf.size) throw IllegalArgumentException("「$name」解壓縮後大小不符")
                        buf
                    } finally {
                        inf.end()
                    }
                }
                else -> throw IllegalArgumentException("壓縮檔「$name」使用不支援的壓縮方式（$method）")
            }
        }
        return out
    }

    /** Fallback for archives without a readable central directory (cut off or streamed). */
    private fun readStream(bytes: ByteArray): Map<String, ByteArray> =
        runCatching { readStreamWith(bytes, Charsets.UTF_8) }.getOrNull()
            ?: readStreamWith(bytes, runCatching { Charset.forName("x-windows-950") }.getOrDefault(Charsets.ISO_8859_1))

    private fun readStreamWith(bytes: ByteArray, charset: Charset): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        var total = 0L
        ZipInputStream(ByteArrayInputStream(bytes), charset).use { z ->
            while (true) {
                val e = z.nextEntry ?: break
                if (out.size >= MAX_ENTRIES) throw IllegalArgumentException("壓縮檔內的檔案太多")
                val name = e.name.replace('\\', '/').trimStart('/')
                if (e.isDirectory || name.isEmpty() || name.split('/').any { it == ".." }) continue
                val buf = ByteArrayOutputStream()
                val chunk = ByteArray(65536)
                while (true) {
                    val n = z.read(chunk)
                    if (n < 0) break
                    total += n
                    if (total > MAX_TOTAL) throw IllegalArgumentException("壓縮檔解開後超過 256 MB")
                    buf.write(chunk, 0, n)
                }
                out[name] = buf.toByteArray()
            }
        }
        return out
    }

    /** A ZIP archive of [files] in order; [stored] names are written without compression (ASiC mimetype). */
    fun write(files: List<Pair<String, ByteArray>>, stored: Set<String> = emptySet()): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { z ->
            for ((name, data) in files) {
                val e = ZipEntry(name)
                if (name in stored) {
                    e.method = ZipEntry.STORED
                    e.size = data.size.toLong()
                    e.compressedSize = data.size.toLong()
                    e.crc = CRC32().apply { update(data) }.value
                }
                z.putNextEntry(e)
                z.write(data)
                z.closeEntry()
            }
        }
        return bos.toByteArray()
    }
}

/** ASiC-E and ASiC-S containers (ETSI EN 319 162-1) with CAdES or XAdES signatures. */
internal object Asic {
    const val MIME_E = "application/vnd.etsi.asic-e+zip"
    const val MIME_S = "application/vnd.etsi.asic-s+zip"
    private const val ASIC_NS = "http://uri.etsi.org/02918/v1.2.1#"

    fun isAsic(files: Map<String, ByteArray>): Boolean {
        val mime = files["mimetype"]?.decodeToString()?.trim()
        return mime == MIME_E || mime == MIME_S || files.keys.any { it.startsWith("META-INF/") && (it.contains("signature", true) || it.contains("ASiCManifest")) }
    }

    suspend fun verify(files: Map<String, ByteArray>, checks: CmsChecks, now: Instant): List<SignatureInfo> {
        val out = ArrayList<SignatureInfo>()
        val dataFiles = files.keys.filter { !it.startsWith("META-INF/") && it != "mimetype" }
        val manifests = files.filterKeys { it.startsWith("META-INF/") && it.contains("ASiCManifest", true) }
        val usedSignatures = HashSet<String>()
        for ((path, manifest) in manifests) {
            val doc = runCatching { XmlParsing.parse(manifest) }.getOrNull() ?: continue
            val sigRef = XmlParsing.descendants(doc, null, "SigReference").firstOrNull()?.getAttribute("URI") ?: continue
            val sig = files[sigRef] ?: continue
            usedSignatures.add(sigRef)
            val problems = ArrayList<String>()
            var digestsOk = Check.PASS
            val covered = HashSet<String>()
            for (ref in XmlParsing.descendants(doc, null, "DataObjectReference")) {
                val uri = java.net.URLDecoder.decode(ref.getAttribute("URI"), "UTF-8")
                covered.add(uri)
                val alg = XmlDsig.digestName(XmlParsing.child(ref, XmlDsig.DS, "DigestMethod")?.getAttribute("Algorithm"))
                val expected = runCatching { Base64.getMimeDecoder().decode(XmlParsing.text(XmlParsing.child(ref, XmlDsig.DS, "DigestValue")).orEmpty()) }.getOrNull()
                val data = files[uri]
                when {
                    data == null -> { problems.add("容器內找不到 $uri"); digestsOk = Check.FAIL }
                    alg == null || expected == null -> { problems.add("$uri 的摘要演算法不支援"); if (digestsOk == Check.PASS) digestsOk = Check.NOT_CHECKED }
                    !DocCrypto.digest(alg, data).contentEquals(expected) -> { problems.add("$uri 在簽署後被修改"); digestsOk = Check.FAIL }
                }
            }
            val results = checks.verify(sig, manifest, SignatureFormat.ASIC_CADES, sigRef.substringAfterLast('/'), now)
            val missing = dataFiles.filter { it !in covered }
            for (r in results) out.add(merge(r, digestsOk, problems, missing))
        }
        // XAdES signatures in the container: detached references resolve to container files.
        for ((path, xml) in files.filterKeys { it.startsWith("META-INF/") && it.contains("signatures", true) && it.endsWith(".xml") }) {
            usedSignatures.add(path)
            val results = runCatching { XmlDsig.verify(xml, path.substringAfterLast('/'), checks, now) { uri -> files[uri] } }
                .getOrElse { listOf(checks.failed(SignatureFormat.XADES, path, "無法解析 XAdES：" + (it.message ?: ""))) }
            val covered = runCatching {
                XmlParsing.descendants(XmlParsing.parse(xml), XmlDsig.DS, "Reference").map { java.net.URLDecoder.decode(it.getAttribute("URI"), "UTF-8") }.toSet()
            }.getOrDefault(emptySet())
            val missing = dataFiles.filter { it !in covered }
            results.forEach { out.add(merge(it, it.integrity, emptyList(), missing)) }
        }
        // ASiC-S (or a container without a manifest): one CAdES signature over the single data file.
        for ((path, sig) in files.filterKeys { it.startsWith("META-INF/") && it.endsWith(".p7s") && it !in usedSignatures }) {
            val data = dataFiles.singleOrNull()?.let { files[it] }
            val results = checks.verify(sig, data, SignatureFormat.ASIC_CADES, path.substringAfterLast('/'), now)
            out.addAll(results.map { it.copy(coversWholeDocument = data != null) })
        }
        return out
    }

    private fun merge(r: SignatureInfo, digests: Check, problems: List<String>, missing: List<String>): SignatureInfo {
        val integrity = when {
            r.integrity == Check.FAIL || digests == Check.FAIL -> Check.FAIL
            r.integrity == Check.PASS -> digests
            else -> r.integrity
        }
        val notes = if (missing.isEmpty()) r.notes else r.notes + ("簽章沒有涵蓋容器內的：" + missing.take(5).joinToString("、"))
        return r.copy(integrity = integrity, problems = r.problems + problems, notes = notes, coversWholeDocument = missing.isEmpty())
    }

    /** ASiCManifest for [files] (SHA-256), naming [signaturePath] as the signature that covers it. */
    fun manifest(files: List<Pair<String, ByteArray>>, signaturePath: String): ByteArray = buildString {
        append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>")
        append("<asic:ASiCManifest xmlns:asic=\"$ASIC_NS\" xmlns:ds=\"${XmlDsig.DS}\">")
        append("<asic:SigReference MimeType=\"application/pkcs7-signature\" URI=\"$signaturePath\"/>")
        for ((name, data) in files) {
            append("<asic:DataObjectReference MimeType=\"${mimeOf(name)}\" URI=\"${xmlAttr(java.net.URLEncoder.encode(name, "UTF-8").replace("+", "%20").replace("%2F", "/"))}\">")
            append("<ds:DigestMethod Algorithm=\"${XmlDsig.SHA256}\"/><ds:DigestValue>" + Base64.getEncoder().encodeToString(DocCrypto.digest("SHA-256", data)) + "</ds:DigestValue>")
            append("</asic:DataObjectReference>")
        }
        append("</asic:ASiCManifest>")
    }.toByteArray(Charsets.UTF_8)

    private fun xmlAttr(s: String) = s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;")

    fun mimeOf(name: String): String = when (name.substringAfterLast('.', "").lowercase()) {
        "pdf" -> "application/pdf"
        "xml", "di" -> "application/xml"
        "json" -> "application/json"
        "txt" -> "text/plain"
        "png" -> "image/png"
        "jpg", "jpeg" -> "image/jpeg"
        "ofd" -> "application/ofd"
        else -> "application/octet-stream"
    }
}
