package diw.wallet.core.document

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
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

    /** The files of a ZIP archive by normalized path (directories omitted). */
    fun read(bytes: ByteArray): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        var total = 0L
        ZipInputStream(ByteArrayInputStream(bytes)).use { z ->
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
