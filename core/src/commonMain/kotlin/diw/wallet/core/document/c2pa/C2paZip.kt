package diw.wallet.core.document.c2pa

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.c2pa.C2paBytes as B

/**
 * ZIP archives (C2PA Appendix A.6: ZIP, OOXML, ODF, EPUB): the manifest store is the stored entry
 * META-INF/content_credential.c2pa, bound with a collection hash (c2pa.hash.collection.data) of every other entry,
 * from its local header to the end of its data, and of the central directory. The central directory hash leaves out
 * the manifest entry's CRC-32, as c2pa-rs computes it; a validator also accepts it over the whole directory.
 */
object C2paZip {
    const val MANIFEST = "META-INF/content_credential.c2pa"
    private const val LFH = 0x04034b50L
    private const val CDH = 0x02014b50L
    private const val EOCD = 0x06054b50L
    private const val DD = 0x08074b50L

    /** An entry as the central directory gives it, with where its local record starts and its data ends. */
    class Entry(
        val name: String,
        val cdStart: Int,
        val cdEnd: Int,
        val localStart: Long,
        val dataStart: Long,
        val dataEnd: Long,
        val method: Int,
        val crc: Long,
        val compressedSize: Long,
        val descriptor: Boolean,
        val large: Boolean,
    ) {
        val directory: Boolean get() = name.endsWith("/")
    }

    class Archive(val entries: List<Entry>, val cdStart: Long, val cdEnd: Long, val eocd: Int, val zip64: Boolean)

    fun isZip(b: ByteArray): Boolean = B.le32(b, 0) == LFH && runCatching { read(b) }.isSuccess

    private fun eocd(b: ByteArray): Int {
        val from = maxOf(0, b.size - 22 - 0xFFFF)
        for (i in b.size - 22 downTo from) if (B.le32(b, i) == EOCD && i + 22 + B.le16(b, i + 20) == b.size) return i
        for (i in b.size - 22 downTo from) if (B.le32(b, i) == EOCD) return i
        C2paContainers.fail("ZIP without an end of central directory record")
    }

    fun read(b: ByteArray): Archive {
        val e = eocd(b)
        var count = B.le16(b, e + 10).toLong()
        var cdSize = B.le32(b, e + 12)
        var cdStart = B.le32(b, e + 16)
        var zip64 = false
        if (e >= 20 && B.le32(b, e - 20) == 0x07064b50L) {
            val z = B.le64(b, e - 12)
            if (z >= 0 && z + 56 <= b.size && B.le32(b, z.toInt()) == 0x06064b50L) {
                zip64 = true
                count = B.le64(b, z.toInt() + 32)
                cdSize = B.le64(b, z.toInt() + 40)
                cdStart = B.le64(b, z.toInt() + 48)
            }
        }
        if (cdStart < 0 || cdStart + cdSize > b.size || count > 1_000_000) C2paContainers.fail("ZIP central directory out of range")
        val entries = ArrayList<Entry>()
        var p = cdStart.toInt()
        for (k in 0 until count) {
            if (B.le32(b, p) != CDH) C2paContainers.fail("ZIP central directory entry $k")
            val flags = B.le16(b, p + 8)
            val method = B.le16(b, p + 10)
            val crc = B.le32(b, p + 16)
            var csize = B.le32(b, p + 20)
            var usize = B.le32(b, p + 24)
            val n = B.le16(b, p + 28); val x = B.le16(b, p + 30); val c = B.le16(b, p + 32)
            var local = B.le32(b, p + 42)
            val name = b.copyOfRange(p + 46, p + 46 + n).decodeToString()
            var large = false
            // ZIP64 extended information: the fields that are 0xFFFFFFFF in the record, in order.
            var xp = p + 46 + n
            val xEnd = xp + x
            while (xp + 4 <= xEnd) {
                val id = B.le16(b, xp); val len = B.le16(b, xp + 2)
                if (id == 1) {
                    var q = xp + 4
                    if (usize == 0xFFFFFFFFL) { usize = B.le64(b, q); q += 8 }
                    if (csize == 0xFFFFFFFFL) { csize = B.le64(b, q); q += 8; large = true }
                    if (local == 0xFFFFFFFFL) { local = B.le64(b, q); q += 8 }
                    large = true
                }
                xp += 4 + len
            }
            if (local < 0 || local + 30 > b.size || B.le32(b, local.toInt()) != LFH) C2paContainers.fail("ZIP local header of $name")
            val dataStart = local + 30 + B.le16(b, local.toInt() + 26) + B.le16(b, local.toInt() + 28)
            val end = p + 46 + n + x + c
            entries.add(Entry(name, p, end, local, dataStart, dataStart + csize, method, crc, csize, flags and 0x08 != 0, large))
            p = end
        }
        return Archive(entries, cdStart, cdStart + cdSize, e, zip64)
    }

    /** The bytes the collection hash covers for an entry: local header to the end of the data (and its descriptor). */
    fun range(b: ByteArray, e: Entry): C2paRange {
        var end = e.dataEnd
        if (e.descriptor && end + 4 <= b.size) {
            val sig = B.le32(b, end.toInt())
            if (sig != LFH && sig != CDH) end += (if (sig == DD) 4 else 0) + 4 + 2 * (if (e.large) 8 else 4)
        }
        return C2paRange(e.localStart, end - e.localStart)
    }

    /** The collection URI of an entry: its name with "/" separators, without a directory's trailing slash. */
    fun uri(e: Entry): String = e.name.replace('\\', '/').trimEnd('/')

    fun locate(b: ByteArray): Pair<ByteArray, C2paRange>? {
        val a = read(b)
        val e = a.entries.firstOrNull { it.name == MANIFEST } ?: return null
        if (e.method != 0) return null
        return b.copyOfRange(e.dataStart.toInt(), e.dataEnd.toInt()) to range(b, e)
    }

    fun mediaType(b: ByteArray): String = runCatching {
        val a = read(b)
        val first = a.entries.minByOrNull { it.localStart }
        val names = a.entries.map { it.name }.toSet()
        when {
            first?.name == "mimetype" && first.method == 0 -> b.copyOfRange(first.dataStart.toInt(), first.dataEnd.toInt()).decodeToString().trim()
            "[Content_Types].xml" in names && names.any { it.startsWith("word/") } -> "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            "[Content_Types].xml" in names && names.any { it.startsWith("xl/") } -> "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            "[Content_Types].xml" in names && names.any { it.startsWith("ppt/") } -> "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            else -> "application/zip"
        }
    }.getOrDefault("application/zip")

    fun cannotEmbed(b: ByteArray): String? = runCatching {
        val a = read(b)
        when {
            a.zip64 || a.entries.any { it.large } -> "ZIP64 archive"
            B.le16(b, a.eocd + 4) != 0 || B.le16(b, a.eocd + 6) != 0 -> "multi-disk ZIP"
            a.cdEnd != a.eocd.toLong() -> "ZIP with data after the central directory"
            else -> null
        }
    }.getOrElse { it.message ?: "unreadable ZIP" }

    private fun localHeader(name: ByteArray, crc: Long, size: Long): ByteArray =
        B.le32b(LFH) + B.le16b(20) + B.le16b(0) + B.le16b(0) + B.le16b(0) + B.le16b(0x21) +
            B.le32b(crc) + B.le32b(size) + B.le32b(size) + B.le16b(name.size) + B.le16b(0) + name

    private fun cdRecord(name: ByteArray, crc: Long, size: Long, local: Long, directory: Boolean): ByteArray =
        B.le32b(CDH) + B.le16b(20) + B.le16b(20) + B.le16b(0) + B.le16b(0) + B.le16b(0) + B.le16b(0x21) +
            B.le32b(crc) + B.le32b(size) + B.le32b(size) + B.le16b(name.size) + B.le16b(0) + B.le16b(0) + B.le16b(0) + B.le16b(0) +
            B.le32b(if (directory) 0x10L else 0L) + B.le32b(local) + name

    private fun eocdRecord(b: ByteArray, a: Archive, count: Int, cdSize: Long, cdStart: Long): ByteArray {
        val comment = b.copyOfRange(a.eocd + 22, b.size)
        return B.le32b(EOCD) + B.le16b(0) + B.le16b(0) + B.le16b(count) + B.le16b(count) + B.le32b(cdSize) + B.le32b(cdStart) + B.le16b(comment.size) + comment
    }

    /** The archive without the manifest entry (its local record and central directory record). */
    fun strip(b: ByteArray): ByteArray {
        val a = read(b)
        val m = a.entries.firstOrNull { it.name == MANIFEST } ?: return b
        val r = range(b, m)
        val cd = ArrayList<ByteArray>()
        for (e in a.entries) {
            if (e === m) continue
            val rec = b.copyOfRange(e.cdStart, e.cdEnd)
            if (e.localStart > r.start) B.putLe32(rec, 42, e.localStart - r.length)
            cd.add(rec)
        }
        val head = b.copyOfRange(0, r.start.toInt()) + b.copyOfRange(r.end.toInt(), a.cdStart.toInt())
        val cdBytes = C2paCbor.concat(cd)
        return head + cdBytes + eocdRecord(b, a, cd.size, cdBytes.size.toLong(), head.size.toLong())
    }

    /** The manifest entry (stored, after the last entry's data) and the META-INF/ directory when the archive has none. */
    fun embed(base: ByteArray, store: ByteArray): C2paLayout {
        cannotEmbed(base)?.let { C2paContainers.fail(it) }
        val a = read(base)
        var pos = a.cdStart
        val locals = ArrayList<ByteArray>()
        val records = ArrayList<ByteArray>()
        if (a.entries.none { it.name == "META-INF/" }) {
            val dir = "META-INF/".encodeToByteArray()
            locals.add(localHeader(dir, 0, 0))
            records.add(cdRecord(dir, 0, 0, pos, true))
            pos += locals.last().size
        }
        val name = MANIFEST.encodeToByteArray()
        val crc = Crc32.of(store).toLong() and 0xFFFFFFFFL
        val manifestAt = pos
        locals.add(localHeader(name, crc, store.size.toLong()) + store)
        records.add(cdRecord(name, crc, store.size.toLong(), manifestAt, false))
        val head = base.copyOfRange(0, a.cdStart.toInt()) + C2paCbor.concat(locals)
        val cd = base.copyOfRange(a.cdStart.toInt(), a.cdEnd.toInt()) + C2paCbor.concat(records)
        val out = head + cd + eocdRecord(base, a, a.entries.size + records.size, cd.size.toLong(), head.size.toLong())
        return C2paLayout(out, C2paRange(manifestAt, (30 + name.size + store.size).toLong()))
    }

    // ---------------------------------------------------------------- collection hash

    /** Hash of the central directory to the end of the file without the manifest entry's CRC-32 (c2pa-rs). */
    fun centralDirectoryHash(b: ByteArray, a: Archive, alg: String, variant: Int = 0): ByteArray {
        val m = a.entries.firstOrNull { it.name == MANIFEST }
        val jca = C2paManifests.jcaHash(alg)
        if (m == null || variant == 1) return DocCrypto.digest(jca, b.copyOfRange(a.cdStart.toInt(), b.size))
        val crcAt = m.cdStart + 16
        if (variant == 2) {
            val copy = b.copyOfRange(a.cdStart.toInt(), b.size)
            for (k in 0 until 4) copy[crcAt - a.cdStart.toInt() + k] = 0
            return DocCrypto.digest(jca, copy)
        }
        return DocCrypto.digest(jca, b.copyOfRange(a.cdStart.toInt(), crcAt) + b.copyOfRange(crcAt + 4, b.size))
    }

    /** The entries a collection hash lists: every entry but the manifest, sorted by URI. */
    fun hashedEntries(a: Archive): List<Entry> = a.entries.filter { it.name != MANIFEST }.sortedBy { uri(it) }

    /** The CBOR of c2pa.hash.collection.data over a laid-out archive ([zero] gives a placeholder of the same size). */
    fun assertionCbor(b: ByteArray, alg: String = "sha256", zero: Boolean = false): ByteArray {
        val a = read(b)
        val jca = C2paManifests.jcaHash(alg)
        val size = DocCrypto.digest(jca, ByteArray(0)).size
        val uris = hashedEntries(a).map { e ->
            val r = range(b, e)
            val h = if (zero) ByteArray(size) else DocCrypto.digest(jca, b.copyOfRange(r.start.toInt(), r.end.toInt()))
            C2paCbor.map(listOf("uri" to C2paCbor.tstr(uri(e)), "hash" to C2paCbor.bstr(h), "size" to C2paCbor.int(r.length)))
        }
        val cd = if (zero) ByteArray(size) else centralDirectoryHash(b, a, alg)
        return C2paCbor.map(listOf(
            "uris" to C2paCbor.array(uris),
            "alg" to C2paCbor.tstr(alg),
            "zip_central_directory_hash" to C2paCbor.bstr(cd),
        ))
    }
}
