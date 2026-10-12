package diw.wallet.core.document.pdf

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.jose.PlatformCrypto

/**
 * Random access to the objects of a PDF file: cross-reference tables and streams (including hybrid files and
 * incremental updates), object streams, stream filters, and the standard security handler opened with [password] or
 * the empty user password (documents that are only protected against copying or editing). A file whose
 * cross-reference data is broken is read by scanning for "n g obj" headers.
 */
class PdfFile(val bytes: ByteArray, password: String = "") {
    /** One xref section: where it starts, the objects it defines, and where its revision ends (after %%EOF). */
    class Revision(val xrefOffset: Int, val objects: Set<Int>, val end: Int, val trailer: PdfDict, val usesXrefStream: Boolean)

    private sealed class Entry {
        class InFile(val offset: Int, val gen: Int) : Entry()
        class InStream(val stream: Int, val index: Int) : Entry()
        object Free : Entry()
    }

    private val entries = HashMap<Int, Entry>()
    private val cache = HashMap<Int, PdfObject>()
    private val objStmCache = HashMap<Int, Map<Int, PdfObject>>()

    /** Newest revision first. */
    val revisions: List<Revision>
    val trailer: PdfDict
    /** True when the xref data could not be read and objects were found by scanning. */
    val reconstructed: Boolean

    val encrypted: Boolean get() = trailer["Encrypt"] != null
    private var security: StandardSecurity? = null
    /** Null when the file is not encrypted or the password (or the empty one) opens it; otherwise why it cannot be read. */
    var encryptionProblem: String? = null
        private set
    /** True when the file is encrypted with a user password that neither the given password nor the empty one opens. */
    var passwordRequired: Boolean = false
        private set

    init {
        if (!isPdf(bytes)) throw PdfException("Not a PDF file")
        var revs: List<Revision>
        var rebuilt = false
        revs = try {
            readXrefChain()
        } catch (e: PdfException) {
            emptyList()
        }
        if (revs.isEmpty() || resolveOrNull(revs.first().trailer["Root"]) !is PdfDict) {
            entries.clear(); cache.clear()
            revs = listOf(scanObjects())
            rebuilt = true
        }
        revisions = revs
        trailer = revs.first().trailer
        reconstructed = rebuilt
        if (encrypted) {
            try {
                security = StandardSecurity.open(resolve(trailer["Encrypt"]) as? PdfDict ?: throw PdfException("No encryption dictionary"), firstId(), password)
            } catch (e: PdfException) {
                encryptionProblem = e.message
                passwordRequired = e is PdfPasswordException
            }
            cache.clear()
            objStmCache.clear()
        }
    }

    val catalog: PdfDict get() = resolve(trailer["Root"]) as? PdfDict ?: throw PdfException("No document catalog")

    fun firstId(): ByteArray = ((trailer["ID"] as? PdfArray)?.firstOrNull() as? PdfString)?.bytes ?: ByteArray(0)

    /** Highest object number in use plus one, for appending objects. */
    val size: Int get() = maxOf((trailer["Size"] as? PdfNumber)?.int ?: 0, (entries.keys.maxOrNull() ?: 0) + 1)

    fun resolveOrNull(o: PdfObject?): PdfObject? = try { resolve(o) } catch (e: PdfException) { null }

    /** Follows indirect references (at most 32 deep); null and missing objects resolve to [PdfNull]. */
    fun resolve(o: PdfObject?): PdfObject {
        var cur: PdfObject = o ?: return PdfNull
        var depth = 0
        while (cur is PdfRef) {
            if (depth++ > 32) throw PdfException("Reference loop")
            cur = getObject(cur.num)
        }
        return cur
    }

    fun dict(o: PdfObject?): PdfDict? = resolve(o) as? PdfDict
    fun array(o: PdfObject?): PdfArray? = resolve(o) as? PdfArray

    fun getObject(num: Int): PdfObject {
        cache[num]?.let { return it }
        val obj = when (val e = entries[num]) {
            null, Entry.Free -> PdfNull
            is Entry.InFile -> readAt(e.offset, num)
            is Entry.InStream -> objectStream(e.stream)[num] ?: PdfNull
        }
        cache[num] = obj
        return obj
    }

    /** Generation of an object as recorded in the cross-reference data (0 for objects in object streams). */
    fun generation(num: Int): Int = (entries[num] as? Entry.InFile)?.gen ?: 0

    /** Where an object stored directly in the file begins, or null. */
    fun offsetOf(num: Int): Int? = (entries[num] as? Entry.InFile)?.offset

    private fun readAt(offset: Int, expectedNum: Int): PdfObject {
        if (offset < 0 || offset >= bytes.size) throw PdfException("Object $expectedNum outside the file")
        val p = PdfParser(bytes, offset, ::streamLength)
        val (num, gen, obj) = try {
            p.parseIndirect()
        } catch (e: PdfException) {
            throw PdfException("Object $expectedNum unreadable: ${e.message}", e)
        }
        if (num != expectedNum) throw PdfException("Object $expectedNum: found object $num at its offset")
        return decryptObject(obj, num, gen)
    }

    private fun streamLength(d: PdfDict): Int? = when (val l = d["Length"]) {
        is PdfNumber -> l.int
        is PdfRef -> (try { getObject(l.num) } catch (e: PdfException) { null } as? PdfNumber)?.int
        else -> null
    }

    private fun objectStream(num: Int): Map<Int, PdfObject> = objStmCache.getOrPut(num) {
        val s = getObject(num) as? PdfStream ?: throw PdfException("Object stream $num missing")
        val data = decode(s)
        val n = (s.dict["N"] as? PdfNumber)?.int ?: 0
        val first = (s.dict["First"] as? PdfNumber)?.int ?: 0
        val p = PdfParser(data)
        val header = (0 until n).map { (p.parseObject() as PdfNumber).int to (p.parseObject() as PdfNumber).int }
        header.associate { (objNum, off) ->
            p.pos = first + off
            objNum to p.parseObject()
        }
    }

    // ---------------------------------------------------------------- cross-reference data

    private fun readXrefChain(): List<Revision> {
        val sx = PdfParser.lastIndexOf(bytes, "startxref".encodeToByteArray())
        if (sx < 0) throw PdfException("No startxref")
        val p = PdfParser(bytes, sx + 9)
        var offset = p.readToken().toIntOrNull() ?: throw PdfException("Bad startxref")
        val revs = ArrayList<Revision>()
        val seen = HashSet<Int>()
        while (offset >= 0 && seen.add(offset)) {
            if (offset >= bytes.size) throw PdfException("xref offset outside the file")
            val rev = readSection(offset)
            revs.add(rev)
            offset = (rev.trailer["Prev"] as? PdfNumber)?.int ?: -1
        }
        return revs
    }

    private fun readSection(offset: Int): Revision {
        val p = PdfParser(bytes, offset, ::streamLength)
        p.skipWhitespace()
        val defined = HashSet<Int>()
        val trailerDict: PdfDict
        val usesStream: Boolean
        if (p.startsWith("xref")) {
            p.pos += 4
            while (true) {
                p.skipWhitespace()
                if (p.startsWith("trailer")) { p.pos += 7; break }
                val start = p.readToken().toIntOrNull() ?: throw PdfException("Bad xref subsection")
                val count = p.readToken().toIntOrNull() ?: throw PdfException("Bad xref subsection")
                for (i in 0 until count) {
                    val off = p.readToken().toLongOrNull() ?: throw PdfException("Bad xref entry")
                    val gen = p.readToken().toIntOrNull() ?: throw PdfException("Bad xref entry")
                    val type = p.readToken()
                    val num = start + i
                    defined.add(num)
                    if (num !in entries) entries[num] = if (type == "n" && off > 0) Entry.InFile(off.toInt(), gen) else Entry.Free
                }
            }
            trailerDict = p.parseObject() as? PdfDict ?: throw PdfException("No trailer dictionary")
            // Hybrid-reference file: objects in object streams are listed in the stream named by /XRefStm.
            (trailerDict["XRefStm"] as? PdfNumber)?.int?.let { xs ->
                runCatching { defined.addAll(readXrefStream(xs).second) }
            }
            usesStream = false
        } else {
            val (dict, nums) = readXrefStream(offset)
            defined.addAll(nums)
            trailerDict = dict
            usesStream = true
        }
        val eof = PdfParser.indexOf(bytes, "%%EOF".encodeToByteArray(), offset)
        var end = if (eof < 0) bytes.size else eof + 5
        while (end < bytes.size && (bytes[end] == '\r'.code.toByte() || bytes[end] == '\n'.code.toByte())) end++
        return Revision(offset, defined, end, trailerDict, usesStream)
    }

    private fun readXrefStream(offset: Int): Pair<PdfDict, Set<Int>> {
        val p = PdfParser(bytes, offset, ::streamLength)
        val (_, _, obj) = p.parseIndirect()
        val s = obj as? PdfStream ?: throw PdfException("xref offset does not point to a cross-reference stream")
        if (s.dict.name("Type") != "XRef") throw PdfException("Not a cross-reference stream")
        val w = (s.dict["W"] as? PdfArray)?.map { (it as PdfNumber).int } ?: throw PdfException("No /W")
        val size = (s.dict["Size"] as? PdfNumber)?.int ?: 0
        val index = (s.dict["Index"] as? PdfArray)?.map { (it as PdfNumber).int } ?: listOf(0, size)
        val data = decode(s)
        val rec = w.sum()
        var pos = 0
        val nums = HashSet<Int>()
        for (k in index.indices step 2) {
            for (i in 0 until index[k + 1]) {
                if (pos + rec > data.size) break
                val f = IntArray(3)
                var q = pos
                for (j in 0 until 3) {
                    var v = 0L
                    for (b in 0 until w.getOrElse(j) { 0 }) v = (v shl 8) or (data[q++].toLong() and 0xFF)
                    f[j] = v.toInt()
                }
                if (w[0] == 0) f[0] = 1
                pos += rec
                val num = index[k] + i
                nums.add(num)
                if (num in entries) continue
                entries[num] = when (f[0]) {
                    1 -> Entry.InFile(f[1], f[2])
                    2 -> Entry.InStream(f[1], f[2])
                    else -> Entry.Free
                }
            }
        }
        return s.dict to nums
    }

    /** Rebuilds the object table by scanning for "n g obj"; the last definition of a number wins. */
    private fun scanObjects(): Revision {
        val nums = HashSet<Int>()
        var trailerDict: PdfDict? = null
        var i = 0
        val objKw = "obj".encodeToByteArray()
        while (true) {
            val k = PdfParser.indexOf(bytes, objKw, i)
            if (k < 0) break
            i = k + 3
            // Walk back over "num gen ".
            var e = k - 1
            while (e >= 0 && PdfParser.isWhite(bytes[e].toInt() and 0xFF)) e--
            val genEnd = e + 1
            while (e >= 0 && bytes[e] in '0'.code.toByte()..'9'.code.toByte()) e--
            val genStart = e + 1
            if (genStart == genEnd) continue
            while (e >= 0 && PdfParser.isWhite(bytes[e].toInt() and 0xFF)) e--
            val numEnd = e + 1
            while (e >= 0 && bytes[e] in '0'.code.toByte()..'9'.code.toByte()) e--
            val numStart = e + 1
            if (numStart == numEnd || (e >= 0 && PdfParser.isRegular(bytes[e].toInt() and 0xFF))) continue
            val num = bytes.decodeToString(numStart, numEnd).toIntOrNull() ?: continue
            val gen = bytes.decodeToString(genStart, genEnd).toIntOrNull() ?: continue
            entries[num] = Entry.InFile(numStart, gen)
            nums.add(num)
        }
        // Objects inside object streams.
        for (num in nums.toList()) {
            val o = runCatching { getObject(num) }.getOrNull() as? PdfStream ?: continue
            if (o.dict.name("Type") == "ObjStm") {
                runCatching { objectStream(num).keys.forEach { n -> if (n !in entries || n !in nums) { entries[n] = Entry.InStream(num, 0); nums.add(n) } } }
            }
            if (o.dict.name("Type") == "XRef" && o.dict["Root"] != null) trailerDict = o.dict
        }
        cache.clear()
        var t = 0
        val trailerKw = "trailer".encodeToByteArray()
        while (true) {
            val k = PdfParser.indexOf(bytes, trailerKw, t)
            if (k < 0) break
            t = k + 7
            runCatching { (PdfParser(bytes, k + 7).parseObject() as? PdfDict)?.let { if (it["Root"] != null) trailerDict = it } }
        }
        val root = trailerDict ?: run {
            val catalog = nums.firstOrNull { (runCatching { getObject(it) }.getOrNull() as? PdfDict)?.name("Type") == "Catalog" }
                ?: throw PdfException("No document catalog found")
            PdfDict.of("Root" to PdfRef(catalog, 0), "Size" to PdfNumber.of((nums.maxOrNull() ?: 0) + 1))
        }
        cache.clear()
        return Revision(-1, nums, bytes.size, root, false)
    }

    // ---------------------------------------------------------------- streams

    /** Decoded data of a stream; filters without a decoder here (images) are left applied. */
    fun decode(s: PdfStream): ByteArray {
        val filters = when (val f = resolve(s.dict["Filter"])) {
            is PdfName -> listOf(f.name)
            is PdfArray -> f.mapNotNull { (resolve(it) as? PdfName)?.name }
            else -> emptyList()
        }
        val parms = when (val d = resolve(s.dict["DecodeParms"] ?: s.dict["DP"])) {
            is PdfDict -> listOf(d)
            is PdfArray -> d.map { resolve(it) as? PdfDict }
            else -> emptyList()
        }
        var data = s.data
        filters.forEachIndexed { i, name ->
            val parm = parms.getOrNull(i)
            data = when (name) {
                "FlateDecode", "Fl" -> predict(PlatformCrypto.inflate(data, raw = false, maxBytes = MAX_STREAM), parm)
                "ASCIIHexDecode", "AHx" -> asciiHex(data)
                "ASCII85Decode", "A85" -> ascii85(data)
                "LZWDecode", "LZW" -> predict(lzw(data, (parm?.get("EarlyChange") as? PdfNumber)?.int ?: 1), parm)
                "RunLengthDecode", "RL" -> runLength(data)
                "Crypt" -> data
                else -> return data
            }
        }
        return data
    }

    private fun predict(data: ByteArray, parm: PdfDict?): ByteArray {
        val predictor = (parm?.get("Predictor") as? PdfNumber)?.int ?: 1
        if (predictor < 2) return data
        val colors = (parm?.get("Colors") as? PdfNumber)?.int ?: 1
        val bpc = (parm?.get("BitsPerComponent") as? PdfNumber)?.int ?: 8
        val columns = (parm?.get("Columns") as? PdfNumber)?.int ?: 1
        val bpp = maxOf(1, (colors * bpc + 7) / 8)
        val rowLen = (colors * bpc * columns + 7) / 8
        if (predictor == 2) {
            val out = data.copyOf()
            if (bpc != 8) return out
            var r = 0
            while (r < out.size) {
                for (i in bpp until rowLen) if (r + i < out.size) out[r + i] = (out[r + i] + out[r + i - bpp]).toByte()
                r += rowLen
            }
            return out
        }
        val out = ArrayList<Byte>(data.size)
        var prev = ByteArray(rowLen)
        var p = 0
        while (p < data.size) {
            val type = data[p++].toInt() and 0xFF
            val row = ByteArray(rowLen)
            for (i in 0 until rowLen) row[i] = if (p + i < data.size) data[p + i] else 0
            p += rowLen
            for (i in 0 until rowLen) {
                val a = if (i >= bpp) row[i - bpp].toInt() and 0xFF else 0
                val b = prev[i].toInt() and 0xFF
                val c = if (i >= bpp) prev[i - bpp].toInt() and 0xFF else 0
                val x = row[i].toInt() and 0xFF
                row[i] = when (type) {
                    0 -> x
                    1 -> x + a
                    2 -> x + b
                    3 -> x + (a + b) / 2
                    4 -> {
                        val pa = kotlin.math.abs(b - c); val pb = kotlin.math.abs(a - c); val pc = kotlin.math.abs(a + b - 2 * c)
                        x + if (pa <= pb && pa <= pc) a else if (pb <= pc) b else c
                    }
                    else -> x
                }.toByte()
            }
            row.forEach { out.add(it) }
            prev = row
        }
        return out.toByteArray()
    }

    private fun asciiHex(d: ByteArray): ByteArray {
        val out = ArrayList<Byte>()
        var hi = -1
        for (b in d) {
            val c = b.toInt() and 0xFF
            if (c == '>'.code) break
            val v = PdfParser.hexVal(c)
            if (v < 0) continue
            if (hi < 0) hi = v else { out.add(((hi shl 4) or v).toByte()); hi = -1 }
        }
        if (hi >= 0) out.add((hi shl 4).toByte())
        return out.toByteArray()
    }

    private fun ascii85(d: ByteArray): ByteArray {
        val out = ArrayList<Byte>()
        val group = IntArray(5)
        var n = 0
        var i = 0
        if (d.size >= 2 && d[0] == '<'.code.toByte() && d[1] == '~'.code.toByte()) i = 2
        while (i < d.size) {
            val c = d[i++].toInt() and 0xFF
            if (c == '~'.code) break
            if (PdfParser.isWhite(c)) continue
            if (c == 'z'.code && n == 0) { repeat(4) { out.add(0) }; continue }
            if (c < '!'.code || c > 'u'.code) continue
            group[n++] = c - '!'.code
            if (n == 5) {
                var v = 0L
                for (g in group) v = v * 85 + g
                for (s in 3 downTo 0) out.add((v shr (s * 8)).toByte())
                n = 0
            }
        }
        if (n > 1) {
            for (k in n until 5) group[k] = 84
            var v = 0L
            for (g in group) v = v * 85 + g
            for (s in 3 downTo 4 - (n - 1)) out.add((v shr (s * 8)).toByte())
        }
        return out.toByteArray()
    }

    private fun runLength(d: ByteArray): ByteArray {
        val out = ArrayList<Byte>()
        var i = 0
        while (i < d.size) {
            val len = d[i++].toInt() and 0xFF
            when {
                len == 128 -> break
                len < 128 -> { for (k in 0..len) if (i < d.size) out.add(d[i++]) }
                else -> { if (i < d.size) { val b = d[i++]; repeat(257 - len) { out.add(b) } } }
            }
        }
        return out.toByteArray()
    }

    private fun lzw(d: ByteArray, earlyChange: Int): ByteArray {
        val out = ArrayList<Byte>()
        val table = ArrayList<ByteArray>()
        fun reset() { table.clear(); for (i in 0 until 256) table.add(byteArrayOf(i.toByte())); table.add(ByteArray(0)); table.add(ByteArray(0)) }
        reset()
        var bitBuf = 0L; var bits = 0; var codeLen = 9; var prev: ByteArray? = null
        var i = 0
        while (true) {
            while (bits < codeLen && i < d.size) { bitBuf = (bitBuf shl 8) or (d[i++].toLong() and 0xFF); bits += 8 }
            if (bits < codeLen) break
            val code = ((bitBuf shr (bits - codeLen)) and ((1L shl codeLen) - 1)).toInt()
            bits -= codeLen
            if (code == 256) { reset(); codeLen = 9; prev = null; continue }
            if (code == 257) break
            val entry = when {
                code < table.size -> table[code]
                prev != null -> prev + prev[0]
                else -> break
            }
            entry.forEach { out.add(it) }
            if (prev != null) table.add(prev + entry[0])
            prev = entry
            val limit = table.size + earlyChange
            codeLen = when { limit >= 2048 -> 12; limit >= 1024 -> 11; limit >= 512 -> 10; else -> 9 }
        }
        return out.toByteArray()
    }

    // ---------------------------------------------------------------- encryption

    private fun decryptObject(o: PdfObject, num: Int, gen: Int): PdfObject {
        val sec = security ?: return o
        return decryptValue(o, sec, num, gen)
    }

    private fun decryptValue(o: PdfObject, sec: StandardSecurity, num: Int, gen: Int): PdfObject = when (o) {
        is PdfString -> PdfString(sec.decryptString(o.bytes, num, gen), o.hex)
        is PdfArray -> PdfArray(o.map { decryptValue(it, sec, num, gen) })
        is PdfDict -> {
            // The signature value is written after encryption and is never encrypted.
            val signature = o.has("ByteRange") || o.name("Type") == "Sig" || o.name("Type") == "DocTimeStamp"
            PdfDict(o.entries.mapValuesTo(LinkedHashMap()) { (k, v) ->
                if (signature && k == "Contents") v else decryptValue(v, sec, num, gen)
            })
        }
        is PdfStream -> {
            val type = o.dict.name("Type")
            val dict = decryptValue(o.dict, sec, num, gen) as PdfDict
            if (type == "XRef" || (type == "Metadata" && !sec.encryptMetadata)) PdfStream(dict, o.data)
            else PdfStream(dict, sec.decryptStream(o.data, num, gen))
        }
        else -> o
    }

    companion object {
        const val MAX_STREAM = 64 * 1024 * 1024

        fun isPdf(b: ByteArray): Boolean = PdfParser.indexOf(b.copyOfRange(0, minOf(b.size, 1024)), "%PDF-".encodeToByteArray(), 0) >= 0
    }
}

/**
 * PDF standard security handler (ISO 32000-1 7.6.3, ISO 32000-2 7.6.4) opened with a user password (tried as given,
 * then empty): RC4 40 to 128 bits (revisions 2 to 4), AES-128 (V4 AESV2) and AES-256 (revisions 5 and 6).
 */
internal class StandardSecurity private constructor(
    private val key: ByteArray,
    private val stringMethod: String,
    private val streamMethod: String,
    val encryptMetadata: Boolean,
    private val revision: Int,
) {
    fun decryptString(b: ByteArray, num: Int, gen: Int) = decrypt(b, num, gen, stringMethod)
    fun decryptStream(b: ByteArray, num: Int, gen: Int) = decrypt(b, num, gen, streamMethod)

    private fun decrypt(b: ByteArray, num: Int, gen: Int, method: String): ByteArray {
        if (method == "Identity" || b.isEmpty()) return b
        val k = if (method == "AESV3") key else objectKey(num, gen, method == "AESV2")
        return when (method) {
            "AESV2", "AESV3" -> {
                if (b.size < 32 || b.size % 16 != 0) return b
                val plain = DocCrypto.aesCbc(false, k, b.copyOfRange(0, 16), b.copyOfRange(16, b.size))
                val pad = plain.last().toInt() and 0xFF
                if (pad in 1..16 && pad <= plain.size) plain.copyOfRange(0, plain.size - pad) else plain
            }
            else -> DocCryptoUtil.rc4(k, b)
        }
    }

    private fun objectKey(num: Int, gen: Int, aes: Boolean): ByteArray {
        val extra = byteArrayOf(num.toByte(), (num shr 8).toByte(), (num shr 16).toByte(), gen.toByte(), (gen shr 8).toByte())
        val salt = if (aes) byteArrayOf(0x73, 0x41, 0x6C, 0x54) else ByteArray(0)
        val h = DocCrypto.digest("MD5", key + extra + salt)
        return h.copyOf(minOf(key.size + 5, 16))
    }

    companion object {
        private val PAD = byteArrayOf(
            0x28, 0xBF.toByte(), 0x4E, 0x5E, 0x4E, 0x75, 0x8A.toByte(), 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF.toByte(), 0xFA.toByte(), 0x01, 0x08,
            0x2E, 0x2E, 0x00, 0xB6.toByte(), 0xD0.toByte(), 0x68, 0x3E, 0x80.toByte(), 0x2F, 0x0C, 0xA9.toByte(), 0xFE.toByte(), 0x64, 0x53, 0x69, 0x7A,
        )

        fun open(enc: PdfDict, id0: ByteArray, password: String = ""): StandardSecurity {
            val filter = enc.name("Filter")
            if (filter != "Standard") throw PdfException("Encrypted with the $filter handler (certificate or other security); the file cannot be opened without it")
            val v = (enc["V"] as? PdfNumber)?.int ?: 0
            val r = (enc["R"] as? PdfNumber)?.int ?: 2
            val o = (enc["O"] as? PdfString)?.bytes ?: throw PdfException("No /O")
            val u = (enc["U"] as? PdfString)?.bytes ?: throw PdfException("No /U")
            val p = (enc["P"] as? PdfNumber)?.long?.toInt() ?: 0
            val encryptMetadata = (enc["EncryptMetadata"] as? PdfBool)?.value ?: true
            var strM = "V2"
            var stmM = "V2"
            if (v >= 4) {
                val cf = enc["CF"] as? PdfDict
                fun method(name: String?): String = when (name) {
                    null, "Identity" -> "Identity"
                    else -> (cf?.get(name) as? PdfDict)?.name("CFM")?.let { if (it == "None") "Identity" else it } ?: "Identity"
                }
                strM = method(enc.name("StrF"))
                stmM = method(enc.name("StmF"))
            }
            for (candidate in listOf(password, "").distinct()) {
                if (r >= 5) {
                    if (u.size < 48) throw PdfException("Malformed /U")
                    val ue = (enc["UE"] as? PdfString)?.bytes ?: throw PdfException("No /UE")
                    // Algorithm 2.A: the password is UTF-8 (SASLprep is the identity for the characters an ID uses), at most 127 bytes.
                    val pw = candidate.encodeToByteArray().let { if (it.size > 127) it.copyOf(127) else it }
                    val check = hashR6(pw, u.copyOfRange(32, 40), ByteArray(0), r)
                    if (!check.contentEquals(u.copyOfRange(0, 32))) continue
                    val ik = hashR6(pw, u.copyOfRange(40, 48), ByteArray(0), r)
                    val fileKey = DocCrypto.aesCbc(false, ik, ByteArray(16), ue.copyOfRange(0, 32))
                    return StandardSecurity(fileKey, "AESV3", "AESV3", encryptMetadata, r)
                }
                // Algorithm 2: the password padded or truncated to 32 bytes (PDFDocEncoding, Latin-1 for the characters an ID uses).
                val pw = ByteArray(candidate.length.coerceAtMost(32)) { i -> candidate[i].code.let { c -> if (c < 256) c.toByte() else '?'.code.toByte() } }
                val padded = pw + PAD.copyOf(32 - pw.size)
                val n = if (r == 2) 5 else ((enc["Length"] as? PdfNumber)?.int ?: 40) / 8
                var h = DocCrypto.digest(
                    "MD5",
                    padded + o.copyOf(32) + byteArrayOf(p.toByte(), (p shr 8).toByte(), (p shr 16).toByte(), (p shr 24).toByte()) + id0 +
                        (if (r >= 4 && !encryptMetadata) byteArrayOf(-1, -1, -1, -1) else ByteArray(0)),
                )
                if (r >= 3) repeat(50) { h = DocCrypto.digest("MD5", h.copyOf(n)) }
                val key = h.copyOf(n)
                // Algorithm 6: check that the password is the user password.
                val ok = if (r == 2) {
                    DocCryptoUtil.rc4(key, PAD).contentEquals(u.copyOf(32))
                } else {
                    var x = DocCryptoUtil.rc4(key, DocCrypto.digest("MD5", PAD + id0))
                    for (i in 1..19) x = DocCryptoUtil.rc4(ByteArray(key.size) { (key[it].toInt() xor i).toByte() }, x)
                    x.contentEquals(u.copyOf(16))
                }
                if (ok) return StandardSecurity(key, strM, stmM, encryptMetadata, r)
            }
            throw PdfPasswordException(if (password.isEmpty()) "A password is needed to open this file" else "The password does not open this file")
        }

        /** Algorithm 2.B (ISO 32000-2) for revision 6; revision 5 is plain SHA-256. */
        private fun hashR6(password: ByteArray, salt: ByteArray, userKey: ByteArray, r: Int): ByteArray {
            var k = DocCrypto.digest("SHA-256", password + salt + userKey)
            if (r == 5) return k
            var round = 0
            while (true) {
                val k1 = (password + k + userKey).let { one -> ByteArray(one.size * 64).also { buf -> for (i in 0 until 64) one.copyInto(buf, i * one.size) } }
                val e = DocCrypto.aesCbc(true, k.copyOfRange(0, 16), k.copyOfRange(16, 32), k1)
                var mod = 0
                for (i in 0 until 16) mod += e[i].toInt() and 0xFF
                k = when (mod % 3) {
                    0 -> DocCrypto.digest("SHA-256", e)
                    1 -> DocCrypto.digest("SHA-384", e)
                    else -> DocCrypto.digest("SHA-512", e)
                }
                round++
                if (round >= 64 && (e.last().toInt() and 0xFF) <= round - 32) break
            }
            return k.copyOf(32)
        }
    }
}
