package diw.wallet.core.document.pgp

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.card.OpenPgpAlgorithm
import diw.wallet.core.document.card.OpenPgpCardKey
import diw.wallet.core.document.card.OpenPgpCurve
import diw.wallet.core.document.card.OpenPgpPublicMaterial
import diw.wallet.core.document.sign.SigningException
import kotlin.io.encoding.Base64

/** A public-key encrypted session key packet (tag 1) of an OpenPGP message, as far as a card needs it. */
class OpenPgpPkesk(
    val version: Int,
    /** The 8-byte key ID (v3), all zero for an anonymous recipient; null for v6. */
    val keyId: ByteArray?,
    /** The recipient fingerprint (v6 packets); null for v3. */
    val fingerprint: ByteArray?,
    val algorithm: Int,
    /** The algorithm-specific fields after the algorithm byte, unparsed. */
    val fields: ByteArray,
) {
    fun isFor(fpr: ByteArray): Boolean = when {
        fingerprint != null -> fingerprint.contentEquals(fpr)
        keyId != null -> keyId.all { it == 0.toByte() } || keyId.contentEquals(fpr.copyOfRange(fpr.size - 8, fpr.size))
        else -> false
    }

    val keyIdText: String get() = (fingerprint ?: keyId)?.let { DocCryptoUtil.hex(it).uppercase() } ?: "?"
}

/**
 * The OpenPGP pieces the wallet writes itself, in pure Kotlin so that a card signature or decryption never depends on
 * a library's synchronous signer interface: v4 public key packets rebuilt from a card key, fingerprints, MPIs, v4
 * signature packets, ASCII armor with CRC-24, PKESK parsing and the RFC 6637 ECDH key unwrapping.
 */
object OpenPgpPackets {
    const val SIG_BINARY = 0x00
    const val HASH_SHA256 = 8
    const val HASH_SHA384 = 9
    const val HASH_SHA512 = 10

    private val DIGEST_INFO = mapOf(
        HASH_SHA256 to "3031300d060960864801650304020105000420",
        HASH_SHA384 to "3041300d060960864801650304020205000430",
        HASH_SHA512 to "3051300d060960864801650304020305000440",
    )

    fun hashName(id: Int): String = when (id) {
        HASH_SHA256 -> "SHA-256"
        HASH_SHA384 -> "SHA-384"
        HASH_SHA512 -> "SHA-512"
        else -> throw SigningException("不支援的雜湊演算法 $id")
    }

    fun hashId(name: String): Int = when (name) {
        "SHA-256" -> HASH_SHA256
        "SHA-384" -> HASH_SHA384
        "SHA-512" -> HASH_SHA512
        else -> throw SigningException("不支援的雜湊演算法 $name")
    }

    /** The hash an OpenPGP signature by a card key uses: SHA-256 for RSA, the curve's size otherwise. */
    fun hashFor(algorithm: OpenPgpAlgorithm): Int = when (algorithm) {
        is OpenPgpAlgorithm.Rsa -> HASH_SHA256
        is OpenPgpAlgorithm.Ec -> hashId(algorithm.curve.hash)
        is OpenPgpAlgorithm.Unsupported -> throw SigningException("OpenPGP 卡的簽章金鑰演算法不支援：$algorithm")
    }

    fun digestInfo(hash: Int, digest: ByteArray): ByteArray = DocCryptoUtil.unhex(DIGEST_INFO.getValue(hash)) + digest

    // ---------------------------------------------------------------- encoding

    /** A multiprecision integer: bit count (2 bytes) and the value without leading zero bytes. */
    fun mpi(value: ByteArray): ByteArray {
        var i = 0
        while (i < value.size - 1 && value[i] == 0.toByte()) i++
        val v = value.copyOfRange(i, value.size)
        if (v.isEmpty() || (v.size == 1 && v[0] == 0.toByte())) return byteArrayOf(0, 0)
        val top = v[0].toInt() and 0xFF
        var bits = (v.size - 1) * 8
        var t = top
        while (t != 0) { bits++; t = t shr 1 }
        return byteArrayOf((bits shr 8).toByte(), bits.toByte()) + v
    }

    private fun u16(n: Int) = byteArrayOf((n shr 8).toByte(), n.toByte())

    private fun u32(n: Long) = byteArrayOf((n shr 24).toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())

    /** A new-format packet: tag and length (one, two or five octets) followed by [body]. */
    fun packet(tag: Int, body: ByteArray): ByteArray {
        val n = body.size
        val len = when {
            n < 192 -> byteArrayOf(n.toByte())
            n < 8384 -> byteArrayOf((((n - 192) shr 8) + 192).toByte(), (n - 192).toByte())
            else -> byteArrayOf(0xFF.toByte()) + u32(n.toLong())
        }
        return byteArrayOf((0xC0 or tag).toByte()) + len + body
    }

    /** The point as an OpenPGP v4 key writes it: 0x40 and the native key for 25519 curves, else the SEC1 point. */
    private fun pgpPoint(curve: OpenPgpCurve, point: ByteArray): ByteArray =
        if (curve.native && point.size == 32) byteArrayOf(0x40) + point else point

    /** The v4 public key packet body of a card key for algorithm fields [fields] and creation time [created]. */
    private fun keyBody(algorithm: Int, created: Long, fields: ByteArray): ByteArray = byteArrayOf(4) + u32(created) + byteArrayOf(algorithm.toByte()) + fields

    /** Candidate v4 public key packet bodies for a card key; ECDH has one per plausible KDF parameter set. */
    fun candidates(key: OpenPgpCardKey): List<ByteArray> {
        val material = key.publicKey ?: return emptyList()
        return when (val alg = key.algorithm) {
            is OpenPgpAlgorithm.Rsa -> {
                val m = material as? OpenPgpPublicMaterial.Rsa ?: return emptyList()
                listOf(keyBody(1, key.created, mpi(m.modulus) + mpi(m.exponent)))
            }
            is OpenPgpAlgorithm.Ec -> {
                val m = material as? OpenPgpPublicMaterial.Ec ?: return emptyList()
                val head = byteArrayOf(alg.curve.oid.size.toByte()) + alg.curve.oid + mpi(pgpPoint(alg.curve, m.point))
                if (alg.pgpId != 18) listOf(keyBody(alg.pgpId, key.created, head))
                else {
                    val preferred = when (alg.curve) {
                        OpenPgpCurve.P384, OpenPgpCurve.BRAINPOOL_P384 -> HASH_SHA384 to 9
                        OpenPgpCurve.P521, OpenPgpCurve.BRAINPOOL_P512 -> HASH_SHA512 to 9
                        else -> HASH_SHA256 to 7
                    }
                    val all = listOf(preferred) + listOf(HASH_SHA256, HASH_SHA384, HASH_SHA512).flatMap { h -> listOf(7, 8, 9).map { h to it } }
                    all.distinct().map { (h, s) -> keyBody(18, key.created, head + byteArrayOf(3, 1, h.toByte(), s.toByte())) }
                }
            }
            is OpenPgpAlgorithm.Unsupported -> emptyList()
        }
    }

    /**
     * The v4 packet body of a card key whose fingerprint matches the card's (C5). [known] are public key packet bodies
     * from the keyring, tried first. When the card stores no fingerprint, the first candidate is used.
     */
    fun matchCardKey(key: OpenPgpCardKey, known: List<ByteArray> = emptyList()): ByteArray? {
        val fpr = key.fingerprint ?: return candidates(key).firstOrNull()
        return (known + candidates(key)).firstOrNull { fingerprint(it).contentEquals(fpr) }
    }

    /**
     * The binary certificate the wallet keeps for a card: the first body as a primary key packet and the rest as
     * subkey packets, without signatures (the card cannot certify them without the PIN, and they are not published).
     */
    fun cardCertificate(keyBodies: List<ByteArray>): ByteArray =
        keyBodies.mapIndexed { i, b -> packet(if (i == 0) 6 else 14, b) }.fold(ByteArray(0)) { acc, x -> acc + x }

    /** v4 fingerprint: SHA-1 over 0x99, the two-octet length and the public key packet body. */
    fun fingerprint(body: ByteArray): ByteArray = DocCrypto.digest("SHA-1", byteArrayOf(0x99.toByte()) + u16(body.size) + body)

    fun keyId(fingerprint: ByteArray): ByteArray = fingerprint.copyOfRange(fingerprint.size - 8, fingerprint.size)

    /** The key ID and fingerprint of a v4 key, as GnuPG prints them. */
    fun fingerprintText(fpr: ByteArray): String = DocCryptoUtil.hex(fpr).uppercase().chunked(4).joinToString(" ")

    // ---------------------------------------------------------------- signatures

    /** The hashed and unhashed parts of a v4 signature before the card signs it, and the digest to sign. */
    class PendingSignature(val prefix: ByteArray, val unhashed: ByteArray, val digest: ByteArray, val hash: Int, val algorithm: Int)

    private fun subpacket(type: Int, data: ByteArray): ByteArray {
        val n = data.size + 1
        val len = if (n < 192) byteArrayOf(n.toByte()) else byteArrayOf((((n - 192) shr 8) + 192).toByte(), (n - 192).toByte())
        return len + byteArrayOf(type.toByte()) + data
    }

    /**
     * Starts a v4 signature of [type] over [data] by the key [keyBody] at [created] (epoch seconds): hashed subpackets
     * are the creation time and the issuer fingerprint, unhashed the issuer key ID.
     */
    fun prepare(data: ByteArray, keyBody: ByteArray, created: Long, hash: Int, type: Int = SIG_BINARY): PendingSignature {
        val algorithm = keyBody[5].toInt() and 0xFF
        val fpr = fingerprint(keyBody)
        val hashed = subpacket(2, u32(created)) + subpacket(33, byteArrayOf(4) + fpr)
        val prefix = byteArrayOf(4, type.toByte(), algorithm.toByte(), hash.toByte()) + u16(hashed.size) + hashed
        val trailer = byteArrayOf(4, 0xFF.toByte()) + u32(prefix.size.toLong())
        val digest = DocCrypto.digest(hashName(hash), data + prefix + trailer)
        return PendingSignature(prefix, subpacket(16, keyId(fpr)), digest, hash, algorithm)
    }

    /**
     * The signature packet once the card answered: [raw] is the RSA signature, or r||s for ECDSA and EdDSA, each half
     * written as an MPI.
     */
    fun finish(p: PendingSignature, raw: ByteArray): ByteArray {
        val mpis = if (p.algorithm == 1) mpi(raw) else {
            if (raw.size % 2 != 0) throw SigningException("OpenPGP 卡回傳的簽章長度不正確")
            val half = raw.size / 2
            mpi(raw.copyOfRange(0, half)) + mpi(raw.copyOfRange(half, raw.size))
        }
        val body = p.prefix + u16(p.unhashed.size) + p.unhashed + p.digest.copyOfRange(0, 2) + mpis
        return packet(2, body)
    }

    // ---------------------------------------------------------------- armor

    /** ASCII armor (RFC 9580 6.2) with a CRC-24 checksum, which GnuPG and older tools still expect. */
    fun armor(type: String, data: ByteArray, comment: String? = null): String = buildString {
        append("-----BEGIN PGP ").append(type).append("-----\n")
        comment?.let { append("Comment: ").append(it).append('\n') }
        append('\n')
        Base64.encode(data).chunked(64).forEach { append(it).append('\n') }
        val crc = crc24(data)
        append('=').append(Base64.encode(byteArrayOf((crc shr 16).toByte(), (crc shr 8).toByte(), crc.toByte()))).append('\n')
        append("-----END PGP ").append(type).append("-----\n")
    }

    /** The binary content of an armored block, or [data] itself when it is not armored. */
    fun dearmor(data: ByteArray): ByteArray {
        val text = runCatching { data.decodeToString(throwOnInvalidSequence = true) }.getOrNull() ?: return data
        val begin = text.indexOf("-----BEGIN PGP ")
        if (begin < 0) return data
        val lines = text.substring(begin).lines().map { it.trimEnd('\r', ' ', '\t') }
        var i = 1
        while (i < lines.size && lines[i].isNotEmpty()) i++
        val body = StringBuilder()
        i++
        while (i < lines.size && !lines[i].startsWith("-----END PGP ") && !lines[i].startsWith("=")) { body.append(lines[i]); i++ }
        return Base64.decode(body.toString())
    }

    fun crc24(data: ByteArray): Int {
        var crc = 0xB704CE
        for (b in data) {
            crc = crc xor ((b.toInt() and 0xFF) shl 16)
            repeat(8) {
                crc = crc shl 1
                if (crc and 0x1000000 != 0) crc = crc xor 0x1864CFB
            }
        }
        return crc and 0xFFFFFF
    }

    // ---------------------------------------------------------------- encrypted messages

    /** The PKESK packets at the start of an OpenPGP message (armored or binary). */
    fun pkesks(message: ByteArray): List<OpenPgpPkesk> {
        val b = dearmor(message)
        val out = ArrayList<OpenPgpPkesk>()
        var p = 0
        while (p < b.size) {
            val h = b[p].toInt() and 0xFF
            if (h and 0x80 == 0) break
            val tag: Int
            val len: Int
            if (h and 0x40 != 0) {
                tag = h and 0x3F
                p++
                val l1 = b[p++].toInt() and 0xFF
                len = when {
                    l1 < 192 -> l1
                    l1 < 224 -> ((l1 - 192) shl 8) + (b[p++].toInt() and 0xFF) + 192
                    l1 == 255 -> { var n = 0; repeat(4) { n = (n shl 8) or (b[p++].toInt() and 0xFF) }; n }
                    else -> break // partial length: a data packet, the session keys are done
                }
            } else {
                tag = (h shr 2) and 0x0F
                p++
                len = when (h and 0x03) {
                    0 -> b[p++].toInt() and 0xFF
                    1 -> { val n = ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF); p += 2; n }
                    2 -> { var n = 0; repeat(4) { n = (n shl 8) or (b[p++].toInt() and 0xFF) }; n }
                    else -> break
                }
            }
            if (p + len > b.size) break
            val body = b.copyOfRange(p, p + len)
            p += len
            when (tag) {
                1 -> parsePkesk(body)?.let { out.add(it) }
                3, 8 -> {}
                else -> break
            }
        }
        return out
    }

    private fun parsePkesk(b: ByteArray): OpenPgpPkesk? {
        if (b.isEmpty()) return null
        return when (b[0].toInt()) {
            3 -> if (b.size < 10) null else OpenPgpPkesk(3, b.copyOfRange(1, 9), null, b[9].toInt() and 0xFF, b.copyOfRange(10, b.size))
            6 -> {
                val n = b[1].toInt() and 0xFF
                if (b.size < 3 + n) return null
                val fpr = if (n == 0) null else b.copyOfRange(3, 2 + n)
                OpenPgpPkesk(6, null, fpr, b[2 + n].toInt() and 0xFF, b.copyOfRange(3 + n, b.size))
            }
            else -> null
        }
    }

    /** Reads an MPI at [off]: its value and the offset after it. */
    fun readMpi(b: ByteArray, off: Int): Pair<ByteArray, Int> {
        if (off + 2 > b.size) throw SigningException("OpenPGP 資料格式錯誤（MPI）")
        val bits = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
        val n = (bits + 7) / 8
        if (off + 2 + n > b.size) throw SigningException("OpenPGP 資料格式錯誤（MPI 長度）")
        return b.copyOfRange(off + 2, off + 2 + n) to off + 2 + n
    }

    /**
     * What the card's PSO:DECIPHER needs for [pkesk]: the RSA ciphertext left-padded to [modulusBytes], or the
     * ephemeral ECDH point (native 32 bytes for Curve25519, SEC1 otherwise).
     */
    fun cardInput(pkesk: OpenPgpPkesk, key: OpenPgpCardKey): ByteArray = when (val alg = key.algorithm) {
        is OpenPgpAlgorithm.Rsa -> {
            if (pkesk.algorithm != 1 && pkesk.algorithm != 2) throw SigningException("加密金鑰演算法與卡片不符")
            val (c, _) = readMpi(pkesk.fields, 0)
            val n = (alg.modulusBits + 7) / 8
            if (c.size > n) throw SigningException("RSA 密文長度不正確")
            ByteArray(n - c.size) + c
        }
        is OpenPgpAlgorithm.Ec -> {
            if (pkesk.algorithm != 18) throw SigningException("加密金鑰演算法與卡片不符")
            val (point, _) = readMpi(pkesk.fields, 0)
            if (alg.curve.native && point.size == 33 && point[0] == 0x40.toByte()) point.copyOfRange(1, 33) else point
        }
        is OpenPgpAlgorithm.Unsupported -> throw SigningException("OpenPGP 卡的解密金鑰演算法不支援")
    }

    /**
     * The session key from the card's answer: the RSA session block, or for ECDH the RFC 6637 KDF over the shared
     * secret and AES key unwrap with the KDF parameters of [keyBody] (the recipient's public key packet body).
     * Returns the symmetric algorithm and the key, with the checksum checked.
     */
    fun sessionKey(pkesk: OpenPgpPkesk, keyBody: ByteArray, cardOutput: ByteArray): Pair<Int, ByteArray> {
        val block = when (pkesk.algorithm) {
            1, 2 -> cardOutput
            18 -> ecdhUnwrap(pkesk, keyBody, cardOutput)
            else -> throw SigningException("不支援的加密金鑰演算法 ${pkesk.algorithm}")
        }
        if (block.size < 4) throw SigningException("解出的會話金鑰格式錯誤")
        val alg = block[0].toInt() and 0xFF
        val key = block.copyOfRange(1, block.size - 2)
        val sum = key.sumOf { it.toInt() and 0xFF } and 0xFFFF
        val stored = ((block[block.size - 2].toInt() and 0xFF) shl 8) or (block[block.size - 1].toInt() and 0xFF)
        if (sum != stored) throw SigningException("會話金鑰檢查碼不符：這份資料不是寄給這張卡片，或資料已損毀")
        return alg to key
    }

    private fun ecdhUnwrap(pkesk: OpenPgpPkesk, keyBody: ByteArray, shared: ByteArray): ByteArray {
        // keyBody: version, time(4), algorithm, oid length, oid, MPI point, KDF parameters (03 01 hash sym).
        val oidLen = keyBody[6].toInt() and 0xFF
        val oid = keyBody.copyOfRange(7, 7 + oidLen)
        val curve = OpenPgpCurve.of(oid) ?: throw SigningException("不支援的 ECDH 曲線")
        val (_, afterPoint) = readMpi(keyBody, 7 + oidLen)
        val kdf = keyBody.copyOfRange(afterPoint, keyBody.size)
        if (kdf.size < 4 || kdf[0].toInt() != 3) throw SigningException("ECDH 公開金鑰缺少 KDF 參數")
        val hash = kdf[2].toInt() and 0xFF
        val sym = kdf[3].toInt() and 0xFF
        val kekSize = when (sym) { 7 -> 16; 8 -> 24; 9 -> 32; else -> throw SigningException("不支援的 ECDH 金鑰包裝演算法 $sym") }
        val z = sharedX(curve, shared)
        val param = byteArrayOf(oidLen.toByte()) + oid + byteArrayOf(18) + byteArrayOf(3, 1, hash.toByte(), sym.toByte()) +
            "Anonymous Sender    ".encodeToByteArray() + fingerprint(keyBody)
        val kek = DocCrypto.digest(hashName(hash), byteArrayOf(0, 0, 0, 1) + z + param).copyOf(kekSize)
        val (_, afterEphemeral) = readMpi(pkesk.fields, 0)
        val wrappedLen = pkesk.fields[afterEphemeral].toInt() and 0xFF
        val wrapped = pkesk.fields.copyOfRange(afterEphemeral + 1, afterEphemeral + 1 + wrappedLen)
        val padded = aesKeyUnwrap(kek, wrapped)
        val pad = padded.last().toInt() and 0xFF
        if (pad == 0 || pad > 8 || pad > padded.size || (padded.size - pad until padded.size).any { (padded[it].toInt() and 0xFF) != pad }) {
            throw SigningException("ECDH 會話金鑰的填充不正確")
        }
        return padded.copyOf(padded.size - pad)
    }

    /** The x coordinate (or native shared secret) from a card's ECDH answer, which may carry 04 or 40 prefixes. */
    private fun sharedX(curve: OpenPgpCurve, shared: ByteArray): ByteArray = when {
        shared.size == curve.size -> shared
        shared.size == curve.size + 1 && shared[0] == 0x40.toByte() -> shared.copyOfRange(1, shared.size)
        shared.size == 2 * curve.size + 1 && shared[0] == 0x04.toByte() -> shared.copyOfRange(1, 1 + curve.size)
        else -> throw SigningException("OpenPGP 卡回傳的共享秘密長度不正確")
    }

    /** AES key unwrap (RFC 3394) with the default IV. */
    fun aesKeyUnwrap(kek: ByteArray, wrapped: ByteArray): ByteArray {
        if (wrapped.size < 24 || wrapped.size % 8 != 0) throw SigningException("金鑰包裝資料長度不正確")
        val n = wrapped.size / 8 - 1
        var a = wrapped.copyOfRange(0, 8)
        val r = Array(n) { wrapped.copyOfRange(8 * (it + 1), 8 * (it + 2)) }
        for (j in 5 downTo 0) {
            for (i in n downTo 1) {
                val t = (n * j + i).toLong()
                val x = a.copyOf()
                for (k in 0 until 8) x[7 - k] = (x[7 - k].toInt() xor ((t shr (8 * k)).toInt() and 0xFF)).toByte()
                val b = DocCrypto.aesEcb(false, kek, x + r[i - 1])
                a = b.copyOfRange(0, 8)
                r[i - 1] = b.copyOfRange(8, 16)
            }
        }
        if (!a.all { it == 0xA6.toByte() }) throw SigningException("金鑰包裝檢查失敗：這份資料不是寄給這張卡片")
        return r.fold(ByteArray(0)) { acc, x -> acc + x }
    }
}
