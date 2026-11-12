package diw.wallet.core.document.mrtd

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.card.CardChannel
import diw.wallet.core.document.card.CardResponse

/** The cipher suite of a secure messaging session (ICAO 9303 part 11, 9.8): 3DES with retail MAC, or AES with CMAC. */
enum class SmCipher(val keyLength: Int, val blockSize: Int) {
    DES3(16, 8), AES128(16, 16), AES192(24, 16), AES256(32, 16);

    val aes: Boolean get() = this != DES3
}

/** Key derivation, padding and the MACs and ciphers the access protocols and secure messaging share. */
object MrtdCrypt {
    const val KDF_ENC = 1
    const val KDF_MAC = 2
    const val KDF_PACE = 3

    /** KDF of ICAO 9303 part 11, 9.7.1: a hash of the shared secret and a 32-bit counter, cut to the key length. */
    fun kdf(cipher: SmCipher, secret: ByteArray, counter: Int): ByteArray {
        val d = secret + byteArrayOf((counter ushr 24).toByte(), (counter ushr 16).toByte(), (counter ushr 8).toByte(), counter.toByte())
        return when (cipher) {
            SmCipher.DES3 -> desParity(DocCrypto.digest("SHA-1", d).copyOf(16))
            SmCipher.AES128 -> DocCrypto.digest("SHA-1", d).copyOf(16)
            SmCipher.AES192 -> DocCrypto.digest("SHA-256", d).copyOf(24)
            SmCipher.AES256 -> DocCrypto.digest("SHA-256", d)
        }
    }

    /** Odd parity on every DES key byte. */
    fun desParity(k: ByteArray): ByteArray = ByteArray(k.size) { i ->
        val b = k[i].toInt() and 0xFE
        (b or (if (b.countOneBits() % 2 == 0) 1 else 0)).toByte()
    }

    /** ISO/IEC 9797-1 padding method 2. */
    fun pad(d: ByteArray, block: Int): ByteArray {
        val n = (d.size / block + 1) * block
        val out = d.copyOf(n)
        out[d.size] = 0x80.toByte()
        return out
    }

    fun unpad(d: ByteArray): ByteArray {
        var i = d.size - 1
        while (i >= 0 && d[i] == 0.toByte()) i--
        if (i < 0 || d[i] != 0x80.toByte()) throw MrtdException("bad_padding")
        return d.copyOf(i)
    }

    /** Single DES CBC encryption with key [k1], as two-key 3DES with both halves equal. */
    private fun desCbc(k1: ByteArray, iv: ByteArray, data: ByteArray): ByteArray = DocCrypto.desEdeCbc(true, k1 + k1, iv, data)

    /** ISO/IEC 9797-1 MAC algorithm 3 (retail MAC) with DES over [data], which is already padded. */
    fun retailMac(key: ByteArray, data: ByteArray): ByteArray {
        require(data.size % 8 == 0 && data.isNotEmpty())
        val k1 = key.copyOfRange(0, 8)
        val head = data.copyOf(data.size - 8)
        val chained = if (head.isEmpty()) ByteArray(8) else desCbc(k1, ByteArray(8), head).let { it.copyOfRange(it.size - 8, it.size) }
        return DocCrypto.desEdeCbc(true, key.copyOf(16), chained, data.copyOfRange(data.size - 8, data.size))
    }

    /** The 8-byte MAC of secure messaging: retail MAC (3DES) or CMAC truncated (AES), over padded [data]. */
    fun mac(cipher: SmCipher, key: ByteArray, padded: ByteArray): ByteArray =
        if (cipher.aes) DocCryptoUtil.aesCmac(key, padded).copyOf(8) else retailMac(key, padded)

    fun encrypt(cipher: SmCipher, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
        if (cipher.aes) DocCrypto.aesCbc(true, key, iv, data) else DocCrypto.desEdeCbc(true, key, iv, data)

    fun decrypt(cipher: SmCipher, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
        if (cipher.aes) DocCrypto.aesCbc(false, key, iv, data) else DocCrypto.desEdeCbc(false, key, iv, data)
}

/** A failure of the chip protocols, with a stable code the app turns into a message. */
class MrtdException(val code: String, val sw: Int? = null, cause: Throwable? = null) :
    Exception(code + (sw?.let { " (" + it.toString(16).uppercase().padStart(4, '0') + ")" } ?: ""), cause)

/**
 * Secure messaging over a [CardChannel] (ICAO 9303 part 11, 9.8): every command is encrypted and MACed with the
 * session keys and the send sequence counter, every response is MAC-checked and decrypted. A response whose MAC
 * does not verify ends the session.
 */
class SecureChannel(
    private val inner: CardChannel,
    val cipher: SmCipher,
    private val kEnc: ByteArray,
    private val kMac: ByteArray,
    ssc: ByteArray,
) : CardChannel {
    private var ssc: ByteArray = ssc.copyOf()

    init {
        require(kEnc.size == cipher.keyLength && kMac.size == cipher.keyLength)
        require(this.ssc.size == cipher.blockSize)
    }

    private fun increment() {
        for (i in ssc.indices.reversed()) {
            val v = (ssc[i].toInt() and 0xFF) + 1
            ssc[i] = v.toByte()
            if (v <= 0xFF) break
        }
    }

    private fun iv(): ByteArray = if (cipher.aes) DocCrypto.aesEcb(true, kEnc, ssc) else ByteArray(8)

    override suspend fun transmit(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): CardResponse {
        val (body, _) = protect(cla, ins, p1, p2, data, le)
        val r = inner.transmit(cla or 0x0C, ins, p1, p2, body, 256)
        return unprotect(r)
    }

    /** The protected command data (DO'87' or DO'85', DO'97', DO'8E'); the SSC is advanced. */
    fun protect(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): Pair<ByteArray, ByteArray> {
        increment()
        val block = cipher.blockSize
        val header = MrtdCrypt.pad(byteArrayOf((cla or 0x0C).toByte(), ins.toByte(), p1.toByte(), p2.toByte()), block)
        var dos = ByteArray(0)
        if (data.isNotEmpty()) {
            val enc = MrtdCrypt.encrypt(cipher, kEnc, iv(), MrtdCrypt.pad(data, block))
            dos += if (ins and 1 == 1) BerTlv.encode(0x85, enc) else BerTlv.encode(0x87, byteArrayOf(1) + enc)
        }
        if (le > 0) dos += byteArrayOf(0x97.toByte(), 1, (if (le >= 256) 0 else le).toByte())
        val mac = MrtdCrypt.mac(cipher, kMac, MrtdCrypt.pad(ssc + header + dos, block))
        return (dos + BerTlv.encode(0x8E, mac)) to mac
    }

    /** Checks the MAC of a protected response and returns the plain status word and data. */
    fun unprotect(r: CardResponse): CardResponse {
        increment()
        // A card answers an error it cannot protect (6987, 6988: secure messaging data objects wrong or missing) with
        // a plain status word; the session is over then. Other plain errors are passed on for the caller to judge.
        if (r.data.isEmpty()) {
            if (r.sw == 0x9000) throw MrtdException("sm_missing")
            if (r.sw == 0x6987 || r.sw == 0x6988) throw MrtdException("sm_error", r.sw)
            return CardResponse(r.sw, ByteArray(0))
        }
        var enc: ByteArray? = null
        var odd = false
        var sw: Int? = null
        var mac: ByteArray? = null
        var macInput = ByteArray(0)
        for (t in BerTlv.children(r.data)) {
            val raw = r.data.copyOfRange(t.start, t.end)
            when (t.tag) {
                0x87 -> { enc = t.value; macInput += raw }
                0x85 -> { enc = t.value; odd = true; macInput += raw }
                0x99 -> { sw = BerTlv.uint(t.value); macInput += raw }
                0x8E -> mac = t.value
            }
        }
        val expected = MrtdCrypt.mac(cipher, kMac, MrtdCrypt.pad(ssc + macInput, cipher.blockSize))
        if (mac == null || !mac.contentEquals(expected)) throw MrtdException("sm_mac")
        val status = sw ?: r.sw
        val plain = enc?.let { e ->
            val c = if (odd) e else {
                if (e.isEmpty() || e[0] != 1.toByte()) throw MrtdException("sm_format")
                e.copyOfRange(1, e.size)
            }
            MrtdCrypt.unpad(MrtdCrypt.decrypt(cipher, kEnc, iv(), c))
        } ?: ByteArray(0)
        return CardResponse(status, plain)
    }

    companion object {
        /** A session from derived keys with the counter at [ssc]; PACE and Chip Authentication start at zero. */
        fun start(inner: CardChannel, cipher: SmCipher, secret: ByteArray, ssc: ByteArray = ByteArray(cipher.blockSize)): SecureChannel =
            SecureChannel(inner, cipher, MrtdCrypt.kdf(cipher, secret, MrtdCrypt.KDF_ENC), MrtdCrypt.kdf(cipher, secret, MrtdCrypt.KDF_MAC), ssc)
    }
}
