package diw.wallet.core.document

/** Symmetric primitives and digests the document and smart card code needs beyond [diw.wallet.core.jose.PlatformCrypto]. */
expect object DocCrypto {
    /** Message digest by JCA name: MD5, SHA-1, SHA-256, SHA-384, SHA-512, SM3. */
    fun digest(algorithm: String, data: ByteArray): ByteArray

    /** AES in CBC mode without padding; [data] is a multiple of 16 bytes. */
    fun aesCbc(encrypt: Boolean, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray

    /** One AES block (ECB, no padding). */
    fun aesEcb(encrypt: Boolean, key: ByteArray, block: ByteArray): ByteArray

    /** Two-key or three-key triple DES in CBC mode without padding; [data] is a multiple of 8 bytes. */
    fun desEdeCbc(encrypt: Boolean, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray

    fun randomBytes(size: Int): ByteArray

    /** Keccak-256 as Ethereum uses it (the original Keccak padding, not SHA3-256). */
    fun keccak256(data: ByteArray): ByteArray

    /**
     * The Ethereum address (20 bytes) whose secp256k1 key made [signature] (r, s, v: 65 bytes, v 27/28 or 0/1) over
     * the 32 byte [hash]; null when no key recovers.
     */
    fun ecRecoverAddress(hash: ByteArray, signature: ByteArray): ByteArray?

    /** The DER certificates in [data]: one DER or PEM certificate, several PEM certificates, or PKCS#7 certs-only. */
    fun certificatesIn(data: ByteArray): List<ByteArray>

    /** The http(s) caIssuers URLs of the Authority Information Access extension of the DER certificate [der]. */
    fun caIssuerUrls(der: ByteArray): List<String>
}

/** Pure-Kotlin helpers on top of [DocCrypto]. */
object DocCryptoUtil {
    /** RC4 (used by PDF standard security handler revisions 2 to 4). */
    fun rc4(key: ByteArray, data: ByteArray): ByteArray {
        val s = IntArray(256) { it }
        var j = 0
        for (i in 0 until 256) {
            j = (j + s[i] + (key[i % key.size].toInt() and 0xFF)) and 0xFF
            val t = s[i]; s[i] = s[j]; s[j] = t
        }
        val out = ByteArray(data.size)
        var i = 0
        j = 0
        for (k in data.indices) {
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val t = s[i]; s[i] = s[j]; s[j] = t
            out[k] = (data[k].toInt() xor s[(s[i] + s[j]) and 0xFF]).toByte()
        }
        return out
    }

    /** AES-CMAC (NIST SP 800-38B, RFC 4493). */
    fun aesCmac(key: ByteArray, data: ByteArray): ByteArray {
        val l = DocCrypto.aesEcb(true, key, ByteArray(16))
        val k1 = shiftXor(l)
        val k2 = shiftXor(k1)
        val n = if (data.isEmpty()) 1 else (data.size + 15) / 16
        val complete = data.isNotEmpty() && data.size % 16 == 0
        val last = ByteArray(16)
        val lastStart = (n - 1) * 16
        if (complete) {
            for (i in 0 until 16) last[i] = (data[lastStart + i].toInt() xor k1[i].toInt()).toByte()
        } else {
            val rem = data.size - lastStart
            for (i in 0 until rem) last[i] = data[lastStart + i]
            last[rem] = 0x80.toByte()
            for (i in 0 until 16) last[i] = (last[i].toInt() xor k2[i].toInt()).toByte()
        }
        var x = ByteArray(16)
        for (b in 0 until n - 1) {
            val y = ByteArray(16) { (x[it].toInt() xor data[b * 16 + it].toInt()).toByte() }
            x = DocCrypto.aesEcb(true, key, y)
        }
        val y = ByteArray(16) { (x[it].toInt() xor last[it].toInt()).toByte() }
        return DocCrypto.aesEcb(true, key, y)
    }

    private fun shiftXor(b: ByteArray): ByteArray {
        val out = ByteArray(16)
        var carry = 0
        for (i in 15 downTo 0) {
            val v = b[i].toInt() and 0xFF
            out[i] = ((v shl 1) or carry).toByte()
            carry = v ushr 7
        }
        if (b[0].toInt() and 0x80 != 0) out[15] = (out[15].toInt() xor 0x87).toByte()
        return out
    }

    fun hex(b: ByteArray): String = b.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    fun unhex(s: String): ByteArray {
        val clean = s.filter { !it.isWhitespace() }
        require(clean.length % 2 == 0) { "Odd hex length" }
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
