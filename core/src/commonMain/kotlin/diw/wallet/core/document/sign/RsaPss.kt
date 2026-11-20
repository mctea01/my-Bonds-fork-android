package diw.wallet.core.document.sign

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.jose.PlatformCrypto

/**
 * EMSA-PSS encoding (RFC 8017 9.1.1) with SHA-256, MGF1 with SHA-256 and a 32-byte salt: the block a card or token
 * that applies its RSA key to a host-padded block (GPKI cards, PIV) signs to make an RSASSA-PSS (PS256) signature,
 * which C2PA and COSE require of RSA keys.
 */
object RsaPss {
    private const val H_LEN = 32
    private const val S_LEN = 32

    /** The encoded block of [modulusBits] bits for SHA-256 of [message], with [salt] (random unless a test gives one). */
    fun encode(message: ByteArray, modulusBits: Int, salt: ByteArray = PlatformCrypto.randomBytes(S_LEN)): ByteArray {
        require(salt.size == S_LEN)
        val emBits = modulusBits - 1
        val emLen = (emBits + 7) / 8
        require(emLen >= H_LEN + S_LEN + 2) { "RSA key too short for PSS" }
        val mHash = DocCrypto.digest("SHA-256", message)
        val h = DocCrypto.digest("SHA-256", ByteArray(8) + mHash + salt)
        val db = ByteArray(emLen - H_LEN - 1)
        db[db.size - S_LEN - 1] = 0x01
        salt.copyInto(db, db.size - S_LEN)
        val mask = mgf1(h, db.size)
        for (i in db.indices) db[i] = (db[i].toInt() xor mask[i].toInt()).toByte()
        val clear = 8 * emLen - emBits
        if (clear > 0) db[0] = (db[0].toInt() and (0xFF ushr clear)).toByte()
        val em = db + h + byteArrayOf(0xBC.toByte())
        // A block shorter than the modulus is left-padded with zeros for cards that take a modulus-sized input.
        val k = (modulusBits + 7) / 8
        return if (em.size < k) ByteArray(k - em.size) + em else em
    }

    private fun mgf1(seed: ByteArray, length: Int): ByteArray {
        val out = ArrayList<Byte>(length + H_LEN)
        var counter = 0
        while (out.size < length) {
            val c = byteArrayOf((counter ushr 24).toByte(), (counter ushr 16).toByte(), (counter ushr 8).toByte(), counter.toByte())
            DocCrypto.digest("SHA-256", seed + c).forEach { out.add(it) }
            counter++
        }
        return out.subList(0, length).toByteArray()
    }

    /** Bits of the RSA modulus of the DER certificate [cert], or null for a key that is not RSA. */
    fun modulusBits(cert: ByteArray): Int? {
        val m = PlatformCrypto.rsaPublicKeyFromCertificate(cert)?.modulus ?: return null
        var i = 0
        while (i < m.size && m[i] == 0.toByte()) i++
        if (i == m.size) return null
        return (m.size - i - 1) * 8 + (32 - (m[i].toInt() and 0xFF).countLeadingZeroBits())
    }
}
