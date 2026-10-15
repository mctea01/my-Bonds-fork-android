package diw.wallet.core.document

import org.bouncycastle.crypto.digests.KeccakDigest
import org.bouncycastle.crypto.digests.SM3Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.math.ec.ECAlgorithms
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual object DocCrypto {
    private val random = SecureRandom()

    actual fun digest(algorithm: String, data: ByteArray): ByteArray = when (algorithm.uppercase()) {
        "SM3" -> SM3Digest().run {
            update(data, 0, data.size)
            ByteArray(digestSize).also { doFinal(it, 0) }
        }
        else -> MessageDigest.getInstance(algorithm).digest(data)
    }

    actual fun aesCbc(encrypt: Boolean, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/CBC/NoPadding").run {
            init(if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(data)
        }

    actual fun aesEcb(encrypt: Boolean, key: ByteArray, block: ByteArray): ByteArray =
        Cipher.getInstance("AES/ECB/NoPadding").run {
            init(if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
            doFinal(block)
        }

    actual fun desEdeCbc(encrypt: Boolean, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        // A two-key 3DES key (K1 K2) is used as K1 K2 K1.
        val k = if (key.size == 16) key + key.copyOfRange(0, 8) else key
        return Cipher.getInstance("DESede/CBC/NoPadding").run {
            init(if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, SecretKeySpec(k, "DESede"), IvParameterSpec(iv))
            doFinal(data)
        }
    }

    actual fun randomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }

    actual fun keccak256(data: ByteArray): ByteArray {
        val d = KeccakDigest(256)
        d.update(data, 0, data.size)
        return ByteArray(32).also { d.doFinal(it, 0) }
    }

    private val secp256k1 by lazy { CustomNamedCurves.getByName("secp256k1") }

    actual fun ecRecoverAddress(hash: ByteArray, signature: ByteArray): ByteArray? {
        if (hash.size != 32 || signature.size != 65) return null
        val v = signature[64].toInt() and 0xFF
        val recId = when (v) {
            27, 28 -> v - 27
            0, 1 -> v
            else -> return null
        }
        val n = secp256k1.n
        val r = BigInteger(1, signature.copyOfRange(0, 32))
        val s = BigInteger(1, signature.copyOfRange(32, 64))
        if (r.signum() == 0 || r >= n || s.signum() == 0 || s >= n) return null
        return runCatching {
            // R is the point with x = r and the parity recId names; Q = r^-1 (sR - eG).
            val x = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, r)
            val point = secp256k1.curve.decodePoint(byteArrayOf((0x02 + (recId and 1)).toByte()) + x)
            if (!point.multiply(n).isInfinity) return null
            val e = BigInteger(1, hash)
            val rInv = r.modInverse(n)
            val q = ECAlgorithms.sumOfTwoMultiplies(secp256k1.g, e.negate().mod(n).multiply(rInv).mod(n), point, s.multiply(rInv).mod(n)).normalize()
            if (q.isInfinity) return null
            val pub = q.getEncoded(false).copyOfRange(1, 65)
            keccak256(pub).copyOfRange(12, 32)
        }.getOrNull()
    }

    actual fun certificatesIn(data: ByteArray): List<ByteArray> = Bc.certificates(data)

    actual fun caIssuerUrls(der: ByteArray): List<String> = Bc.holder(der)?.let { Bc.caIssuers(it) }.orEmpty()
}
