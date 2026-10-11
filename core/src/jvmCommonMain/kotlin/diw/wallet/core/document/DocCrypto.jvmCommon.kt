package diw.wallet.core.document

import org.bouncycastle.crypto.digests.SM3Digest
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
}
