package diw.wallet.core.zkpassport

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.RSAPublicKey
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import java.math.BigInteger

/**
 * CSCA public keys in the form zkPassport's certificate packages use (`publicKeyToBytes`): the RSA modulus, or
 * the EC point's x then y. Read from the certificate's own encoding, so curves the platform's providers do not
 * know (brainpool on some Android versions) still compare.
 */
object ZkPassportCsca {
    private val RSA_KEYS = setOf<ASN1ObjectIdentifier>(PKCSObjectIdentifiers.rsaEncryption, PKCSObjectIdentifiers.id_RSASSA_PSS)

    /** The key of a DER certificate as numbers: the modulus, or x and y; null for other or compressed keys. */
    fun publicKey(der: ByteArray): List<BigInteger>? = runCatching {
        val spki = Certificate.getInstance(der).subjectPublicKeyInfo
        val algorithm = spki.algorithm.algorithm
        when {
            algorithm in RSA_KEYS -> listOf(RSAPublicKey.getInstance(spki.parsePublicKey()).modulus)
            algorithm == X9ObjectIdentifiers.id_ecPublicKey -> {
                val point = spki.publicKeyData.octets
                if (point.size < 3 || point[0] != 4.toByte() || point.size % 2 == 0) null
                else {
                    val half = (point.size - 1) / 2
                    listOf(BigInteger(1, point.copyOfRange(1, 1 + half)), BigInteger(1, point.copyOfRange(1 + half, point.size)))
                }
            }
            else -> null
        }
    }.getOrNull()

    /** Whether a package key (hex of the modulus, or of x then y in two equal halves) is [key]. */
    fun same(key: List<BigInteger>, packaged: String): Boolean {
        val hex = packaged.removePrefix("0x")
        if (hex.isEmpty() || hex.any { Character.digit(it, 16) < 0 }) return false
        return when (key.size) {
            1 -> BigInteger(hex, 16) == key[0]
            2 -> hex.length % 2 == 0 && hex.length >= 4 &&
                BigInteger(hex.substring(0, hex.length / 2), 16) == key[0] && BigInteger(hex.substring(hex.length / 2), 16) == key[1]
            else -> false
        }
    }
}
