package diw.wallet.core.jose

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec

actual object PlatformCrypto {
    private val random = SecureRandom()

    actual fun rsaPublicKeyFromCertificate(der: ByteArray): VerificationKey.Rsa? {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der))
        val pk = cert.publicKey as? RSAPublicKey ?: return null
        return VerificationKey.Rsa(pk.modulus.toUnsignedBytes(), pk.publicExponent.toUnsignedBytes())
    }

    actual fun verifyRsa(alg: String, key: VerificationKey.Rsa, data: ByteArray, signature: ByteArray): Boolean {
        val pub = KeyFactory.getInstance("RSA").generatePublic(
            RSAPublicKeySpec(BigInteger(1, key.modulus), BigInteger(1, key.exponent))
        )
        val sig = when (alg) {
            "RS256" -> Signature.getInstance("SHA256withRSA")
            "RS384" -> Signature.getInstance("SHA384withRSA")
            "RS512" -> Signature.getInstance("SHA512withRSA")
            "PS256" -> pss("SHA-256", 32)
            "PS384" -> pss("SHA-384", 48)
            "PS512" -> pss("SHA-512", 64)
            else -> return false
        }
        sig.initVerify(pub)
        sig.update(data)
        return try { sig.verify(signature) } catch (_: Exception) { false }
    }

    private fun pss(hash: String, saltLen: Int): Signature {
        val s = Signature.getInstance("RSASSA-PSS")
        s.setParameter(PSSParameterSpec(hash, "MGF1", MGF1ParameterSpec(hash), saltLen, 1))
        return s
    }

    actual fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    actual fun randomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }

    actual fun decompressEcPoint(curveName: String, compressed: ByteArray): ByteArray {
        val spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(curveName)
            ?: throw IllegalArgumentException("Unknown curve $curveName")
        return spec.curve.decodePoint(compressed).getEncoded(false)
    }

    private fun BigInteger.toUnsignedBytes(): ByteArray {
        val b = toByteArray()
        return if (b.size > 1 && b[0] == 0.toByte()) b.copyOfRange(1, b.size) else b
    }
}
