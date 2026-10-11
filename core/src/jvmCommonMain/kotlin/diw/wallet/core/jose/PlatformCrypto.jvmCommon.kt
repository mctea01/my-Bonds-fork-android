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

    actual fun verifyEcdsaRaw(curveName: String, x: ByteArray, y: ByteArray, data: ByteArray, signature: ByteArray): Boolean = try {
        val spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(curveName)
        val point = spec.curve.createPoint(BigInteger(1, x), BigInteger(1, y))
        val signer = org.bouncycastle.crypto.signers.ECDSASigner()
        val domain = org.bouncycastle.crypto.params.ECDomainParameters(spec.curve, spec.g, spec.n, spec.h)
        signer.init(false, org.bouncycastle.crypto.params.ECPublicKeyParameters(point, domain))
        val half = signature.size / 2
        signer.verifySignature(sha256(data), BigInteger(1, signature.copyOfRange(0, half)), BigInteger(1, signature.copyOfRange(half, signature.size)))
    } catch (_: Exception) {
        false
    }

    actual fun gzip(data: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        java.util.zip.GZIPOutputStream(out).use { it.write(data) }
        return out.toByteArray()
    }

    actual fun gunzip(data: ByteArray, maxBytes: Int): ByteArray =
        java.util.zip.GZIPInputStream(ByteArrayInputStream(data)).use { readLimited(it, maxBytes) }

    actual fun deflate(data: ByteArray, raw: Boolean): ByteArray {
        val deflater = java.util.zip.Deflater(java.util.zip.Deflater.BEST_COMPRESSION, raw)
        val out = java.io.ByteArrayOutputStream()
        java.util.zip.DeflaterOutputStream(out, deflater).use { it.write(data) }
        deflater.end()
        return out.toByteArray()
    }

    actual fun inflate(data: ByteArray, raw: Boolean, maxBytes: Int): ByteArray {
        val inflater = java.util.zip.Inflater(raw)
        return try {
            java.util.zip.InflaterInputStream(ByteArrayInputStream(data), inflater).use { readLimited(it, maxBytes) }
        } finally {
            inflater.end()
        }
    }

    private fun readLimited(input: java.io.InputStream, maxBytes: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > maxBytes) throw IllegalArgumentException("Decompressed data exceeds $maxBytes bytes")
        }
        return out.toByteArray()
    }

    actual fun certificateSignedBy(childDer: ByteArray, issuerDer: ByteArray): Boolean = try {
        val cf = CertificateFactory.getInstance("X.509")
        val child = cf.generateCertificate(ByteArrayInputStream(childDer))
        val issuer = cf.generateCertificate(ByteArrayInputStream(issuerDer))
        child.verify(issuer.publicKey)
        true
    } catch (_: Exception) {
        false
    }

    actual fun certificateSubjectCn(der: ByteArray): String? = try {
        val cert = org.bouncycastle.cert.X509CertificateHolder(der)
        cert.subject.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.CN).firstOrNull()?.first?.value?.toString()
    } catch (_: Exception) {
        null
    }

    private fun BigInteger.toUnsignedBytes(): ByteArray {
        val b = toByteArray()
        return if (b.size > 1 && b[0] == 0.toByte()) b.copyOfRange(1, b.size) else b
    }
}
