package diw.wallet.core.document.mrtd

import diw.wallet.core.document.DocCrypto
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.pkcs.DHParameter
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x9.DomainParameters
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.asn1.x9.X962Parameters
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.crypto.params.DHParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.SecureRandom

actual object MrtdCrypto {
    private val random = SecureRandom()

    private val CURVES = mapOf(
        8 to "secp192r1", 9 to "brainpoolP192r1", 10 to "secp224r1", 11 to "brainpoolP224r1", 12 to "secp256r1",
        13 to "brainpoolP256r1", 14 to "brainpoolP320r1", 15 to "secp384r1", 16 to "brainpoolP384r1",
        17 to "brainpoolP512r1", 18 to "secp521r1",
    )

    /** RFC 5114 groups 2.1 to 2.3 (p, g, q): PACE standardized domain parameters 0 to 2. */
    private val RFC5114 = listOf(
        Triple(
            "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0" +
            "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0" +
            "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
            "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213" +
            "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A" +
            "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
            "F518AA8781A8DF278ABA4E7D64B7CB9D49462353",
        ),
        Triple(
            "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" +
            "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
            "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330" +
            "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
            "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" +
            "CF9DE5384E71B81C0AC4DFFE0C10E64F",
            "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA" +
            "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
            "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EF" +
            "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
            "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" +
            "81BC087F2A7065B384B890D3191F2BFA",
            "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB",
        ),
        Triple(
            "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30" +
            "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B" +
            "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E" +
            "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026" +
            "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F" +
            "693877FAD7EF09CADB094AE91E1A1597",
            "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555" +
            "BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B" +
            "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55" +
            "A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915" +
            "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D4795451" +
            "5E2327CFEF98C582664B4C0F6CC41659",
            "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3",
        ),
    )

    actual fun standardDomain(id: Int): AgreementDomain? = when (id) {
        in 0..2 -> RFC5114[id].let { (p, g, q) -> DhDomain(DHParameters(BigInteger(p, 16), BigInteger(g, 16), BigInteger(q, 16))) }
        else -> CURVES[id]?.let { name -> ECNamedCurveTable.getByName(name)?.let { EcDomain(it.curve, it.g, it.n, it.h) } }
    }

    actual fun publicKeyDomain(spki: ByteArray): Pair<AgreementDomain, ByteArray>? = runCatching {
        val info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spki))
        val alg = info.algorithm.algorithm
        when (alg) {
            X9ObjectIdentifiers.id_ecPublicKey -> {
                val x9 = x9(info) ?: return null
                val domain = EcDomain(x9.curve, x9.g, x9.n, x9.h)
                domain to x9.curve.decodePoint(info.publicKeyData.bytes).getEncoded(false)
            }
            X9ObjectIdentifiers.dhpublicnumber -> {
                val dp = DomainParameters.getInstance(info.algorithm.parameters)
                val y = ASN1Integer.getInstance(info.parsePublicKey()).positiveValue
                val domain = DhDomain(DHParameters(dp.p, dp.g, dp.q))
                domain to domain.encode(y)
            }
            PKCSObjectIdentifiers.dhKeyAgreement -> {
                val p = DHParameter.getInstance(info.algorithm.parameters)
                val y = ASN1Integer.getInstance(info.parsePublicKey()).positiveValue
                val domain = DhDomain(DHParameters(p.p, p.g, null, p.l?.toInt() ?: 0))
                domain to domain.encode(y)
            }
            else -> null
        }
    }.getOrNull()

    private fun x9(info: SubjectPublicKeyInfo): X9ECParameters? {
        val params = X962Parameters.getInstance(info.algorithm.parameters)
        return when {
            params.isNamedCurve -> ECNamedCurveTable.getByOID(ASN1ObjectIdentifier.getInstance(params.parameters))
            params.isImplicitlyCA -> null
            else -> X9ECParameters.getInstance(params.parameters)
        }
    }

    actual fun verifyActiveAuthentication(spki: ByteArray, challenge: ByteArray, response: ByteArray, signatureOid: String?): String? = runCatching {
        val info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spki))
        when (info.algorithm.algorithm) {
            PKCSObjectIdentifiers.rsaEncryption -> rsaIso9796(info, challenge, response)
            X9ObjectIdentifiers.id_ecPublicKey -> ecdsa(info, challenge, response, signatureOid)
            else -> null
        }
    }.getOrNull()

    /** ISO/IEC 9796-2 digital signature scheme 1 with partial or total message recovery. */
    private fun rsaIso9796(info: SubjectPublicKeyInfo, challenge: ByteArray, response: ByteArray): String? {
        val key = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(info.parsePublicKey())
        val n = key.modulus
        val s = BigInteger(1, response)
        if (s >= n) return null
        val size = (n.bitLength() + 7) / 8
        val m = unsigned(s.modPow(key.publicExponent, n), size)
        // The representative starts with 01 (header 0x6A for partial, 0x4B for total recovery) after a leading pad.
        val start = m.indexOfFirst { it != 0.toByte() }.takeIf { it >= 0 } ?: return null
        val header = m[start].toInt() and 0xFF
        if (header != 0x6A && header != 0x4B && header and 0xF0 != 0x60 && header and 0xF0 != 0x40) return null
        val (trailerLen, hash) = when {
            m.last() == 0xBC.toByte() -> 1 to "SHA-1"
            m.last() == 0xCC.toByte() -> 2 to when (m[m.size - 2].toInt() and 0xFF) {
                0x33 -> "SHA-1"; 0x34 -> "SHA-256"; 0x35 -> "SHA-512"; 0x36 -> "SHA-384"; 0x38 -> "SHA-224"
                else -> return null
            }
            else -> return null
        }
        val hashLen = DocCrypto.digest(hash, ByteArray(0)).size
        val digestStart = m.size - trailerLen - hashLen
        if (digestStart <= start + 1) return null
        // For total recovery the message starts after the padding nibbles (0B ... BA); scheme 1 partial has none.
        var msgStart = start + 1
        if (header and 0xF0 == 0x40 || header == 0x4B) {
            while (msgStart < digestStart && m[msgStart] == 0xBB.toByte()) msgStart++
            if (msgStart < digestStart && m[msgStart] == 0xBA.toByte()) msgStart++
        }
        val m1 = m.copyOfRange(msgStart, digestStart)
        val d = m.copyOfRange(digestStart, m.size - trailerLen)
        return if (DocCrypto.digest(hash, m1 + challenge).contentEquals(d)) hash else null
    }

    private val PLAIN_HASHES = mapOf(
        "0.4.0.127.0.7.1.1.4.1.1" to "SHA-1", "0.4.0.127.0.7.1.1.4.1.2" to "SHA-224", "0.4.0.127.0.7.1.1.4.1.3" to "SHA-256",
        "0.4.0.127.0.7.1.1.4.1.4" to "SHA-384", "0.4.0.127.0.7.1.1.4.1.5" to "SHA-512",
        "1.2.840.10045.4.1" to "SHA-1", "1.2.840.10045.4.3.1" to "SHA-224", "1.2.840.10045.4.3.2" to "SHA-256",
        "1.2.840.10045.4.3.3" to "SHA-384", "1.2.840.10045.4.3.4" to "SHA-512",
    )

    private fun ecdsa(info: SubjectPublicKeyInfo, challenge: ByteArray, response: ByteArray, oid: String?): String? {
        val x9 = x9(info) ?: return null
        val domain = ECDomainParameters(x9.curve, x9.g, x9.n, x9.h)
        val q = x9.curve.decodePoint(info.publicKeyData.bytes)
        // Plain r || s; a DER signature is accepted too, as some chips send one.
        val (r, s) = runCatching {
            val seq = ASN1Sequence.getInstance(response)
            ASN1Integer.getInstance(seq.getObjectAt(0)).positiveValue to ASN1Integer.getInstance(seq.getObjectAt(1)).positiveValue
        }.getOrNull() ?: run {
            if (response.size % 2 != 0) return null
            BigInteger(1, response.copyOf(response.size / 2)) to BigInteger(1, response.copyOfRange(response.size / 2, response.size))
        }
        val hashes = oid?.let { PLAIN_HASHES[it] }?.let { listOf(it) } ?: listOf("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512")
        for (h in hashes) {
            val signer = ECDSASigner()
            signer.init(false, ECPublicKeyParameters(q, domain))
            if (signer.verifySignature(DocCrypto.digest(h, challenge), r, s)) return h
        }
        return null
    }

    private val alpha2ByAlpha3: Map<String, String> by lazy {
        java.util.Locale.getISOCountries().mapNotNull { a2 ->
            runCatching { @Suppress("DEPRECATION") java.util.Locale("", a2).isO3Country }.getOrNull()?.takeIf { it.length == 3 }?.let { it to a2 }
        }.toMap()
    }

    actual fun alpha2(code: String): String? = when (val c = code.trim('<', ' ').uppercase()) {
        "D" -> "DE"
        "RKS" -> "XK"
        else -> alpha2ByAlpha3[c]
    }

    actual fun describeKey(spki: ByteArray): String? = runCatching {
        val info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spki))
        when (info.algorithm.algorithm) {
            PKCSObjectIdentifiers.rsaEncryption -> "RSA " + org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(info.parsePublicKey()).modulus.bitLength()
            X9ObjectIdentifiers.id_ecPublicKey -> {
                val params = X962Parameters.getInstance(info.algorithm.parameters)
                val name = if (params.isNamedCurve) ECNamedCurveTable.getName(ASN1ObjectIdentifier.getInstance(params.parameters)) else null
                "EC " + (name ?: x9(info)?.let { namedFor(it) } ?: (x9(info)?.curve?.fieldSize?.toString() ?: "?"))
            }
            X9ObjectIdentifiers.dhpublicnumber, PKCSObjectIdentifiers.dhKeyAgreement -> "DH"
            else -> info.algorithm.algorithm.id
        }
    }.getOrNull()

    actual fun masterList(bytes: ByteArray): MasterList? = runCatching {
        val sd = org.bouncycastle.cms.CMSSignedData(bytes)
        if (sd.signedContentTypeOID != "2.23.136.1.1.2") return null
        val content = sd.signedContent?.content as? ByteArray ?: return null
        val seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(content))
        val set = org.bouncycastle.asn1.ASN1Set.getInstance(seq.getObjectAt(1))
        val certs = set.map { it.toASN1Primitive().encoded }
        val holders = sd.certificates.getMatches(null).filterIsInstance<org.bouncycastle.cert.X509CertificateHolder>()
        val signerInfo = sd.signerInfos.signers.firstOrNull()
        val signerCert = signerInfo?.let { si -> holders.firstOrNull { si.sid.match(it) } }
        val valid = signerInfo != null && signerCert != null && runCatching {
            signerInfo.verify(org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder().setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider()).build(signerCert))
        }.getOrDefault(false)
        MasterList(certs, signerCert?.subject?.toString(), valid)
    }.getOrNull()

    /** The name of a standard curve given with explicit parameters, as DG14 and DG15 usually do. */
    private fun namedFor(x9: X9ECParameters): String? {
        val names = ECNamedCurveTable.getNames().toList().filterIsInstance<String>()
        return names.firstOrNull { n ->
            val c = ECNamedCurveTable.getByName(n) ?: return@firstOrNull false
            c.curve.equals(x9.curve) && c.g.equals(x9.g)
        }
    }

    internal fun unsigned(v: BigInteger, size: Int): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == size -> b
            b.size > size -> b.copyOfRange(b.size - size, b.size)
            else -> ByteArray(size - b.size) + b
        }
    }

    internal fun randomBelow(n: BigInteger): BigInteger {
        while (true) {
            val k = BigInteger(n.bitLength(), random)
            if (k.signum() > 0 && k < n) return k
        }
    }

    private class EcDomain(val curve: ECCurve, val g: ECPoint, val n: BigInteger, val h: BigInteger?) : AgreementDomain {
        override val elliptic = true
        override val size: Int = (curve.fieldSize + 7) / 8

        private fun point(b: ByteArray): ECPoint = curve.decodePoint(b).normalize()

        override fun generate(): AgreementKeyPair {
            val d = randomBelow(n)
            return AgreementKeyPair(g.multiply(d).normalize().getEncoded(false), d)
        }

        private fun shared(own: AgreementKeyPair, peer: ByteArray): ECPoint {
            val p = point(peer)
            if (!valid(p)) throw MrtdException("bad_public_key")
            val r = p.multiply(own.handle as BigInteger).normalize()
            if (r.isInfinity) throw MrtdException("bad_public_key")
            return r
        }

        override fun agree(own: AgreementKeyPair, peerPublic: ByteArray): ByteArray =
            unsigned(shared(own, peerPublic).affineXCoord.toBigInteger(), size)

        override fun mapGeneric(nonce: ByteArray, own: AgreementKeyPair, peerPublic: ByteArray): AgreementDomain {
            val p = point(peerPublic)
            if (!valid(p)) throw MrtdException("bad_public_key")
            val hPoint = p.multiply(own.handle as BigInteger).normalize()
            val mapped = g.multiply(BigInteger(1, nonce)).add(hPoint).normalize()
            if (mapped.isInfinity) throw MrtdException("bad_mapping")
            return EcDomain(curve, mapped, n, h)
        }

        private fun valid(p: ECPoint): Boolean = !p.isInfinity && p.isValid

        override fun validPublic(publicKey: ByteArray): Boolean = runCatching { valid(point(publicKey)) }.getOrDefault(false)
    }

    private class DhDomain(val params: DHParameters) : AgreementDomain {
        override val elliptic = false
        override val size: Int = (params.p.bitLength() + 7) / 8

        fun encode(v: BigInteger) = unsigned(v, size)

        override fun generate(): AgreementKeyPair {
            val q = params.q
            val x = if (q != null) randomBelow(q) else BigInteger(maxOf(params.l, 256).coerceAtMost(params.p.bitLength() - 1), random).setBit(0)
            return AgreementKeyPair(encode(params.g.modPow(x, params.p)), x)
        }

        private fun element(b: ByteArray): BigInteger {
            val y = BigInteger(1, b)
            val p = params.p
            if (y <= BigInteger.ONE || y >= p.subtract(BigInteger.ONE)) throw MrtdException("bad_public_key")
            params.q?.let { q -> if (y.modPow(q, p) != BigInteger.ONE) throw MrtdException("bad_public_key") }
            return y
        }

        override fun agree(own: AgreementKeyPair, peerPublic: ByteArray): ByteArray =
            encode(element(peerPublic).modPow(own.handle as BigInteger, params.p))

        override fun mapGeneric(nonce: ByteArray, own: AgreementKeyPair, peerPublic: ByteArray): AgreementDomain {
            val p = params.p
            val hv = element(peerPublic).modPow(own.handle as BigInteger, p)
            val g2 = params.g.modPow(BigInteger(1, nonce), p).multiply(hv).mod(p)
            if (g2 <= BigInteger.ONE) throw MrtdException("bad_mapping")
            return DhDomain(DHParameters(p, g2, params.q))
        }

        override fun validPublic(publicKey: ByteArray): Boolean = runCatching { element(publicKey) }.isSuccess
    }
}
