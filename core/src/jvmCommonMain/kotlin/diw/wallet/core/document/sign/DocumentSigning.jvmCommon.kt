package diw.wallet.core.document.sign

import diw.wallet.core.document.Asic
import diw.wallet.core.document.Bc
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.GmSignedData
import diw.wallet.core.document.XmlDsig
import diw.wallet.core.document.Zip
import diw.wallet.core.document.pdf.PdfIncrementalSigner
import diw.wallet.core.document.pdf.PdfSignOptions
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.BEROctetString
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.asn1.cms.SignerIdentifier
import org.bouncycastle.asn1.cms.SignerInfo
import org.bouncycastle.asn1.ess.ESSCertIDv2
import org.bouncycastle.asn1.ess.SigningCertificateV2
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.Time
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.time.Clock

actual object DocumentSigning {
    private val SHA256 = AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE)
    private val RSA_SHA256 = AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE)
    private val ECDSA_SHA256 = AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)

    /**
     * CMS SignedData with one signer: content type, message digest and ESS signing-certificate-v2 attributes (plus
     * signing time unless [pades]), and a signature time stamp when [timestamper] is given.
     */
    suspend fun cms(content: ByteArray, signer: DocumentSigner, encapsulate: Boolean, pades: Boolean, timestamper: Timestamper?): ByteArray {
        val chain = signer.certificateChain.map { X509CertificateHolder(it) }
        val leaf = chain.first()
        val attrs = ASN1EncodableVector()
        attrs.add(Attribute(CMSAttributes.contentType, DERSet(CMSObjectIdentifiers.data)))
        if (!pades) attrs.add(Attribute(CMSAttributes.signingTime, DERSet(org.bouncycastle.asn1.cms.Time(Date()))))
        attrs.add(Attribute(CMSAttributes.messageDigest, DERSet(DEROctetString(DocCrypto.digest("SHA-256", content)))))
        val essId = ESSCertIDv2(SHA256, DocCrypto.digest("SHA-256", leaf.encoded), org.bouncycastle.asn1.x509.IssuerSerial(leaf.issuer, leaf.serialNumber))
        attrs.add(Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, DERSet(SigningCertificateV2(arrayOf(essId)))))
        val signedAttrs = DERSet(attrs)
        val signature = signer.sign(signedAttrs.encoded)
        verifyRaw(leaf, signer.keyType, signedAttrs.encoded, signature)
        val unsigned = timestamper?.let { ts ->
            val token = ts.timestamp(signature)
            DERSet(Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, DERSet(Bc.parse(token))))
        }
        val si = SignerInfo(
            SignerIdentifier(IssuerAndSerialNumber(leaf.toASN1Structure())),
            SHA256,
            signedAttrs,
            if (signer.keyType == SignerKeyType.RSA) RSA_SHA256 else ECDSA_SHA256,
            DEROctetString(signature),
            unsigned,
        )
        val certs = ASN1EncodableVector().apply { chain.forEach { add(it.toASN1Structure()) } }
        val sd = SignedData(
            DERSet(SHA256),
            ContentInfo(CMSObjectIdentifiers.data, if (encapsulate) BEROctetString(content) else null),
            DERSet(certs),
            null as ASN1Set?,
            DERSet(si),
        )
        val der = ContentInfo(CMSObjectIdentifiers.signedData, sd).getEncoded("DER")
        // The result must verify like any third party would verify it.
        val parsed = if (encapsulate) CMSSignedData(der) else CMSSignedData(CMSProcessableByteArray(content), der)
        val ok = parsed.signerInfos.signers.first().verify(JcaSimpleSignerInfoVerifierBuilder().setProvider(Bc.provider).build(leaf))
        if (!ok) throw SigningException("產生的簽章無法通過驗證")
        return der
    }

    private fun verifyRaw(cert: X509CertificateHolder, type: SignerKeyType, data: ByteArray, signature: ByteArray) {
        val ok = GmSignedData.verifySignature(cert, if (type == SignerKeyType.RSA) "1.2.840.113549.1.1.11" else "1.2.840.10045.4.3.2", null, data, signature)
        if (!ok) throw SigningException("簽章無法以憑證的公開金鑰驗證：卡片或金鑰與憑證不相符")
    }

    actual suspend fun signPdf(pdf: ByteArray, signer: DocumentSigner, options: PdfSignOptions, timestamper: Timestamper?): ByteArray {
        val prepared = PdfIncrementalSigner.prepare(pdf, options)
        val cms = cms(prepared.signedData(), signer, encapsulate = false, pades = options.subFilter == "ETSI.CAdES.detached", timestamper = timestamper)
        return prepared.finish(cms)
    }

    actual suspend fun signCades(content: ByteArray, signer: DocumentSigner, detached: Boolean, timestamper: Timestamper?): ByteArray =
        cms(content, signer, encapsulate = !detached, pades = false, timestamper = timestamper)

    actual suspend fun buildAsic(files: List<Pair<String, ByteArray>>, signer: DocumentSigner, timestamper: Timestamper?): ByteArray {
        require(files.isNotEmpty())
        val names = files.map { it.first }
        if (names.toSet().size != names.size || names.any { it.startsWith("META-INF/") || it == "mimetype" || it.contains("..") }) {
            throw SigningException("檔名重複或不合法")
        }
        val sigPath = "META-INF/signature001.p7s"
        val manifest = Asic.manifest(files, sigPath)
        val signature = cms(manifest, signer, encapsulate = false, pades = false, timestamper = timestamper)
        val entries = ArrayList<Pair<String, ByteArray>>()
        entries.add("mimetype" to Asic.MIME_E.encodeToByteArray())
        entries.addAll(files)
        entries.add("META-INF/ASiCManifest001.xml" to manifest)
        entries.add(sigPath to signature)
        return Zip.write(entries, stored = setOf("mimetype"))
    }

    actual suspend fun signXml(xml: ByteArray, signer: DocumentSigner, timestamper: Timestamper?): ByteArray =
        XmlDsig.signEnveloped(xml, signer, Clock.System.now(), timestamper?.let { t -> { data: ByteArray -> t.timestamp(data) } })

    actual fun unzip(bytes: ByteArray): Map<String, ByteArray> = Zip.read(bytes)

    actual fun pkcs12Signer(p12: ByteArray, password: String): DocumentSigner {
        val ks = try {
            KeyStore.getInstance("PKCS12", Bc.provider).apply { load(ByteArrayInputStream(p12), password.toCharArray()) }
        } catch (e: Exception) {
            throw SigningException("無法開啟憑證檔：密碼錯誤或格式不支援", e)
        }
        val alias = ks.aliases().toList().firstOrNull { ks.isKeyEntry(it) } ?: throw SigningException("憑證檔內沒有私密金鑰")
        val key = ks.getKey(alias, password.toCharArray()) as? PrivateKey ?: throw SigningException("憑證檔內沒有私密金鑰")
        val chain = ks.getCertificateChain(alias)?.map { (it as X509Certificate).encoded } ?: throw SigningException("憑證檔內沒有憑證")
        val type = when (key.algorithm) {
            "RSA" -> SignerKeyType.RSA
            "EC", "ECDSA" -> SignerKeyType.EC_P256
            else -> throw SigningException("不支援的金鑰類型 ${key.algorithm}")
        }
        return object : DocumentSigner {
            override val certificateChain = chain
            override val keyType = type
            override val source = SignerSource.PKCS12
            override suspend fun sign(data: ByteArray): ByteArray {
                val s = Signature.getInstance(if (type == SignerKeyType.RSA) "SHA256withRSA" else "SHA256withECDSA", Bc.provider)
                s.initSign(key)
                s.update(data)
                return s.sign()
            }
        }
    }

    actual suspend fun selfIssuedCertificate(
        publicKeyDer: ByteArray,
        subjectName: String,
        sign: suspend (ByteArray) -> ByteArray,
        keyType: SignerKeyType,
        validDays: Int,
    ): ByteArray {
        val name = X500Name("CN=" + subjectName.replace(",", " ").replace("=", " ") + ",O=DIW MY WALLET self-issued")
        val now = System.currentTimeMillis()
        val alg = if (keyType == SignerKeyType.RSA) RSA_SHA256 else ECDSA_SHA256
        val gen = V3TBSCertificateGenerator()
        gen.setSerialNumber(ASN1Integer(BigInteger(1, DocCrypto.randomBytes(16))))
        gen.setIssuer(name)
        gen.setSubject(name)
        gen.setStartDate(Time(Date(now - 60_000)))
        gen.setEndDate(Time(Date(now + validDays * 86_400_000L)))
        gen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(publicKeyDer))
        gen.setSignature(alg)
        val ext = ExtensionsGenerator()
        ext.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        ext.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.nonRepudiation))
        // Key identifiers let another wallet import this certificate as its own trust anchor.
        val keyIds = org.bouncycastle.cert.bc.BcX509ExtensionUtils()
        val spki = SubjectPublicKeyInfo.getInstance(publicKeyDer)
        ext.addExtension(Extension.subjectKeyIdentifier, false, keyIds.createSubjectKeyIdentifier(spki))
        ext.addExtension(Extension.authorityKeyIdentifier, false, keyIds.createAuthorityKeyIdentifier(spki))
        gen.setExtensions(ext.generate())
        val tbs = gen.generateTBSCertificate()
        val sig = sign(tbs.encoded)
        val v = ASN1EncodableVector()
        v.add(tbs); v.add(alg); v.add(org.bouncycastle.asn1.DERBitString(sig))
        val cert = Certificate.getInstance(DERSequence(v))
        val holder = X509CertificateHolder(cert)
        if (!holder.isSignatureValid(org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().setProvider(Bc.provider).build(holder))) {
            throw SigningException("錢包金鑰產生的憑證簽章無效")
        }
        return cert.encoded
    }

    actual fun certificateSummary(der: ByteArray): Pair<String, String>? = runCatching {
        val h = X509CertificateHolder(der)
        val cn = h.subject.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.CN).firstOrNull()?.first?.value?.toString() ?: h.subject.toString()
        cn to h.serialNumber.toString(16)
    }.getOrNull()
}
