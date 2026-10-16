package diw.wallet.core.document.sign

import diw.wallet.core.document.ApprovalSignatures
import diw.wallet.core.document.Asic
import diw.wallet.core.document.Bc
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.GmSignedData
import diw.wallet.core.document.XmlDsig
import diw.wallet.core.document.Zip
import diw.wallet.core.document.official.ApprovalPoint
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
    suspend fun cms(content: ByteArray, signer: DocumentSigner, encapsulate: Boolean, pades: Boolean, timestamper: Timestamper?, validation: HttpFetch? = null): ByteArray {
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
        val token = timestamper?.timestamp(signature)
        val unsigned = token?.let { DERSet(Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, DERSet(Bc.parse(it)))) }
        // CAdES baseline LT: the chains of the signer and the time-stamp authority with their revocation data go in
        // SignedData.certificates and SignedData.crls (OCSP as other revocation info), outside the signed attributes.
        val lt = validation?.let { f -> collectValidation(signer.certificateChain, f).plus(token?.let { timestampValidation(it, f) } ?: ValidationData()) }
        val si = SignerInfo(
            SignerIdentifier(IssuerAndSerialNumber(leaf.toASN1Structure())),
            SHA256,
            signedAttrs,
            if (signer.keyType == SignerKeyType.RSA) RSA_SHA256 else ECDSA_SHA256,
            DEROctetString(signature),
            unsigned,
        )
        val certDers = (chain.map { it.encoded } + lt?.certificates.orEmpty().map { java.util.Base64.getDecoder().decode(it) }).distinctBy { it.contentHashCode() }
        val certs = ASN1EncodableVector().apply { certDers.forEach { add(Certificate.getInstance(it)) } }
        val revocation = lt?.takeIf { !it.empty }?.let { v ->
            ASN1EncodableVector().apply {
                v.crls.forEach { add(org.bouncycastle.asn1.x509.CertificateList.getInstance(java.util.Base64.getDecoder().decode(it))) }
                v.ocsps.forEach {
                    add(org.bouncycastle.asn1.DERTaggedObject(false, 1, org.bouncycastle.asn1.cms.OtherRevocationInfoFormat(
                        org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response,
                        org.bouncycastle.asn1.ocsp.OCSPResponse.getInstance(java.util.Base64.getDecoder().decode(it)),
                    )))
                }
            }.let { DERSet(it) }
        }
        val sd = SignedData(
            DERSet(SHA256),
            ContentInfo(CMSObjectIdentifiers.data, if (encapsulate) BEROctetString(content) else null),
            DERSet(certs),
            revocation as ASN1Set?,
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
        var out = prepared.finish(cms)
        // B-LT: the signer's and the time-stamp authority's chains with OCSP responses or CRLs in the DSS.
        options.validation?.let { fetch ->
            val token = signatureTimestamp(cms)
            val v = collectValidation(signer.certificateChain, fetch).plus(token?.let { timestampValidation(it, fetch) } ?: ValidationData())
            if (v.empty && options.requireValidation) throw SigningException("取不到撤銷資訊（OCSP 與 CRL 都無法取得）：" + v.summary())
            val dec = java.util.Base64.getDecoder()
            out = PdfIncrementalSigner.addValidationData(
                out, v.certificates.map { dec.decode(it) }, v.ocsps.map { dec.decode(it) }, v.crls.map { dec.decode(it) },
                listOf(DocCryptoUtil.hex(DocCrypto.digest("SHA-1", cms)).uppercase()),
            )
        }
        // B-LTA: a document time stamp over everything, the validation data included.
        if (options.documentTimestamp) {
            val ts = timestamper ?: throw SigningException("B-LTA 需要時戳機構")
            val docTs = PdfIncrementalSigner.prepare(out, PdfSignOptions(subFilter = "ETSI.RFC3161", reserve = 20 * 1024, allowBreakingCertification = options.allowBreakingCertification))
            out = docTs.finish(ts.timestamp(docTs.signedData()))
        }
        return out
    }

    actual suspend fun signCades(content: ByteArray, signer: DocumentSigner, detached: Boolean, timestamper: Timestamper?, validation: HttpFetch?): ByteArray =
        cms(content, signer, encapsulate = !detached, pades = false, timestamper = timestamper, validation = validation)

    actual suspend fun collectValidation(chain: List<ByteArray>, fetch: HttpFetch, known: List<ByteArray>): ValidationData =
        ValidationCollector.collect(chain, fetch, known)

    actual suspend fun timestampValidation(token: ByteArray, fetch: HttpFetch, known: List<ByteArray>): ValidationData {
        val chain = timestampChain(token)
        if (chain.isEmpty()) return ValidationData(statuses = listOf(RevocationStatus("時戳機構", "NONE", "UNAVAILABLE", "時戳沒有附上時戳機構的憑證")))
        return ValidationCollector.collect(chain, fetch, known)
    }

    /** The certificates of a time-stamp token, the time-stamp authority's own first. */
    private fun timestampChain(token: ByteArray): List<ByteArray> = runCatching {
        // A token, or a whole time-stamp response holding one.
        val cms = runCatching { CMSSignedData(token) }.getOrElse { CMSSignedData(DocumentInspector.timestampToken(token)) }
        val tst = org.bouncycastle.tsp.TimeStampToken(cms)
        @Suppress("UNCHECKED_CAST")
        val certs = tst.certificates.getMatches(null).toList() as List<X509CertificateHolder>
        val own = certs.firstOrNull { tst.sid.match(it) }
        (listOfNotNull(own) + certs.filter { it != own }).map { it.encoded }
    }.getOrDefault(emptyList())

    /** The signature time-stamp token of a CMS signature, when it has one. */
    private fun signatureTimestamp(cms: ByteArray): ByteArray? = runCatching {
        val si = CMSSignedData(cms).signerInfos.signers.first()
        si.unsignedAttributes?.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)?.attrValues?.getObjectAt(0)?.toASN1Primitive()?.encoded
    }.getOrNull()

    actual suspend fun buildAsic(files: List<Pair<String, ByteArray>>, signer: DocumentSigner, timestamper: Timestamper?, validation: HttpFetch?): ByteArray {
        require(files.isNotEmpty())
        val names = files.map { it.first }
        if (names.toSet().size != names.size || names.any { it.startsWith("META-INF/") || it == "mimetype" || it.contains("..") }) {
            throw SigningException("檔名重複或不合法")
        }
        val sigPath = "META-INF/signature001.p7s"
        val manifest = Asic.manifest(files, sigPath)
        val signature = cms(manifest, signer, encapsulate = false, pades = false, timestamper = timestamper, validation = validation)
        val entries = ArrayList<Pair<String, ByteArray>>()
        entries.add("mimetype" to Asic.MIME_E.encodeToByteArray())
        entries.addAll(files)
        entries.add("META-INF/ASiCManifest001.xml" to manifest)
        entries.add(sigPath to signature)
        return Zip.write(entries, stored = setOf("mimetype"))
    }

    actual suspend fun signXml(xml: ByteArray, signer: DocumentSigner, timestamper: Timestamper?, validation: HttpFetch?): ByteArray =
        XmlDsig.signEnveloped(
            xml, signer, Clock.System.now(), timestamper?.let { t -> { data: ByteArray -> t.timestamp(data) } },
            validation?.let { f -> { token: ByteArray? -> collectValidation(signer.certificateChain, f).plus(token?.let { timestampValidation(it, f) } ?: ValidationData()) } },
        )

    actual suspend fun signApproval(approval: ByteArray?, files: List<Pair<String, ByteArray>>, signer: DocumentSigner, point: ApprovalPoint): ByteArray =
        ApprovalSignatures.sign(approval, files, signer, point)

    actual fun unzip(bytes: ByteArray): Map<String, ByteArray> = Zip.read(bytes)

    actual fun zip(files: List<Pair<String, ByteArray>>): ByteArray = Zip.write(files)

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
