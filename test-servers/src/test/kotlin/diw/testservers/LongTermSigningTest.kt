package diw.testservers

import diw.testservers.fixtures.PdfComposer
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfSignOptions
import diw.wallet.core.document.pdf.PdfSignatures
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.CleartextHttp
import diw.wallet.core.document.sign.HttpFetch
import diw.wallet.core.document.sign.SignedDataFetch
import diw.wallet.core.document.sign.SignedDataHttp
import diw.wallet.core.document.sign.SignedDataRoutes
import diw.wallet.core.document.sign.TsaClient
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.Timestamper
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AccessDescription
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.AuthorityInformationAccess
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.CRLReason
import org.bouncycastle.asn1.x509.DistributionPoint
import org.bouncycastle.asn1.x509.DistributionPointName
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v2CRLBuilder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder
import org.bouncycastle.cert.ocsp.CertificateStatus
import org.bouncycastle.cert.ocsp.OCSPReq
import org.bouncycastle.cert.ocsp.OCSPRespBuilder
import org.bouncycastle.cert.ocsp.RespID
import org.bouncycastle.cert.ocsp.RevokedStatus
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.tsp.TSPAlgorithms
import org.bouncycastle.tsp.TimeStampRequest
import org.bouncycastle.tsp.TimeStampResponseGenerator
import org.bouncycastle.tsp.TimeStampTokenGenerator
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import com.sun.net.httpserver.HttpServer
import java.math.BigInteger
import java.net.InetSocketAddress
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Long-term signatures: PAdES B-LT and B-LTA, CAdES and XAdES with validation data, and the revocation data of a
 * time-stamp authority, against a test PKI whose OCSP responder and CRL are served by a fake [HttpFetch].
 */
class LongTermSigningTest {
    companion object {
        private val bc = BouncyCastleProvider()
        private val now = Date()
        private const val OCSP = "http://ocsp.test/"
        private const val CRL = "http://crl.test/root.crl"
        private const val ROOT_URL = "http://aia.test/root.cer"

        private fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

        private val rootKey = rsa()
        private val root: X509CertificateHolder = build("CN=LT Test Root", rootKey, ca = true)

        private fun build(subject: String, key: KeyPair, ca: Boolean = false, tsa: Boolean = false, ocsp: Boolean = false): X509CertificateHolder {
            val b = JcaX509v3CertificateBuilder(X500Name("CN=LT Test Root"), BigInteger.valueOf(System.nanoTime()), Date(now.time - 86_400_000), Date(now.time + 86_400_000L * 365), X500Name(subject), key.public)
            val ext = JcaX509ExtensionUtils()
            b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(key.public))
            b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(rootKey.public))
            b.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
            b.addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature or KeyUsage.nonRepudiation))
            if (tsa) b.addExtension(Extension.extendedKeyUsage, true, ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))
            if (!ca) {
                val access = listOfNotNull(
                    AccessDescription(AccessDescription.id_ad_caIssuers, GeneralName(GeneralName.uniformResourceIdentifier, ROOT_URL)),
                    if (ocsp) AccessDescription(AccessDescription.id_ad_ocsp, GeneralName(GeneralName.uniformResourceIdentifier, OCSP)) else null,
                )
                b.addExtension(Extension.authorityInfoAccess, false, AuthorityInformationAccess(access.toTypedArray()))
                b.addExtension(Extension.cRLDistributionPoints, false, CRLDistPoint(arrayOf(DistributionPoint(
                    DistributionPointName(GeneralNames(GeneralName(GeneralName.uniformResourceIdentifier, CRL))), null, null,
                ))))
            }
            return b.build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(rootKey.private))
        }

        private val signerKey = rsa()
        private val signerCert = build("CN=LT Test Signer", signerKey, ocsp = true)
        private val revokedKey = rsa()
        private val revokedCert = build("CN=LT Revoked Signer", revokedKey, ocsp = true)
        // The authority has no OCSP responder, so its status comes from the CRL.
        private val tsaKey = rsa()
        private val tsaCert = build("CN=LT Test TSA", tsaKey, tsa = true)
    }

    private val requests = ArrayList<String>()

    private val fetch = HttpFetch { url, body, _ ->
        requests.add(url)
        when {
            url == OCSP && body != null -> {
                val req = OCSPReq(body)
                val b = BasicOCSPRespBuilder(RespID(root.subject))
                for (r in req.requestList) {
                    b.addResponse(r.certID, if (r.certID.serialNumber == revokedCert.serialNumber) RevokedStatus(Date(now.time - 3_600_000), CRLReason.keyCompromise) else CertificateStatus.GOOD)
                }
                val basic = b.build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(rootKey.private), arrayOf(root), Date())
                OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).encoded
            }
            url == CRL -> X509v2CRLBuilder(root.subject, Date()).apply {
                setNextUpdate(Date(now.time + 86_400_000))
                addCRLEntry(revokedCert.serialNumber, Date(now.time - 3_600_000), CRLReason.keyCompromise)
            }.build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(rootKey.private)).encoded
            url == ROOT_URL -> root.encoded
            else -> null
        }
    }

    private fun signer(revoked: Boolean = false) = object : DocumentSigner {
        override val certificateChain = listOf(if (revoked) revokedCert.encoded else signerCert.encoded)
        override val keyType = SignerKeyType.RSA
        override val source = SignerSource.PKCS12
        override suspend fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withRSA").run {
            initSign(if (revoked) revokedKey.private else signerKey.private); update(data); sign()
        }
    }

    private fun tokenGenerator() = TimeStampTokenGenerator(
        JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().setProvider(bc).build())
            .build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(tsaKey.private), tsaCert),
        JcaDigestCalculatorProviderBuilder().setProvider(bc).build().get(AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)),
        ASN1ObjectIdentifier("1.2.3.4.2"),
    ).apply { addCertificates(JcaCertStore(listOf(tsaCert))) }

    /** What an RFC 3161 server answers to [request]: a TimeStampResp with a granted token. */
    private fun tsaResponse(request: ByteArray): ByteArray =
        TimeStampResponseGenerator(tokenGenerator(), TSPAlgorithms.ALLOWED).generate(TimeStampRequest(request), BigInteger.valueOf(System.nanoTime()), Date()).encoded

    private val timestamper = Timestamper { data ->
        val req = TimeStampRequest(DocumentInspector.timestampRequest(data))
        val gen = TimeStampTokenGenerator(
            JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().setProvider(bc).build())
                .build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(tsaKey.private), tsaCert),
            JcaDigestCalculatorProviderBuilder().setProvider(bc).build().get(AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)),
            ASN1ObjectIdentifier("1.2.3.4.2"),
        )
        gen.addCertificates(JcaCertStore(listOf(tsaCert)))
        gen.generate(req, BigInteger.valueOf(System.nanoTime()), Date()).encoded
    }

    private val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
    private val trust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: kotlin.time.Instant): TrustDecision = registry.decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
    }

    private suspend fun trustRoot() {
        for (role in listOf(TrustRole.DOCUMENT, TrustRole.TSA)) {
            registry.addAnchor(role, TrustEnvironment.USER, X509Cert(ByteString(root.encoded)), "LT Test Root", official = false, source = "test")
        }
    }

    private fun pdf() = PdfComposer.compose("長期驗證測試", listOf(PdfComposer.Block.Heading("長期驗證"), PdfComposer.Block.Paragraph("內容")), emptyList())

    @Test
    fun padesLongTermLevels() = runBlocking<Unit> {
        trustRoot()
        val lt = DocumentSigning.signPdf(pdf(), signer(), PdfSignOptions(validation = fetch, requireValidation = true), timestamper)
        val dss = PdfSignatures(PdfFile(lt)).dss()!!
        assertEquals(1, dss.ocsps.size, "the signer by OCSP")
        assertEquals(1, dss.crls.size, "the authority by CRL")
        assertTrue(dss.certificates.size >= 3, "signer, authority and root")
        assertTrue(OCSP in requests && CRL in requests && ROOT_URL in requests, requests.toString())
        val r = DocumentInspector.inspect(lt, "lt.pdf", trust)
        assertTrue("PAdES 等級：B-LT" in r.notes, r.notes.toString())
        val sig = r.signatures.single()
        assertEquals(DocumentVerdict.VALID, sig.verdict, sig.problems.toString())
        assertTrue(sig.revocationData, sig.notes.toString())

        val lta = DocumentSigning.signPdf(pdf(), signer(), PdfSignOptions(validation = fetch, documentTimestamp = true), timestamper)
        val r2 = DocumentInspector.inspect(lta, "lta.pdf", trust)
        assertTrue("PAdES 等級：B-LTA" in r2.notes, r2.notes.toString())
        assertEquals(2, r2.signatures.size)
        assertTrue(r2.signatures.all { it.verdict == DocumentVerdict.VALID }, r2.signatures.map { it.problems }.toString())

        // A signature by a revoked certificate is refused by the inspector with the data that came with it.
        val revoked = DocumentSigning.signPdf(pdf(), signer(revoked = true), PdfSignOptions(validation = fetch), timestamper)
        assertEquals(DocumentVerdict.INVALID, DocumentInspector.inspect(revoked, "r.pdf", trust).signatures.single().verdict)
    }

    @Test
    fun cadesAndXadesCarryValidationData() = runBlocking<Unit> {
        trustRoot()
        val content = "長期驗證內容".toByteArray()
        val p7s = DocumentSigning.signCades(content, signer(), true, timestamper, fetch)
        val sd = CMSSignedData(CMSProcessableByteArray(content), p7s)
        assertEquals(1, sd.crLs.getMatches(null).size, "the authority's CRL")
        assertEquals(1, sd.getOtherRevocationInfo(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response).getMatches(null).size, "the signer's OCSP")
        val r = DocumentInspector.inspect(p7s, "a.txt.p7s", trust, content)
        assertEquals(DocumentVerdict.VALID, r.signatures.single().verdict, r.signatures.single().problems.toString())
        assertTrue(r.signatures.single().revocationData)

        val xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><a>長期</a></doc>".toByteArray()
        val signed = DocumentSigning.signXml(xml, signer(), timestamper, fetch)
        val text = String(signed)
        assertTrue("<xades:EncapsulatedOCSPValue>" in text && "<xades:EncapsulatedCRLValue>" in text && "<xades:CertificateValues>" in text)
        val rx = DocumentInspector.inspect(signed, "a.xml", trust)
        assertEquals(DocumentVerdict.VALID, rx.signatures.single().verdict, rx.signatures.single().problems.toString())
        assertTrue(rx.signatures.single().revocationData)
    }

    @Test
    fun timestampAuthorityRevocationData() = runBlocking<Unit> {
        val token = timestamper.timestamp("文件".toByteArray())
        val v = DocumentSigning.timestampValidation(token, fetch)
        assertEquals(1, v.crls.size)
        assertTrue(v.ocsps.isEmpty())
        assertEquals(listOf("CRL" to "GOOD"), v.statuses.map { it.source to it.status })
        assertTrue(v.summary().startsWith("已保存撤銷資訊：1 份 CRL"), v.summary())
        val s = DocumentSigning.collectValidation(listOf(revokedCert.encoded), fetch)
        assertEquals(listOf("OCSP" to "REVOKED"), s.statuses.map { it.source to it.status })
    }

    /**
     * Android release builds refuse clear text in OkHttp, so time stamps, OCSP, CRLs and AIA certificates on http go
     * through CleartextHttp: a chunked RFC 3161 reply, an OCSP POST, a CRL behind a redirect and a 404 over a socket.
     */
    @Test
    fun cleartextRouteForTimeStampsAndRevocationData() = runBlocking<Unit> {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { ex ->
            val body = ex.requestBody.readBytes()
            val path = ex.requestURI.path
            val reply = when (path) {
                "/tsa" -> tsaResponse(body)
                "/ocsp/" -> runBlocking { fetch.fetch(OCSP, body, null) }
                "/root.crl" -> runBlocking { fetch.fetch(CRL, null, null) }
                "/root.cer" -> runBlocking { fetch.fetch(ROOT_URL, null, null) }
                else -> null
            }
            when {
                path == "/old.crl" -> {
                    ex.responseHeaders.add("Location", "/root.crl")
                    ex.sendResponseHeaders(302, -1)
                }
                reply == null -> ex.sendResponseHeaders(404, -1)
                // A length of 0 makes the JDK server send the reply chunked.
                path == "/tsa" -> ex.sendResponseHeaders(200, 0).also { ex.responseBody.write(reply) }
                else -> ex.sendResponseHeaders(200, reply.size.toLong()).also { ex.responseBody.write(reply) }
            }
            ex.close()
        }
        server.start()
        try {
            val base = "http://127.0.0.1:${server.address.port}"
            val http = SignedDataRoutes(SignedDataHttp { url, _, _, _ -> error("Only http is expected here: $url") }, CleartextHttp())
            val token = TsaClient(http, "$base/tsa").timestamp("文件".toByteArray())
            val info = DocumentInspector.verifyTimestamp(token, "文件".toByteArray(), trust)
            assertEquals(Check.PASS, info.imprint)
            assertEquals(Check.PASS, info.signature)
            val local = SignedDataFetch(http)
            val routed = HttpFetch { url, body, contentType ->
                local.fetch(when (url) { OCSP -> "$base/ocsp/"; CRL -> "$base/old.crl"; ROOT_URL -> "$base/root.cer"; else -> url }, body, contentType)
            }
            val v = DocumentSigning.timestampValidation(token, routed)
            assertEquals(listOf("CRL" to "GOOD"), v.statuses.map { it.source to it.status })
            val s = DocumentSigning.collectValidation(listOf(revokedCert.encoded), routed)
            assertEquals(listOf("OCSP" to "REVOKED"), s.statuses.map { it.source to it.status })
            assertEquals(404, http.exchange("$base/missing", null, null, null).status)
        } finally {
            server.stop(0)
        }
    }
}
