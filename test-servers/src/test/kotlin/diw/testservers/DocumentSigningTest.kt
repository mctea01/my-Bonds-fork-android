package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.LaterChanges
import diw.wallet.core.document.SignatureFormat
import diw.wallet.core.document.pdf.PdfComposer
import diw.wallet.core.document.pdf.PdfSignOptions
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.document.sign.Timestamper
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.tsp.TimeStampRequest
import org.bouncycastle.tsp.TimeStampTokenGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.xml.crypto.dsig.XMLSignatureFactory
import javax.xml.crypto.dsig.dom.DOMValidateContext
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Signing documents with a software key and checking the result with the wallet's own inspector and the JDK. */
class DocumentSigningTest {
    // One PKI for the whole class, so samples saved by different tests share a root.
    companion object {
        private val bc = BouncyCastleProvider()
        private val now = Date()

        private fun keys(ec: Boolean): KeyPair = if (ec) KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        else KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

        private fun cert(subject: String, issuer: String, key: KeyPair, signer: PrivateKey, ca: Boolean, tsa: Boolean = false, issuerKey: java.security.PublicKey = key.public): X509CertificateHolder {
            val b = JcaX509v3CertificateBuilder(X500Name(issuer), BigInteger.valueOf(System.nanoTime()), Date(now.time - 86_400_000), Date(now.time + 86_400_000L * 365), X500Name(subject), key.public)
            val ext = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils()
            b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(key.public))
            b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuerKey))
            b.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
            b.addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature or KeyUsage.nonRepudiation))
            if (tsa) b.addExtension(Extension.extendedKeyUsage, true, ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))
            val alg = if (signer.algorithm == "RSA") "SHA256withRSA" else "SHA256withECDSA"
            return b.build(JcaContentSignerBuilder(alg).setProvider(bc).build(signer))
        }

        private val rootKey = keys(false)
        private val root = cert("CN=Document Test Root", "CN=Document Test Root", rootKey, rootKey.private, true)
        private val rsaKey = keys(false)
        private val rsaCert = cert("CN=Test Signer RSA", "CN=Document Test Root", rsaKey, rootKey.private, false, issuerKey = rootKey.public)
        private val ecKey = keys(true)
        private val ecCert = cert("CN=Test Signer EC", "CN=Document Test Root", ecKey, rootKey.private, false, issuerKey = rootKey.public)
        private val tsaKey = keys(false)
        private val tsaCert = cert("CN=Test TSA", "CN=Document Test Root", tsaKey, rootKey.private, false, tsa = true, issuerKey = rootKey.public)
    }

    private fun signer(ec: Boolean) = object : DocumentSigner {
        override val certificateChain = listOf(if (ec) ecCert.encoded else rsaCert.encoded)
        override val keyType = if (ec) SignerKeyType.EC_P256 else SignerKeyType.RSA
        override val source = SignerSource.PKCS12
        override suspend fun sign(data: ByteArray): ByteArray = Signature.getInstance(if (ec) "SHA256withECDSA" else "SHA256withRSA").run {
            initSign(if (ec) ecKey.private else rsaKey.private); update(data); sign()
        }
    }

    /** A local RFC 3161 authority. */
    private val timestamper = Timestamper { data ->
        val req = TimeStampRequest(DocumentInspector.timestampRequest(data))
        val gen = TimeStampTokenGenerator(
            JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().setProvider(bc).build())
                .build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(tsaKey.private), tsaCert),
            JcaDigestCalculatorProviderBuilder().setProvider(bc).build().get(org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1)),
            org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4.1"),
        )
        gen.addCertificates(org.bouncycastle.cert.jcajce.JcaCertStore(listOf(tsaCert)))
        gen.generate(req, BigInteger.ONE, Date()).encoded
    }

    private val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
    private val trust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: kotlin.time.Instant): TrustDecision = registry.decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
    }

    private suspend fun trustRoot() {
        save("root.cer", root.encoded)
        save("tsa.cer", tsaCert.encoded)
        for (role in listOf(TrustRole.DOCUMENT, TrustRole.TSA)) {
            registry.addAnchor(role, TrustEnvironment.USER, X509Cert(ByteString(root.encoded)), "Document Test Root", official = false, source = "test")
        }
    }

    private fun save(name: String, bytes: ByteArray) {
        System.getenv("DIW_SIGNED_OUT")?.let { dir -> File(dir).apply { mkdirs() }.resolve(name).writeBytes(bytes) }
    }

    private fun composed() = PdfComposer.compose(
        "測試證書",
        listOf(PdfComposer.Block.Heading("測試證書 Test"), PdfComposer.Block.Field("姓名", "王小明"), PdfComposer.Block.Paragraph("這是一份由錢包產生的文件。".repeat(20))),
        listOf(PdfComposer.Attachment("credential.json", "application/json", "{\"a\":1}".toByteArray(), "可驗證憑證")),
    )

    @Test
    fun padesOnComposedAndSignedPdfs() = runBlocking<Unit> {
        trustRoot()
        val pdf = composed()
        val unsigned = DocumentInspector.inspect(pdf, "c.pdf", trust)
        assertEquals(DocumentVerdict.UNSIGNED, unsigned.verdict)
        assertEquals(1, unsigned.pages)

        val signed = DocumentSigning.signPdf(pdf, signer(false), PdfSignOptions(reason = "測試簽署", location = "台北"), timestamper)
        save("pades-rsa.pdf", signed)
        val r = DocumentInspector.inspect(signed, "s.pdf", trust)
        val s = r.signatures.single()
        assertEquals(SignatureFormat.PADES, s.format)
        assertEquals(Check.PASS, s.integrity, s.problems.toString())
        assertEquals(true, s.coversWholeDocument)
        assertEquals("測試簽署", s.reason)
        assertTrue(s.timestamp?.trusted == true, s.timestamp.toString())
        assertEquals(TrustTier.T3, s.trust?.decision()?.tier)
        assertEquals(DocumentVerdict.VALID, r.verdict, s.problems.toString() + s.notes)

        // A second signature (EC) keeps the first one valid.
        val twice = DocumentSigning.signPdf(signed, signer(true), PdfSignOptions(), null)
        save("pades-twice.pdf", twice)
        val r2 = DocumentInspector.inspect(twice, "t.pdf", trust)
        assertEquals(2, r2.signatures.size)
        assertTrue(r2.signatures.all { it.integrity == Check.PASS }, r2.signatures.map { it.problems }.toString())
        assertEquals(LaterChanges.SIGNATURES_ONLY, r2.signatures.first().laterChanges, r2.signatures.first().problems.toString())

        // Changing a byte inside the signed range breaks the signature.
        val tampered = twice.copyOf().also { val i = String(it, Charsets.ISO_8859_1).indexOf("/Producer"); it[i + 1] = 'p'.code.toByte() }
        assertEquals(DocumentVerdict.INVALID, DocumentInspector.inspect(tampered, "x.pdf", trust).verdict)
    }

    @Test
    fun padesOnXrefStreamPdf() = runBlocking<Unit> {
        // A minimal PDF whose cross-reference data is a stream (PDF 1.5).
        val sb = StringBuilder("%PDF-1.5\n")
        val offsets = IntArray(5)
        fun obj(n: Int, body: String) { offsets[n] = sb.length; sb.append("$n 0 obj\n$body\nendobj\n") }
        obj(1, "<</Type /Catalog /Pages 2 0 R>>")
        obj(2, "<</Type /Pages /Kids [3 0 R] /Count 1>>")
        obj(3, "<</Type /Page /Parent 2 0 R /MediaBox [0 0 200 200]>>")
        val xrefAt = sb.length
        offsets[4] = xrefAt
        val rows = ArrayList<Byte>()
        rows.addAll(listOf(0, 0, 0, 0xFF.toByte()))
        for (n in 1..4) { rows.add(1); rows.add((offsets[n] shr 8).toByte()); rows.add(offsets[n].toByte()); rows.add(0) }
        val data = rows.toByteArray()
        val head = "4 0 obj\n<</Type /XRef /Size 5 /W [1 2 1] /Root 1 0 R /Length ${data.size}>>\nstream\n"
        val bytes = (sb.toString() + head).toByteArray(Charsets.ISO_8859_1) + data + "\nendstream\nendobj\nstartxref\n$xrefAt\n%%EOF\n".toByteArray()
        val signed = DocumentSigning.signPdf(bytes, signer(true), PdfSignOptions(), null)
        save("pades-xrefstream.pdf", signed)
        val r = DocumentInspector.inspect(signed, "x.pdf", trust)
        assertEquals(Check.PASS, r.signatures.single().integrity, r.signatures.single().problems.toString())
        assertEquals(true, r.signatures.single().coversWholeDocument)
    }

    @Test
    fun refusesEncryptedOrCertifiedNoChanges() = runBlocking<Unit> {
        val encrypted = "%PDF-1.4\n1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type /Pages /Kids [] /Count 0>>\nendobj\n3 0 obj\n<</Filter /Standard /V 1 /R 2 /O <00> /U <00> /P -4>>\nendobj\n"
        val xref = encrypted.length
        val pdf = (encrypted + "xref\n0 4\n0000000000 65535 f\r\n" + listOf(9, 59, 112).joinToString("") { it.toString().padStart(10, '0') + " 00000 n\r\n" } +
            "trailer\n<</Size 4 /Root 1 0 R /Encrypt 3 0 R /ID [<00> <00>]>>\nstartxref\n$xref\n%%EOF\n").toByteArray()
        assertFailsWith<SigningException> { DocumentSigning.signPdf(pdf, signer(false), PdfSignOptions(), null) }
    }

    @Test
    fun cadesAndAsic() = runBlocking<Unit> {
        trustRoot()
        val content = "內容 content".toByteArray()
        val p7s = DocumentSigning.signCades(content, signer(false), detached = true, timestamper = timestamper)
        save("detached.p7s", p7s)
        save("detached.bin", content)
        val r = DocumentInspector.inspect(p7s, "a.p7s", trust, content)
        assertEquals(Check.PASS, r.signatures.single().integrity, r.signatures.single().problems.toString())
        assertEquals(Check.PASS, r.signatures.single().timestamp?.imprint)
        val wrong = DocumentInspector.inspect(p7s, "a.p7s", trust, "other".toByteArray())
        assertEquals(Check.FAIL, wrong.signatures.single().integrity)

        val p7m = DocumentSigning.signCades(content, signer(true), detached = false, timestamper = null)
        save("enveloping.p7m", p7m)
        assertTrue(DocumentInspector.encapsulatedContent(p7m)!!.contentEquals(content))
        assertEquals(DocumentVerdict.VALID, DocumentInspector.inspect(p7m, "a.p7m", trust).verdict)

        val asic = DocumentSigning.buildAsic(listOf("文件.pdf" to composed(), "data.json" to "{}".toByteArray()), signer(false), timestamper)
        save("container.asice", asic)
        val ra = DocumentInspector.inspect(asic, "c.asice", trust)
        assertEquals(DocumentFormat.ASIC_E, ra.format)
        val sa = ra.signatures.single()
        assertEquals(Check.PASS, sa.integrity, sa.problems.toString())
        assertEquals(true, sa.coversWholeDocument)
        assertEquals(2, ra.entries.size)
    }

    @Test
    fun xadesEnvelopedVerifiesWithJdk() = runBlocking<Unit> {
        trustRoot()
        val xml = """<?xml version="1.0" encoding="UTF-8"?>
<函 xmlns:x="urn:example"><發文機關><全銜>測試機關</全銜></發文機關><主旨><文字>測試 &amp; 簽章</文字></主旨>
  <x:附註 x:屬性="值">註</x:附註>
</函>
""".toByteArray()
        for (ec in listOf(false, true)) {
            val signed = DocumentSigning.signXml(xml, signer(ec), if (ec) null else timestamper)
            save(if (ec) "xades-ec.xml" else "xades-rsa.xml", signed)
            val r = DocumentInspector.inspect(signed, "d.di", trust)
            val s = r.signatures.single()
            assertEquals(SignatureFormat.XADES, s.format)
            assertEquals(Check.PASS, s.integrity, s.problems.toString())
            assertEquals(true, s.coversWholeDocument)
            assertTrue(r.notes.any { it.contains("電子公文") })
            if (!ec) assertEquals(Check.PASS, s.timestamp?.imprint)

            // The JDK's own XML signature implementation agrees.
            val f = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            val doc = f.newDocumentBuilder().parse(signed.inputStream())
            val sigEl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0) as org.w3c.dom.Element
            val props = doc.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties").item(0) as org.w3c.dom.Element
            props.setIdAttribute("Id", true)
            val ctx = DOMValidateContext(if (ec) ecKey.public else rsaKey.public, sigEl)
            val sig = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(ctx)
            assertTrue(sig.validate(ctx), "JDK rejects the signature")

            val tampered = String(signed).replace("測試機關", "其他機關").toByteArray()
            assertEquals(Check.FAIL, DocumentInspector.inspect(tampered, "d.di", trust).signatures.single().integrity)
        }
    }

    @Test
    fun officialLetterSignedWithXades() = runBlocking<Unit> {
        trustRoot()
        val letter = diw.wallet.core.document.official.OfficialLetter(
            sender = "測試機關", senderCode = "A00000000", recipient = "王小明", subject = "檢送測試文件 <請查照>",
            explanations = List(12) { "說明第 ${it + 1} 項" }, wordPrefix = "測字", serial = "1150000001",
            date = kotlin.time.Instant.parse("2026-10-11T04:00:00Z"),
        )
        assertEquals("中華民國115年10月11日", letter.rocDate().second)
        val xml = letter.toXml()
        assertTrue(String(xml).contains("序號=\"十二、\""))
        val signed = DocumentSigning.signXml(xml, signer(false), timestamper)
        save("letter.di", signed)
        val r = DocumentInspector.inspect(signed, "letter.di", trust)
        assertEquals("檢送測試文件 <請查照>", r.title)
        assertTrue(r.notes.any { it.contains("函") })
        assertEquals(DocumentVerdict.VALID, r.signatures.single().verdict, r.signatures.single().problems.toString())
    }

    @Test
    fun selfIssuedCertificate() = runBlocking<Unit> {
        val k = keys(true)
        val der = DocumentSigning.selfIssuedCertificate(k.public.encoded, "王小明", { data ->
            Signature.getInstance("SHA256withECDSA").run { initSign(k.private); update(data); sign() }
        }, SignerKeyType.EC_P256, 365)
        val (cn, _) = DocumentSigning.certificateSummary(der)!!
        assertEquals("王小明", cn)
        val signer = object : DocumentSigner {
            override val certificateChain = listOf(der)
            override val keyType = SignerKeyType.EC_P256
            override val source = SignerSource.WALLET
            override suspend fun sign(data: ByteArray) = Signature.getInstance("SHA256withECDSA").run { initSign(k.private); update(data); sign() }
        }
        val signed = DocumentSigning.signPdf(composed(), signer, PdfSignOptions(), null)
        val s = DocumentInspector.inspect(signed, "w.pdf", trust).signatures.single()
        assertEquals(Check.PASS, s.integrity)
        // A self-issued certificate is not an anchor: integrity holds, identity is not established.
        assertEquals(DocumentVerdict.PARTIAL, s.verdict)
        // A key that does not match the certificate is caught before anything is written.
        val mismatched = object : DocumentSigner by signer {
            override suspend fun sign(data: ByteArray) = Signature.getInstance("SHA256withECDSA").run { initSign(ecKey.private); update(data); sign() }
        }
        assertFailsWith<SigningException> { DocumentSigning.signPdf(composed(), mismatched, PdfSignOptions(), null) }
    }
}
