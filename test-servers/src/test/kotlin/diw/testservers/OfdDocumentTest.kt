package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.SignatureFormat
import diw.wallet.core.document.derived.ChinaInvoice
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.ofd.OfdObject
import diw.wallet.core.document.ofd.OfdPackage
import diw.wallet.core.document.ofd.OfdPathCommand
import diw.wallet.core.document.ofd.OfdText
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.document.sign.Timestamper
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.LocalDate
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.tsp.TimeStampRequest
import org.bouncycastle.tsp.TimeStampTokenGenerator
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** OFD content (pages, text, custom tags, seals), the invoice read from it, and OFD digital signatures the wallet makes. */
class OfdDocumentTest {
    private val bc = BouncyCastleProvider()
    private val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
    private val trust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: kotlin.time.Instant): TrustDecision = registry.decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
    }

    private fun sample(name: String) = javaClass.getResourceAsStream("/documents/$name")!!.readBytes()

    private fun zip(vararg files: Pair<String, String>) = DocumentSigning.zip(files.map { it.first to it.second.encodeToByteArray() })

    private val ns = "xmlns:ofd=\"http://www.ofdspec.org/2016\""

    /**
     * A synthetic invoice in the layout of a mainland China electronic invoice (buyer and seller side by side), with
     * an eInvoice custom tag file written with an empty prefix as some producers do. All values are made up.
     */
    private fun invoice(withTags: Boolean): ByteArray {
        fun text(id: Int, x: Double, y: Double, s: String, size: Double = 3.175) =
            "<ofd:TextObject ID=\"$id\" Boundary=\"$x $y 120 5\" Font=\"1\" Size=\"$size\"><ofd:FillColor Value=\"0 0 0\"/>" +
                "<ofd:TextCode X=\"0\" Y=\"3\" DeltaX=\"g ${s.length - 1} $size\">$s</ofd:TextCode></ofd:TextObject>"
        val content = listOf(
            text(10, 70.0, 8.0, "电子发票（普通发票）", 7.0),
            text(11, 155.0, 11.0, "发票号码："), text(12, 171.0, 11.0, "12345678901234567890"),
            text(13, 155.0, 17.0, "开票日期："), text(14, 171.0, 17.0, "2026年01月02日"),
            text(15, 11.0, 34.0, "名称："), text(16, 19.0, 34.0, "测试个人（个人）"),
            text(17, 111.0, 34.0, "名称："), text(18, 119.0, 34.0, "测试销售有限公司"),
            text(19, 11.0, 44.0, "统一社会信用代码/纳税人识别号："), text(20, 111.0, 44.0, "统一社会信用代码/纳税人识别号："),
            text(21, 159.0, 44.0, "91000000MA00000000"),
            text(22, 4.0, 57.0, "*信息技术服务*软件服务费"),
            text(23, 20.0, 93.0, "合        计"), text(24, 144.0, 93.0, "¥100.00"), text(25, 190.0, 93.0, "¥6.00"),
            text(26, 17.0, 99.0, "价税合计（大写）"), text(27, 61.0, 99.0, "壹佰零陆圆整"), text(28, 141.0, 99.0, "（小写）"), text(29, 154.0, 99.0, "¥106.00"),
            text(30, 20.0, 130.0, "开票人:"), text(31, 32.0, 130.0, "测试开票员"),
            "<ofd:PathObject ID=\"40\" Boundary=\"10 120 20 20\" Fill=\"true\"><ofd:FillColor Value=\"200 0 0\"/>" +
                "<ofd:AbbreviatedData>M 0 10 A 10 10 0 0 1 20 10 L 0 10 C</ofd:AbbreviatedData></ofd:PathObject>",
        ).joinToString("")
        val tags = """<?xml version="1.0" encoding="UTF-8"?><:eInvoice xmlns:="http://www.edrm.org.cn/schema/e-invoice/2019" xmlns:ofd="http://www.ofdspec.org/2016">""" +
            "<:InvoiceNo><ofd:ObjectRef PageRef=\"1\">12</ofd:ObjectRef></:InvoiceNo><:IssueDate><ofd:ObjectRef PageRef=\"1\">14</ofd:ObjectRef></:IssueDate>" +
            "<:Buyer><:BuyerName><ofd:ObjectRef PageRef=\"1\">16</ofd:ObjectRef></:BuyerName></:Buyer>" +
            "<:Seller><:SellerName><ofd:ObjectRef PageRef=\"1\">18</ofd:ObjectRef></:SellerName><:SellerTaxID><ofd:ObjectRef PageRef=\"1\">21</ofd:ObjectRef></:SellerTaxID></:Seller>" +
            "<:TaxInclusiveTotalAmount><ofd:ObjectRef PageRef=\"1\">29</ofd:ObjectRef></:TaxInclusiveTotalAmount><:Note>ignored</:Note></:eInvoice>"
        val doc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ofd:Document $ns><ofd:CommonData><ofd:MaxUnitID>50</ofd:MaxUnitID>" +
            "<ofd:PageArea><ofd:PhysicalBox>0 0 210 140</ofd:PhysicalBox></ofd:PageArea><ofd:PublicRes>PublicRes.xml</ofd:PublicRes></ofd:CommonData>" +
            "<ofd:Pages><ofd:Page ID=\"1\" BaseLoc=\"Pages/Page_0/Content.xml\"/></ofd:Pages>" +
            (if (withTags) "<ofd:CustomTags>Tags/CustomTags.xml</ofd:CustomTags>" else "") + "</ofd:Document>"
        val files = mutableListOf(
            "OFD.xml" to "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ofd:OFD $ns Version=\"1.0\" DocType=\"OFD\"><ofd:DocBody><ofd:DocInfo><ofd:DocID>test</ofd:DocID></ofd:DocInfo><ofd:DocRoot>Doc_0/Document.xml</ofd:DocRoot></ofd:DocBody></ofd:OFD>",
            "Doc_0/Document.xml" to doc,
            "Doc_0/PublicRes.xml" to "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ofd:Res $ns BaseLoc=\"Res\"><ofd:Fonts><ofd:Font ID=\"1\" FontName=\"SimSun\" FamilyName=\"SimSun\"/></ofd:Fonts></ofd:Res>",
            "Doc_0/Pages/Page_0/Content.xml" to "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ofd:Page $ns><ofd:Content><ofd:Layer ID=\"2\">$content</ofd:Layer></ofd:Content></ofd:Page>",
        )
        if (withTags) {
            files.add("Doc_0/Tags/CustomTags.xml" to "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ofd:CustomTags $ns><ofd:CustomTag NameSpace=\"http://www.edrm.org.cn/schema/e-invoice/2019\"><ofd:FileLoc>CustomTag.xml</ofd:FileLoc></ofd:CustomTag></ofd:CustomTags>")
            files.add("Doc_0/Tags/CustomTag.xml" to tags)
        }
        return zip(*files.toTypedArray())
    }

    private fun pkg(bytes: ByteArray) = assertNotNull(OfdPackage.read(DocumentSigning.unzip(bytes)))

    @Test
    fun readsPagesTextAndSeal() = runBlocking<Unit> {
        val bytes = sample("signed-sesv4.ofd")
        val p = pkg(bytes)
        assertEquals(1, p.pageCount)
        val text = OfdText.extract(p)
        assertTrue("Wallet PoC OFD 测试文档 / test document" in text, text)
        assertTrue("金额: 100 元" in text, text)

        val stamps = DocumentInspector.ofdStamps(bytes)
        assertEquals(1, stamps.size)
        assertNotNull(stamps.single().picture)
        val r = DocumentInspector.inspect(bytes, "signed-sesv4.ofd", trust)
        assertEquals(DocumentFormat.OFD, r.format)
        val placement = r.signaturePlacements.single()
        assertEquals(r.signatures.single().label, placement.label)
        assertTrue(placement.x1 > placement.x0 && placement.y1 > placement.y0, placement.toString())
        assertTrue(r.signatures.single().notes.any { "GB/T 38540" in it }, r.signatures.single().notes.toString())
    }

    @Test
    fun readsInvoiceFromTagsAndText() {
        val tagged = pkg(invoice(withTags = true))
        val tags = tagged.documents.single().tagValues()
        assertEquals("12345678901234567890", tags["InvoiceNo"])
        assertEquals("测试销售有限公司", tags["SellerName"])
        assertEquals(null, tags["Note"]?.takeIf { it != "ignored" })

        val text = OfdText.extract(tagged)
        val fromTags = assertNotNull(ChinaInvoice.parse(text, tags))
        val fromText = assertNotNull(ChinaInvoice.parse(OfdText.extract(pkg(invoice(withTags = false)))))
        for (inv in listOf(fromTags, fromText)) {
            assertEquals("电子发票（普通发票）", inv.kind)
            assertEquals("12345678901234567890", inv.number)
            assertEquals(LocalDate(2026, 1, 2), inv.issueDate)
            assertEquals("测试销售有限公司", inv.sellerName)
            assertEquals("91000000MA00000000", inv.sellerTaxId)
            assertEquals(null, inv.buyerTaxId)
            assertEquals("106.00", inv.total)
            assertEquals("测试开票员", inv.issuedBy)
        }
        assertTrue(fromText.buyerName!!.startsWith("测试个人"), fromText.buyerName)
        assertEquals("100.00", fromText.amount)
        assertEquals("6.00", fromText.tax)
        assertEquals("壹佰零陆圆整", fromText.totalInWords)
        assertEquals(listOf("*信息技术服务*软件服务费"), fromText.items)

        // The derived credential carries the invoice's fields.
        val report = diw.wallet.core.document.DocumentReport(DocumentFormat.OFD, "", 0, checkedAt = 0)
        val claims = DerivedCredentials.suggested(report, "invoice.ofd", null, text, structured = fromTags).claims.associate { it.name to it.value }
        assertEquals("12345678901234567890", claims["invoiceNumber"])
        assertEquals("106.00", claims["totalAmount"])
    }

    @Test
    fun parsesPathsWithArcs() {
        val page = pkg(invoice(withTags = false)).pages.single()
        val path = page.objects.filterIsInstance<OfdObject.Path>().single()
        assertTrue(path.commands.first() is OfdPathCommand.Move)
        val cubics = path.commands.filterIsInstance<OfdPathCommand.Cubic>()
        assertTrue(cubics.size >= 2, path.commands.toString())
        assertEquals(20.0, cubics.last().x, 1e-9)
        assertEquals(10.0, cubics.last().y, 1e-9)
        // A half circle over the chord from (0,10) to (20,10) bulges up to y = 0.
        val top = cubics.first()
        assertEquals(10.0, top.x, 1e-6)
        assertEquals(0.0, top.y, 1e-6)
        assertEquals(OfdPathCommand.Close, path.commands.last())
        assertEquals(10.0, path.matrix.e, 1e-9)
    }

    private fun sm2Signer(): DocumentSigner {
        val p12 = DocumentSigning.sm2Pkcs12("OFD Test SM2", "secret1", 30)
        return DocumentSigning.pkcs12Signer(p12, "secret1")
    }

    private val tsaKey = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val tsaCert = JcaX509v3CertificateBuilder(
        X500Name("CN=OFD Test TSA"), BigInteger.TEN, Date(System.currentTimeMillis() - 86_400_000), Date(System.currentTimeMillis() + 86_400_000L * 30),
        X500Name("CN=OFD Test TSA"), tsaKey.public,
    ).addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        .addExtension(Extension.extendedKeyUsage, true, ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))
        .build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(tsaKey.private))

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

    @Test
    fun signsWithSm2AndKeepsEarlierSignatures() = runBlocking<Unit> {
        val signer = sm2Signer()
        assertEquals(SignerKeyType.SM2, signer.keyType)
        val once = DocumentSigning.signOfd(sample("unsigned.ofd"), signer, timestamper)
        val r1 = DocumentInspector.inspect(once, "signed.ofd", trust)
        val s1 = r1.signatures.single()
        assertEquals(SignatureFormat.OFD_SIGN, s1.format)
        assertEquals(Check.PASS, s1.integrity, s1.problems.toString())
        assertEquals(true, s1.coversWholeDocument, s1.notes.toString())
        assertTrue(s1.notes.any { "GB/T 35275" in it }, s1.notes.toString())
        assertNotNull(s1.timestamp)
        assertEquals(Check.PASS, s1.timestamp!!.imprint, s1.timestamp.toString())

        // A second signature (and one over a sealed document) leaves the earlier ones valid.
        val twice = DocumentSigning.signOfd(once, signer, null)
        val r2 = DocumentInspector.inspect(twice, "signed2.ofd", trust)
        assertEquals(2, r2.signatures.size)
        assertTrue(r2.signatures.all { it.integrity == Check.PASS }, r2.signatures.map { it.problems }.toString())
        val overSeal = DocumentInspector.inspect(DocumentSigning.signOfd(sample("signed-sesv4.ofd"), signer, null), "s.ofd", trust)
        assertEquals(listOf(SignatureFormat.OFD_SEAL, SignatureFormat.OFD_SIGN), overSeal.signatures.map { it.format })
        assertTrue(overSeal.signatures.all { it.integrity == Check.PASS }, overSeal.signatures.map { it.problems }.toString())

        // Changing a page afterwards is caught.
        val files = LinkedHashMap(DocumentSigning.unzip(twice))
        val page = files.keys.first { it.endsWith("Content.xml") }
        files[page] = files[page]!!.decodeToString().replace("100", "900").encodeToByteArray()
        val tampered = DocumentInspector.inspect(DocumentSigning.zip(files.entries.map { it.key to it.value }), "t.ofd", trust)
        assertTrue(tampered.signatures.all { it.integrity == Check.FAIL })
        assertEquals(DocumentVerdict.INVALID, tampered.verdict)
    }

    @Test
    fun signsWithRsaAsPkcs7AndRefusesSm2Elsewhere() = runBlocking<Unit> {
        val key = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val cert = JcaX509v3CertificateBuilder(
            X500Name("CN=OFD Test RSA"), BigInteger.TWO, Date(System.currentTimeMillis() - 86_400_000), Date(System.currentTimeMillis() + 86_400_000L * 30),
            X500Name("CN=OFD Test RSA"), key.public,
        ).build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(key.private))
        val rsa = object : DocumentSigner {
            override val certificateChain = listOf(cert.encoded)
            override val keyType = SignerKeyType.RSA
            override val source = SignerSource.PKCS12
            override suspend fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withRSA").run { initSign(key.private); update(data); sign() }
        }
        val r = DocumentInspector.inspect(DocumentSigning.signOfd(sample("unsigned.ofd"), rsa, null), "rsa.ofd", trust)
        val s = r.signatures.single()
        assertEquals(Check.PASS, s.integrity, s.problems.toString())
        assertTrue(s.notes.any { "PKCS#7" in it }, s.notes.toString())

        assertFailsWith<SigningException> { DocumentSigning.signCades("x".encodeToByteArray(), sm2Signer(), true, null) }
        assertFailsWith<SigningException> { DocumentSigning.signOfd("not an ofd".encodeToByteArray(), rsa, null) }
    }
}
