package diw.testservers

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.pdf.PdfComposer
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfTextExtractor
import diw.wallet.core.document.pdf.PdfPlain
import diw.wallet.core.document.pdf.PdfPasswordException
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsNationalId
import diw.wallet.core.profile.bonds.BondsNationalIdException
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.BondsOfflineVerifier
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.profile.bonds.MoicaCa
import diw.wallet.core.profile.bonds.NationalIdFields
import diw.wallet.core.profile.bonds.RocDate
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respondError
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.encryption.AccessPermission
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

/**
 * The Bonds national ID card: the MyData national ID PDF (encrypted with the ID number) is opened, its text read and
 * its fields parsed as Bonds does, then signed with the citizen certificate as a vc+moica NationalIDCredential that a
 * Bonds self-issued request ("s") accepts. The PDFs are made here with made-up data: a hand-written Identity-H font
 * with a ToUnicode CMap, and PdfComposer's Unicode CMap font, each encrypted by PDFBox with RC4 and AES.
 */
class BondsNationalIdTest {
    private val id = "A123456789"

    // ---------------------------------------------------------------- PDFs

    /** One page; each line is a list of (x, text) runs drawn at the same baseline, 20 points apart. */
    private fun identityPdf(lines: List<List<Pair<Double, String>>>): ByteArray {
        val chars = lines.flatten().flatMap { it.second.toList() }.filter { !it.isDigit() }.distinct()
        // Digits use a bfrange (codes 0x1000-0x1009); other characters one bfchar each, from code 1.
        val code = HashMap<Char, Int>()
        chars.forEachIndexed { i, c -> code[c] = i + 1 }
        ('0'..'9').forEach { code[it] = 0x1000 + (it - '0') }
        fun hex(s: String) = s.toList().joinToString("") { code.getValue(it).toString(16).padStart(4, '0') }
        val content = buildString {
            append("BT /F1 12 Tf\n")
            var y = 780.0
            lines.forEachIndexed { li, runs ->
                runs.forEachIndexed { ri, (x, text) ->
                    if (li == 1 && ri == 0) {
                        // Absolute placement and a kerned TJ for the second line.
                        append("1 0 0 1 $x $y Tm [<${hex(text.take(1))}> -20 <${hex(text.drop(1))}>] TJ\n")
                    } else {
                        append("1 0 0 1 $x $y Tm <${hex(text)}> Tj\n")
                    }
                }
                y -= 20
            }
            append("ET\n")
        }
        val cmap = buildString {
            append("/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n")
            append("/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def /CMapType 2 def\n")
            append("1 begincodespacerange <0000> <FFFF> endcodespacerange\n")
            append("${chars.size} beginbfchar\n")
            chars.forEach { c -> append("<${code.getValue(c).toString(16).padStart(4, '0')}> <${c.code.toString(16).padStart(4, '0')}>\n") }
            append("endbfchar\n1 beginbfrange\n<1000> <1009> <0030>\nendbfrange\nendcmap CMapName currentdict /CMap defineresource pop end end\n")
        }
        val objects = listOf(
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 5 0 R >> >> >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>",
            "<< /Length ${content.toByteArray().size} >>\nstream\n$content\nendstream",
            "<< /Type /Font /Subtype /Type0 /BaseFont /TestSans /Encoding /Identity-H /DescendantFonts [6 0 R] /ToUnicode 7 0 R >>",
            "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /TestSans /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 8 0 R /DW 1000 /W [4096 4105 500] >>",
            "<< /Length ${cmap.toByteArray().size} >>\nstream\n$cmap\nendstream",
            "<< /Type /FontDescriptor /FontName /TestSans /Flags 4 /FontBBox [0 -200 1000 900] /ItalicAngle 0 /Ascent 900 /Descent -200 /CapHeight 700 /StemV 80 >>",
        )
        val out = ByteArrayOutputStream()
        out.write("%PDF-1.7\n".toByteArray())
        val offsets = objects.mapIndexed { i, body ->
            val at = out.size()
            out.write("${i + 1} 0 obj\n$body\nendobj\n".toByteArray(Charsets.UTF_8))
            at
        }
        val xref = out.size()
        out.write(buildString {
            append("xref\n0 ${objects.size + 1}\n0000000000 65535 f \n")
            offsets.forEach { append(it.toString().padStart(10, '0')).append(" 00000 n \n") }
            append("trailer\n<< /Size ${objects.size + 1} /Root 1 0 R /ID [<00112233445566778899AABBCCDDEEFF> <00112233445566778899AABBCCDDEEFF>] >>\nstartxref\n$xref\n%%EOF\n")
        }.toByteArray())
        return out.toByteArray()
    }

    /** Encrypts [pdf] with the ID number as user password: key length 40 (RC4 R2), 128 (RC4 R3 or AES R4), 256 (AES R6). */
    private fun encrypt(pdf: ByteArray, keyLength: Int, aes: Boolean): ByteArray = Loader.loadPDF(pdf).use { doc ->
        val policy = StandardProtectionPolicy("owner-secret-not-the-id", id, AccessPermission())
        policy.encryptionKeyLength = keyLength
        policy.isPreferAES = aes
        doc.protect(policy)
        ByteArrayOutputStream().also { doc.save(it) }.toByteArray()
    }

    private val documentLines = listOf(
        listOf(200.0 to "國民身分證資料"),
        listOf(60.0 to "統號：$id", 260.0 to "姓名：測試人員"),
        listOf(60.0 to "出生日期：民國 083年03月06日"),
        listOf(60.0 to "性別：男"),
        listOf(60.0 to "戶籍地址：臺北市中正區"),
        listOf(60.0 to "重慶南路一段"),
        listOf(60.0 to "122號"),
        listOf(60.0 to "備註"),
    )

    private fun assertFields(f: NationalIdFields?) {
        assertNotNull(f)
        assertEquals(id, f.unifiedNo)
        assertEquals("測試人員", f.name)
        assertEquals("民國 083年03月06日", f.birthdate)
        assertEquals("臺北市中正區重慶南路一段122號", f.addressOfHousehold)
        assertEquals("中華民國（臺灣）", f.nationality)
    }

    @Test
    fun identityFontTextAndFields() {
        val text = PdfTextExtractor.extract(PdfFile(identityPdf(documentLines)))
        val lines = text.lines()
        assertEquals("國民身分證資料", lines[0])
        assertEquals("統號：$id 姓名：測試人員", lines[1], "runs apart on one line are joined by a space")
        assertEquals("出生日期：民國 083年03月06日", lines[2])
        assertFields(BondsNationalId.parse(text))
    }

    @Test
    fun encryptedWithEveryRevisionOpensWithTheIdNumber() {
        val plain = identityPdf(documentLines)
        for ((length, aes) in listOf(40 to false, 128 to false, 128 to true, 256 to true)) {
            val enc = encrypt(plain, length, aes)
            val locked = PdfFile(enc)
            assertTrue(locked.encrypted)
            assertTrue(locked.passwordRequired, "key length $length, AES $aes")
            assertTrue(PdfFile(enc, "B987654321").passwordRequired)
            // Typed in lower case with spaces: Bonds tries the normalized form too.
            assertFields(BondsNationalId.parse(BondsNationalId.readPdf(enc, " a123456789 ")))
            val e = assertFailsWith<BondsNationalIdException> { BondsNationalId.readPdf(enc, "A000000000") }
            assertTrue(e.message!!.contains("身分證統一編號不正確"))
        }
    }

    @Test
    fun decryptedCopyForPreviewOpensWithoutPassword() {
        val plain = identityPdf(documentLines)
        for ((length, aes) in listOf(40 to false, 128 to false, 128 to true, 256 to true)) {
            val enc = encrypt(plain, length, aes)
            assertFailsWith<PdfPasswordException> { PdfPlain.of(enc) }
            val copy = PdfPlain.of(enc, id)
            val reopened = PdfFile(copy)
            assertFalse(reopened.encrypted, "key length $length, AES $aes")
            assertFields(BondsNationalId.parse(PdfTextExtractor.extract(reopened)))
            // Other readers (PDFBox here, PdfRenderer on Android) open the copy without a password.
            Loader.loadPDF(copy).use { doc ->
                assertFalse(doc.isEncrypted)
                assertEquals(1, doc.numberOfPages)
                assertTrue(org.apache.pdfbox.rendering.PDFRenderer(doc).renderImage(0).width > 0)
            }
        }
        // An unencrypted file is handed back as it is.
        assertTrue(PdfPlain.of(plain).contentEquals(plain))
    }

    @Test
    fun composedPdfWithUnicodeCMapFont() {
        val pdf = PdfComposer.compose(
            "國民身分證資料",
            listOf(
                PdfComposer.Block.Heading("國民身分證資料"),
                PdfComposer.Block.Paragraph("統號：$id 姓名：測試人員"),
                PdfComposer.Block.Paragraph("出生日期：民國 083年03月06日"),
                PdfComposer.Block.Paragraph("戶籍地址：臺北市中正區重慶南路一段122號"),
                PdfComposer.Block.Paragraph("備註"),
            ),
        )
        val f = BondsNationalId.parse(BondsNationalId.readPdf(encrypt(pdf, 256, true), id))
        assertNotNull(f)
        assertEquals(id, f.unifiedNo)
        assertEquals("測試人員", f.name)
        assertEquals("民國 083年03月06日", f.birthdate)
        assertEquals("臺北市中正區重慶南路一段122號", f.addressOfHousehold)
    }

    // ---------------------------------------------------------------- parsing (Bonds' cases)

    @Test
    fun parsesTheLayoutsBondsHandles() {
        val single = BondsNationalId.parse("國民身分證資料\n統號：A123456789 姓名:王小明\n出生日期:0700101\n性別:男\n父:王大明\n母:陳小美\n戶籍地址:臺北市中正區重慶南路一段122號\n備註")
        assertEquals("A123456789", single?.unifiedNo)
        assertEquals("王小明", single?.name)
        assertEquals("0700101", single?.birthdate)
        assertEquals("臺北市中正區重慶南路一段122號", single?.addressOfHousehold)

        val multi = BondsNationalId.parse("國民身分證資料\n統號：A123456789 姓名:王小明\n出生日期:0700101\n戶籍地址:臺北市中正區\n重慶南路一段\n122號\n備註")
        assertEquals("臺北市中正區重慶南路一段122號", multi?.addressOfHousehold)

        val reordered = BondsNationalId.parse("國民身分證資料\n出生日期:0700101\n姓名:王小明\n統號：A123456789\n戶籍地址:高雄市鹽埕區\n備註")
        assertEquals("A123456789", reordered?.unifiedNo)
        assertEquals("高雄市鹽埕區", reordered?.addressOfHousehold)

        val noAddress = BondsNationalId.parse("國民身分證資料\n統號：A123456789 姓名:王小明\n出生日期:0700101\n備註")
        assertEquals("A123456789", noAddress?.unifiedNo)
        assertNull(noAddress?.addressOfHousehold)

        assertNull(BondsNationalId.parse("國民身分證資料\n統號 姓名\n出生日期\n戶籍地址\n備註"), "labels without a separator")
        assertNull(BondsNationalId.parse("勞工保險投保資料\n投保單位:某某公司\n投保日期:1100101"), "another document")
        for (short in listOf("", "國民身分證資料", "國民身分證資料\n統號：A123456789 姓名:王小明")) BondsNationalId.parse(short)
    }

    @Test
    fun rocDatesAndTheAgeClaim() {
        assertEquals(RocDate(83, 3, 6), RocDate.parse("民國 083年03月06日"))
        assertEquals(RocDate(83, 3, 6), RocDate.parse("民國８３年３月６日"), "full-width digits")
        assertNull(RocDate.parse("0700101"), "a bare digit run is not a known format")
        assertNull(RocDate.parse("民國 083年13月06日"))
        // 1994-03-06: 18 on 2012-03-06 in Taipei (UTC+8), whatever the device zone.
        assertEquals("false", BondsNationalId.over18("民國 083年03月06日", Instant.parse("2012-03-05T15:59:59Z")))
        assertEquals("true", BondsNationalId.over18("民國 083年03月06日", Instant.parse("2012-03-05T16:00:00Z")))
        assertNull(BondsNationalId.over18("0700101", Instant.parse("2026-01-01T00:00:00Z")), "unknown is not under age")
        val claims = BondsNationalId.claims(NationalIdFields(id, "王小明", "0700101", null), Instant.parse("2026-01-01T00:00:00Z")).toMap()
        assertEquals(setOf("nationality", "unifiedNo", "name", "birthdate"), claims.keys)
    }

    // ---------------------------------------------------------------- card

    private fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun cert(subject: String, issuer: String, key: PublicKey, signer: PrivateKey, issuerKey: PublicKey, ca: Boolean): X509CertificateHolder {
        val now = System.currentTimeMillis()
        val b = JcaX509v3CertificateBuilder(X500Name(issuer), BigInteger.valueOf(System.nanoTime()), Date(now - 86_400_000), Date(now + 86_400_000L * 365), X500Name(subject), key)
        val ext = JcaX509ExtensionUtils()
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(key))
        b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuerKey))
        b.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
        b.addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature or KeyUsage.nonRepudiation))
        return b.build(JcaContentSignerBuilder("SHA256withRSA").build(signer))
    }

    private val rootKey = rsa()
    private val root = cert("CN=Test GRCA", "CN=Test GRCA", rootKey.public, rootKey.private, rootKey.public, true)
    private val moicaKey = rsa()
    private val moica = cert("CN=Test MOICA", "CN=Test GRCA", moicaKey.public, rootKey.private, rootKey.public, true)
    private val testCa = MoicaCa(moica.encoded, root.encoded)
    private val resolver = DidResolver(HttpClient(MockEngine { respondError(HttpStatusCode.ServiceUnavailable) }))

    private fun card(name: String): DocumentSigner {
        val key = rsa()
        val holderCert = cert("CN=$name,C=TW", "CN=Test MOICA", key.public, moicaKey.private, moicaKey.public, false)
        return object : DocumentSigner {
            override val certificateChain = listOf(holderCert.encoded, moica.encoded)
            override val keyType = SignerKeyType.RSA
            override val source = SignerSource.SMART_CARD
            override suspend fun sign(data: ByteArray): ByteArray =
                Signature.getInstance("SHA256withRSA").run { initSign(key.private); update(data); sign() }
        }
    }

    private suspend fun holder(): HolderKey {
        val area = SoftwareSecureArea.create(EphemeralStorage())
        val info = area.createKey(null, SoftwareCreateKeySettings.Builder().build())
        return HolderKey(area, info, shared = true, did = DidKeys.didKey(info.publicKey))
    }

    @Test
    fun cardIsBondsNationalIdAndDisclosesOnlyTheAge() = runBlocking<Unit> {
        val fields = BondsNationalId.parse(BondsNationalId.readPdf(encrypt(identityPdf(documentLines), 128, true), id))!!
        val self = holder()
        val issued = BondsNationalId.issue(fields, self, card("測試人員"))
        assertTrue(BondsNationalId.isNationalId(issued))

        val vc = issued.credential()
        assertEquals(listOf("VerifiableCredential", "NationalIDCredential"), (vc["type"] as JsonArray).map { (it as JsonPrimitive).content })
        assertEquals(self.did, (vc["issuer"] as JsonPrimitive).content)
        assertEquals<Map<String, Any>>(mapOf("id" to JsonPrimitive(self.did!!)), vc["credentialSubject"] as JsonObject, "every field is behind a digest")
        val context = vc["@context"] as JsonArray
        assertEquals("https://www.w3.org/ns/credentials/v2", (context[0] as JsonPrimitive).content)
        assertEquals("https://bonds.tw/ns/credentials#unifiedNo", ((context[1] as JsonObject)["unifiedNo"] as JsonPrimitive).content)
        assertFalse("_sd_alg" in vc, "Bonds writes no _sd_alg")
        assertEquals(6, (vc["_sd"] as JsonArray).size)
        val all = BondsOfflinePresentation.disclosableClaims(issued).toMap()
        assertEquals("true", all["over18AtIssuance"])
        assertEquals(id, all["unifiedNo"])

        // A Bonds self-issued request: only the age claim is chosen, the name is always shown and matches the card.
        val req = BondsPresentationRequest.generate("年齡確認", BondsCredentialSource.SELF_ISSUED)
        val jws = BondsOfflinePresentation.presentMoica(req, issued, self, setOf("over18AtIssuance"))
        val r = BondsOfflineVerifier(resolver, moicaCa = testCa).verify(jws, req)
        assertEquals(mapOf("name" to "測試人員", "over18AtIssuance" to "true"), r.claims)
        assertTrue(r.moica!!.nameChecked)
        assertEquals(4, r.moica!!.withheldClaims)
    }

    @Test
    fun cardholderMustBeThePersonInTheDocument() = runBlocking<Unit> {
        val fields = NationalIdFields(id, "王小明", "民國 083年03月06日", null)
        val e = assertFailsWith<BondsNationalIdException> { BondsNationalId.issue(fields, holder(), card("測試人員")) }
        assertTrue(e.message!!.contains("姓名"))
        assertFailsWith<BondsNationalIdException> { BondsNationalId.issue(fields.copy(unifiedNo = null), holder(), card("王小明")) }
        Unit
    }
}
