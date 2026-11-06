package diw.testservers.mrtd

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.card.CardResponse
import diw.wallet.core.document.mrtd.AccessSecret
import diw.wallet.core.document.mrtd.BerTlv
import diw.wallet.core.document.mrtd.ChipCheck
import diw.wallet.core.document.mrtd.Lds
import diw.wallet.core.document.mrtd.LdsFile
import diw.wallet.core.document.mrtd.MrtdCrypt
import diw.wallet.core.document.mrtd.MrtdCrypto
import diw.wallet.core.document.mrtd.MrtdDump
import diw.wallet.core.document.mrtd.MrtdException
import diw.wallet.core.document.mrtd.MrtdOids
import diw.wallet.core.document.mrtd.MrtdReader
import diw.wallet.core.document.mrtd.Mrz
import diw.wallet.core.document.mrtd.MrzKey
import diw.wallet.core.document.mrtd.SecureChannel
import diw.wallet.core.document.mrtd.SmCipher
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.imageio.ImageIO
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Instant

/** The electronic passport reader against a software chip, and passive authentication of what it read. */
class MrtdTest {
    private val bc = BouncyCastleProvider()
    private val day = 86_400_000L
    private val now = System.currentTimeMillis()

    private fun rsa(bits: Int = 2048): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()

    private fun cert(subject: String, issuer: String, key: PublicKey, signer: KeyPair, ca: Boolean): X509CertificateHolder {
        val b = JcaX509v3CertificateBuilder(X500Name(issuer), BigInteger.valueOf(System.nanoTime()), Date(now - 30 * day), Date(now + 3650 * day), X500Name(subject), key)
        val ext = JcaX509ExtensionUtils()
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(key))
        b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(signer.public))
        if (ca) b.addExtension(Extension.basicConstraints, true, BasicConstraints(0))
        b.addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature))
        return b.build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(signer.private))
    }

    private val cscaKey = rsa()
    private val csca = cert("C=TW,O=Test Ministry,CN=Test CSCA", "C=TW,O=Test Ministry,CN=Test CSCA", cscaKey.public, cscaKey, true)
    private val dscKey = rsa()
    private val dsc = cert("C=TW,O=Test Ministry,CN=Test DSC", "C=TW,O=Test Ministry,CN=Test CSCA", dscKey.public, cscaKey, false)

    private fun trust(withAnchor: Boolean): DocumentTrustSource {
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        if (withAnchor) runBlocking { registry.addAnchor(TrustRole.TRAVEL_DOCUMENT, TrustEnvironment.USER, X509Cert(ByteString(csca.encoded)), "Test CSCA", official = false, source = "test") }
        return object : DocumentTrustSource {
            override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision = registry.decide(role, chain, at)
            override suspend fun fetchIssuerCertificates(url: String) = emptyList<ByteArray>()
        }
    }

    // ---- data page and LDS files

    private fun line2(number: String, nat: String, birth: String, sex: Char, expiry: String, personal: String): String {
        val n = number.padEnd(9, '<')
        val p = personal.padEnd(14, '<')
        val body = n + Mrz.checkDigit(n) + nat + birth + Mrz.checkDigit(birth) + sex + expiry + Mrz.checkDigit(expiry) + p + Mrz.checkDigit(p)
        val composite = body.substring(0, 10) + body.substring(13, 20) + body.substring(21, 43)
        return body + Mrz.checkDigit(composite)
    }

    private val mrzLine1 = "P<TWNLIN<<CHE<CHUAN".padEnd(44, '<')
    private val mrzLine2 = line2("312345678", "TWN", "900115", 'M', "300101", "A123456789")
    private val key = MrzKey("312345678", "900115", "300101")

    private fun jpeg(): ByteArray {
        val img = BufferedImage(24, 32, BufferedImage.TYPE_INT_RGB)
        for (x in 0 until 24) for (y in 0 until 32) img.setRGB(x, y, (x * 10 shl 16) or (y * 8 shl 8) or 0x40)
        return ByteArrayOutputStream().also { ImageIO.write(img, "jpg", it) }.toByteArray()
    }

    /** An ISO/IEC 19794-5 facial record around [image], padded so the file needs READ BINARY past 32767. */
    private fun dg2(image: ByteArray, padding: Int): ByteArray {
        val img = image + ByteArray(padding)
        fun u16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())
        fun u32(v: Int) = u16(v shr 16) + u16(v)
        val facial = u32(20 + 12 + img.size) + u16(0) + byteArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) +
            byteArrayOf(1, 0) + u16(24) + u16(32) + byteArrayOf(1, 0) + u16(0) + u16(0) + img
        val record = "FAC".encodeToByteArray() + byteArrayOf(0) + "010".encodeToByteArray() + byteArrayOf(0) + u32(14 + facial.size) + u16(1) + facial
        val bit = BerTlv.encode(0x7F60, BerTlv.encode(0xA1, BerTlv.encode(0x80, byteArrayOf(1, 1))) + BerTlv.encode(0x5F2E, record))
        return BerTlv.encode(0x75, BerTlv.encode(0x7F61, BerTlv.encode(0x02, byteArrayOf(1)) + bit))
    }

    private fun sod(files: Map<LdsFile, ByteArray>, signer: KeyPair = dscKey, signerCert: X509CertificateHolder = dsc): ByteArray {
        val hashes = ASN1EncodableVector()
        for ((f, b) in files) {
            val n = f.dataGroup ?: continue
            hashes.add(DERSequence(arrayOf(ASN1Integer(n.toLong()), DEROctetString(MessageDigest.getInstance("SHA-256").digest(b)))))
        }
        val lso = DERSequence(arrayOf(ASN1Integer(0), AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), DERSequence(hashes))).encoded
        val gen = CMSSignedDataGenerator()
        gen.addSignerInfoGenerator(JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().setProvider(bc).build())
            .build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(signer.private), signerCert))
        gen.addCertificates(JcaCertStore(listOf(signerCert)))
        val cms = gen.generate(CMSProcessableByteArray(ASN1ObjectIdentifier(MrtdOids.LDS_SECURITY_OBJECT), lso), true).encoded
        return BerTlv.encode(0x77, cms)
    }

    private fun securityInfos(vararg infos: ByteArray): ByteArray = BerTlv.encode(0x31, infos.fold(ByteArray(0)) { a, b -> a + b })

    private fun seq(vararg parts: ByteArray) = BerTlv.encode(0x30, parts.fold(ByteArray(0)) { a, b -> a + b })
    private fun oid(s: String) = BerTlv.encode(0x06, BerTlv.oidValue(s))
    private fun int(v: Int) = BerTlv.encode(0x02, byteArrayOf(v.toByte()))

    private class Chip(val passport: SoftwarePassport, val files: Map<LdsFile, ByteArray>)

    /**
     * A passport with DG1, DG2, DG11, DG12, DG14 (Chip Authentication key on brainpoolP256r1 or P-256) and DG15 (RSA
     * Active Authentication); [paceOid] and [paceParam] fill EF.CardAccess, null makes a BAC-only chip.
     */
    private fun chip(
        paceOid: String? = MrtdOids.PACE_ECDH_GM + ".2",
        paceParam: Int = 13,
        caOid: String = MrtdOids.CA_ECDH + ".2",
        clone: Boolean = false,
        ecAa: Boolean = false,
        refusePace: Boolean = false,
        mutate: (MutableMap<LdsFile, ByteArray>) -> Unit = {},
    ): Chip {
        val caPair = KeyPairGenerator.getInstance("EC", bc).apply { initialize(ECGenParameterSpec("brainpoolP256r1")) }.generateKeyPair()
        val (caDomain, _) = MrtdCrypto.publicKeyDomain(caPair.public.encoded)!!
        // The chip's agreement key: the DG14 key itself, or (a clone) a different key on the same curve.
        val chipCa = if (clone) caDomain.generate() else diw.wallet.core.document.mrtd.AgreementKeyPair(ByteArray(0), (caPair.private as java.security.interfaces.ECPrivateKey).s)
        val aaRsa = if (ecAa) null else rsa(1024)
        val aaEc = if (ecAa) KeyPairGenerator.getInstance("EC", bc).apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair() else null
        val dg14 = BerTlv.encode(0x6E, securityInfos(
            seq(oid(MrtdOids.PK_ECDH), caPair.public.encoded),
            seq(oid(caOid), int(1)),
            *(if (ecAa) arrayOf(seq(oid(MrtdOids.AA), int(1), oid("0.4.0.127.0.7.1.1.4.1.3"))) else emptyArray()),
        ))
        val files = linkedMapOf(
            LdsFile.DG1 to BerTlv.encode(0x61, BerTlv.encode(0x5F1F, (mrzLine1 + mrzLine2).encodeToByteArray())),
            LdsFile.DG2 to dg2(jpeg(), 40_000),
            LdsFile.DG11 to BerTlv.encode(0x6B, BerTlv.encode(0x5C, byteArrayOf(0x5F, 0x0E, 0x5F, 0x2B)) +
                BerTlv.encode(0x5F0E, "LIN<<CHE<CHUAN".encodeToByteArray()) + BerTlv.encode(0x5F2B, "19900115".encodeToByteArray()) +
                BerTlv.encode(0x5F11, "TAIPEI".encodeToByteArray())),
            LdsFile.DG12 to BerTlv.encode(0x6C, BerTlv.encode(0x5F19, "BUREAU OF CONSULAR AFFAIRS".encodeToByteArray()) + BerTlv.encode(0x5F26, "20200101".encodeToByteArray())),
            LdsFile.DG14 to dg14,
            LdsFile.DG15 to BerTlv.encode(0x6F, (aaRsa ?: aaEc)!!.public.encoded),
        )
        val sodFiles = LinkedHashMap(files)
        mutate(files)
        val com = BerTlv.encode(0x60, BerTlv.encode(0x5F01, "0107".encodeToByteArray()) + BerTlv.encode(0x5F36, "040000".encodeToByteArray()) +
            BerTlv.encode(0x5C, files.keys.map { it.tag.toByte() }.toByteArray()))
        val all = LinkedHashMap<LdsFile, ByteArray>().apply { put(LdsFile.COM, com); putAll(files); put(LdsFile.SOD, sod(sodFiles)) }
        val cardAccess = paceOid?.let { securityInfos(seq(oid(it), int(2), int(paceParam))) }
        val passport = SoftwarePassport(
            files = all.mapKeys { it.key.fid }, key = key, cardAccess = cardAccess,
            caKey = caDomain to chipCa, caOid = caOid, aaRsa = aaRsa, aaEc = aaEc, refusePace = refusePace,
        )
        return Chip(passport, all)
    }

    private fun read(c: Chip, secret: AccessSecret = AccessSecret.MrzSecret(key)): MrtdDump = runBlocking { MrtdReader(c.passport, secret).read() }

    private fun inspect(dump: MrtdDump, anchor: Boolean = true) = runBlocking {
        DocumentInspector.inspect(dump.encode(), "passport." + MrtdDump.FILE_EXTENSION, trust(anchor))
    }

    // ---- tests

    @Test fun icaoBacKeysAndSecureMessaging() = runBlocking {
        // ICAO 9303 part 11, appendix D: key derivation and the protected SELECT of EF.COM.
        val info = MrzKey("L898902C", "690806", "940623").information
        assertEquals("L898902C<369080619406236", info)
        val seed = diw.wallet.core.document.DocCrypto.digest("SHA-1", info.encodeToByteArray()).copyOf(16)
        assertEquals("239ab9cb282daf66231dc5a4df6bfbae", DocCryptoUtil.hex(seed))
        assertEquals("ab94fdecf2674fdfb9b391f85d7f76f2", DocCryptoUtil.hex(MrtdCrypt.kdf(SmCipher.DES3, seed, 1)))
        assertEquals("7962d9ece03d1acd4c76089dce131543", DocCryptoUtil.hex(MrtdCrypt.kdf(SmCipher.DES3, seed, 2)))
        val sent = ArrayList<ByteArray>()
        val sc = SecureChannel({ _, _, _, _, data, _ ->
            sent.add(data)
            CardResponse(0x9000, DocCryptoUtil.unhex("990290008e08fa855a5d4c50a8ed"))
        }, SmCipher.DES3, DocCryptoUtil.unhex("979ec13b1cbfe9dcd01ab0fed307eae5"), DocCryptoUtil.unhex("f1cb1f1fb5adf208806b89dc579dc1f8"),
            DocCryptoUtil.unhex("887022120c06c226"))
        val r = sc.transmit(0x00, 0xA4, 0x02, 0x0C, byteArrayOf(0x01, 0x1E), 0)
        assertEquals("8709016375432908c044f68e08bf8b92d635ff24f8", DocCryptoUtil.hex(sent.single()))
        assertEquals(0x9000, r.sw)
    }

    @Test fun mrzKeepsEveryGivenName() {
        val td3 = Mrz.parse("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10")!!
        assertTrue(td3.checkDigitsValid, td3.failedChecks.toString())
        assertEquals(listOf("ANNA", "MARIA"), td3.givenNames)
        assertEquals("ERIKSSON, ANNA MARIA", td3.fullName)
        val td1 = Mrz.parse("I<UTOD231458907<<<<<<<<<<<<<<<\n7408122F1204159UTO<<<<<<<<<<<6\nERIKSSON<<ANNA<MARIA<<<<<<<<<<")!!
        assertTrue(td1.checkDigitsValid, td1.failedChecks.toString())
        assertEquals("D23145890", td1.documentNumber)
        assertEquals(listOf("ANNA", "MARIA"), td1.givenNames)
        val ocr = Mrz.find("PASSPORT\nP<TWNLIN<<CHE<CHUAN<<<<<<<<<<<<<<<<<<<<<<<<<\n" + mrzLine2.replace('<', ' ') + "\n")
        assertEquals(listOf("CHE", "CHUAN"), ocr?.givenNames)
        assertEquals("312345678", ocr?.documentNumber)
    }

    @Test fun paceAesBrainpoolWithChipAndActiveAuthentication() {
        val c = chip()
        val dump = read(c)
        assertEquals("PACE-ECDH-GM-AES-128", dump.access)
        assertEquals(ChipCheck.PASS, dump.chipAuthentication)
        assertEquals("CA-ECDH-AES-128", dump.chipAuthenticationProtocol)
        assertEquals(ChipCheck.PASS, dump.activeAuthenticationResult)
        assertTrue(0xB1 in c.passport.instructions, "DG2 past 32767 bytes is read with READ BINARY B1")
        assertContentEquals(c.files.getValue(LdsFile.DG2), dump.file(LdsFile.DG2))
        val mrz = Lds.dg1(dump.file(LdsFile.DG1)!!)!!
        assertEquals(listOf("CHE", "CHUAN"), mrz.givenNames)
        assertEquals("LIN, CHE CHUAN", Lds.dg11(dump.file(LdsFile.DG11)!!)?.fullName)
        assertEquals("19900115", Lds.dg11(dump.file(LdsFile.DG11)!!)?.fullBirthDate)
        assertEquals("BUREAU OF CONSULAR AFFAIRS", Lds.dg12(dump.file(LdsFile.DG12)!!)?.issuingAuthority)
        val face = Lds.dg2(dump.file(LdsFile.DG2)!!).single()
        assertEquals("image/jpeg", face.mediaType)
        assertNotNull(ImageIO.read(face.data.inputStream()))

        val report = inspect(dump)
        assertEquals(DocumentFormat.EMRTD, report.format)
        assertEquals(DocumentVerdict.VALID, report.verdict, report.signatures.flatMap { it.problems }.toString())
        val td = report.travelDocument!!
        assertEquals(listOf(1, 2, 11, 12, 14, 15), td.matched)
        assertEquals(ChipCheck.PASS, td.activeAuthentication)
        assertEquals("TW", td.signerCountry)
        assertEquals(MrtdDump.decode(dump.encode()), dump)
    }

    /** A passport-derived credential: zone claims, the wallet's statement, and passive authentication repeated from DG1 and SOD. */
    @Test fun derivedCredentialEvidenceIsRepeatedFromDg1AndSod() = runBlocking {
        val dump = read(chip())
        val report = inspect(dump)
        val claims = diw.wallet.core.document.derived.TravelDocumentFields.claims(dump, 2026)
        val byName = claims.associate { it.name to it.value }
        assertEquals("312345678", byName["documentNumber"])
        assertEquals("CHE CHUAN", byName["givenNames"])
        assertEquals("1990-01-15", byName["birthDate"])
        assertEquals("2030-01-01", byName["expiryDate"])
        val evidence = diw.wallet.core.document.derived.TravelDocumentFields.evidence(report, dump)!!
        val disclosed = claims.associate { it.name to kotlinx.serialization.json.JsonPrimitive(it.value) as kotlinx.serialization.json.JsonElement }
        val verify = { d: Map<String, kotlinx.serialization.json.JsonElement>, anchor: Boolean ->
            runBlocking { diw.wallet.core.document.derived.TravelDocumentFields.verify(evidence, d, trust(anchor), own = false) }
        }
        val full = verify(disclosed, true)
        assertEquals(listOf(Check.PASS, Check.PASS), full.map { it.check }, full.toString())
        assertEquals(Check.WARN, verify(disclosed, false).first().check)
        val statementOnly = verify(disclosed.filterKeys { !diw.wallet.core.document.derived.TravelDocumentFields.isRaw(it) }, true)
        assertEquals(Check.NOT_CHECKED, statementOnly.single().check)
        val changed = verify(disclosed + ("documentNumber" to kotlinx.serialization.json.JsonPrimitive("999999999")), true)
        assertEquals(Check.FAIL, changed.last().check)
        val otherSod = disclosed + ("travelDocumentSod" to kotlinx.serialization.json.JsonPrimitive(java.util.Base64.getEncoder().encodeToString(byteArrayOf(1, 2, 3))))
        assertEquals(Check.FAIL, verify(otherSod, true).single().check)
    }

    @Test fun bacOnlyChipWithChipAuthenticationVersionOne() {
        val dump = read(chip(paceOid = null, caOid = MrtdOids.CA_ECDH + ".1"))
        assertEquals("BAC", dump.access)
        assertEquals(ChipCheck.PASS, dump.chipAuthentication)
        assertEquals(DocumentVerdict.VALID, inspect(dump).verdict)
    }

    @Test fun paceDiffieHellmanAnd3Des() {
        val dump = read(chip(paceOid = MrtdOids.PACE_DH_GM + ".1", paceParam = 2))
        assertEquals("PACE-DH-GM-3DES", dump.access)
        assertEquals(ChipCheck.PASS, dump.chipAuthentication)
    }

    @Test fun paceOnP256WithAes256() {
        val dump = read(chip(paceOid = MrtdOids.PACE_ECDH_GM + ".4", paceParam = 12))
        assertEquals("PACE-ECDH-GM-AES-256", dump.access)
    }

    @Test fun refusedPaceFallsBackToBac() {
        val dump = read(chip(refusePace = true))
        assertEquals("BAC", dump.access)
    }

    @Test fun ecdsaActiveAuthentication() {
        val dump = read(chip(ecAa = true))
        assertEquals(ChipCheck.PASS, dump.activeAuthenticationResult)
        assertEquals(ChipCheck.PASS, inspect(dump).travelDocument?.activeAuthentication)
    }

    @Test fun wrongDocumentDataIsRefused() {
        val wrong = AccessSecret.MrzSecret(MrzKey("312345679", "900115", "300101"))
        assertEquals("access_denied", assertFailsWith<MrtdException> { read(chip(), wrong) }.code)
        assertEquals("access_denied", assertFailsWith<MrtdException> { read(chip(paceOid = null), wrong) }.code)
    }

    @Test fun clonedChipFailsChipAuthentication() {
        assertEquals("ca_failed", assertFailsWith<MrtdException> { read(chip(clone = true)) }.code)
    }

    @Test fun changedDataGroupFailsPassiveAuthentication() {
        val c = chip(mutate = { it[LdsFile.DG1] = BerTlv.encode(0x61, BerTlv.encode(0x5F1F, (mrzLine1.replace("CHUAN", "CHUAM") + mrzLine2).encodeToByteArray())) })
        val report = inspect(read(c))
        assertEquals(DocumentVerdict.INVALID, report.verdict)
        assertEquals(listOf(1), report.travelDocument?.mismatched)
    }

    @Test fun tamperedDumpIsCaught() {
        val dump = read(chip())
        val changed = dump.copy(files = dump.files + (LdsFile.DG11.name to Base64.encode(BerTlv.encode(0x6B, BerTlv.encode(0x5F0E, "LIN<<OTHER".encodeToByteArray())))))
        assertEquals(DocumentVerdict.INVALID, inspect(changed).verdict)
    }

    @Test fun masterListGivesItsCertificatesAndChecksItsSignature() {
        val other = rsa()
        val second = cert("C=JP,O=Test,CN=Test CSCA JP", "C=JP,O=Test,CN=Test CSCA JP", other.public, other, true)
        val content = DERSequence(arrayOf(ASN1Integer(0), org.bouncycastle.asn1.DERSet(arrayOf(csca.toASN1Structure(), second.toASN1Structure())))).encoded
        fun signed(body: ByteArray): ByteArray {
            val gen = CMSSignedDataGenerator()
            gen.addSignerInfoGenerator(JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().setProvider(bc).build())
                .build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(dscKey.private), dsc))
            gen.addCertificates(JcaCertStore(listOf(dsc)))
            return gen.generate(CMSProcessableByteArray(ASN1ObjectIdentifier("2.23.136.1.1.2"), body), true).encoded
        }
        val list = assertNotNull(MrtdCrypto.masterList(signed(content)))
        assertTrue(list.signatureValid)
        assertEquals(setOf(csca.encoded.toList(), second.encoded.toList()), list.certificates.map { it.toList() }.toSet())
        // A byte changed inside the second certificate's own signature keeps the list readable but breaks the list signature.
        val tampered = signed(content).also { b ->
            val sig = second.signature
            val at = (0..b.size - sig.size).first { i -> (sig.indices).all { b[i + it] == sig[it] } } + sig.size / 2
            b[at] = (b[at] + 1).toByte()
        }
        assertEquals(false, MrtdCrypto.masterList(tampered)?.signatureValid)
        assertEquals(null, MrtdCrypto.masterList(BerTlv.encode(0x77, ByteArray(4))))
    }

    @Test fun unknownCountrySigningCaIsPartial() {
        val report = inspect(read(chip()), anchor = false)
        assertEquals(DocumentVerdict.PARTIAL, report.verdict)
        assertEquals(Check.PASS, report.signatures.single().integrity)
    }
}
