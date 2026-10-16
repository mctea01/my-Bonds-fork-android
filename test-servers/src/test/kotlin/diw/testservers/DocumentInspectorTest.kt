package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.LaterChanges
import diw.wallet.core.document.SignatureFormat
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import kotlinx.coroutines.runBlocking
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Instant

/** Signature verification of sample files made with EU DSS, ofdrw and BouncyCastle (a local test PKI). */
class DocumentInspectorTest {
    private val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
    private val trust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision = registry.decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
    }

    private fun sample(name: String): ByteArray = javaClass.getResourceAsStream("/documents/$name")!!.readBytes()

    // The samples were made on 2026-10-10; check them as of that day so the test PKI is in its validity period.
    private val at = Instant.parse("2026-10-10T12:00:00Z")

    private suspend fun inspect(name: String, detached: ByteArray? = null) = DocumentInspector.inspect(sample(name), name, trust, detached, at)

    @Test
    fun padesLevels() = runBlocking<Unit> {
        val b = inspect("signed-ec-signer-PAdES_BASELINE_B.pdf")
        assertEquals(DocumentFormat.PDF, b.format)
        assertEquals(1, b.signatures.size)
        val s = b.signatures.single()
        assertEquals(SignatureFormat.PADES, s.format)
        assertEquals(Check.PASS, s.integrity, s.problems.toString())
        assertEquals(true, s.coversWholeDocument)
        assertTrue(b.notes.any { it.contains("B-B") }, b.notes.toString())

        val t = inspect("signed-rsa-signer-PAdES_BASELINE_T.pdf")
        assertEquals(Check.PASS, t.signatures.single().integrity)
        assertEquals(Check.PASS, t.signatures.single().timestamp?.imprint)
        assertTrue(t.notes.any { it.contains("B-T") }, t.notes.toString())

        val lt = inspect("signed-rsa-signer-PAdES_BASELINE_LT.pdf")
        assertTrue(lt.notes.any { it.contains("B-LT") }, lt.notes.toString())
        assertEquals(LaterChanges.SIGNATURES_ONLY, lt.signatures.first().laterChanges)

        val lta = inspect("signed-rsa-signer-PAdES_BASELINE_LTA.pdf")
        assertTrue(lta.notes.any { it.contains("B-LTA") }, lta.notes.toString())
        assertTrue(lta.signatures.any { it.format == SignatureFormat.PDF_DOC_TIMESTAMP && it.integrity == Check.PASS })
        assertTrue(lta.signatures.all { it.integrity == Check.PASS }, lta.signatures.map { it.problems }.toString())
    }

    @Test
    fun tamperedPdfFails() = runBlocking<Unit> {
        val r = inspect("tampered-lta.pdf")
        assertEquals(DocumentVerdict.INVALID, r.verdict, r.signatures.map { it.problems }.toString())
    }

    @Test
    fun sm2PdfAndDetachedCms() = runBlocking<Unit> {
        val pdf = inspect("signed-sm2.pdf")
        assertEquals(Check.PASS, pdf.signatures.single().integrity, pdf.signatures.single().problems.toString())
        assertTrue(pdf.signatures.single().algorithm!!.contains("SM"))

        val p7s = inspect("sm2-detached.p7s")
        assertEquals(DocumentFormat.CMS_SIGNED, p7s.format)
        assertEquals(Check.NOT_CHECKED, p7s.signatures.single().integrity)
    }

    @Test
    fun cadesAndXades() = runBlocking<Unit> {
        val cades = inspect("signed-cades-t.p7m")
        assertEquals(DocumentFormat.CMS_SIGNED, cades.format)
        val c = cades.signatures.single()
        assertEquals(Check.PASS, c.integrity, c.problems.toString())
        assertEquals(Check.PASS, c.timestamp?.imprint)

        val xades = inspect("signed-xades-t.xml")
        val x = xades.signatures.single()
        assertEquals(SignatureFormat.XADES, x.format)
        assertEquals(Check.PASS, x.integrity, x.problems.toString())
        assertEquals(Check.PASS, x.timestamp?.imprint, x.timestamp?.problems.toString())

        val tampered = String(sample("signed-xades-t.xml")).replaceFirst("100", "900").toByteArray()
        if (!tampered.contentEquals(sample("signed-xades-t.xml"))) {
            val r = DocumentInspector.inspect(tampered, "x.xml", trust, null, at)
            assertEquals(Check.FAIL, r.signatures.single().integrity)
        }
    }

    @Test
    fun ofdSeal() = runBlocking<Unit> {
        val r = inspect("signed-sesv4.ofd")
        assertEquals(DocumentFormat.OFD, r.format)
        val s = r.signatures.single()
        assertEquals(SignatureFormat.OFD_SEAL, s.format)
        assertEquals(Check.PASS, s.integrity, s.problems.toString())
        assertTrue(s.notes.any { it.startsWith("印章名稱") }, s.notes.toString())

        val t = inspect("tampered-sesv4.ofd")
        assertEquals(Check.FAIL, t.signatures.single().integrity)

        assertEquals(DocumentVerdict.UNSIGNED, inspect("unsigned.ofd").verdict)
        assertEquals(DocumentVerdict.UNSIGNED, inspect("unsigned.pdf").verdict)
    }

    @Test
    fun timestampToken() = runBlocking<Unit> {
        val r = inspect("preserved-document.bin.tsr", sample("preserved-document.bin"))
        assertEquals(DocumentFormat.TIMESTAMP, r.format)
        assertEquals(Check.PASS, r.signatures.single().integrity, r.signatures.single().problems.toString())
        val wrong = inspect("preserved-document.bin.tsr", byteArrayOf(1, 2, 3))
        assertEquals(Check.FAIL, wrong.signatures.single().integrity)
    }
}
