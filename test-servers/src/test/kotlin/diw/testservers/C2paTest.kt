package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.SignatureFormat
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.BuiltInPublicRoots
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

/** Content credentials (C2PA) on pictures: manifests, claim signatures, hashed assertions and the hard binding. */
class C2paTest {
    private val at = Instant.parse("2027-01-01T00:00:00Z")
    private val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
    private val trust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision = registry.decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
    }

    private fun sample(name: String): ByteArray = javaClass.getResourceAsStream("/c2pa/$name")!!.readBytes()

    private fun pem(name: String): X509Cert = X509Cert(ByteString(Base64.getMimeDecoder().decode(
        javaClass.getResource("/c2pa/$name")!!.readText().substringAfter("-----BEGIN CERTIFICATE-----").substringBefore("-----END CERTIFICATE-----"))))

    private suspend fun trustTestRoot() {
        registry.addAnchor(TrustRole.CONTENT, TrustEnvironment.USER, pem("test-root.pem"), "DIW Test C2PA Root", official = false, source = "test")
    }

    private suspend fun inspect(bytes: ByteArray, name: String): DocumentReport = DocumentInspector.inspect(bytes, name, trust, null, at)

    private fun DocumentReport.codes() = c2pa!!.manifests.first().statuses.map { it.code }

    @Test
    fun signedPicturesAreValidUnderATrustedRoot() = runBlocking<Unit> {
        trustTestRoot()
        for (name in listOf("signed.jpg", "signed.png")) {
            val r = inspect(sample(name), name)
            val c = assertNotNull(r.c2pa, name)
            val m = c.manifests.first()
            assertTrue(m.active)
            assertEquals(2, m.claimVersion)
            assertEquals("測試圖片." + name.substringAfter('.'), m.title)
            assertEquals(listOf("c2pa.created"), m.actions.map { it.action })
            assertEquals("digitalCapture", m.actions.first().digitalSourceType)
            assertEquals(listOf("測試作者"), m.authors)
            assertTrue(m.generator!!.startsWith("diw-test 1.0"))
            assertTrue(r.codes().containsAll(listOf("claimSignature.validated", "assertion.hashedURI.match", "assertion.dataHash.match", "signingCredential.trusted")), r.codes().toString())
            val s = r.signatures.single()
            assertEquals(SignatureFormat.C2PA, s.format)
            assertEquals("ES256", s.algorithm)
            assertEquals(Check.PASS, s.integrity)
            assertEquals(true, s.coversWholeDocument)
            assertEquals("DIW Test C2PA Signer", s.signerName)
            assertEquals(DocumentVerdict.VALID, r.verdict, "$name: ${s.problems}")
        }
    }

    @Test
    fun unknownSignerIsUntrustedButIntact() = runBlocking<Unit> {
        val r = inspect(sample("signed.jpg"), "signed.jpg")
        assertTrue("signingCredential.untrusted" in r.codes())
        assertEquals(Check.PASS, r.signatures.single().integrity)
        assertEquals(DocumentVerdict.PARTIAL, r.verdict)
    }

    @Test
    fun changedPixelsBreakTheHardBinding() = runBlocking<Unit> {
        trustTestRoot()
        val b = sample("signed.jpg").copyOf()
        b[b.size - 10] = (b[b.size - 10].toInt() xor 0x01).toByte()
        val r = inspect(b, "signed.jpg")
        assertTrue("assertion.dataHash.mismatch" in r.codes())
        assertTrue("claimSignature.validated" in r.codes(), "the claim itself is untouched")
        assertEquals(Check.FAIL, r.signatures.single().integrity)
        assertEquals(DocumentVerdict.INVALID, r.verdict)
    }

    @Test
    fun changedAssertionBreaksItsHashedUri() = runBlocking<Unit> {
        trustTestRoot()
        val b = sample("signed.png").copyOf()
        val author = "測試作者".encodeToByteArray()
        val at = (0..b.size - author.size).first { i -> author.indices.all { b[i + it] == author[it] } }
        "測試作家".encodeToByteArray().copyInto(b, at)
        val r = inspect(b, "signed.png")
        assertTrue("assertion.hashedURI.mismatch" in r.codes(), r.codes().toString())
        assertTrue("assertion.dataHash.match" in r.codes(), "the manifest store is excluded from the data hash")
        assertEquals(DocumentVerdict.INVALID, r.verdict)
    }

    @Test
    fun sidecarManifestHasNoAssetToBind() = runBlocking<Unit> {
        trustTestRoot()
        val png = sample("signed.png")
        var i = 8
        var store: ByteArray? = null
        while (i + 12 <= png.size) {
            val len = java.nio.ByteBuffer.wrap(png, i, 4).int
            if (String(png, i + 4, 4, Charsets.ISO_8859_1) == "caBX") { store = png.copyOfRange(i + 8, i + 8 + len); break }
            i += 12 + len
        }
        val r = inspect(assertNotNull(store), "signed.c2pa")
        assertEquals("sidecar", r.c2pa!!.container)
        assertTrue("assertion.dataHash.notChecked" in r.codes())
        assertEquals(Check.WARN, r.signatures.single().integrity)
        assertNull(r.signatures.single().coversWholeDocument)
        assertEquals(DocumentVerdict.PARTIAL, r.verdict)
    }

    @Test
    fun c2paRsFixtureWithV1ClaimTimestampAndIngredient() = runBlocking<Unit> {
        val r = inspect(sample("c2pa-rs-CA.jpg"), "CA.jpg")
        val m = r.c2pa!!.manifests.first()
        assertEquals(1, m.claimVersion)
        assertEquals("CA.jpg", m.title)
        assertEquals("image/jpeg", m.format)
        assertEquals(listOf("John Doe"), m.authors)
        assertEquals(listOf("c2pa.opened", "c2pa.color_adjustments"), m.actions.map { it.action })
        assertEquals("A.jpg", m.ingredients.single().title)
        assertEquals("parentOf", m.ingredients.single().relationship)
        assertTrue(r.codes().containsAll(listOf("claimSignature.validated", "assertion.dataHash.match", "timeStamp.validated")), r.codes().toString())
        val s = r.signatures.single()
        assertEquals("PS256", s.algorithm)
        assertEquals(Check.PASS, s.integrity)
        assertEquals(Check.PASS, s.timestamp!!.imprint)
        assertEquals("C2PA Signer", s.signerName)
    }

    @Test
    fun c2paTrustListAnchorsContentSignersOnly() = runBlocking<Unit> {
        val roots = BuiltInPublicRoots.contentCredentials
        assertTrue(roots.size >= 20)
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy(systemStoreEnabled = true))
        val digicert = roots.first { it.name == "DigiCert ECC P384 Root for C2PA G1" }.certificate
        val content = registry.decide(TrustRole.CONTENT, listOf(digicert), at)
        assertTrue(content.anchorName?.startsWith("C2PA 信任清單") == true, content.toString())
        val document = registry.decide(TrustRole.DOCUMENT, listOf(digicert), at)
        assertTrue(document.anchorName?.startsWith("C2PA") != true, "the C2PA list does not anchor document signatures")
    }

    @Test
    fun picturesWithoutCredentialsStayUnsigned() = runBlocking<Unit> {
        val plain = javaClass.getResourceAsStream("/images/gray-expected.png")!!.readBytes()
        val r = inspect(plain, "gray.png")
        assertNull(r.c2pa)
        assertEquals(DocumentVerdict.UNSIGNED, r.verdict)
    }
}
