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
    fun unsignedHardBindingIsNotUsed() = runBlocking<Unit> {
        trustTestRoot()
        val png = sample("signed.png")
        val (chunk, store) = caBX(png)
        // A forged data hash, not referenced by the claim, put before the signed one, over changed pixels.
        val label = "c2pa.hash.data__1".encodeToByteArray() + 0
        val jumd = box("jumd", hex("63626f72001100108000" + "00aa00389b71") + byteArrayOf(0x03) + label)
        val placeholder = ByteArray(32)
        val forgedLength = 8 + jumd.size + 8 + cborHash(0, 0, placeholder).size
        val newChunkSize = 12 + store.size + forgedLength
        val cbor = cborHash(chunk.toLong(), newChunkSize.toLong(), placeholder)
        val forged = box("jumb", jumd + box("cbor", cbor))
        assertEquals(forgedLength, forged.size)
        val assertions = labelBox(store, "c2pa.assertions")
        val at = assertions + 8 + u32(store, assertions + 8)
        val newStore = grow(store, at, forged)
        val out = png.copyOfRange(0, chunk) + pngChunk("caBX", newStore) + png.copyOfRange(chunk + 12 + store.size, png.size)
        val idat = (8 until out.size - 4).first { String(out, it, 4, Charsets.ISO_8859_1) == "IDAT" }
        out[idat + 6] = (out[idat + 6].toInt() xor 0x01).toByte()
        val digest = java.security.MessageDigest.getInstance("SHA-256").apply {
            update(out, 0, chunk); update(out, chunk + newChunkSize, out.size - chunk - newChunkSize)
        }.digest()
        val hashAt = chunk + 8 + at + forged.size - placeholder.size
        digest.copyInto(out, hashAt)
        val r = inspect(out, "signed.png")
        assertTrue("assertion.dataHash.mismatch" in r.codes(), r.codes().toString())
        assertTrue("c2pa.hash.data__1" !in r.c2pa!!.manifests.first().assertions)
        assertEquals(DocumentVerdict.INVALID, r.verdict)
    }

    @Test
    fun embeddedPayloadMustBeTheParsedClaim() = runBlocking<Unit> {
        trustTestRoot()
        val png = sample("signed.png")
        val (chunk, store) = caBX(png)
        val claim = labelBox(store, "c2pa.claim.v2")
        val claimCbor = claim + 8 + u32(store, claim + 8) + 8
        val claimBytes = store.copyOfRange(claimCbor, claim + u32(store, claim))
        // The signed claim goes into the COSE payload, then the manifest's claim is changed.
        val sig = labelBox(store, "c2pa.signature")
        val sigEnd = sig + u32(store, sig)
        val nil = sigEnd - 66 - 1
        assertEquals(0xf6, store[nil].toInt() and 0xFF)
        val payload = byteArrayOf(0x59, (claimBytes.size shr 8).toByte(), claimBytes.size.toByte()) + claimBytes
        var newStore = grow(store, nil, payload.copyOfRange(0, payload.size - 1))
        payload.copyInto(newStore, nil)
        val title = "測試圖片".encodeToByteArray()
        val t = (claimCbor until claimCbor + claimBytes.size).first { i -> title.indices.all { newStore[i + it] == title[it] } }
        "偽造圖片".encodeToByteArray().copyInto(newStore, t)
        val out = png.copyOfRange(0, chunk) + pngChunk("caBX", newStore) + png.copyOfRange(chunk + 12 + store.size, png.size)
        val r = inspect(out, "signed.png")
        val m = r.c2pa!!.manifests.first()
        assertEquals("偽造圖片.png", m.title)
        assertTrue("claimSignature.mismatch" in r.codes(), r.codes().toString())
        assertTrue("claimSignature.validated" !in r.codes())
        assertEquals(Check.FAIL, r.signatures.single().integrity)
    }

    private fun caBX(png: ByteArray): Pair<Int, ByteArray> {
        var i = 8
        while (i + 12 <= png.size) {
            val len = java.nio.ByteBuffer.wrap(png, i, 4).int
            if (String(png, i + 4, 4, Charsets.ISO_8859_1) == "caBX") return i to png.copyOfRange(i + 8, i + 8 + len)
            i += 12 + len
        }
        error("no caBX chunk")
    }

    private fun pngChunk(type: String, data: ByteArray): ByteArray {
        val t = type.toByteArray(Charsets.ISO_8859_1)
        val crc = java.util.zip.CRC32().apply { update(t); update(data) }.value
        return java.nio.ByteBuffer.allocate(12 + data.size).putInt(data.size).put(t).put(data).putInt(crc.toInt()).array()
    }

    private fun u32(b: ByteArray, at: Int) = java.nio.ByteBuffer.wrap(b, at, 4).int

    private fun box(type: String, body: ByteArray) =
        java.nio.ByteBuffer.allocate(8 + body.size).putInt(8 + body.size).put(type.toByteArray(Charsets.ISO_8859_1)).put(body).array()

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /** Start of the superbox whose description box carries [label]. */
    private fun labelBox(store: ByteArray, label: String): Int {
        val l = label.encodeToByteArray() + 0
        val pos = (0..store.size - l.size).first { i -> l.indices.all { store[i + it] == l[it] } && String(store, i - 21, 4, Charsets.ISO_8859_1) == "jumd" }
        return pos - 25 - 8
    }

    /** Inserts [bytes] at [at] and grows every JUMBF box that contains that position. */
    private fun grow(store: ByteArray, at: Int, bytes: ByteArray): ByteArray {
        val out = store.copyOfRange(0, at) + bytes + store.copyOfRange(at, store.size)
        fun walk(from: Int, to: Int) {
            var off = from
            while (off + 8 <= to) {
                val len = u32(store, off)
                if (off < at && at < off + len) {
                    java.nio.ByteBuffer.wrap(out, off, 4).putInt(len + bytes.size)
                    if (String(store, off + 4, 4, Charsets.ISO_8859_1) == "jumb") walk(off + 8, off + len)
                }
                off += len
            }
        }
        walk(0, store.size)
        return out
    }

    /** CBOR of a c2pa.hash.data assertion with one exclusion; the hash is the last field. */
    private fun cborHash(start: Long, length: Long, hash: ByteArray): ByteArray {
        fun head(major: Int, n: Long): ByteArray = java.nio.ByteBuffer.allocate(5).put(((major shl 5) or 26).toByte()).putInt(n.toInt()).array()
        fun tstr(s: String) = byteArrayOf((0x60 or s.length).toByte()) + s.toByteArray()
        return byteArrayOf(0xa3.toByte()) +
            tstr("exclusions") + byteArrayOf(0x81.toByte(), 0xa2.toByte()) + tstr("start") + head(0, start) + tstr("length") + head(0, length) +
            tstr("alg") + tstr("sha256") +
            tstr("hash") + byteArrayOf(0x58, hash.size.toByte()) + hash
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
