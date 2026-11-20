package diw.testservers

import diw.wallet.core.did.DidDocument
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.c2pa.C2paAuthoring
import diw.wallet.core.document.c2pa.C2paIdentity
import diw.wallet.core.document.c2pa.C2paManifests
import diw.wallet.core.document.c2pa.C2paSignRequest
import diw.wallet.core.document.c2pa.C2paSigned
import diw.wallet.core.document.c2pa.C2paWriter
import diw.wallet.core.document.c2pa.SignerPayloadOrder
import diw.wallet.core.document.c2pa.SoftBindingAlgorithms
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.JcaDocumentSigner
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.Timestamper
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.tsp.TimeStampRequest
import org.bouncycastle.tsp.TimeStampTokenGenerator
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Signing pictures and other files with C2PA manifests and CAWG identity assertions, checked with the wallet's own
 * validator; the c2pa-rs identity claims aggregation samples check the ICA validation steps.
 */
class C2paSigningTest {
    companion object {
        private val bc = BouncyCastleProvider()
        private val now = Date()
        private const val DOCUMENT_SIGNING = "1.3.6.1.5.5.7.3.36"

        private fun keys(ec: Boolean): KeyPair = if (ec) KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        else KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

        private fun cert(
            subject: String, issuer: String, key: KeyPair, signer: PrivateKey, ca: Boolean,
            eku: List<String> = emptyList(), issuerKey: PublicKey = key.public,
        ): X509CertificateHolder {
            val b = JcaX509v3CertificateBuilder(X500Name(issuer), BigInteger.valueOf(System.nanoTime()), Date(now.time - 86_400_000), Date(now.time + 86_400_000L * 365), X500Name(subject), key.public)
            val ext = JcaX509ExtensionUtils()
            b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(key.public))
            b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuerKey))
            b.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
            b.addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature or KeyUsage.nonRepudiation))
            // RFC 3161 requires the time stamping EKU to be critical.
            if (eku.isNotEmpty()) b.addExtension(Extension.extendedKeyUsage, KeyPurposeId.id_kp_timeStamping.id in eku, ExtendedKeyUsage(eku.map { KeyPurposeId.getInstance(ASN1ObjectIdentifier(it)) }.toTypedArray()))
            val alg = if (signer.algorithm == "RSA") "SHA256withRSA" else "SHA256withECDSA"
            return b.build(JcaContentSignerBuilder(alg).setProvider(bc).build(signer))
        }

        private val rootKey = keys(false)
        private val root = cert("CN=C2PA Signing Test Root", "CN=C2PA Signing Test Root", rootKey, rootKey.private, true)
        private val otherRootKey = keys(false)
        private val ecKey = keys(true)
        private val ecCert = cert("CN=Test Creator EC,O=DIW Test", "CN=C2PA Signing Test Root", ecKey, rootKey.private, false, listOf(DOCUMENT_SIGNING), rootKey.public)
        private val rsaKey = keys(false)
        private val rsaCert = cert("CN=Test Creator RSA", "CN=C2PA Signing Test Root", rsaKey, rootKey.private, false, listOf(DOCUMENT_SIGNING), rootKey.public)
        private val plainKey = keys(true)
        private val plainCert = cert("CN=Test Signer Without Profile", "CN=C2PA Signing Test Root", plainKey, rootKey.private, false, issuerKey = rootKey.public)
        private val strangerKey = keys(true)
        private val strangerCert = cert("CN=Test Stranger", "CN=Unknown Root", strangerKey, otherRootKey.private, false, listOf(DOCUMENT_SIGNING), otherRootKey.public)
        private val tsaKey = keys(false)
        private val tsaCert = cert("CN=C2PA Test TSA", "CN=C2PA Signing Test Root", tsaKey, rootKey.private, false, listOf(KeyPurposeId.id_kp_timeStamping.id), rootKey.public)

        /** The issuer of the c2pa-rs identity claims aggregation samples (an Ed25519 did:jwk). */
        private const val ADOBE_ISSUER = "did:web:connected-identities.identity-stage.adobe.com"
        private const val ICA_ISSUER = "did:jwk:eyJhbGciOiJFZERTQSIsImt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiTXA1LTBlODNuTmdRaGRoQlc4UnNoa2p5OTBzYTFBOUpJemtJdGNEcUN1SSJ9"
    }

    private fun signer(key: KeyPair, cert: X509CertificateHolder): DocumentSigner =
        JcaDocumentSigner(key.private, listOf(JcaX509CertificateConverter().getCertificate(cert)), SignerSource.PKCS12)

    /** A local RFC 3161 authority. */
    private val timestamper = Timestamper { data ->
        val req = TimeStampRequest(DocumentInspector.timestampRequest(data))
        val digests = JcaDigestCalculatorProviderBuilder().setProvider(bc).build()
        val gen = TimeStampTokenGenerator(
            JcaSignerInfoGeneratorBuilder(digests).build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(tsaKey.private), tsaCert),
            digests.get(org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1)),
            ASN1ObjectIdentifier("1.2.3.4.1"),
        )
        gen.addCertificates(JcaCertStore(listOf(tsaCert)))
        gen.generate(req, BigInteger.ONE, Date()).encoded
    }

    private val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
    /** did:web of the Adobe sample served from its saved DID document; everything else is offline. */
    private val dids = DidResolver(HttpClient(MockEngine { req ->
        if (req.url.toString() == "https://connected-identities.identity-stage.adobe.com/.well-known/did.json") {
            respond(javaClass.getResource("/c2pa/ica/connected_identities_did.json")!!.readText(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
        } else respond("", HttpStatusCode.NotFound)
    }))
    private var trustedIssuers = emptySet<String>()
    private val trust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision = registry.decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
        override suspend fun resolveDid(did: String): DidDocument = dids.resolve(did)
        override suspend fun decideDid(did: String, role: TrustRole): TrustDecision? =
            if (did in trustedIssuers) TrustDecision(TrustTier.T2, TrustEnvironment.USER, false, "ICA test issuer", emptySet()) else null
    }

    private suspend fun trustRoot() {
        for (role in listOf(TrustRole.CONTENT, TrustRole.DOCUMENT, TrustRole.TSA)) {
            registry.addAnchor(role, TrustEnvironment.USER, X509Cert(ByteString(root.encoded)), "C2PA Signing Test Root", official = false, source = "test")
        }
    }

    private suspend fun inspect(bytes: ByteArray, name: String, detached: ByteArray? = null): DocumentReport =
        DocumentInspector.inspect(bytes, name, trust, detached, Clock.System.now())

    private fun save(name: String, bytes: ByteArray) {
        System.getenv("DIW_SIGNED_OUT")?.let { dir -> File(dir).apply { mkdirs() }.resolve(name).writeBytes(bytes) }
    }

    private fun picture(format: String): ByteArray {
        val img = BufferedImage(16, 16, BufferedImage.TYPE_INT_RGB)
        for (x in 0 until 16) for (y in 0 until 16) img.setRGB(x, y, (x * 16) shl 16 or (y * 16 shl 8) or 0x80)
        return ByteArrayOutputStream().also { ImageIO.write(img, format, it) }.toByteArray()
    }

    /** A 1x1 lossless WebP. */
    private val webp = "RIFF".encodeToByteArray() + byteArrayOf(0x1a, 0, 0, 0) + "WEBPVP8L".encodeToByteArray() +
        byteArrayOf(0x0d, 0, 0, 0, 0x2f, 0, 0, 0, 0x10, 0x07, 0x10, 0x11, 0x11, 0x88.toByte(), 0x88.toByte(), 0xfe.toByte(), 0x07, 0x00)

    private fun request(title: String, authoring: C2paAuthoring = C2paAuthoring.Created("digitalCapture"), order: SignerPayloadOrder = SignerPayloadOrder.DETERMINISTIC) =
        C2paSignRequest(title, authoring, identity = true, roles = listOf("cawg.creator"), allowTraining = false, payloadOrder = order, generatorVersion = "test", time = Clock.System.now())

    private suspend fun sign(asset: ByteArray, request: C2paSignRequest, claim: DocumentSigner = signer(ecKey, ecCert), identity: DocumentSigner? = null, ts: Timestamper? = timestamper): C2paSigned =
        C2paWriter.sign(asset, request, claim, identity, ts)

    private fun DocumentReport.active() = c2pa!!.manifests.first { it.active }
    private fun DocumentReport.codes() = active().statuses.map { it.code }
    private fun C2paIdentity.codes() = statuses.map { it.code }

    private fun assertSignedAndTrusted(r: DocumentReport, name: String) {
        val codes = r.codes()
        for (c in listOf("claimSignature.validated", "assertion.dataHash.match", "assertion.hashedURI.match", "signingCredential.trusted", "timeStamp.validated", "timeStamp.trusted")) {
            assertTrue(c in codes, "$name: $c missing in $codes")
        }
        val id = r.active().identities.single()
        assertEquals(C2paWriter.X509_SIG_TYPE, id.sigType)
        assertTrue("cawg.x509.signature.validated" in id.codes(), "$name: ${id.codes()}")
        assertTrue("cawg.x509.credential.trusted" in id.codes(), "$name: ${id.codes()}")
        assertTrue("cawg.identity.trusted" in id.codes(), "$name: ${id.codes()} ${id.detail}")
        assertEquals(Check.PASS, id.signature)
        assertEquals(listOf("cawg.creator"), id.roles)
        assertTrue("c2pa.hash.data" in id.referenced, id.referenced.toString())
        assertEquals(Check.PASS, r.signatures.single().integrity, "$name: ${r.signatures.single().problems}")
    }

    @Test
    fun picturesAndSidecarRoundTrip() = runBlocking<Unit> {
        trustRoot()
        val samples = listOf("jpg" to picture("jpg"), "png" to picture("png"), "webp" to webp)
        for ((ext, bytes) in samples) {
            val signed = sign(bytes, request("測試圖片.$ext"))
            assertFalse(signed.sidecar, ext)
            save("signed-c2pa.$ext", signed.bytes)
            val r = inspect(signed.bytes, "signed.$ext")
            assertSignedAndTrusted(r, ext)
            val m = r.active()
            assertEquals("測試圖片.$ext", m.title)
            assertEquals(signed.manifestLabel, m.label)
            assertEquals(listOf("c2pa.created"), m.actions.map { it.action })
            assertEquals("digitalCapture", m.actions.first().digitalSourceType?.substringAfterLast('/'))
            assertTrue(m.training.isNotEmpty(), "cawg.training-mining is read")
            assertEquals("ES256", r.signatures.single().algorithm)
        }

        val asset = "這是一份要附 C2PA 外部清單的文字檔。\n".encodeToByteArray()
        val sidecar = sign(asset, request("說明.txt", C2paAuthoring.Opened))
        assertTrue(sidecar.sidecar)
        assertTrue(C2paManifests.isSidecar(sidecar.bytes))
        save("note.txt.c2pa", sidecar.bytes)
        val r = inspect(sidecar.bytes, "說明.txt.c2pa", asset)
        assertSignedAndTrusted(r, "sidecar")
        assertEquals(listOf("c2pa.opened"), r.active().actions.map { it.action })
        val tampered = inspect(sidecar.bytes, "說明.txt.c2pa", asset + 0x20)
        assertTrue("assertion.dataHash.mismatch" in tampered.codes(), tampered.codes().toString())
    }

    @Test
    fun rsaKeysSignWithPss() = runBlocking<Unit> {
        trustRoot()
        val rsa = signer(rsaKey, rsaCert)
        val signed = sign(picture("jpg"), request("rsa.jpg"), claim = rsa)
        val r = inspect(signed.bytes, "rsa.jpg")
        assertSignedAndTrusted(r, "rsa")
        assertEquals("PS256", r.signatures.single().algorithm)
        assertEquals("PS256", r.active().identities.single().x509?.algorithm)
    }

    @Test
    fun c2paRsPayloadOrderAndSeparateIdentityKey() = runBlocking<Unit> {
        trustRoot()
        val signed = sign(picture("png"), request("order.png", order = SignerPayloadOrder.C2PA_RS), claim = signer(rsaKey, rsaCert), identity = signer(ecKey, ecCert))
        save("c2pa-rs-order.png", signed.bytes)
        val r = inspect(signed.bytes, "order.png")
        assertSignedAndTrusted(r, "c2pa-rs order")
        val id = r.active().identities.single()
        assertTrue("Test Creator EC" in id.names, id.names.toString())
        assertEquals("ES256", id.x509?.algorithm)
    }

    @Test
    fun identityWithoutTheCawgProfileIsOnlyWellFormed() = runBlocking<Unit> {
        trustRoot()
        val signed = sign(picture("jpg"), request("plain.jpg"), identity = signer(plainKey, plainCert))
        val id = inspect(signed.bytes, "plain.jpg").active().identities.single()
        assertTrue("cawg.x509.signature.validated" in id.codes(), id.codes().toString())
        assertTrue("cawg.identity.well-formed" in id.codes(), id.codes().toString())
        assertFalse("cawg.identity.trusted" in id.codes())
        assertEquals(Check.WARN, id.signature)
        assertFalse(id.trusted)
        assertTrue(id.detail.isNotEmpty(), "the missing document signing profile is explained")
    }

    @Test
    fun identityUnderAnUnknownRootIsUntrustedButWellFormed() = runBlocking<Unit> {
        trustRoot()
        val signed = sign(picture("jpg"), request("stranger.jpg"), identity = signer(strangerKey, strangerCert))
        val r = inspect(signed.bytes, "stranger.jpg")
        assertTrue("claimSignature.validated" in r.codes())
        val id = r.active().identities.single()
        assertTrue("cawg.x509.credential.untrusted" in id.codes(), id.codes().toString())
        assertTrue("cawg.identity.well-formed" in id.codes(), id.codes().toString())
        assertEquals(Check.WARN, id.signature)
    }

    @Test
    fun resigningKeepsTheEarlierManifestAsIngredient() = runBlocking<Unit> {
        trustRoot()
        val first = sign(picture("jpg"), request("first.jpg"))
        val second = sign(first.bytes, request("second.jpg", C2paAuthoring.Opened), ts = null)
        save("resigned-c2pa.jpg", second.bytes)
        val r = inspect(second.bytes, "second.jpg")
        assertEquals(2, r.c2pa!!.manifests.size)
        val m = r.active()
        assertEquals(second.manifestLabel, m.label)
        assertEquals("second.jpg", m.title)
        assertEquals(listOf("c2pa.opened"), m.actions.map { it.action })
        val parent = m.ingredients.single()
        assertEquals("parentOf", parent.relationship)
        assertTrue(parent.manifest?.contains(first.manifestLabel) == true, parent.toString())
        assertTrue("claimSignature.validated" in r.codes(), r.codes().toString())
        assertTrue("assertion.dataHash.match" in r.codes(), r.codes().toString())
        // Without its own time stamp the identity is checked at the current time.
        assertTrue("cawg.identity.trusted" in m.identities.single().codes(), m.identities.single().codes().toString())
    }

    @Test
    fun changedPixelsBreakTheDataHash() = runBlocking<Unit> {
        trustRoot()
        val signed = sign(picture("jpg"), request("tamper.jpg")).bytes.copyOf()
        signed[signed.size - 10] = (signed[signed.size - 10].toInt() xor 0x01).toByte()
        val r = inspect(signed, "tamper.jpg")
        assertTrue("assertion.dataHash.mismatch" in r.codes(), r.codes().toString())
        assertEquals(Check.FAIL, r.signatures.single().integrity)
        // The identity assertion covers the data hash assertion, which is unchanged.
        assertTrue("cawg.x509.signature.validated" in r.active().identities.single().codes())
    }

    @Test
    fun aiGenerationIsDeclaredAndSigned() = runBlocking<Unit> {
        trustRoot()
        val signed = sign(picture("png"), request("ai.png", C2paAuthoring.Created("trainedAlgorithmicMedia")))
        val ai = assertNotNull(inspect(signed.bytes, "ai.png").aiProvenance)
        assertTrue(ai.aiDeclared)
        val d = ai.declarations.single { it.source == "c2pa" }
        assertEquals("trainedAlgorithmicMedia", d.code)
        assertEquals(true, d.signed)
        assertTrue(d.active)
        assertFalse(ai.synthIdPossible, "the wallet is not a Google tool")

        val camera = inspect(sign(picture("png"), request("camera.png")).bytes, "camera.png").aiProvenance
        assertNotNull(camera)
        assertFalse(camera.aiDeclared)
    }

    @Test
    fun xmpGoogleAiDeclarationSuggestsSynthId() = runBlocking<Unit> {
        val xmp = """<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">""" +
            """<rdf:Description xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/" xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" """ +
            """Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia" photoshop:Credit="Made with Google AI"/>""" +
            """</rdf:RDF></x:xmpmeta>"""
        val payload = "http://ns.adobe.com/xap/1.0/\u0000".encodeToByteArray() + xmp.encodeToByteArray()
        val jpeg = picture("jpg")
        val app1 = byteArrayOf(0xFF.toByte(), 0xE1.toByte(), ((payload.size + 2) shr 8).toByte(), (payload.size + 2).toByte()) + payload
        val withXmp = jpeg.copyOfRange(0, 2) + app1 + jpeg.copyOfRange(2, jpeg.size)
        val r = inspect(withXmp, "gemini.jpg")
        assertNull(r.c2pa)
        val ai = assertNotNull(r.aiProvenance)
        assertEquals(listOf("trainedAlgorithmicMedia"), ai.declarations.map { it.code })
        assertEquals("xmp", ai.declarations.single().source)
        assertNull(ai.declarations.single().signed)
        assertTrue(ai.googleAi)
        assertTrue(ai.synthIdPossible)
        assertFalse(ai.synthIdDeclared)
        assertTrue("Made with Google AI" in ai.aiTools)
    }

    @Test
    fun softBindingListIsBundled() {
        assertTrue(SoftBindingAlgorithms.ALL.size > 50)
        assertTrue(SoftBindingAlgorithms.ALL.all { it.alg.isNotBlank() })
        assertNull(SoftBindingAlgorithms.find("com.example.not-registered"))
        val first = SoftBindingAlgorithms.ALL.first()
        assertEquals(first, SoftBindingAlgorithms.find(first.alg))
    }

    // ---- c2pa-rs identity claims aggregation samples ----

    private fun ica(name: String): C2paIdentity = runBlocking {
        val bytes = javaClass.getResourceAsStream("/c2pa/ica/$name")!!.readBytes()
        inspect(bytes, name).active().identities.single()
    }

    @Test
    fun adobeIcaSampleIsValidWhenItsIssuerIsTrusted() {
        trustedIssuers = setOf(ADOBE_ISSUER)
        val id = ica("adobe_connected_identities.jpg")
        assertEquals("cawg.identity_claims_aggregation", id.sigType)
        assertTrue("cawg.ica.credential_valid" in id.codes(), id.codes().toString())
        assertTrue("cawg.identity.trusted" in id.codes(), id.codes().toString())
        assertEquals(Check.PASS, id.signature, id.statuses.toString())
        val v = id.verifiedIdentities.single()
        assertEquals("cawg.social_media", v.type)
        assertEquals("testuser23", v.username)
        assertEquals("cawg.federated_login", v.method)
    }

    @Test
    fun icaSampleWithAnUnknownIssuerIsWellFormed() {
        trustedIssuers = emptySet()
        val id = ica("adobe_connected_identities.jpg")
        assertTrue("cawg.ica.untrusted_issuer" in id.codes(), id.codes().toString())
        assertTrue("cawg.identity.well-formed" in id.codes(), id.codes().toString())
        assertFalse("cawg.ica.credential_valid" in id.codes())
        assertEquals(Check.WARN, id.signature)
    }

    @Test
    fun c2paRsIcaSamples() {
        trustedIssuers = setOf(ICA_ISSUER)
        // Signature and binding hold (c2pa-rs writes the hash as the bytes of its base64 text), but its
        // cawg.crypto_wallet entry has no address, which CAWG requires.
        val success = ica("success.jpg")
        assertFalse("cawg.ica.signature_mismatch" in success.codes(), success.codes().toString())
        assertFalse("cawg.ica.signer_payload.mismatch" in success.codes(), success.codes().toString())
        assertEquals(listOf("cawg.ica.verified_identities.invalid"), success.statuses.filter { !it.success && !it.informational }.map { it.code })
        assertEquals(4, success.verifiedIdentities.size)

        val signature = ica("signature_mismatch.jpg")
        assertTrue("cawg.ica.signature_mismatch" in signature.codes(), signature.codes().toString())
        assertEquals(Check.FAIL, signature.signature)
        val payload = ica("signer_payload_mismatch.jpg")
        assertTrue("cawg.ica.signer_payload.mismatch" in payload.codes(), payload.codes().toString())
        assertEquals(Check.FAIL, payload.signature)
    }
}
