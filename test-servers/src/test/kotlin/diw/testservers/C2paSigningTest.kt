package diw.testservers

import diw.wallet.core.did.DidDocument
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.c2pa.C2paAuthoring
import diw.wallet.core.document.c2pa.C2paBinding
import diw.wallet.core.document.c2pa.C2paBoxHash
import diw.wallet.core.document.c2pa.C2paContainers
import diw.wallet.core.document.c2pa.C2paFormat
import diw.wallet.core.document.c2pa.C2paIdentity
import diw.wallet.core.document.c2pa.C2paManifests
import diw.wallet.core.document.c2pa.C2paSignRequest
import diw.wallet.core.document.c2pa.C2paSigned
import diw.wallet.core.document.c2pa.C2paWriter
import diw.wallet.core.document.c2pa.SignerPayloadOrder
import diw.wallet.core.document.c2pa.SoftBindingAlgorithms
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.JcaDocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
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
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Date
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.imageio.IIOImage
import javax.imageio.ImageIO
import javax.sound.sampled.AudioFileFormat
import javax.sound.sampled.AudioFormat
import javax.sound.sampled.AudioInputStream
import javax.sound.sampled.AudioSystem
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

    private fun request(title: String, authoring: C2paAuthoring = C2paAuthoring.Created("digitalCapture"), order: SignerPayloadOrder = SignerPayloadOrder.DETERMINISTIC, binding: C2paBinding? = null) =
        C2paSignRequest(title, authoring, identity = true, roles = listOf("cawg.creator"), allowTraining = false, payloadOrder = order, generatorVersion = "test", time = Clock.System.now(), binding = binding)

    private suspend fun sign(asset: ByteArray, request: C2paSignRequest, claim: DocumentSigner = signer(ecKey, ecCert), identity: DocumentSigner? = null, ts: Timestamper? = timestamper): C2paSigned =
        C2paWriter.sign(asset, request, claim, identity, ts)

    private fun DocumentReport.active() = c2pa!!.manifests.first { it.active }
    private fun DocumentReport.codes() = active().statuses.map { it.code }
    private fun C2paIdentity.codes() = statuses.map { it.code }

    private fun assertSignedAndTrusted(r: DocumentReport, name: String, match: String = "assertion.dataHash.match", hashLabel: String = "c2pa.hash.data") {
        val codes = r.codes()
        for (c in listOf("claimSignature.validated", match, "assertion.hashedURI.match", "signingCredential.trusted", "timeStamp.validated", "timeStamp.trusted")) {
            assertTrue(c in codes, "$name: $c missing in $codes")
        }
        val id = r.active().identities.single()
        assertEquals(C2paWriter.X509_SIG_TYPE, id.sigType)
        assertTrue("cawg.x509.signature.validated" in id.codes(), "$name: ${id.codes()}")
        assertTrue("cawg.x509.credential.trusted" in id.codes(), "$name: ${id.codes()}")
        assertTrue("cawg.identity.trusted" in id.codes(), "$name: ${id.codes()} ${id.detail}")
        assertEquals(Check.PASS, id.signature)
        assertEquals(listOf("cawg.creator"), id.roles)
        assertTrue(id.referenced.any { it.startsWith(hashLabel) }, id.referenced.toString())
        val c2pa = r.signatures.last()
        assertEquals(Check.PASS, c2pa.integrity, "$name: ${c2pa.problems}")
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
            assertEquals("ES256", r.signatures.last().algorithm)
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
    fun algorithmThatDoesNotFitTheCertificateIsAMismatch() = runBlocking<Unit> {
        trustRoot()
        // ES256 signatures under an RSA certificate: the report must say the signature does not match, not drop it.
        val mislabeled = object : DocumentSigner {
            override val certificateChain = listOf(rsaCert.encoded)
            override val keyType = SignerKeyType.EC_P256
            override val source = SignerSource.PKCS12
            override suspend fun sign(data: ByteArray): ByteArray = java.security.Signature.getInstance("SHA256withECDSA").run {
                initSign(ecKey.private); update(data); sign()
            }
        }
        val signed = sign(picture("jpg"), request("mislabeled.jpg"), claim = mislabeled, ts = null)
        val r = inspect(signed.bytes, "mislabeled.jpg")
        assertTrue("claimSignature.mismatch" in r.codes(), r.codes().toString())
        assertEquals(Check.FAIL, r.signatures.single().integrity)
        assertEquals(DocumentVerdict.INVALID, r.verdict)
        assertTrue("cawg.x509.signature.mismatch" in r.active().identities.single().codes())
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

    // ---------------------------------------------------------------- other containers (C2PA 2.2 Appendix A)

    private fun fixture(name: String): ByteArray = javaClass.getResource("/c2pa/containers/$name")!!.readBytes()

    private fun be32(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    private fun le32(v: Int) = byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte())
    private fun bmffBox(type: String, body: ByteArray) = be32(8 + body.size) + type.encodeToByteArray() + body
    private fun riffChunk(id: String, body: ByteArray) = id.encodeToByteArray() + le32(body.size) + body + if (body.size % 2 == 1) byteArrayOf(0) else ByteArray(0)

    /** Media data that is easy to find again in a signed file. */
    private fun payload(n: Int) = ByteArray(n) { ((it * 31 + 7) % 251).toByte() }

    /** An MP4 whose sample table points into mdat, so moving mdat must move the chunk offset. */
    private fun mp4(): ByteArray {
        val ftyp = bmffBox("ftyp", "isom".encodeToByteArray() + be32(0x200) + "isommp41".encodeToByteArray())
        fun moov(offset: Int) = bmffBox("moov", bmffBox("trak", bmffBox("mdia", bmffBox("minf", bmffBox("stbl",
            bmffBox("stco", be32(0) + be32(1) + be32(offset)))))))
        val size = ftyp.size + moov(0).size
        return ftyp + moov(size + 8) + bmffBox("mdat", payload(4096))
    }

    private fun stcoTarget(b: ByteArray): Int {
        val at = indexOf(b, "stco".encodeToByteArray())
        return java.nio.ByteBuffer.wrap(b, at + 12, 4).int
    }

    private fun wav(): ByteArray {
        val pcm = payload(8000)
        val out = ByteArrayOutputStream()
        AudioSystem.write(AudioInputStream(ByteArrayInputStream(pcm), AudioFormat(8000f, 16, 1, true, false), pcm.size / 2L), AudioFileFormat.Type.WAVE, out)
        return out.toByteArray()
    }

    private fun avi(): ByteArray {
        val hdrl = "hdrl".encodeToByteArray() + riffChunk("avih", ByteArray(56))
        val movi = "movi".encodeToByteArray() + riffChunk("00dc", payload(3001))
        val body = "AVI ".encodeToByteArray() + riffChunk("LIST", hdrl) + riffChunk("LIST", movi) + riffChunk("idx1", ByteArray(16))
        return "RIFF".encodeToByteArray() + le32(body.size) + body
    }

    /** Three MPEG-1 Layer III frames (128 kbit/s, 44.1 kHz). */
    private fun mp3(): ByteArray = (0 until 3).fold(ByteArray(0)) { a, i ->
        a + byteArrayOf(0xFF.toByte(), 0xFB.toByte(), 0x90.toByte(), 0x00) + payload(413).also { it[0] = i.toByte() }
    }

    private fun flac(): ByteArray = "fLaC".encodeToByteArray() + byteArrayOf(0x80.toByte(), 0, 0, 34) + payload(34) +
        byteArrayOf(0xFF.toByte(), 0xF8.toByte()) + payload(2000)

    private fun jxlCodestream(): ByteArray = byteArrayOf(0xFF.toByte(), 0x0A) + payload(3000)

    private fun jxlContainer(): ByteArray = be32(12) + "JXL ".encodeToByteArray() + byteArrayOf(0x0D, 0x0A, 0x87.toByte(), 0x0A) +
        bmffBox("ftyp", "jxl ".encodeToByteArray() + be32(0) + "jxl ".encodeToByteArray()) + bmffBox("jxlc", jxlCodestream())

    private val svg = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\">" +
        "<title>測試向量圖</title><rect width=\"16\" height=\"16\" fill=\"#c00\"/>" + "<!-- padding -->".repeat(64) + "</svg>\n").encodeToByteArray()

    private fun tiff(pages: Int): ByteArray {
        val writer = ImageIO.getImageWritersByFormatName("tiff").next()
        val out = ByteArrayOutputStream()
        ImageIO.createImageOutputStream(out).use { ios ->
            writer.output = ios
            if (pages == 1) writer.write(BufferedImage(16, 16, BufferedImage.TYPE_INT_RGB).also { fill(it) })
            else {
                writer.prepareWriteSequence(null)
                repeat(pages) { writer.writeToSequence(IIOImage(BufferedImage(16, 16, BufferedImage.TYPE_INT_RGB).also { fill(it) }, null, null), null) }
                writer.endWriteSequence()
            }
        }
        writer.dispose()
        return out.toByteArray()
    }

    private fun tiffDirectories(b: ByteArray): Int = ImageIO.createImageInputStream(ByteArrayInputStream(b)).use { input ->
        val reader = ImageIO.getImageReadersByFormatName("tiff").next()
        reader.input = input
        reader.getNumImages(true).also { reader.dispose() }
    }

    private fun fill(img: BufferedImage) { for (x in 0 until 16) for (y in 0 until 16) img.setRGB(x, y, (x * 16) shl 16 or (y * 16 shl 8) or 0x80) }

    /** A ZIP with a stored entry, a deflated one written with a data descriptor, a directory and a non-ASCII name. */
    private fun zip(): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { z ->
            val text = "這是封存檔裡的文字。\n".repeat(40).encodeToByteArray()
            z.putNextEntry(ZipEntry("docs/"))
            z.closeEntry()
            z.putNextEntry(ZipEntry("docs/說明.txt"))
            z.write(text)
            z.closeEntry()
            val raw = payload(2000)
            z.putNextEntry(ZipEntry("data.bin").apply { method = ZipEntry.STORED; size = raw.size.toLong(); compressedSize = raw.size.toLong(); crc = CRC32().also { it.update(raw) }.value })
            z.write(raw)
            z.closeEntry()
        }
        return out.toByteArray()
    }

    /** A ZIP whose names are code page 437 without the UTF-8 flag; both names are one non-ASCII byte apart. */
    private fun zipCp437(): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out, java.nio.charset.Charset.forName("IBM437")).use { z ->
            for (n in listOf("\u00E9.txt", "\u00E2.txt")) {
                z.putNextEntry(ZipEntry(n))
                z.write(payload(1500).also { it[0] = n[0].code.toByte() })
                z.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private fun indexOf(b: ByteArray, x: ByteArray, from: Int = 0): Int {
        outer@ for (i in from..b.size - x.size) { for (j in x.indices) if (b[i + j] != x[j]) continue@outer; return i }
        return -1
    }

    /** [signed] with one byte flipped inside content that [original] had in the middle (not the manifest). */
    private fun tamper(original: ByteArray, signed: ByteArray): ByteArray {
        val mid = original.size / 2
        val probe = original.copyOfRange(mid, mid + 16)
        val at = indexOf(signed, probe)
        assertTrue(at >= 0, "the original content is kept")
        return signed.copyOf().also { it[at + 8] = (it[at + 8].toInt() xor 0x01).toByte() }
    }

    private class Case(val name: String, val bytes: ByteArray, val format: C2paFormat, val match: String, val label: String, val binding: C2paBinding? = null)

    private fun cases() = listOf(
        Case("gif", picture("gif"), C2paFormat.GIF, "assertion.dataHash.match", "c2pa.hash.data"),
        Case("tif", tiff(1), C2paFormat.TIFF, "assertion.dataHash.match", "c2pa.hash.data"),
        Case("pages.tif", tiff(3), C2paFormat.TIFF, "assertion.dataHash.match", "c2pa.hash.data"),
        Case("wav", wav(), C2paFormat.WAV, "assertion.dataHash.match", "c2pa.hash.data"),
        Case("avi", avi(), C2paFormat.AVI, "assertion.dataHash.match", "c2pa.hash.data"),
        Case("mp3", mp3(), C2paFormat.MP3, "assertion.dataHash.match", "c2pa.hash.data"),
        Case("flac", flac(), C2paFormat.FLAC, "assertion.dataHash.match", "c2pa.hash.data"),
        Case("svg", svg, C2paFormat.SVG, "assertion.dataHash.match", "c2pa.hash.data"),
        Case("jxl", jxlCodestream(), C2paFormat.JXL, "assertion.boxesHash.match", "c2pa.hash.boxes"),
        Case("box.jxl", jxlContainer(), C2paFormat.JXL, "assertion.boxesHash.match", "c2pa.hash.boxes"),
        Case("data.jxl", jxlContainer(), C2paFormat.JXL, "assertion.dataHash.match", "c2pa.hash.data", C2paBinding.DATA),
        Case("mp4", mp4(), C2paFormat.BMFF, "assertion.bmffHash.match", "c2pa.hash.bmff"),
        Case("avif", fixture("sample1.avif"), C2paFormat.BMFF, "assertion.bmffHash.match", "c2pa.hash.bmff"),
        Case("pdf", fixture("basic.pdf"), C2paFormat.PDF, "assertion.dataHash.match", "c2pa.hash.data"),
        Case("zip", zip(), C2paFormat.ZIP, "assertion.collectionHash.match", "c2pa.hash.collection"),
        Case("cp437.zip", zipCp437(), C2paFormat.ZIP, "assertion.collectionHash.match", "c2pa.hash.collection"),
        Case("docx", fixture("sample1.docx"), C2paFormat.ZIP, "assertion.collectionHash.match", "c2pa.hash.collection"),
        Case("odt", fixture("sample1.odt"), C2paFormat.ZIP, "assertion.collectionHash.match", "c2pa.hash.collection"),
        Case("box.jpg", picture("jpg"), C2paFormat.JPEG, "assertion.boxesHash.match", "c2pa.hash.boxes", C2paBinding.BOXES),
        Case("box.png", picture("png"), C2paFormat.PNG, "assertion.boxesHash.match", "c2pa.hash.boxes", C2paBinding.BOXES),
        Case("box.gif", picture("gif"), C2paFormat.GIF, "assertion.boxesHash.match", "c2pa.hash.boxes", C2paBinding.BOXES),
    )

    @Test
    fun everyContainerRoundTrips() = runBlocking<Unit> {
        trustRoot()
        for (c in cases()) {
            assertEquals(c.format, C2paContainers.detect(c.bytes), c.name)
            val signed = sign(c.bytes, request("測試檔.${c.name}", C2paAuthoring.Opened, binding = c.binding))
            assertFalse(signed.sidecar, "${c.name}: ${signed.sidecarReason}")
            assertEquals(c.format.title, signed.container, c.name)
            assertEquals(c.format, C2paContainers.detect(signed.bytes), "${c.name} keeps its format")
            save("signed-c2pa.${c.name}", signed.bytes)
            val r = inspect(signed.bytes, "signed.${c.name}")
            assertEquals(c.format.title, r.c2pa?.container, c.name)
            assertSignedAndTrusted(r, c.name, c.match, c.label)
            assertEquals(listOf("c2pa.opened"), r.active().actions.map { it.action }, c.name)

            // Signing again keeps the first manifest as the parent ingredient and replaces the store.
            val again = sign(signed.bytes, request("測試檔.${c.name}", C2paAuthoring.Opened, binding = c.binding))
            val r2 = inspect(again.bytes, "again.${c.name}")
            assertEquals(2, r2.c2pa!!.manifests.size, c.name)
            assertSignedAndTrusted(r2, "${c.name} again", c.match, c.label)
            if (c.format == C2paFormat.TIFF) {
                // The C2PA-only last IFD of a multi-page TIFF is replaced, not left behind as an empty directory.
                val pages = tiffDirectories(c.bytes)
                val expected = if (pages > 1) pages + 1 else pages
                assertEquals(expected, tiffDirectories(signed.bytes), c.name)
                assertEquals(expected, tiffDirectories(again.bytes), "${c.name} again")
            }

            val bad = inspect(tamper(c.bytes, signed.bytes), "tampered.${c.name}")
            assertTrue(bad.codes().any { it.endsWith(".mismatch") }, "${c.name}: ${bad.codes()}")
        }
    }

    @Test
    fun svgManifestElementWithAttributesIsFound() = runBlocking<Unit> {
        trustRoot()
        val signed = sign(svg, request("向量圖.svg", C2paAuthoring.Opened)).bytes.decodeToString()
        // The namespace declared on the element itself, and white space before the closing brackets.
        val moved = signed.replace(" xmlns:c2pa=\"http://c2pa.org/manifest\"", "")
            .replace("<c2pa:manifest>", "<c2pa:manifest xmlns:c2pa='http://c2pa.org/manifest' >")
            .replace("</c2pa:manifest>", "</c2pa:manifest >").encodeToByteArray()
        assertNotNull(C2paManifests.read(moved), "the store is found")
        val again = sign(moved, request("向量圖.svg", C2paAuthoring.Opened))
        val r = inspect(again.bytes, "again.svg")
        assertEquals(2, r.c2pa!!.manifests.size, "the earlier manifest is kept as the parent")
        assertSignedAndTrusted(r, "svg again")
        assertEquals(1, Regex("<c2pa:manifest").findAll(again.bytes.decodeToString()).count(), "the old element is removed")
    }

    @Test
    fun bmffOffsetsFollowTheMovedMediaData() = runBlocking<Unit> {
        trustRoot()
        val original = mp4()
        val target = stcoTarget(original)
        val expected = original.copyOfRange(target, target + 32)
        val signed = sign(original, request("影片.mp4", C2paAuthoring.Opened)).bytes
        val moved = stcoTarget(signed)
        assertTrue(moved > target, "the store goes before mdat")
        assertTrue(signed.copyOfRange(moved, moved + 32).contentEquals(expected), "stco points at the same samples")
        val stripped = C2paContainers.strip(signed, C2paFormat.BMFF)
        assertTrue(stripped.contentEquals(original), "removing the store restores the file")
    }

    @Test
    fun strippingRestoresTheOriginalFile() = runBlocking<Unit> {
        trustRoot()
        // PDF keeps its incremental update, TIFF the rewritten IFD, JPEG XL its container, GIF its version 89a, SVG
        // the c2pa namespace, an ID3 tag stays and ZIP the META-INF directory; the other containers come back as they were.
        for (c in cases().filter { it.format !in setOf(C2paFormat.PDF, C2paFormat.TIFF, C2paFormat.JXL, C2paFormat.GIF, C2paFormat.MP3, C2paFormat.ZIP, C2paFormat.SVG) }) {
            val signed = sign(c.bytes, request("測試檔.${c.name}", C2paAuthoring.Opened, binding = c.binding)).bytes
            assertTrue(C2paContainers.strip(signed, c.format).contentEquals(c.bytes), c.name)
        }
    }

    @Test
    fun pdfThatCannotTakeAnUpdateGetsASidecar() = runBlocking<Unit> {
        trustRoot()
        val pdf = fixture("basic.pdf")
        val text = pdf.decodeToString()
        // A catalog with /Perms /DocMDP: an approval signature would be allowed, a C2PA update would break the certification.
        val certified = text.replaceFirst("/Type /Catalog", "/Type /Catalog /Perms << /DocMDP 99 0 R >>").encodeToByteArray()
        if (!certified.contentEquals(pdf)) {
            val out = sign(certified, request("認證.pdf", C2paAuthoring.Opened))
            assertTrue(out.sidecar)
            assertNotNull(out.sidecarReason)
        }
    }

    @Test
    fun c2paRsSamplesOfOtherBindings() = runBlocking<Unit> {
        // The box hash c2pa-rs computed for boxhash.jpg (boxhash.json): the same box names and the same hashes.
        val jpeg = fixture("boxhash.jpg")
        val boxes = C2paBoxHash.boxes(jpeg, C2paFormat.JPEG)
        val expected = Json.parseToJsonElement(fixture("boxhash.json").decodeToString()).jsonObject["boxes"]!!.jsonArray
        assertEquals(expected.flatMap { e -> e.jsonObject["names"]!!.jsonArray.map { it.jsonPrimitive.content } }, boxes.map { it.name })
        var i = 0
        for (e in expected) {
            val names = e.jsonObject["names"]!!.jsonArray
            val group = boxes.subList(i, i + names.size)
            i += names.size
            if (names.size == 1 && names[0].jsonPrimitive.content == C2paBoxHash.C2PA) continue
            val hash = e.jsonObject["hash"]!!.jsonArray.map { it.jsonPrimitive.int.toByte() }.toByteArray()
            val data = jpeg.copyOfRange(group.first().start.toInt(), group.last().end.toInt())
            assertTrue(java.security.MessageDigest.getInstance("SHA-256").digest(data).contentEquals(hash), names.toString())
        }
        val dash = inspect(fixture("dashinit.mp4"), "dashinit.mp4")
        assertTrue(dash.codes().none { it.endsWith(".mismatch") || it.endsWith(".malformed") }, dash.codes().toString())
        assertTrue("assertion.bmffHash.match" in dash.codes(), dash.codes().toString())
        assertTrue("claimSignature.validated" in dash.codes(), dash.codes().toString())
    }

    /**
     * The larger signed samples of c2pa-rs (sdk/tests/fixtures), which are not kept in this repository: run with
     * DIW_C2PA_FIXTURES set to that folder.
     */
    @Test
    fun c2paRsLargeSamples() = runBlocking<Unit> {
        val dir = System.getenv("DIW_C2PA_FIXTURES")?.let(::File)?.takeIf { it.isDirectory } ?: return@runBlocking
        for (name in listOf("video1.mp4", "legacy.mp4", "express-signed.pdf", "C.jpg", "CA.jpg", "exp-test1.png")) {
            val f = dir.resolve(name).takeIf { it.isFile } ?: continue
            val r = inspect(f.readBytes(), name)
            val codes = r.codes()
            println("$name: ${r.c2pa?.container} $codes")
            assertTrue(codes.none { it.endsWith(".mismatch") || it.endsWith(".malformed") || it == "assertion.missing" }, "$name: $codes")
            assertTrue(codes.any { it.endsWith("Hash.match") }, "$name: $codes")
        }
    }
}

