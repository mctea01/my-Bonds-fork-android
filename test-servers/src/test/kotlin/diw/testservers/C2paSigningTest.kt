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
import diw.wallet.core.document.c2pa.C2paBmff
import diw.wallet.core.document.c2pa.C2paBindings
import diw.wallet.core.document.c2pa.C2paBoxHash
import diw.wallet.core.document.c2pa.C2paCbor
import diw.wallet.core.document.c2pa.C2paContainers
import diw.wallet.core.document.c2pa.C2paFormat
import diw.wallet.core.document.c2pa.C2paIdentity
import diw.wallet.core.document.c2pa.C2paIdentityAggregation
import diw.wallet.core.document.c2pa.CawgAggregation
import diw.wallet.core.document.c2pa.CawgVerifiedIdentity
import diw.wallet.core.document.c2pa.IcaSigner
import diw.wallet.core.document.sign.SigningException
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborInt
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.Tstr
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.EcPublicKeyOkp
import org.multipaz.crypto.EcSignature
import diw.wallet.core.document.c2pa.C2paManifests
import diw.wallet.core.document.c2pa.C2paRange
import diw.wallet.core.document.c2pa.C2paSignRequest
import diw.wallet.core.document.c2pa.C2paSigned
import diw.wallet.core.document.c2pa.C2paWriter
import diw.wallet.core.document.c2pa.C2paZip
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
        private const val BASE = 8
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

    // ---- the wallet as identity claims aggregator ----

    /** An aggregator signer of a JCA key: P-256 signs ES256 (r||s), Ed25519 signs EdDSA. */
    private suspend fun icaSigner(ed25519: Boolean): IcaSigner {
        if (ed25519) {
            val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
            // The X.509 SubjectPublicKeyInfo of Ed25519 ends with the 32 bytes of the key.
            val x = kp.public.encoded.takeLast(32).toByteArray()
            return IcaSigner.of(EcPublicKeyOkp(EcCurve.ED25519, x)) { data ->
                java.security.Signature.getInstance("Ed25519").run { initSign(kp.private); update(data); sign() }
            }
        }
        val kp = keys(true)
        val pub = kp.public as java.security.interfaces.ECPublicKey
        fun fixed(v: BigInteger) = v.toByteArray().let { b -> if (b.size > 32) b.copyOfRange(b.size - 32, b.size) else ByteArray(32 - b.size) + b }
        return IcaSigner.of(EcPublicKeyDoubleCoordinate(EcCurve.P256, fixed(pub.w.affineX), fixed(pub.w.affineY))) { data ->
            val der = java.security.Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(data); sign() }
            EcSignature.fromDerEncoded(256, der).toCoseEncoded()
        }
    }

    private val verifiedAt = Instant.parse("2026-11-01T08:00:00Z")

    private fun person() = CawgVerifiedIdentity(
        type = CawgAggregation.DOCUMENT_VERIFICATION, name = "王小明", verifiedAt = verifiedAt,
        providerId = "https://issuer.example.gov.tw", providerName = "測試發證機關",
    )

    private fun aggregationRequest(signer: IcaSigner, identity: Boolean, identities: List<CawgVerifiedIdentity> = listOf(person())) =
        request("彙整.jpg").copy(identity = identity, aggregation = C2paIdentityAggregation(signer, identities))

    /** The credential and protected header of an identity assertion of [bytes]. */
    private fun icaParts(bytes: ByteArray, label: String): Pair<kotlinx.serialization.json.JsonObject, Map<Long, Any?>> {
        val store = C2paManifests.read(bytes)!!
        val box = C2paManifests.identityBoxes(store.active!!).single { it.label == label }
        val cbor = Cbor.decode(box.content("cbor")!!) as CborMap
        val sig = (cbor.items.entries.single { (k, _) -> (k as Tstr).value == "signature" }.value as Bstr).value
        val cose = C2paManifests.cose(sig)
        val prot = (Cbor.decode(cose.protectedBytes) as CborMap).items.entries.associate { (k, v) ->
            (k as CborInt).asNumber to when (v) { is Tstr -> v.value; is Bstr -> v.value.decodeToString(); is CborInt -> v.asNumber; else -> null }
        }
        return Json.parseToJsonElement(cose.payload!!.decodeToString()).jsonObject to prot
    }

    @Test
    fun walletIssuesAnIdentityClaimsAggregation() = runBlocking<Unit> {
        trustRoot()
        val signer = icaSigner(ed25519 = false)
        assertTrue(signer.did.startsWith("did:jwk:"))
        val signed = sign(picture("jpg"), aggregationRequest(signer, identity = false))
        save("ica-es256.jpg", signed.bytes)

        trustedIssuers = emptySet()
        val untrusted = inspect(signed.bytes, "ica.jpg").active().identities.single()
        assertEquals(CawgAggregation.SIG_TYPE, untrusted.sigType)
        assertEquals("cawg.identity", untrusted.label)
        assertTrue("cawg.ica.untrusted_issuer" in untrusted.codes(), untrusted.codes().toString())
        assertTrue("cawg.identity.well-formed" in untrusted.codes(), untrusted.codes().toString())
        assertEquals(Check.WARN, untrusted.signature, untrusted.statuses.toString())

        trustedIssuers = setOf(signer.did)
        val id = inspect(signed.bytes, "ica.jpg").active().identities.single()
        assertTrue("cawg.ica.credential_valid" in id.codes(), id.codes().toString())
        assertTrue("cawg.identity.trusted" in id.codes(), id.codes().toString())
        assertEquals(Check.PASS, id.signature, id.statuses.toString())
        assertEquals(signer.did, id.issuer)
        assertEquals(listOf("cawg.creator"), id.roles)
        assertTrue(id.referenced.any { it.startsWith("c2pa.hash.data") }, id.referenced.toString())
        val v = id.verifiedIdentities.single()
        assertEquals(CawgAggregation.DOCUMENT_VERIFICATION, v.type)
        assertEquals("王小明", v.name)
        assertEquals("https://issuer.example.gov.tw", v.providerId)
        assertEquals("測試發證機關", v.providerName)
        assertEquals("2026-11-01T08:00:00Z", v.verifiedAt)

        // The claim signature, binding and the rest of the manifest are unaffected.
        val r = inspect(signed.bytes, "ica.jpg")
        for (c in listOf("claimSignature.validated", "assertion.dataHash.match", "assertion.hashedURI.match")) assertTrue(c in r.codes(), "$c missing in ${r.codes()}")
    }

    @Test
    fun aggregationFollowsTheShapeOfTheC2paRsSamples() = runBlocking<Unit> {
        trustRoot()
        val signer = icaSigner(ed25519 = true)
        // c2pa-rs decodes did:jwk with a padded base64url decoder: the value must need no padding.
        val encoded = signer.did.removePrefix("did:jwk:")
        assertEquals(0, encoded.length % 4, encoded)
        val jwk = Json.parseToJsonElement(java.util.Base64.getUrlDecoder().decode(encoded).decodeToString()).jsonObject
        assertEquals(setOf("alg", "crv", "kty", "x"), jwk.keys)
        assertEquals("EdDSA", jwk["alg"]!!.jsonPrimitive.content)

        val signed = sign(picture("jpg"), aggregationRequest(signer, identity = true))
        save("ica-eddsa.jpg", signed.bytes)
        trustedIssuers = setOf(signer.did)
        val ids = inspect(signed.bytes, "ica.jpg").active().identities
        assertEquals(listOf("cawg.identity", "cawg.identity__1"), ids.map { it.label })
        assertEquals(listOf(C2paWriter.X509_SIG_TYPE, CawgAggregation.SIG_TYPE), ids.map { it.sigType })
        assertTrue(ids.all { it.signature == Check.PASS }, ids.map { it.statuses }.toString())
        assertEquals(ids[0].referenced, ids[1].referenced)

        // The same contexts, types, content type and members as the c2pa-rs sample success.jpg.
        val (vc, prot) = icaParts(signed.bytes, "cawg.identity__1")
        val sample = javaClass.getResourceAsStream("/c2pa/ica/success.jpg")!!.readBytes()
        val sampleLabel = C2paManifests.identityBoxes(C2paManifests.read(sample)!!.active!!).single().label!!
        val (sampleVc, sampleProt) = icaParts(sample, sampleLabel)
        assertEquals(sampleVc["@context"], vc["@context"])
        assertEquals(sampleVc["type"], vc["type"])
        assertEquals(sampleProt[1L], prot[1L])
        assertEquals("application/vc", prot[3L])
        assertEquals(sampleProt[3L], prot[3L])
        assertEquals(signer.keyId, prot[4L])
        val subject = vc["credentialSubject"]!!.jsonObject
        val sampleSubject = sampleVc["credentialSubject"]!!.jsonObject
        assertEquals(sampleSubject.keys, subject.keys)
        val asset = subject["c2paAsset"]!!.jsonObject
        assertEquals(CawgAggregation.SIG_TYPE, asset["sig_type"]!!.jsonPrimitive.content)
        // Standard base64 of the 32-byte hashes, which c2pa-rs decodes too.
        asset["referenced_assertions"]!!.jsonArray.forEach { assertEquals(32, java.util.Base64.getDecoder().decode(it.jsonObject["hash"]!!.jsonPrimitive.content).size) }
        val entry = subject["verifiedIdentities"]!!.jsonArray.single().jsonObject
        assertEquals(setOf("type", "name", "verifiedAt", "provider"), entry.keys)
        assertEquals(setOf("id", "name"), entry["provider"]!!.jsonObject.keys)
        assertNotNull(vc["validFrom"])
        assertEquals(signer.did, vc["issuer"]!!.jsonPrimitive.content)
    }

    @Test
    fun aggregationIsCheckedBeforeSigning() = runBlocking<Unit> {
        val signer = icaSigner(ed25519 = false)
        val nameless = person().copy(name = null)
        for (bad in listOf(emptyList(), listOf(nameless), listOf(person().copy(providerId = "not a uri")), listOf(person().copy(type = "cawg.social_media")))) {
            val e = runCatching { sign(picture("png"), aggregationRequest(signer, identity = false, identities = bad)) }.exceptionOrNull()
            assertTrue(e is SigningException, "$bad: $e")
        }
        // An affiliation needs no name.
        trustRoot()
        trustedIssuers = setOf(signer.did)
        val signed = sign(picture("png"), aggregationRequest(signer, identity = false, identities = listOf(nameless.copy(type = CawgAggregation.AFFILIATION))))
        val id = inspect(signed.bytes, "ica.png").active().identities.single()
        assertEquals(Check.PASS, id.signature, id.statuses.toString())
        assertNull(id.verifiedIdentities.single().name)
    }

    @Test
    fun aggregationTamperingIsDetected() = runBlocking<Unit> {
        trustRoot()
        val signer = icaSigner(ed25519 = false)
        trustedIssuers = setOf(signer.did)
        val signed = sign(picture("jpg"), aggregationRequest(signer, identity = false)).bytes
        // Another name of the same length inside the credential: the claim's hash of the identity assertion no
        // longer matches, so the assertion is not taken as part of the signed manifest.
        val at = indexOf(signed, "王小明".encodeToByteArray())
        assertTrue(at > 0)
        val changed = signed.copyOf().also { "王大明".encodeToByteArray().copyInto(it, at) }
        val r = inspect(changed, "ica.jpg")
        assertTrue("assertion.hashedURI.mismatch" in r.codes(), r.codes().toString())
        assertTrue(r.active().identities.none { it.signature == Check.PASS })
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
    fun svgWhoseRootUsesTheC2paPrefixGetsTheRightNamespace() = runBlocking<Unit> {
        trustRoot()
        val taken = svg.decodeToString().replaceFirst("<svg ", "<svg xmlns:c2pa=\"urn:unrelated\" ").encodeToByteArray()
        val signed = sign(taken, request("向量圖.svg", C2paAuthoring.Opened)).bytes
        val text = signed.decodeToString()
        assertTrue(text.contains("<c2pa:manifest xmlns:c2pa=\"http://c2pa.org/manifest\">"), "the manifest element declares the C2PA namespace")
        assertTrue(text.contains("xmlns:c2pa=\"urn:unrelated\""), "the declaration of the root stays")
        assertSignedAndTrusted(inspect(signed, "prefix.svg"), "svg with a taken prefix")
    }

    @Test
    fun svgMarkupThatIsNotAC2paManifestIsKept() = runBlocking<Unit> {
        trustRoot()
        // Text in CDATA and a comment, and a manifest element of another namespace that only shares the prefix.
        val shown = "<text><![CDATA[<c2pa:manifest>example</c2pa:manifest>]]></text><!-- <c2pa:manifest>note</c2pa:manifest> -->" +
            "<metadata><c2pa:manifest xmlns:c2pa=\"urn:other\">inventory</c2pa:manifest></metadata>" +
            "<g xmlns:c2pa=\"urn:other\" data-note=\"xmlns:c2pa='http://c2pa.org/manifest'\"><c2pa:manifest>list</c2pa:manifest></g>"
        val original = svg.decodeToString().replaceFirst("<title>", shown + "<title>").encodeToByteArray()
        assertNull(C2paManifests.read(original), "text that looks like a manifest holds no store")
        assertTrue(C2paContainers.strip(original, C2paFormat.SVG).contentEquals(original), "nothing is removed")
        val signed = sign(original, request("向量圖.svg", C2paAuthoring.Opened)).bytes
        assertTrue(signed.decodeToString().contains(shown), "the CDATA text and the comment stay")
        assertSignedAndTrusted(inspect(signed, "cdata.svg"), "svg with cdata")
    }

    @Test
    fun openDmlAviWithFurtherRiffPartsGetsASidecar() = runBlocking<Unit> {
        trustRoot()
        val single = avi()
        assertNull(C2paContainers.cannotEmbed(single, C2paFormat.AVI))
        val avix = "RIFF".encodeToByteArray() + le32(12) + "AVIX".encodeToByteArray() + "JUNK".encodeToByteArray() + le32(0)
        val out = sign(single + avix, request("影片.avi", C2paAuthoring.Opened))
        assertTrue(out.sidecar, "the later RIFF part would move under its absolute indexes")
        assertNotNull(out.sidecarReason)
    }

    /** A ZIP of stored entries written by hand, so that two entries may share a name. */
    private fun rawZip(entries: List<Pair<String, ByteArray>>): ByteArray {
        val local = ByteArrayOutputStream()
        val cd = ByteArrayOutputStream()
        fun le16(v: Int) = byteArrayOf(v.toByte(), (v ushr 8).toByte())
        for ((name, data) in entries) {
            val n = name.encodeToByteArray()
            val crc = CRC32().also { it.update(data) }.value.toInt()
            val offset = local.size()
            local.write(le32(0x04034b50) + le16(20) + le16(0x800) + le16(0) + le16(0) + le16(0x21) + le32(crc) + le32(data.size) + le32(data.size) + le16(n.size) + le16(0) + n + data)
            cd.write(le32(0x02014b50) + le16(20) + le16(20) + le16(0x800) + le16(0) + le16(0) + le16(0x21) + le32(crc) + le32(data.size) + le32(data.size) +
                le16(n.size) + le16(0) + le16(0) + le16(0) + le16(0) + le32(0) + le32(offset) + n)
        }
        val cdBytes = cd.toByteArray()
        val eocd = le32(0x06054b50) + le16(0) + le16(0) + le16(entries.size) + le16(entries.size) + le32(cdBytes.size) + le32(local.size()) + le16(0)
        return local.toByteArray() + cdBytes + eocd
    }

    @Test
    fun zipWithTwoEntriesOfOneNameGetsASidecar() = runBlocking<Unit> {
        trustRoot()
        val data = payload(500)
        val unique = rawZip(listOf("a.txt" to data, "b.txt" to data))
        assertFalse(sign(unique, request("封存.zip", C2paAuthoring.Opened)).sidecar, "the hand-made ZIP can take a manifest")
        val twice = rawZip(listOf("a.txt" to data, "a.txt" to data))
        val out = sign(twice, request("封存.zip", C2paAuthoring.Opened))
        assertTrue(out.sidecar, "a collection hash could not tell the two entries apart")
        assertNotNull(out.sidecarReason)
    }

    @Test
    fun zipWithAPathACollectionCannotNameGetsASidecar() = runBlocking<Unit> {
        trustRoot()
        val out = sign(rawZip(listOf("./hello.txt" to payload(100))), request("封存.zip", C2paAuthoring.Opened))
        assertTrue(out.sidecar, "a collection URI cannot hold a . component")
        assertNotNull(out.sidecarReason)
        assertTrue(C2paZip.validUri("dir/hello.txt"))
        assertFalse(C2paZip.validUri("../hello.txt"))
        assertFalse(C2paZip.validUri("/hello.txt"))
        assertFalse(C2paZip.validUri("C:/hello.txt"))
    }

    @Test
    fun svgInAnotherEncodingKeepsItsBytes() = runBlocking<Unit> {
        trustRoot()
        val text = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\"><text>caf\u00E9</text></svg>\n"
        val latin1 = text.toByteArray(Charsets.ISO_8859_1)
        val signed = sign(latin1, request("latin1.svg", C2paAuthoring.Opened)).bytes
        val word = "<text>caf\u00E9</text>".toByteArray(Charsets.ISO_8859_1)
        assertTrue(indexOf(signed, word) >= 0, "the ISO-8859-1 text is kept byte for byte")
        assertSignedAndTrusted(inspect(signed, "latin1.svg"), "latin1 svg")
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
    fun ilocExtentsRelativeToABaseBeforeTheStoreFollowTheData() {
        // iloc version 0: offset, length and base offset of 4 bytes; one item whose base lies in ftyp (before the
        // store) and whose extent reaches into mdat (after it).
        val ftyp = bmffBox("ftyp", "avif".encodeToByteArray() + be32(0) + "avifmif1".encodeToByteArray())
        val data = ByteArray(64) { (it * 7 + 3).toByte() }
        fun file(off: Int): ByteArray {
            val iloc = bmffBox("iloc", be32(0) + byteArrayOf(0x44, 0x40) + byteArrayOf(0, 1) +
                byteArrayOf(0, 1) + byteArrayOf(0, 0) + be32(BASE) + byteArrayOf(0, 1) + be32(off) + be32(data.size))
            val meta = bmffBox("meta", be32(0) + iloc)
            return ftyp + meta + bmffBox("mdat", data)
        }
        val probe = file(0)
        val original = file(probe.size - data.size - BASE)
        val signed = C2paBmff.embed(original, ByteArray(40)).bytes
        val ilocAt = indexOf(signed, "iloc".encodeToByteArray()) - 4
        val base = BigInteger(1, signed.copyOfRange(ilocAt + 20, ilocAt + 24)).toInt()
        val off = BigInteger(1, signed.copyOfRange(ilocAt + 26, ilocAt + 30)).toInt()
        assertEquals(BASE, base, "a base before the store stays")
        assertTrue(signed.copyOfRange(base + off, base + off + data.size).contentEquals(data), "the extent still points at the item data")
    }

    @Test
    fun bmffFlagsOfAnExclusionThatIsNotExactFollowTheSpecificationFirst() {
        val ftyp = bmffBox("ftyp", "isom".encodeToByteArray() + be32(0) + "isom".encodeToByteArray())
        fun file(flags: Int) = ftyp + bmffBox("meta", be32(flags))
        fun excluded(flags: Int, want: Int, mode: C2paBmff.FlagMatch): Boolean {
            val x = C2paBmff.Exclusion("/meta", flags = byteArrayOf((want ushr 16).toByte(), (want ushr 8).toByte(), want.toByte()), exact = false)
            return C2paBmff.excluded(file(flags), listOf(x), true, mode).ranges.isNotEmpty()
        }
        // The specification: the box has every bit the exclusion sets.
        assertTrue(excluded(3, 1, C2paBmff.FlagMatch.STANDARD))
        assertFalse(excluded(1, 3, C2paBmff.FlagMatch.STANDARD))
        // c2pa-rs: the box sets no bit the exclusion leaves clear.
        assertFalse(excluded(3, 1, C2paBmff.FlagMatch.C2PA_RS))
        assertTrue(excluded(1, 3, C2paBmff.FlagMatch.C2PA_RS))
    }

    @Test
    fun tiffWithADirectoryChainPastTheLimitGetsASidecar() {
        // Empty IFDs chained one after another: a header, then for each a zero count and the next offset.
        fun chain(pages: Int, loop: Boolean = false): ByteArray {
            val out = ByteArrayOutputStream()
            out.write("II".encodeToByteArray() + byteArrayOf(42, 0) + le32(8))
            for (k in 0 until pages) {
                val next = if (k == pages - 1) (if (loop) 8 else 0) else 8 + (k + 1) * 6
                out.write(byteArrayOf(0, 0) + le32(next))
            }
            return out.toByteArray()
        }
        assertNull(C2paContainers.cannotEmbed(chain(4095), C2paFormat.TIFF), "one more directory still fits")
        assertNotNull(C2paContainers.cannotEmbed(chain(4096), C2paFormat.TIFF), "the new directory would not be read back")
        assertNotNull(C2paContainers.cannotEmbed(chain(4200), C2paFormat.TIFF), "pages past the limit would be cut off")
        assertNotNull(C2paContainers.cannotEmbed(chain(3, loop = true), C2paFormat.TIFF), "a loop has no last directory")
        // One page whose IFD0 already holds n entries: the C2PA entry makes n + 1.
        fun page(n: Int): ByteArray {
            val out = ByteArrayOutputStream()
            out.write("II".encodeToByteArray() + byteArrayOf(42, 0) + le32(8) + byteArrayOf(n.toByte(), (n ushr 8).toByte()))
            for (k in 0 until n) out.write(byteArrayOf((k + 1).toByte(), ((k + 1) ushr 8).toByte(), 1, 0) + le32(1) + le32(0))
            out.write(le32(0))
            return out.toByteArray()
        }
        assertNull(C2paContainers.cannotEmbed(page(9999), C2paFormat.TIFF), "the C2PA entry still fits")
        assertNotNull(C2paContainers.cannotEmbed(page(10000), C2paFormat.TIFF), "the IFD would hold more entries than are read back")
    }

    @Test
    fun strippingRestoresTheOriginalFile() = runBlocking<Unit> {
        trustRoot()
        // PDF keeps its incremental update, TIFF the rewritten IFD, JPEG XL its container, GIF its version 89a, an
        // ID3 tag stays and ZIP the META-INF directory; the other containers come back as they were.
        for (c in cases().filter { it.format !in setOf(C2paFormat.PDF, C2paFormat.TIFF, C2paFormat.JXL, C2paFormat.GIF, C2paFormat.MP3, C2paFormat.ZIP) }) {
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
    fun pdfManifestStreamIsFoundPastAStreamWordInItsDictionary() = runBlocking<Unit> {
        trustRoot()
        val signed = sign(fixture("basic.pdf"), request("註解.pdf", C2paAuthoring.Opened)).bytes
        val text = String(signed, Charsets.ISO_8859_1)
        val type = "/Type /EmbeddedFile"
        val at = text.lastIndexOf(type)
        assertTrue(at > 0, "no embedded file dictionary")
        // A comment of the same length that holds the word "stream" before the real keyword: offsets stay valid.
        val comment = "%stream x".padEnd(type.length - 1, ' ') + "\n"
        val changed = (text.substring(0, at) + comment + text.substring(at + type.length)).toByteArray(Charsets.ISO_8859_1)
        val located = C2paContainers.locate(changed)
        assertNotNull(located, "manifest not found")
        assertEquals(C2paContainers.locate(signed)!!.region!!.start, located.region!!.start)
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
        for (name in listOf("video1.mp4", "legacy.mp4", "express-signed.pdf", "C.jpg", "CA.jpg", "exp-test1.png", "update_manifest.jpg")) {
            val f = dir.resolve(name).takeIf { it.isFile } ?: continue
            val r = inspect(f.readBytes(), name)
            val codes = r.codes()
            println("$name: ${r.c2pa?.container} $codes")
            assertTrue(codes.none { it.endsWith(".mismatch") || it.endsWith(".malformed") || it == "assertion.missing" }, "$name: $codes")
            assertTrue(codes.any { it.endsWith("Hash.match") }, "$name: $codes")
            // The c2pa-rs update manifest sample: the binding is that of the standard manifest it updates.
            if (name == "update_manifest.jpg") assertTrue(C2paManifests.read(f.readBytes())!!.active!!.update, name)
        }
    }

    // ---------------------------------------------------------------- multi-asset hash, update and compressed manifests

    /** A baseline JPEG with an MPF index (APP2) after APP0 whose second entry points at [second], appended. */
    private fun mpfJpeg(second: ByteArray): ByteArray {
        val primary = picture("jpg")
        val at = 4 + ((primary[4].toInt() and 0xFF) shl 8 or (primary[5].toInt() and 0xFF))
        fun app2(size: Int, offset: Int): ByteArray {
            val ifd = byteArrayOf(0, 1) + byteArrayOf(0xB0.toByte(), 0x02, 0, 7) + be32(32) + be32(8 + 2 + 12 + 4) + be32(0)
            val entries = be32(0x20030000) + be32(size) + be32(0) + ByteArray(4) + be32(0) + be32(second.size) + be32(offset) + ByteArray(4)
            val body = "MPF".encodeToByteArray() + 0 + "MM".encodeToByteArray() + byteArrayOf(0, 0x2A) + be32(8) + ifd + entries
            return byteArrayOf(0xFF.toByte(), 0xE2.toByte(), ((body.size + 2) ushr 8).toByte(), (body.size + 2).toByte()) + body
        }
        val len = app2(0, 0).size
        val size = primary.size + len
        val seg = app2(size, size - (at + 8))
        return primary.copyOfRange(0, at) + seg + primary.copyOfRange(at, primary.size) + second
    }

    /** A JPEG whose XMP declares a Motion Photo, with [video] after it. */
    private fun motionPhoto(video: ByteArray): ByteArray {
        val primary = picture("jpg")
        val at = 4 + ((primary[4].toInt() and 0xFF) shl 8 or (primary[5].toInt() and 0xFF))
        val xmp = "http://ns.adobe.com/xap/1.0/".encodeToByteArray() + 0 +
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description xmlns:GCamera=\"http://ns.google.com/photos/1.0/camera/\" GCamera:MotionPhoto=\"1\"/></rdf:RDF></x:xmpmeta>".encodeToByteArray()
        val app1 = byteArrayOf(0xFF.toByte(), 0xE1.toByte(), ((xmp.size + 2) ushr 8).toByte(), (xmp.size + 2).toByte()) + xmp
        return primary.copyOfRange(0, at) + app1 + primary.copyOfRange(at, primary.size) + video
    }

    @Test
    fun jpegWithAnMpfImageGetsAMultiAssetHashOfEachPart() = runBlocking<Unit> {
        trustRoot()
        val gainMap = picture("jpg")
        for (binding in listOf(C2paBinding.DATA, C2paBinding.BOXES)) {
            val signed = sign(mpfJpeg(gainMap), request("mpf.jpg", binding = binding))
            assertEquals(2, signed.parts, "$binding")
            val r = inspect(signed.bytes, "mpf.jpg")
            assertSignedAndTrusted(r, "mpf $binding", if (binding == C2paBinding.DATA) "assertion.dataHash.match" else "assertion.boxesHash.match",
                if (binding == C2paBinding.DATA) "c2pa.hash.data" else "c2pa.hash.boxes")
            assertTrue(C2paBindings.MULTI_ASSET in r.active().assertions, r.active().assertions.toString())
            // The secondary image starts where the MPF index says, also after the store was inserted.
            val store = C2paManifests.read(signed.bytes)!!
            val parts = C2paManifests.assertion(store.active!!, C2paBindings.MULTI_ASSET).single().second.jsonObject["parts"]!!.jsonArray
            val second = parts[1].jsonObject["location"]!!.jsonObject
            val start = second["byteOffset"]!!.jsonPrimitive.int
            assertTrue(signed.bytes.copyOfRange(start, signed.bytes.size).contentEquals(gainMap), "$binding: second part offset")
            // A changed gain map breaks the whole-file binding; the multi-asset hash names the part.
            val changed = signed.bytes.copyOf().also { it[it.size - 40] = (it[it.size - 40] + 1).toByte() }
            val bad = inspect(changed, "mpf.jpg")
            assertTrue("assertion.multiAssetHash.mismatch" in bad.codes(), "$binding: ${bad.codes()}")
            assertFalse(bad.codes().any { it == "assertion.dataHash.mismatch" || it == "assertion.boxesHash.mismatch" }, bad.codes().toString())
            assertEquals(Check.FAIL, bad.signatures.last().integrity)
        }
    }

    @Test
    fun motionPhotoVideoIsAnOptionalPartThatMayBeRemoved() = runBlocking<Unit> {
        trustRoot()
        val video = mp4()
        val signed = sign(motionPhoto(video), request("motion.jpg"))
        assertEquals(2, signed.parts)
        assertSignedAndTrusted(inspect(signed.bytes, "motion.jpg"), "motion photo")
        // Without the video the data hash over the whole file fails, and the primary image still matches its part.
        val still = signed.bytes.copyOfRange(0, signed.bytes.size - video.size)
        val r = inspect(still, "motion.jpg")
        val codes = r.codes()
        assertTrue("assertion.multiAssetHash.match" in codes, codes.toString())
        assertTrue("assertion.multiAssetHash.missingPart" in codes, codes.toString())
        assertFalse("assertion.dataHash.mismatch" in codes, codes.toString())
        assertEquals(Check.PASS, r.signatures.last().integrity, r.signatures.last().problems.toString())
        // A request without multi-asset hashes writes the plain data hash only.
        val plain = sign(motionPhoto(video), request("motion.jpg").copy(multiAsset = false))
        assertEquals(0, plain.parts)
    }

    @Test
    fun updateManifestKeepsTheBindingOfItsParent() = runBlocking<Unit> {
        trustRoot()
        val samples = listOf("jpg" to picture("jpg"), "png" to picture("png"), "mp4" to mp4())
        for ((ext, bytes) in samples) {
            val first = sign(bytes, request("原始.$ext"))
            val upd = request("更新.$ext", C2paAuthoring.Opened).copy(update = true, identity = false, allowTraining = true)
            val second = sign(first.bytes, upd)
            assertTrue(second.update, ext)
            val third = sign(second.bytes, upd.copy(title = "再次更新.$ext"))
            for ((n, out) in listOf(2 to second, 3 to third)) {
                val r = inspect(out.bytes, "updated.$ext")
                val m = r.active()
                assertEquals(out.manifestLabel, m.label, ext)
                assertEquals(n, r.c2pa!!.manifests.size, ext)
                val codes = r.codes()
                val match = if (ext == "mp4") "assertion.bmffHash.match" else "assertion.dataHash.match"
                for (c in listOf("claimSignature.validated", match, "signingCredential.trusted", "timeStamp.validated")) assertTrue(c in codes, "$ext $n: $c missing in $codes")
                assertFalse(codes.any { it.startsWith("manifest.update") || it == "claim.hardBindings.missing" }, "$ext $n: $codes")
                assertEquals(listOf("c2pa.opened"), m.actions.map { it.action }, ext)
                assertEquals(Check.PASS, r.signatures.last().integrity, "$ext $n: ${r.signatures.last().problems}")
            }
            if (ext == "mp4") {
                // The standard store becomes original; one update store at the end holds both update manifests.
                assertEquals(listOf("original", "update"), C2paBmff.c2paBoxes(third.bytes).map { it.purpose })
                assertTrue(C2paBmff.c2paBoxes(third.bytes).last().box.end == third.bytes.size.toLong())
                assertEquals(stcoTarget(first.bytes), stcoTarget(third.bytes))
                // A standard manifest folds the update store back into one store of purpose manifest.
                val fourth = sign(third.bytes, request("標準.$ext", C2paAuthoring.Opened))
                assertEquals(listOf("manifest"), C2paBmff.c2paBoxes(fourth.bytes).map { it.purpose })
                val r = inspect(fourth.bytes, "standard.mp4")
                assertEquals(4, r.c2pa!!.manifests.size)
                assertSignedAndTrusted(r, "mp4 after update", "assertion.bmffHash.match", "c2pa.hash.bmff")
            }
        }
        // A file without content credentials cannot take an update manifest.
        val e = runCatching { sign(picture("jpg"), request("x.jpg", C2paAuthoring.Opened).copy(update = true)) }.exceptionOrNull()
        assertNotNull(e)
        // An MP4 whose last box has size 0 runs to the end: no update store is appended inside it.
        val open = mp4().also { java.nio.ByteBuffer.wrap(it, it.size - 4096 - 8, 4).putInt(0) }
        val signedOpen = sign(open, request("開放.mp4"))
        assertSignedAndTrusted(inspect(signedOpen.bytes, "open.mp4"), "mp4 with size 0 mdat", "assertion.bmffHash.match", "c2pa.hash.bmff")
        val refused = runCatching { sign(signedOpen.bytes, request("更新.mp4", C2paAuthoring.Opened).copy(update = true, identity = false)) }.exceptionOrNull()
        assertTrue(refused is diw.wallet.core.document.sign.SigningException && "mdat" in refused.message.orEmpty(), refused.toString())
    }

    @Test
    fun changedContentUnderAnUpdateManifestStillFails() = runBlocking<Unit> {
        trustRoot()
        val first = sign(picture("png"), request("a.png"))
        val second = sign(first.bytes, request("b.png", C2paAuthoring.Opened).copy(update = true, identity = false))
        val chunk = indexOf(second.bytes, "IDAT".encodeToByteArray())
        val changed = second.bytes.copyOf().also { it[chunk + 6] = (it[chunk + 6] + 1).toByte() }
        val r = inspect(changed, "b.png")
        assertTrue("assertion.dataHash.mismatch" in r.codes(), r.codes().toString())
        assertEquals(Check.FAIL, r.signatures.last().integrity)
    }

    @Test
    fun compressedManifestsDecompressAndKeepTheirBinding() = runBlocking<Unit> {
        trustRoot()
        val cases = listOf(Triple("jpg", picture("jpg"), C2paBinding.BOXES), Triple("png", picture("png"), C2paBinding.BOXES), Triple("mp4", mp4(), null))
        for ((ext, bytes, binding) in cases) {
            val signed = sign(bytes, request("壓縮.$ext", binding = binding).copy(compress = true))
            assertTrue(signed.compressed, ext)
            val store = C2paManifests.read(signed.bytes)!!
            assertTrue(store.active!!.box.compressed, ext)
            assertTrue(store.problems.isEmpty(), ext)
            val r = inspect(signed.bytes, "compressed.$ext")
            if (ext == "mp4") assertSignedAndTrusted(r, ext, "assertion.bmffHash.match", "c2pa.hash.bmff")
            else assertSignedAndTrusted(r, ext, "assertion.boxesHash.match", "c2pa.hash.boxes")
            // The next manifest names the compressed one as stored.
            val next = sign(signed.bytes, request("下一個.$ext", C2paAuthoring.Opened, binding = binding))
            val r2 = inspect(next.bytes, "next.$ext")
            assertTrue(r2.c2pa!!.manifests.size == 2, ext)
            assertFalse(r2.codes().any { it.endsWith(".mismatch") || it.startsWith("manifest.") }, "$ext: ${r2.codes()}")
        }
        // A data hash is never written with a compressed manifest.
        assertFalse(sign(picture("jpg"), request("data.jpg").copy(compress = true)).compressed)
        // An update manifest can be compressed in any container.
        val first = sign(picture("jpg"), request("c.jpg"))
        val upd = sign(first.bytes, request("c2.jpg", C2paAuthoring.Opened).copy(update = true, identity = false, compress = true))
        assertTrue(C2paManifests.read(upd.bytes)!!.active!!.box.compressed)
        assertTrue("assertion.dataHash.match" in inspect(upd.bytes, "c2.jpg").codes())
    }

    @Test
    fun brokenBrobIsReportedAsAnInvalidCompressedManifest() = runBlocking<Unit> {
        trustRoot()
        val first = sign(picture("jpg"), request("first.jpg", binding = C2paBinding.BOXES))
        val signed = sign(first.bytes, request("broken.jpg", C2paAuthoring.Opened, binding = C2paBinding.BOXES).copy(compress = true))
        val at = indexOf(signed.bytes, "brob".encodeToByteArray())
        val broken = signed.bytes.copyOf().also { for (k in 8 until 40) it[at + k] = 0x55 }
        val store = C2paManifests.read(broken)
        assertEquals("manifest.compressed.invalid", store?.problems?.single()?.code)
    }

    @Test
    fun aCompressedManifestInsideACompressedManifestIsNotDecompressed() {
        val enc = diw.wallet.core.document.c2pa.BrotliEncoder
        val empty = listOf("c2pa.hash.data" to C2paCbor.map(listOf("alg" to C2paCbor.tstr("sha256"))))
        val plain = unsignedManifest("urn:c2pa:test", empty)
        val label = "urn:c2pa:nested"
        val relabeled = unsignedManifest(label, empty)
        fun packed(inner: ByteArray) = jumbf("6332636d00110010800000aa00389b71", label, listOf(bmffBox("brob", enc.encode(inner))))
        fun store(second: ByteArray) = jumbf("6332706100110010800000aa00389b71", "c2pa", listOf(plain, second))
        // One level is a compressed manifest; a compressed manifest holding another one is reported, not unpacked.
        assertTrue(C2paManifests.read(store(packed(relabeled)))!!.problems.isEmpty())
        val nested = C2paManifests.read(store(packed(packed(relabeled))))!!
        assertEquals(listOf("manifest.compressed.invalid"), nested.problems.map { it.code })
    }

    @Test
    fun brotliEncoderRoundTrips() {
        val random = java.util.Random(7)
        val samples = listOf(
            ByteArray(0), byteArrayOf(42), ByteArray(70000) { 0 }, ByteArray(5000) { random.nextInt().toByte() },
            "C2PA manifest ".repeat(3000).encodeToByteArray(), ByteArray(200_000) { (it / 97 % 13 + random.nextInt(3)).toByte() },
            picture("png"), mp4(),
        )
        for (b in samples) {
            val packed = diw.wallet.core.document.c2pa.BrotliEncoder.encode(b)
            val back = org.brotli.dec.BrotliInputStream(ByteArrayInputStream(packed)).readBytes()
            assertTrue(back.contentEquals(b), "size ${b.size}")
        }
        assertTrue(diw.wallet.core.document.c2pa.BrotliEncoder.encode("C2PA manifest ".repeat(3000).encodeToByteArray()).size < 1000)
    }

    // ---------------------------------------------------------------- BMFF Merkle trees

    private fun jumbf(uuid: String, label: String, contents: List<ByteArray>): ByteArray {
        val desc = bmffBox("jumd", hex(uuid) + byteArrayOf(3) + label.encodeToByteArray() + 0)
        return bmffBox("jumb", desc + contents.fold(ByteArray(0)) { a, x -> a + x })
    }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun sha(b: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(b)

    /** An unsigned store with one manifest whose claim references a BMFF hash assertion of [cbor]. */
    private fun bmffStore(cbor: ByteArray): ByteArray {
        val assertion = jumbf("63626f7200110010800000aa00389b71", "c2pa.hash.bmff.v3", listOf(bmffBox("cbor", cbor)))
        val claim = C2paCbor.map(listOf(
            "instanceID" to C2paCbor.tstr("xmp:iid:test"),
            "claim_generator_info" to C2paCbor.map(listOf("name" to C2paCbor.tstr("test"))),
            "signature" to C2paCbor.tstr("self#jumbf=c2pa.signature"),
            "created_assertions" to C2paCbor.array(listOf(C2paCbor.map(listOf(
                "url" to C2paCbor.tstr("self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3"),
                "hash" to C2paCbor.bstr(sha(assertion.copyOfRange(8, assertion.size))),
            )))),
            "alg" to C2paCbor.tstr("sha256"),
        ))
        val manifest = jumbf("63326d6100110010800000aa00389b71", "urn:c2pa:test", listOf(
            jumbf("6332617300110010800000aa00389b71", "c2pa.assertions", listOf(assertion)),
            jumbf("6332636c00110010800000aa00389b71", "c2pa.claim.v2", listOf(bmffBox("cbor", claim))),
        ))
        return jumbf("6332706100110010800000aa00389b71", "c2pa", listOf(manifest))
    }

    /** An unsigned store with one manifest whose claim references the [assertions] (labels to CBOR), in order. */
    private fun unsignedStore(assertions: List<Pair<String, ByteArray>>): ByteArray =
        jumbf("6332706100110010800000aa00389b71", "c2pa", listOf(unsignedManifest("urn:c2pa:test", assertions)))

    /** An unsigned standard manifest [label] whose claim references the [assertions] (labels to CBOR), in order. */
    private fun unsignedManifest(label: String, assertions: List<Pair<String, ByteArray>>): ByteArray {
        val boxes = assertions.map { (label, cbor) -> label to jumbf("63626f7200110010800000aa00389b71", label, listOf(bmffBox("cbor", cbor))) }
        val claim = C2paCbor.map(listOf(
            "instanceID" to C2paCbor.tstr("xmp:iid:test"),
            "claim_generator_info" to C2paCbor.map(listOf("name" to C2paCbor.tstr("test"))),
            "signature" to C2paCbor.tstr("self#jumbf=c2pa.signature"),
            "created_assertions" to C2paCbor.array(boxes.map { (label, box) -> hashedUri(label, box) }),
            "alg" to C2paCbor.tstr("sha256"),
        ))
        return jumbf("63326d6100110010800000aa00389b71", label, listOf(
            jumbf("6332617300110010800000aa00389b71", "c2pa.assertions", boxes.map { it.second }),
            jumbf("6332636c00110010800000aa00389b71", "c2pa.claim.v2", listOf(bmffBox("cbor", claim))),
        ))
    }

    private fun hashedUri(label: String, box: ByteArray) = C2paCbor.map(listOf(
        "url" to C2paCbor.tstr("self#jumbf=c2pa.assertions/$label"), "hash" to C2paCbor.bstr(sha(box.copyOfRange(8, box.size))),
    ))

    private fun assertionOf(label: String, cbor: ByteArray) = jumbf("63626f7200110010800000aa00389b71", label, listOf(bmffBox("cbor", cbor)))

    private fun c2paUuid(purpose: String, data: ByteArray): ByteArray =
        bmffBox("uuid", C2paBmff.UUID + ByteArray(4) + purpose.encodeToByteArray() + 0 + data)

    private fun fullBox(type: String, body: ByteArray) = bmffBox(type, ByteArray(4) + body)

    /** A track (id 1) of four samples in two chunks inside mdat, with c2pa-rs style Merkle data over the chunks. */
    private fun timedMp4(tamper: Boolean = false, aux: Boolean = true, extraChunk: Boolean = false, extraTrack: Boolean = false): ByteArray {
        val signed = listOf(payload(300), payload(500).reversedArray(), payload(200), payload(700).reversedArray())
        // A third chunk added to the sample tables after signing: the tree counts two.
        val samples = if (extraChunk) signed + payload(100) else signed
        val ftyp = bmffBox("ftyp", "isom".encodeToByteArray() + be32(0x200) + "isommp41".encodeToByteArray())
        fun trak(id: Int, sizes: List<Int>, chunks: List<Int>) = bmffBox("trak",
            fullBox("tkhd", ByteArray(8) + be32(id) + ByteArray(68)) + bmffBox("mdia", bmffBox("minf", bmffBox("stbl",
                fullBox("stsz", be32(0) + be32(sizes.size) + sizes.fold(ByteArray(0)) { a, x -> a + be32(x) }) +
                fullBox("stsc", be32(1) + be32(1) + be32(2) + be32(1)) +
                fullBox("stco", be32(chunks.size) + chunks.fold(ByteArray(0)) { a, c -> a + be32(c) })))))
        // A second track added after signing, whose data follows the signed samples: no tree names it.
        val added = payload(400)
        fun moov(chunks: List<Int>) = bmffBox("moov", trak(1, samples.map { it.size }, chunks) +
            if (extraTrack) trak(2, listOf(added.size), listOf(chunks.first() + samples.sumOf { it.size })) else ByteArray(0))
        val leaf1 = sha(samples[0] + samples[1])
        val leaf2 = sha(samples[2] + samples[3])
        val root = sha(leaf1 + leaf2)
        val mm = C2paCbor.map(listOf("uniqueId" to C2paCbor.int(1), "localId" to C2paCbor.int(1), "count" to C2paCbor.int(2), "hashes" to C2paCbor.array(listOf(C2paCbor.bstr(root)))))
        val exclusions = C2paCbor.array(listOf(
            C2paCbor.map(listOf("xpath" to C2paCbor.tstr("/uuid"), "data" to C2paCbor.array(listOf(C2paCbor.map(listOf("offset" to C2paCbor.int(8), "value" to C2paCbor.bstr(C2paBmff.UUID))))))),
            C2paCbor.map(listOf("xpath" to C2paCbor.tstr("/ftyp"))),
            C2paCbor.map(listOf("xpath" to C2paCbor.tstr("/mfra"))),
        ))
        val store = c2paUuid("manifest", ByteArray(8) + bmffStore(C2paCbor.map(listOf("exclusions" to exclusions, "alg" to C2paCbor.tstr("sha256"), "merkle" to C2paCbor.array(listOf(mm))))))
        val starts = if (extraChunk) listOf(0, 800, 1700) else listOf(0, 800)
        val head = ftyp.size + store.size + moov(starts).size + 8
        val data = samples.fold(ByteArray(0)) { a, x -> a + x }.also { if (tamper) it[350] = (it[350] + 1).toByte() } + if (extraTrack) added else ByteArray(0)
        fun auxBox(loc: Int, peer: ByteArray) = c2paUuid("merkle", C2paCbor.map(listOf(
            "uniqueId" to C2paCbor.int(1), "localId" to C2paCbor.int(1), "location" to C2paCbor.int(loc), "hashes" to C2paCbor.array(listOf(C2paCbor.bstr(peer))),
        )) + ByteArray(6))
        return ftyp + store + moov(starts.map { head + it }) + bmffBox("mdat", data) + if (aux) auxBox(0, leaf2) + auxBox(1, leaf1) else ByteArray(0)
    }

    @Test
    fun merkleTreeByMediaTimeIsCheckedAsTheC2paRsFallback() {
        fun check(b: ByteArray) = C2paManifests.read(b)!!.let { C2paBindings.check(it, it.active!!) }
        val ok = check(timedMp4())
        assertEquals("assertion.bmffHash.match", ok.first().code, ok.toString())
        // The match says it came from the c2pa-rs reading.
        assertNotNull(ok.first().explanation, ok.toString())
        val bad = check(timedMp4(tamper = true))
        assertFalse(bad.first().success, bad.toString())
        // Without auxiliary boxes neither reading can check a stored row above the leaves.
        assertFalse(check(timedMp4(aux = false)).first().success)
        // A chunk the tree does not count is not left unchecked.
        assertFalse(check(timedMp4(extraChunk = true)).first().success)
        // Nor is a track no tree names.
        assertFalse(check(timedMp4(extraTrack = true)).first().success)
    }

    @Test
    fun aBmffBoxPartCoversItsHeaderAndHashesItsPayload() {
        // A Motion Photo style MP4: the primary part by byte range, then an mpvd box located by bmffBox whose hash is
        // over its payload only; together they cover the file including the mpvd header.
        val ftyp = bmffBox("ftyp", "isom".encodeToByteArray() + be32(0x200) + "isommp41".encodeToByteArray())
        val mdat = bmffBox("mdat", payload(900))
        val video = payload(700).reversedArray()
        val mpvd = bmffBox("mpvd", video)
        fun dataHash(start: Int, length: Int, hash: ByteArray) = C2paCbor.map(listOf(
            "exclusions" to C2paCbor.array(if (length > 0) listOf(C2paCbor.map(listOf("start" to C2paCbor.int(start), "length" to C2paCbor.int(length)))) else emptyList()),
            "alg" to C2paCbor.tstr("sha256"), "hash" to C2paCbor.bstr(hash),
        ))
        val hard = C2paCbor.map(listOf(
            "exclusions" to C2paCbor.array(listOf(C2paCbor.map(listOf("xpath" to C2paCbor.tstr("/uuid"), "data" to C2paCbor.array(listOf(C2paCbor.map(listOf("offset" to C2paCbor.int(8), "value" to C2paCbor.bstr(C2paBmff.UUID))))))))),
            "alg" to C2paCbor.tstr("sha256"), "hash" to C2paCbor.bstr(ByteArray(32)),
        ))
        var uuidSize = 0
        var file = ByteArray(0)
        repeat(4) {
            val part0 = assertionOf("c2pa.hash.data.part", dataHash(ftyp.size, uuidSize, sha(ftyp + mdat)))
            val part1 = assertionOf("c2pa.hash.data.part__1", dataHash(0, 0, sha(video)))
            val primary = ftyp.size + uuidSize + mdat.size
            val multi = C2paCbor.map(listOf("parts" to C2paCbor.array(listOf(
                C2paCbor.map(listOf("location" to C2paCbor.map(listOf("byteOffset" to C2paCbor.int(0), "length" to C2paCbor.int(primary))),
                    "hashAssertion" to hashedUri("c2pa.hash.data.part", part0))),
                C2paCbor.map(listOf("location" to C2paCbor.map(listOf("bmffBox" to C2paCbor.tstr("/mpvd"))),
                    "hashAssertion" to hashedUri("c2pa.hash.data.part__1", part1), "optional" to byteArrayOf(0xF5.toByte()))),
            ))))
            val store = c2paUuid("manifest", ByteArray(8) + unsignedStore(listOf(
                "c2pa.hash.bmff.v3" to hard,
                "c2pa.hash.data.part" to dataHash(ftyp.size, uuidSize, sha(ftyp + mdat)),
                "c2pa.hash.data.part__1" to dataHash(0, 0, sha(video)),
                C2paBindings.MULTI_ASSET to multi,
            )))
            uuidSize = store.size
            file = ftyp + store + mdat + mpvd
        }
        fun check(b: ByteArray) = C2paManifests.read(b)!!.let { C2paBindings.check(it, it.active!!) }
        val ok = check(file)
        assertEquals(listOf("assertion.multiAssetHash.match", "assertion.multiAssetHash.match"), ok.map { it.code }, ok.toString())
        // The optional video removed: the primary part still covers the whole file.
        val without = check(file.copyOfRange(0, file.size - mpvd.size))
        assertEquals(listOf("assertion.multiAssetHash.match", "assertion.multiAssetHash.missingPart"), without.map { it.code }, without.toString())
        // A changed video byte fails its part.
        val changed = file.copyOf().also { it[it.size - 10] = (it[it.size - 10] + 1).toByte() }
        assertEquals("assertion.multiAssetHash.mismatch", check(changed).first().code)
    }

    @Test
    fun sampleTablesThatCannotFitTheFileAreNotExpanded() {
        // A stsz box of a few bytes stating 0x10000000 samples of 4 bytes: rejected before anything that size is made.
        fun mp4(stsz: ByteArray) = bmffBox("ftyp", "isom".encodeToByteArray() + be32(0x200)) + bmffBox("moov", bmffBox("trak",
            fullBox("tkhd", ByteArray(8) + be32(1) + ByteArray(68)) + bmffBox("mdia", bmffBox("minf", bmffBox("stbl",
                stsz + fullBox("stsc", be32(1) + be32(1) + be32(2) + be32(1)) + fullBox("stco", be32(1) + be32(0)))))))
        assertEquals(null, C2paBmff.trackChunks(mp4(fullBox("stsz", be32(4) + be32(0x10000000))), 1))
        // A fixed size that fits: each chunk is one range from its offset.
        val small = mp4(fullBox("stsz", be32(4) + be32(2)))
        assertEquals(listOf(C2paRange(0, 8)), C2paBmff.trackChunks(small, 1)!![1])
    }

    @Test
    fun merkleTreeOverTheMdatPayloadFollowsTheSpecification() {
        // One tree for the only mdat (localId 0), fixed blocks of 256 bytes after the first 16 bytes of the box, the
        // stored row is the root and each block's auxiliary box carries its proof.
        val ftyp = bmffBox("ftyp", "isom".encodeToByteArray() + be32(0x200) + "isommp41".encodeToByteArray())
        val mdatBody = payload(1000)
        val blocks = mdatBody.copyOfRange(8, mdatBody.size).toList().chunked(256).map { it.toByteArray() }
        val leaves = blocks.map(::sha)
        val l1 = listOf(sha(leaves[0] + leaves[1]), sha(leaves[2] + leaves[3]))
        val root = sha(l1[0] + l1[1])
        val mm = C2paCbor.map(listOf("uniqueId" to C2paCbor.int(0), "localId" to C2paCbor.int(0), "count" to C2paCbor.int(leaves.size),
            "hashes" to C2paCbor.array(listOf(C2paCbor.bstr(root))), "fixedBlockSize" to C2paCbor.int(256)))
        val exclusions = C2paCbor.array(listOf(
            C2paCbor.map(listOf("xpath" to C2paCbor.tstr("/uuid"), "data" to C2paCbor.array(listOf(C2paCbor.map(listOf("offset" to C2paCbor.int(8), "value" to C2paCbor.bstr(C2paBmff.UUID))))))),
            C2paCbor.map(listOf("xpath" to C2paCbor.tstr("/ftyp"))),
        ))
        val store = c2paUuid("manifest", ByteArray(8) + bmffStore(C2paCbor.map(listOf("exclusions" to exclusions, "alg" to C2paCbor.tstr("sha256"), "merkle" to C2paCbor.array(listOf(mm))))))
        fun proof(k: Int) = listOf(leaves[k xor 1], l1[(k / 2) xor 1])
        fun aux(k: Int) = c2paUuid("merkle", C2paCbor.map(listOf("uniqueId" to C2paCbor.int(0), "localId" to C2paCbor.int(0), "location" to C2paCbor.int(k),
            "hashes" to C2paCbor.array(proof(k).map { C2paCbor.bstr(it) }))))
        val file = ftyp + store + bmffBox("mdat", mdatBody) + (0 until 4).fold(ByteArray(0)) { a, k -> a + aux(k) }
        fun check(b: ByteArray) = C2paManifests.read(b)!!.let { C2paBindings.check(it, it.active!!) }
        val ok = check(file)
        assertEquals(listOf("assertion.bmffHash.match"), ok.map { it.code }, ok.toString())
        // Swapping two auxiliary boxes breaks the order of the locations.
        val a0 = aux(0); val a1 = aux(1)
        val swapped = ftyp + store + bmffBox("mdat", mdatBody) + a1 + a0 + aux(2) + aux(3)
        assertFalse(check(swapped).first().success)
        val changed = file.copyOf().also { it[ftyp.size + store.size + 600] = (it[ftyp.size + store.size + 600] + 1).toByte() }
        assertEquals("assertion.bmffHash.mismatch", check(changed).first().code)
    }
}
