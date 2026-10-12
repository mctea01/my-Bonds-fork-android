package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.pdf.PdfComposer
import diw.wallet.core.document.pdf.PdfIncrementalSigner
import diw.wallet.core.document.pdf.PdfSignOptions
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.BuiltInPublicRoots
import diw.wallet.core.trust.Pkix
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERUTCTime
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.CMSAttributeTableGenerator
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Instant

/** Signed documents as some signing services write them: lenient parsing, missing or wrong signing times, cross-signed roots. */
class DocumentEdgeCaseTest {
    private val bc = BouncyCastleProvider()
    private val day = 86_400_000L
    private val now = System.currentTimeMillis()

    private fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun cert(subject: String, issuer: String, key: PublicKey, signer: KeyPair, ca: Boolean, from: Long, to: Long): X509CertificateHolder {
        val b = JcaX509v3CertificateBuilder(X500Name(issuer), BigInteger.valueOf(System.nanoTime()), Date(from), Date(to), X500Name(subject), key)
        val ext = JcaX509ExtensionUtils()
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(key))
        b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(signer.public))
        b.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
        b.addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature or KeyUsage.nonRepudiation))
        return b.build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(signer.private))
    }

    private val rootKey = rsa()
    private val root = cert("CN=Edge Test Root", "CN=Edge Test Root", rootKey.public, rootKey, true, now - 400 * day, now + 3650 * day)
    private val signerKey = rsa()

    private val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
    private val trust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision = registry.decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
    }

    private suspend fun trustRoot() {
        registry.addAnchor(TrustRole.DOCUMENT, TrustEnvironment.USER, X509Cert(ByteString(root.encoded)), "Edge Test Root", official = false, source = "test")
    }

    /**
     * A PKCS#7 detached signature over [data]; [signingTime] null leaves the attribute out (only content type and
     * message digest are signed), as some PDF signing libraries do.
     */
    private fun cms(data: ByteArray, signer: X509CertificateHolder, signingTime: Date?): ByteArray {
        val digests = JcaDigestCalculatorProviderBuilder().setProvider(bc).build()
        val attributes = if (signingTime != null) {
            DefaultSignedAttributeTableGenerator(AttributeTable(ASN1EncodableVector().apply {
                add(Attribute(CMSAttributes.signingTime, DERSet(DERUTCTime(signingTime))))
            }))
        } else CMSAttributeTableGenerator { params ->
            val v = ASN1EncodableVector()
            v.add(Attribute(CMSAttributes.contentType, DERSet(params[CMSAttributeTableGenerator.CONTENT_TYPE] as org.bouncycastle.asn1.ASN1ObjectIdentifier)))
            v.add(Attribute(CMSAttributes.messageDigest, DERSet(org.bouncycastle.asn1.DEROctetString(params[CMSAttributeTableGenerator.DIGEST] as ByteArray))))
            AttributeTable(v)
        }
        val gen = CMSSignedDataGenerator()
        gen.addSignerInfoGenerator(
            JcaSignerInfoGeneratorBuilder(digests).setSignedAttributeGenerator(attributes)
                .build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(signerKey.private), signer),
        )
        gen.addCertificates(JcaCertStore(listOf(signer, root)))
        return gen.generate(CMSProcessableByteArray(data), false).toASN1Structure().getEncoded(ASN1Encoding.BER)
    }

    private fun pdf() = PdfComposer.compose("Edge", listOf(PdfComposer.Block.Paragraph("edge case")), emptyList())

    @Test
    fun berSignatureWithStrayEndMarkerAndWrongSigningTime() = runBlocking<Unit> {
        trustRoot()
        val signer = cert("CN=Edge Signer", "CN=Edge Test Root", signerKey.public, rootKey, false, now - day, now + 365 * day)
        val prepared = PdfIncrementalSigner.prepare(pdf(), PdfSignOptions(subFilter = "adbe.pkcs7.detached"))
        // An extra end-of-contents marker after the BER encoding, as an e-sign service writes it, and a signing time
        // years before the certificate was issued.
        val signed = prepared.finish(cms(prepared.signedData(), signer, Date(now - 5000 * day)) + byteArrayOf(0, 0))
        val r = DocumentInspector.inspect(signed, "e.pdf", trust)
        val s = r.signatures.single()
        assertEquals(Check.PASS, s.integrity, s.problems.toString())
        assertEquals(Check.PASS, s.certificateValidity, s.problems.toString())
        assertEquals(DocumentVerdict.VALID, r.verdict, s.problems.toString() + s.notes)
    }

    @Test
    fun pdfSigningTimeStandsInForMissingAttribute() = runBlocking<Unit> {
        trustRoot()
        // Valid from 20 to 10 days ago; signed 15 days ago by the PDF's /M entry, without a signingTime attribute.
        val signer = cert("CN=Expired Signer", "CN=Edge Test Root", signerKey.public, rootKey, false, now - 20 * day, now - 10 * day)
        val options = PdfSignOptions(subFilter = "adbe.pkcs7.detached", time = Instant.fromEpochMilliseconds(now - 15 * day))
        val prepared = PdfIncrementalSigner.prepare(pdf(), options)
        val signed = prepared.finish(cms(prepared.signedData(), signer, null))
        val s = DocumentInspector.inspect(signed, "m.pdf", trust).signatures.single()
        assertEquals(Check.PASS, s.integrity, s.problems.toString())
        // Not proven by a time stamp, but within the validity at the claimed time, and the chain reaches the anchor then.
        assertEquals(Check.WARN, s.certificateValidity, s.problems.toString())
        val labels = s.trust!!.decision().labels
        assertTrue(TrustLabel.USER_ANCHOR in labels && TrustLabel.UNKNOWN_ANCHOR !in labels, labels.toString())
    }

    @Test
    fun crossSignedRootInBundle() {
        // The bundle carries the root's key cross-signed by an older root that is not an anchor; the self-signed root is.
        val oldKey = rsa()
        val cross = cert("CN=Edge Test Root", "CN=Old Root", rootKey.public, oldKey, true, now - day, now + 365 * day)
        val leaf = cert("CN=Leaf", "CN=Edge Test Root", signerKey.public, rootKey, false, now - day, now + 365 * day)
        fun x(h: X509CertificateHolder) = X509Cert(ByteString(h.encoded))
        val anchor = Pkix.anchorOf(listOf(x(leaf), x(cross)), listOf(x(root)), Instant.fromEpochMilliseconds(now))
        assertEquals(x(root), anchor)
        assertEquals(null, Pkix.anchorOf(listOf(x(leaf), x(cross)), listOf(x(cert("CN=Other", "CN=Other", oldKey.public, oldKey, true, now - day, now + day))), Instant.fromEpochMilliseconds(now)))
    }

    @Test
    fun timeStampingRootsAreBuiltIn() {
        val names = BuiltInPublicRoots.timestamping.map { it.name }
        assertTrue(names.any { it.contains("Time Stamping", ignoreCase = true) || it.contains("Timestamping", ignoreCase = true) }, names.toString())
        assertNotEquals(0, names.size)
        assertTrue(BuiltInPublicRoots.timestamping.all { it.source.isNotEmpty() })
    }
}
