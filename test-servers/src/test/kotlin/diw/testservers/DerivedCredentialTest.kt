package diw.testservers

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.derived.DerivedClaim
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.DerivedDocument
import diw.wallet.core.document.pdf.PdfComposer
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.document.sign.Timestamper
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.BondsOfflineVerifier
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.profile.bonds.MoicaCa
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.ProtocolException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respondError
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.tsp.TimeStampRequest
import org.bouncycastle.tsp.TimeStampTokenGenerator
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.X509Cert
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Credentials derived from a document: the SD-JWT VC and its vc+moica form share disclosures, the citizen card
 * signature and an RFC 3161 time stamp travel as evidence, and a verifier checks them over the Bonds offline
 * presentation (source "a" for the SD-JWT VC, "s" for vc+moica). The citizen certificate comes from a local CA in
 * place of MOICA G3; the production CA must refuse it.
 */
class DerivedCredentialTest {
    private val bc = BouncyCastleProvider()
    private val now = Date()

    private fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun cert(subject: String, issuer: String, key: KeyPair, signer: PrivateKey, ca: Boolean, issuerKey: java.security.PublicKey, tsa: Boolean = false): X509CertificateHolder {
        val b = JcaX509v3CertificateBuilder(X500Name(issuer), BigInteger.valueOf(System.nanoTime()), Date(now.time - 86_400_000), Date(now.time + 86_400_000L * 365), X500Name(subject), key.public)
        val ext = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils()
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(key.public))
        b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuerKey))
        b.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
        b.addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature or KeyUsage.nonRepudiation))
        if (tsa) b.addExtension(Extension.extendedKeyUsage, true, ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))
        return b.build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(signer))
    }

    private val rootKey = rsa()
    private val root = cert("CN=Test GRCA", "CN=Test GRCA", rootKey, rootKey.private, true, rootKey.public)
    private val moicaKey = rsa()
    private val moica = cert("CN=Test MOICA", "CN=Test GRCA", moicaKey, rootKey.private, true, rootKey.public)
    private val holderCardKey = rsa()
    private val holderCert = cert("CN=測試人員,C=TW", "CN=Test MOICA", holderCardKey, moicaKey.private, false, moicaKey.public)
    private val tsaKey = rsa()
    private val tsaCert = cert("CN=Test TSA", "CN=Test GRCA", tsaKey, rootKey.private, false, rootKey.public, tsa = true)
    private val testCa = MoicaCa(moica.encoded, root.encoded)

    private val card = object : DocumentSigner {
        override val certificateChain = listOf(holderCert.encoded, moica.encoded)
        override val keyType = SignerKeyType.RSA
        override val source = SignerSource.SMART_CARD
        override suspend fun sign(data: ByteArray): ByteArray =
            Signature.getInstance("SHA256withRSA").run { initSign(holderCardKey.private); update(data); sign() }
    }

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

    private val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
    private val trust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: kotlin.time.Instant): TrustDecision = registry.decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
    }
    private val resolver = DidResolver(HttpClient(MockEngine { respondError(HttpStatusCode.ServiceUnavailable) }))

    private suspend fun key(): HolderKey {
        val area = SoftwareSecureArea.create(EphemeralStorage())
        val info = area.createKey(null, SoftwareCreateKeySettings.Builder().build())
        return HolderKey(area, info, shared = true, did = DidKeys.didKey(info.publicKey))
    }

    private class Issued(val compact: String, val moica: MoicaSignedCredential, val credentialKey: org.multipaz.crypto.EcPrivateKey, val selfHolder: HolderKey)

    private suspend fun issue(): Issued {
        registry.addAnchor(TrustRole.TSA, TrustEnvironment.USER, X509Cert(ByteString(root.encoded)), "Test GRCA", official = false, source = "test")
        val pdf = PdfComposer.compose("在學證明", listOf(PdfComposer.Block.Heading("在學證明"), PdfComposer.Block.Paragraph("測試用文件")))
        val report = DocumentInspector.inspect(pdf, "proof.pdf", trust)
        val claims = DerivedCredentials.suggestedClaims(report, "proof.pdf", "測試來源") + DerivedClaim(DerivedCredentials.CLAIM_NAME, "測試人員")
        assertTrue(claims.any { it.name == DerivedCredentials.CLAIM_TITLE && it.value == "在學證明" })
        val disclosures = DerivedCredentials.disclosures(claims)
        val token = timestamper.timestamp(pdf)
        val tsInfo = DocumentInspector.verifyTimestamp(token, pdf, trust)
        assertTrue(tsInfo.trusted)
        val document = DerivedDocument(report.sha256, report.format.mediaType, report.size)
        val evidence = listOf(DerivedCredentials.signatureEvidence(report), DerivedCredentials.timestampEvidence(token, tsInfo))
        val self = key()
        val payload = DerivedCredentials.moicaPayload(self.did!!, document, evidence, disclosures)
        val moica = DerivedCredentials.signMoica(payload, disclosures, self, card)
        val issuer = key()
        val credentialKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val compact = DerivedCredentials.sdJwtVc(issuer, credentialKey.publicKey, document, evidence, disclosures, moica)
        return Issued(compact, moica, credentialKey, self)
    }

    @Test
    fun sdJwtVcWithEvidenceVerifiesOverBonds() = runBlocking<Unit> {
        val issued = issue()
        val req = BondsPresentationRequest.generate("文件查驗", BondsCredentialSource.ANY)
        val jws = BondsOfflinePresentation.presentSdJwtVc(
            req, issued.compact, AsymmetricKey.anonymous(issued.credentialKey, Algorithm.ES256), issued.credentialKey.publicKey,
            setOf(DerivedCredentials.CLAIM_TITLE, DerivedCredentials.CLAIM_NAME),
        )
        val r = BondsOfflineVerifier(resolver, documentTrust = trust, moicaCa = testCa).verify(jws, req)
        assertEquals(DerivedCredentials.VCT, r.credentialType)
        assertEquals("在學證明", r.claims[DerivedCredentials.CLAIM_TITLE])
        assertEquals("測試人員", r.claims[DerivedCredentials.CLAIM_NAME])
        assertTrue(DerivedCredentials.CLAIM_FILE_NAME !in r.claims)
        assertEquals("application/pdf", r.claims["document.mediaType"])
        val byType = r.evidence.associateBy { it.type }
        assertEquals(Check.PASS, byType.getValue(DerivedCredentials.EVIDENCE_TIMESTAMP).check)
        assertEquals(Check.PASS, byType.getValue(DerivedCredentials.EVIDENCE_CITIZEN).check, byType.getValue(DerivedCredentials.EVIDENCE_CITIZEN).detail)
        assertEquals(Check.NOT_CHECKED, byType.getValue(DerivedCredentials.EVIDENCE_SIGNATURE).check)

        // The production CA does not know the test card: the citizen evidence fails, the credential itself still verifies.
        val production = BondsOfflineVerifier(resolver, documentTrust = trust).verify(jws, req)
        assertEquals(Check.FAIL, production.evidence.first { it.type == DerivedCredentials.EVIDENCE_CITIZEN }.check)
    }

    @Test
    fun vcMoicaFormVerifiesWithSelfIssuedRequest() = runBlocking<Unit> {
        val issued = issue()
        val req = BondsPresentationRequest.generate("文件查驗", BondsCredentialSource.SELF_ISSUED)
        val jws = BondsOfflinePresentation.presentMoica(req, issued.moica, issued.selfHolder, setOf(DerivedCredentials.CLAIM_SIGNER))
        val r = BondsOfflineVerifier(resolver, documentTrust = trust, moicaCa = testCa).verify(jws, req)
        assertEquals("測試人員", r.moica!!.cardholderName)
        assertTrue(r.moica!!.nameChecked)
        assertEquals(setOf(DerivedCredentials.CLAIM_NAME), r.claims.keys, "the composed PDF is unsigned, so only the name is shown")
        assertEquals(Check.PASS, r.evidence.first { it.type == DerivedCredentials.EVIDENCE_TIMESTAMP }.check)

        // Another holder key cannot present the card.
        val other = key()
        val e = assertFailsWith<ProtocolException> { BondsOfflinePresentation.presentMoica(req, issued.moica, other) }
        assertEquals("invalid_key", e.code)
        // A request for any card does not take vc+moica.
        assertFailsWith<ProtocolException> {
            BondsOfflinePresentation.presentMoica(BondsPresentationRequest.generate("文件查驗", BondsCredentialSource.ANY), issued.moica, issued.selfHolder)
        }
    }

    @Test
    fun citizenEvidenceOverOtherClaimsFails() = runBlocking<Unit> {
        val issued = issue()
        val issuer = key()
        val credentialKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val payload = issued.moica.credential()
        val document = payload["document"]!!.let { d ->
            val o = d as kotlinx.serialization.json.JsonObject
            DerivedDocument(o["sha256"]!!.toString().trim('"'), o["mediaType"]!!.toString().trim('"'), o["size"]!!.toString().toLong())
        }
        // A new credential with other claims reusing the card signature: the signed commitments differ.
        val disclosures = DerivedCredentials.disclosures(listOf(DerivedClaim(DerivedCredentials.CLAIM_NAME, "測試人員"), DerivedClaim("degree", "博士")))
        val forged = DerivedCredentials.sdJwtVc(issuer, credentialKey.publicKey, document, emptyList(), disclosures, issued.moica)
        val req = BondsPresentationRequest.generate("文件查驗", BondsCredentialSource.ANY)
        val jws = BondsOfflinePresentation.presentSdJwtVc(req, forged, AsymmetricKey.anonymous(credentialKey, Algorithm.ES256), credentialKey.publicKey)
        val r = BondsOfflineVerifier(resolver, documentTrust = trust, moicaCa = testCa).verify(jws, req)
        assertEquals(Check.FAIL, r.evidence.single { it.type == DerivedCredentials.EVIDENCE_CITIZEN }.check)
    }

    @Test
    fun moicaNeedsAnRsaCard() = runBlocking<Unit> {
        val self = key()
        val ec = object : DocumentSigner by card {
            override val keyType = SignerKeyType.EC_P256
        }
        val payload = DerivedCredentials.moicaPayload(self.did!!, DerivedDocument("00".repeat(32), "application/pdf", 1), emptyList(), emptyList())
        assertFailsWith<SigningException> { DerivedCredentials.signMoica(payload, emptyList(), self, ec) }
    }
}
