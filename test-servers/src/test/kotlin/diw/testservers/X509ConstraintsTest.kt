package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.selfIssuedNeedsRenewal
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.x509.CertificateConstraints
import diw.wallet.core.x509.CertificatePurpose
import diw.wallet.core.x509.ConstraintReport
import diw.wallet.core.x509.ConstraintRule
import diw.wallet.core.x509.ConstraintSeverity
import diw.wallet.core.x509.GeneralName as WalletGeneralName
import diw.wallet.core.x509.KeyType
import diw.wallet.core.x509.X509Details
import diw.wallet.core.x509.X509Names
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AccessDescription
import org.bouncycastle.asn1.x509.AuthorityInformationAccess
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.CertificatePolicies
import org.bouncycastle.asn1.x509.DistributionPoint
import org.bouncycastle.asn1.x509.DistributionPointName
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.GeneralSubtree
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.NameConstraints
import org.bouncycastle.asn1.x509.PolicyConstraints
import org.bouncycastle.asn1.x509.PolicyInformation
import org.bouncycastle.asn1.x509.PolicyQualifierInfo
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * The X.509 parser behind the certificate details (every field and extension, unknown ones as DER) and the usage and
 * path rules of [CertificateConstraints], alone and through [TrustRegistry.decide].
 */
class X509ConstraintsTest {
    private val now = Clock.System.now()
    private val ecGen = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
    private val rootKey = ecGen.generateKeyPair()
    private val midKey = ecGen.generateKeyPair()
    private var serial = 1L

    private class Ext(val oid: ASN1ObjectIdentifier, val critical: Boolean, val value: org.bouncycastle.asn1.ASN1Encodable)

    private fun cert(
        subject: String,
        issuer: String,
        key: KeyPair,
        signer: KeyPair,
        extensions: List<Ext>,
        algorithm: String? = null,
        keyIds: Boolean = true,
    ): X509Cert {
        val b = JcaX509v3CertificateBuilder(
            X500Name(issuer), BigInteger.valueOf(serial++), Date(System.currentTimeMillis() - 86_400_000L),
            Date(System.currentTimeMillis() + 86_400_000L * 365), X500Name(subject), key.public,
        )
        val util = JcaX509ExtensionUtils()
        if (keyIds) {
            b.addExtension(Extension.subjectKeyIdentifier, false, util.createSubjectKeyIdentifier(key.public))
            b.addExtension(Extension.authorityKeyIdentifier, false, util.createAuthorityKeyIdentifier(signer.public))
        }
        extensions.forEach { b.addExtension(it.oid, it.critical, it.value) }
        val alg = algorithm ?: if (signer.private.algorithm == "EC") "SHA256withECDSA" else "SHA256withRSA"
        return X509Cert(ByteString(b.build(JcaContentSignerBuilder(alg).build(signer.private)).encoded))
    }

    private fun ca(pathLen: Int? = null) = Ext(Extension.basicConstraints, true, if (pathLen == null) BasicConstraints(true) else BasicConstraints(pathLen))
    private fun ku(bits: Int, critical: Boolean = true) = Ext(Extension.keyUsage, critical, KeyUsage(bits))
    private fun eku(vararg p: KeyPurposeId, critical: Boolean = false) = Ext(Extension.extendedKeyUsage, critical, ExtendedKeyUsage(p))
    private fun ekuOid(vararg oid: String) = Ext(Extension.extendedKeyUsage, false, DERSequence(oid.map { ASN1ObjectIdentifier(it) }.toTypedArray()))
    private fun san(vararg n: GeneralName) = Ext(Extension.subjectAlternativeName, false, GeneralNames(n))
    private val caUsage = ku(KeyUsage.keyCertSign or KeyUsage.cRLSign)
    private val signUsage = ku(KeyUsage.digitalSignature or KeyUsage.nonRepudiation)

    private fun root(vararg extra: Ext) = cert("CN=Constraint Root,O=Test,C=TW", "CN=Constraint Root,O=Test,C=TW", rootKey, rootKey, listOf(ca(), caUsage) + extra)
    private fun mid(vararg ext: Ext) = cert("CN=Constraint CA,O=Test,C=TW", "CN=Constraint Root,O=Test,C=TW", midKey, rootKey, ext.toList())
    private fun leaf(vararg ext: Ext, subject: String = "CN=Leaf,O=Test,C=TW", issuer: KeyPair = midKey, issuerName: String = "CN=Constraint CA,O=Test,C=TW") =
        cert(subject, issuerName, ecGen.generateKeyPair(), issuer, ext.toList())

    private fun ConstraintReport.rules(severity: ConstraintSeverity) = findings.filter { it.severity == severity }.map { it.rule }

    @Test
    fun parsesEveryFieldAndExtension() {
        val unknown = "1.3.6.1.4.1.99999.1"
        val c = cert(
            "CN=Parse Test,O=測試機關,C=TW,E=parse@example.tw", "CN=Constraint Root,O=Test,C=TW", ecGen.generateKeyPair(), rootKey,
            listOf(
                signUsage,
                eku(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth),
                Ext(Extension.basicConstraints, true, BasicConstraints(false)),
                san(GeneralName(GeneralName.dNSName, "parse.example.tw"), GeneralName(GeneralName.rfc822Name, "a@example.tw"),
                    GeneralName(GeneralName.uniformResourceIdentifier, "https://parse.example.tw/x"), GeneralName(GeneralName.iPAddress, "192.0.2.7")),
                Ext(Extension.certificatePolicies, false, CertificatePolicies(arrayOf(
                    PolicyInformation(ASN1ObjectIdentifier("2.16.886.101.0.3.0"), DERSequence(PolicyQualifierInfo("https://cps.example.tw"))),
                ))),
                Ext(Extension.cRLDistributionPoints, false, CRLDistPoint(arrayOf(DistributionPoint(
                    DistributionPointName(GeneralNames(GeneralName(GeneralName.uniformResourceIdentifier, "http://crl.example.tw/a.crl"))), null, null)))),
                Ext(Extension.authorityInfoAccess, false, AuthorityInformationAccess(arrayOf(
                    AccessDescription(AccessDescription.id_ad_ocsp, GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.tw")),
                    AccessDescription(AccessDescription.id_ad_caIssuers, GeneralName(GeneralName.uniformResourceIdentifier, "http://ca.example.tw/ca.cer")),
                ))),
                Ext(ASN1ObjectIdentifier(unknown), true, DEROctetString(byteArrayOf(1, 2, 3))),
            ),
        )
        val d = X509Details.of(c)
        assertEquals(3, d.version)
        assertEquals("測試機關", d.subject.first("2.5.4.10"))
        assertEquals("parse@example.tw", d.subject.first(X509Names.EMAIL_ADDRESS))
        assertEquals("Constraint Root", d.issuer.first("2.5.4.3"))
        assertEquals(KeyType.EC, d.publicKey.type)
        assertEquals(256, d.publicKey.bits)
        assertEquals("1.2.840.10045.4.3.2", d.signatureAlgorithm.oid)
        assertEquals(d.signatureAlgorithm, d.tbsSignatureAlgorithm)
        assertTrue(d.problems.isEmpty(), d.problems.toString())
        assertEquals(64, d.sha256Hex.length)
        assertEquals(setOf(0, 1), d.keyUsage)
        assertEquals(listOf(X509Names.KP_SERVER_AUTH, X509Names.KP_CLIENT_AUTH), d.extendedKeyUsage)
        assertEquals(false to null, d.basicConstraints)
        assertEquals(
            listOf(WalletGeneralName.Type.DNS, WalletGeneralName.Type.RFC822, WalletGeneralName.Type.URI, WalletGeneralName.Type.IP),
            d.subjectAltNames.map { it.type },
        )
        assertEquals("192.0.2.7", d.subjectAltNames.last().value)
        assertEquals(listOf("2.16.886.101.0.3.0"), d.policies)
        // Every known extension is decoded into fields; the unknown one is kept with its criticality and DER value.
        val known = d.extensions.filter { it.known }
        assertEquals(9, known.size)
        assertTrue(known.all { it.fields.isNotEmpty() && it.error == null }, known.filter { it.fields.isEmpty() }.toString())
        assertTrue(d.extension(Extension.cRLDistributionPoints.id)!!.fields.any { "crl.example.tw" in it.value })
        assertTrue(d.extension(Extension.authorityInfoAccess.id)!!.fields.any { "ocsp.example.tw" in it.value })
        val u = d.extension(unknown)!!
        assertTrue(u.critical && !u.known)
        assertEquals("0403010203", u.valueHex.lowercase())

        // The unknown critical extension rejects the certificate; on the trust anchor it is only noted.
        val asLeaf = CertificateConstraints.check(listOf(c), CertificatePurpose.ISSUER, now, anchored = false)
        assertTrue(ConstraintRule.UNKNOWN_CRITICAL_EXTENSION in asLeaf.rules(ConstraintSeverity.FAIL), asLeaf.toString())
        val anchor = cert("CN=Odd Root,C=TW", "CN=Odd Root,C=TW", rootKey, rootKey, listOf(ca(), caUsage, Ext(ASN1ObjectIdentifier(unknown), true, DEROctetString(byteArrayOf(0)))))
        val l = leaf(signUsage, issuer = rootKey, issuerName = "CN=Odd Root,C=TW")
        val anchored = CertificateConstraints.check(listOf(l, anchor), CertificatePurpose.DOCUMENT, now, anchored = true)
        assertFalse(anchored.failed, anchored.toString())
        assertTrue(ConstraintRule.UNKNOWN_CRITICAL_EXTENSION in anchored.rules(ConstraintSeverity.NOTE))
    }

    @Test
    fun rsaKeyAndVersionOne() {
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val c = cert("CN=RSA,C=TW", "CN=RSA,C=TW", rsa, rsa, listOf(ca(), caUsage))
        val d = X509Details.of(c)
        assertEquals(KeyType.RSA, d.publicKey.type)
        assertEquals(2048, d.publicKey.bits)
        assertEquals("65537", d.publicKey.rsaExponent)
        assertTrue(d.selfIssued)
    }

    @Test
    fun leafUsageFollowsThePurpose() {
        val r = root()
        val m = mid(ca(), caUsage)
        fun check(purpose: CertificatePurpose, vararg ext: Ext) = CertificateConstraints.check(listOf(leaf(*ext), m, r), purpose, now, anchored = true)

        // keyUsage without a signing bit may not sign anything.
        assertTrue(ConstraintRule.KEY_USAGE in check(CertificatePurpose.DOCUMENT, ku(KeyUsage.keyEncipherment)).rules(ConstraintSeverity.FAIL))
        // Document signatures: a TLS server certificate is not allowed; documentSigning, emailProtection and unknown purposes are.
        assertTrue(check(CertificatePurpose.DOCUMENT, signUsage, eku(KeyPurposeId.id_kp_serverAuth)).failed)
        assertFalse(check(CertificatePurpose.DOCUMENT, signUsage, ekuOid(X509Names.KP_DOCUMENT_SIGNING)).failed)
        assertFalse(check(CertificatePurpose.DOCUMENT, signUsage, eku(KeyPurposeId.id_kp_emailProtection)).failed)
        val vendor = check(CertificatePurpose.DOCUMENT, signUsage, ekuOid("1.3.6.1.4.1.99999.7"))
        assertFalse(vendor.failed)
        assertTrue(ConstraintRule.EXTENDED_KEY_USAGE in vendor.rules(ConstraintSeverity.NOTE))
        assertFalse(check(CertificatePurpose.DOCUMENT, signUsage).failed)

        // RFC 3161 2.3: exactly timeStamping, critical.
        assertFalse(check(CertificatePurpose.TSA, signUsage, eku(KeyPurposeId.id_kp_timeStamping, critical = true)).failed)
        assertTrue(check(CertificatePurpose.TSA, signUsage, eku(KeyPurposeId.id_kp_timeStamping)).failed)
        assertTrue(check(CertificatePurpose.TSA, signUsage, eku(KeyPurposeId.id_kp_timeStamping, KeyPurposeId.id_kp_serverAuth, critical = true)).failed)
        assertTrue(check(CertificatePurpose.TSA, signUsage).failed)

        // C2PA 14.5.1: EKU required, no anyExtendedKeyUsage, a claim signing purpose.
        assertTrue(check(CertificatePurpose.CONTENT, signUsage).failed)
        assertTrue(check(CertificatePurpose.CONTENT, signUsage, eku(KeyPurposeId.anyExtendedKeyUsage)).failed)
        assertTrue(check(CertificatePurpose.CONTENT, signUsage, eku(KeyPurposeId.id_kp_serverAuth)).failed)
        assertFalse(check(CertificatePurpose.CONTENT, signUsage, ekuOid(X509Names.KP_DOCUMENT_SIGNING)).failed)

        // ISO/IEC 18013-5 Table B.3: a document signer needs digitalSignature and, with an EKU, 1.0.18013.5.1.2.
        assertFalse(check(CertificatePurpose.MDOC_ISSUER, ku(KeyUsage.digitalSignature), ekuOid(X509Names.KP_MDOC_DS)).failed)
        assertTrue(check(CertificatePurpose.MDOC_ISSUER, ku(KeyUsage.nonRepudiation), ekuOid(X509Names.KP_MDOC_DS)).failed)
        assertTrue(check(CertificatePurpose.MDOC_ISSUER, ku(KeyUsage.digitalSignature), ekuOid(X509Names.KP_MDOC_READER)).failed)
        val noEku = check(CertificatePurpose.MDOC_ISSUER, ku(KeyUsage.digitalSignature))
        assertFalse(noEku.failed)
        assertTrue(ConstraintRule.EXTENDED_KEY_USAGE in noEku.rules(ConstraintSeverity.NOTE))

        // Other roles: a key dedicated to time stamps or OCSP signs nothing else; an unusual purpose is only noted.
        assertTrue(check(CertificatePurpose.ISSUER, signUsage, eku(KeyPurposeId.id_kp_timeStamping)).failed)
        val reader = check(CertificatePurpose.ISSUER, signUsage, ekuOid(X509Names.KP_MDOC_READER))
        assertFalse(reader.failed)
        assertTrue(ConstraintRule.EXTENDED_KEY_USAGE in reader.rules(ConstraintSeverity.NOTE))
        assertFalse(check(CertificatePurpose.VERIFIER, signUsage, eku(KeyPurposeId.id_kp_serverAuth)).failed)

        // RFC 6960 4.2.2.2: a delegated OCSP responder needs OCSPSigning.
        assertTrue(CertificateConstraints.ocspResponderAllowed(leaf(signUsage, eku(KeyPurposeId.id_kp_OCSPSigning))))
        assertFalse(CertificateConstraints.ocspResponderAllowed(leaf(signUsage)))
        assertFalse(CertificateConstraints.ocspResponderAllowed(leaf(signUsage, eku(KeyPurposeId.id_kp_serverAuth))))
    }

    @Test
    fun issuingCertificatesMustBeCas() {
        val r = root()
        val l = leaf(signUsage)
        assertFalse(CertificateConstraints.check(listOf(l, mid(ca(), caUsage), r), null, now, anchored = true).failed)
        // An intermediate without cA=TRUE, or whose keyUsage lacks keyCertSign, issues nothing.
        val notCa = CertificateConstraints.check(listOf(l, mid(caUsage), r), null, now, anchored = true)
        assertTrue(ConstraintRule.BASIC_CONSTRAINTS in notCa.rules(ConstraintSeverity.FAIL))
        assertEquals(1, notCa.failures.single().index)
        val noSign = CertificateConstraints.check(listOf(l, mid(ca(), ku(KeyUsage.digitalSignature)), r), null, now, anchored = true)
        assertTrue(ConstraintRule.CA_KEY_USAGE in noSign.rules(ConstraintSeverity.FAIL))
        // The anchor's own pathLenConstraint counts the intermediates below it.
        val tight = cert("CN=Constraint Root,O=Test,C=TW", "CN=Constraint Root,O=Test,C=TW", rootKey, rootKey, listOf(ca(0), caUsage))
        val tooLong = CertificateConstraints.check(listOf(l, mid(ca(), caUsage), tight), null, now, anchored = true)
        assertTrue(ConstraintRule.PATH_LENGTH in tooLong.rules(ConstraintSeverity.FAIL))
        val one = cert("CN=Constraint Root,O=Test,C=TW", "CN=Constraint Root,O=Test,C=TW", rootKey, rootKey, listOf(ca(1), caUsage))
        assertFalse(CertificateConstraints.check(listOf(l, mid(ca(), caUsage), one), null, now, anchored = true).failed)
        // An intermediate's pathLen 0 still allows the leaf.
        assertFalse(CertificateConstraints.check(listOf(l, mid(ca(0), caUsage), r), null, now, anchored = true).failed)
    }

    @Test
    fun nameConstraintsIncludeTheAnchors() {
        // Names in the usual order (country first), so that the directory name constraint is a prefix of the subjects.
        val nc = Ext(Extension.nameConstraints, true, NameConstraints(
            arrayOf(GeneralSubtree(GeneralName(GeneralName.dNSName, "example.tw")), GeneralSubtree(GeneralName(X500Name("C=TW,O=Test")))),
            arrayOf(GeneralSubtree(GeneralName(GeneralName.dNSName, "bad.example.tw"))),
        ))
        val r = root(nc)
        val midName = "C=TW,O=Test,CN=Constraint CA"
        val m = cert(midName, "CN=Constraint Root,O=Test,C=TW", midKey, rootKey, listOf(ca(), caUsage))
        fun check(vararg ext: Ext, subject: String = "C=TW,O=Test,CN=Leaf") =
            CertificateConstraints.check(listOf(leaf(*ext, subject = subject, issuerName = midName), m, r), CertificatePurpose.DOCUMENT, now, anchored = true)

        val inside = check(signUsage, san(GeneralName(GeneralName.dNSName, "www.example.tw")))
        assertFalse(inside.failed, inside.toString())
        val outside = check(signUsage, san(GeneralName(GeneralName.dNSName, "www.example.com")))
        assertTrue(ConstraintRule.NAME_CONSTRAINTS in outside.rules(ConstraintSeverity.FAIL))
        assertEquals(0, outside.failures.single().index)
        assertTrue(check(signUsage, san(GeneralName(GeneralName.dNSName, "x.bad.example.tw"))).failed)
        // The subject must sit under the permitted directory name.
        assertTrue(check(signUsage, subject = "C=TW,O=Other,CN=Leaf").failed)
        // An intermediate outside the anchor's constraints fails too.
        val stray = cert("C=JP,O=Test,CN=Constraint CA", "CN=Constraint Root,O=Test,C=TW", midKey, rootKey, listOf(ca(), caUsage))
        val strayLeaf = leaf(signUsage, subject = "C=TW,O=Test,CN=Leaf", issuerName = "C=JP,O=Test,CN=Constraint CA")
        assertEquals(1, CertificateConstraints.check(listOf(strayLeaf, stray, r), null, now, anchored = true).failures.single().index)
        // A name form the constraints restrict but the wallet cannot compare fails closed.
        val other = Ext(Extension.nameConstraints, true, NameConstraints(arrayOf(GeneralSubtree(GeneralName(GeneralName.registeredID, "1.2.3"))), null))
        val strict = CertificateConstraints.check(
            listOf(leaf(signUsage, san(GeneralName(GeneralName.registeredID, "1.2.3.4"))), mid(ca(), caUsage), root(other)), CertificatePurpose.DOCUMENT, now, anchored = true,
        )
        assertTrue(ConstraintRule.NAME_CONSTRAINTS in strict.rules(ConstraintSeverity.FAIL), strict.toString())
    }

    @Test
    fun explicitPolicyIsEnforced() {
        val policy = "2.16.886.101.0.3.1"
        fun cp(vararg oid: String) = Ext(Extension.certificatePolicies, false, CertificatePolicies(oid.map { PolicyInformation(ASN1ObjectIdentifier(it)) }.toTypedArray()))
        // The anchor's own policy extensions are not processed (RFC 5280 6.1.1): the intermediate requires the policy.
        val require = Ext(Extension.policyConstraints, true, PolicyConstraints(BigInteger.ZERO, null))
        val r = root()
        val m = mid(ca(), caUsage, cp(policy), require)
        assertFalse(CertificateConstraints.check(listOf(leaf(signUsage, cp(policy)), m, r), null, now, anchored = true).failed)
        val none = CertificateConstraints.check(listOf(leaf(signUsage), m, r), null, now, anchored = true)
        assertTrue(ConstraintRule.CERTIFICATE_POLICIES in none.rules(ConstraintSeverity.FAIL), none.toString())
        assertTrue(CertificateConstraints.check(listOf(leaf(signUsage, cp("2.16.886.101.0.3.9")), m, r), null, now, anchored = true).failed)
        // anyPolicy in the intermediate passes the leaf's policy on.
        val any = mid(ca(), caUsage, cp(X509Names.ANY_POLICY), require)
        assertFalse(CertificateConstraints.check(listOf(leaf(signUsage, cp(policy)), any, r), null, now, anchored = true).failed)
        // Without a requirement, certificates without policies are fine.
        assertFalse(CertificateConstraints.check(listOf(leaf(signUsage), mid(ca(), caUsage), root()), null, now, anchored = true).failed)
    }

    @Test
    fun weakAlgorithmsDependOnTheTime() {
        val rsaRoot = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val short = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val rootName = "CN=RSA Root,C=TW"
        val r = cert(rootName, rootName, rsaRoot, rsaRoot, listOf(ca(), caUsage))
        val shortLeaf = cert("CN=Short,C=TW", rootName, short, rsaRoot, listOf(signUsage))
        val sha1Leaf = cert("CN=SHA1,C=TW", rootName, ecGen.generateKeyPair(), rsaRoot, listOf(signUsage), algorithm = "SHA1withRSA")
        val before = Instant.parse("2012-06-01T00:00:00Z")

        val shortNow = CertificateConstraints.check(listOf(shortLeaf, r), CertificatePurpose.DOCUMENT, now, anchored = true)
        assertTrue(shortNow.weak && !shortNow.failed, shortNow.toString())
        assertTrue(ConstraintRule.KEY_STRENGTH in shortNow.rules(ConstraintSeverity.WEAK))
        assertFalse(CertificateConstraints.check(listOf(shortLeaf, r), CertificatePurpose.DOCUMENT, before, anchored = true).weak)
        val sha1 = CertificateConstraints.check(listOf(sha1Leaf, r), CertificatePurpose.DOCUMENT, now, anchored = true)
        assertTrue(ConstraintRule.SIGNATURE_ALGORITHM in sha1.rules(ConstraintSeverity.WEAK))
        assertFalse(CertificateConstraints.check(listOf(sha1Leaf, r), CertificatePurpose.DOCUMENT, before, anchored = true).weak)
        // The anchor's own self-signature is not relied on.
        val sha1Root = cert(rootName, rootName, rsaRoot, rsaRoot, listOf(ca(), caUsage), algorithm = "SHA1withRSA")
        val good = cert("CN=Good,C=TW", rootName, ecGen.generateKeyPair(), rsaRoot, listOf(signUsage))
        assertFalse(CertificateConstraints.check(listOf(good, sha1Root), CertificatePurpose.DOCUMENT, now, anchored = true).weak)
    }

    @Test
    fun trustDecisionReportsTheRule() = runBlocking<Unit> {
        val r = root()
        val m = mid(ca(), caUsage)
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addAnchor(TrustRole.DOCUMENT, TrustEnvironment.USER, r, "Constraint Root", official = false, source = "test")
        registry.addAnchor(TrustRole.TSA, TrustEnvironment.USER, r, "Constraint Root", official = false, source = "test")

        val good = registry.decide(TrustRole.DOCUMENT, listOf(leaf(signUsage, ekuOid(X509Names.KP_DOCUMENT_SIGNING)), m))
        assertEquals(TrustTier.T2, good.tier)
        assertFalse(TrustLabel.CERTIFICATE_CONSTRAINT in good.labels)

        // A TLS server certificate under the same root may not sign documents: T4 naming the rule and the root.
        val server = leaf(signUsage, eku(KeyPurposeId.id_kp_serverAuth))
        val bad = registry.decide(TrustRole.DOCUMENT, listOf(server, m))
        assertEquals(TrustTier.T4, bad.tier)
        assertTrue(TrustLabel.CERTIFICATE_CONSTRAINT in bad.labels)
        assertEquals("Constraint Root", bad.anchorName)
        assertTrue(bad.reasons.single().startsWith("Leaf: "), bad.reasons.toString())
        assertEquals(null, registry.match(TrustRole.DOCUMENT, listOf(server, m)))
        val rejected = registry.evaluate(TrustRole.DOCUMENT, listOf(server, m))
        assertNotNull(rejected.rejected)

        // The chain screen draws the path to the root and puts the finding on the leaf.
        val p = registry.path(listOf(server, m), TrustRole.DOCUMENT)
        assertTrue(p.rootReached)
        assertEquals(bad, p.decision)
        assertEquals(ConstraintRule.EXTENDED_KEY_USAGE, p.constraints.at(0).single { it.severity == ConstraintSeverity.FAIL }.rule)
        assertTrue(p.constraints.at(1).none { it.severity == ConstraintSeverity.FAIL })

        // The same leaf is a valid TSA only with the RFC 3161 profile.
        assertEquals(TrustTier.T4, registry.decide(TrustRole.TSA, listOf(server, m)).tier)
        assertEquals(TrustTier.T2, registry.decide(TrustRole.TSA, listOf(leaf(signUsage, eku(KeyPurposeId.id_kp_timeStamping, critical = true)), m)).tier)

        // A chain to no anchor that breaks a rule is T4 as well, not T3.
        val stranger = TrustRegistry(EphemeralStorage(), EnvironmentPolicy()).decide(TrustRole.DOCUMENT, listOf(server, m, r))
        assertEquals(TrustTier.T4, stranger.tier)

        // A weak key keeps the chain valid but at most T3.
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val weakLeaf = cert("CN=Weak,O=Test,C=TW", "CN=Constraint CA,O=Test,C=TW", rsa, midKey, listOf(signUsage))
        val weak = registry.decide(TrustRole.DOCUMENT, listOf(weakLeaf, m))
        assertEquals(TrustTier.T3, weak.tier)
        assertTrue(TrustLabel.WEAK_ALGORITHM in weak.labels)
        assertEquals("Constraint Root", weak.anchorName)
    }

    /** The wallet's own self-issued certificates carry an extKeyUsage that document and C2PA signatures accept. */
    @Test
    fun selfIssuedCertificatesMeetTheContentProfile() = runBlocking<Unit> {
        val key = ecGen.generateKeyPair()
        suspend fun make(purposes: List<String>?): ByteArray {
            val sign: suspend (ByteArray) -> ByteArray = { data ->
                java.security.Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(data); sign() }
            }
            return if (purposes == null) DocumentSigning.selfIssuedCertificate(key.public.encoded, "Self", sign, SignerKeyType.EC_P256, 30)
            else DocumentSigning.selfIssuedCertificate(key.public.encoded, "Self", sign, SignerKeyType.EC_P256, 30, purposes)
        }
        val made = make(null)
        val cert = X509Cert(ByteString(made))
        assertFalse(selfIssuedNeedsRenewal(made))
        for (purpose in listOf(CertificatePurpose.CONTENT, CertificatePurpose.DOCUMENT)) {
            assertFalse(CertificateConstraints.check(listOf(cert), purpose, now, anchored = false).failed, purpose.name)
        }
        // A certificate without extKeyUsage (made before, or the reader key) is renewed for signing.
        assertTrue(selfIssuedNeedsRenewal(make(emptyList())))
    }

    /**
     * A key rollover certificate under the root's own name stays on the checked path when the certificates below it
     * name no authorityKeyIdentifier: the anchor must verify the signature, a name match is not enough.
     */
    @Test
    fun rolloverCertificateStaysOnThePath() = runBlocking<Unit> {
        val name = "CN=Rollover Root,C=TW"
        val rsaOld = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val rsaNew = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val root = cert(name, name, rsaOld, rsaOld, listOf(ca(), caUsage))
        val rollover = cert(name, name, rsaNew, rsaOld, listOf(ca(), caUsage), algorithm = "SHA1withRSA", keyIds = false)
        val leafCert = cert("CN=Rollover Leaf,C=TW", name, ecGen.generateKeyPair(), rsaNew, listOf(signUsage), keyIds = false)
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addAnchor(TrustRole.DOCUMENT, TrustEnvironment.USER, root, "Rollover Root", official = false, source = "test")
        val ev = registry.evaluate(TrustRole.DOCUMENT, listOf(leafCert, rollover))
        val m = assertNotNull(ev.match, ev.toString())
        assertEquals(listOf(leafCert, rollover, root), m.path)
        assertTrue(ConstraintRule.SIGNATURE_ALGORITHM in ev.constraints.rules(ConstraintSeverity.WEAK), ev.constraints.toString())
        assertEquals(TrustTier.T3, registry.decision(ev).tier)
    }

    /**
     * An intermediate trust anchor signed with SHA-1: the decision does not rely on that signature, and the chain
     * screen, drawn on to the root above the anchor, shows the decision's findings rather than checking again.
     */
    @Test
    fun chainScreenUsesTheDecisionsFindings() = runBlocking<Unit> {
        val rsaRoot = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val rootName = "CN=Old Root,C=TW"
        val midName = "CN=Anchored CA,C=TW"
        val r = cert(rootName, rootName, rsaRoot, rsaRoot, listOf(ca(), caUsage))
        val m = cert(midName, rootName, midKey, rsaRoot, listOf(ca(), caUsage), algorithm = "SHA1withRSA")
        val l = leaf(signUsage, issuerName = midName)
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addAnchor(TrustRole.DOCUMENT, TrustEnvironment.USER, m, "Anchored CA", official = false, source = "test")
        val d = registry.decide(TrustRole.DOCUMENT, listOf(l, m, r))
        assertEquals(TrustTier.T2, d.tier, d.reasons.toString())
        val p = registry.path(listOf(l, m, r), TrustRole.DOCUMENT)
        assertEquals(listOf(l, m, r), p.steps.map { it.certificate })
        assertEquals(d, p.decision)
        assertFalse(p.constraints.weak || p.constraints.failed, p.constraints.toString())
        // Without a role only the path rules apply to the path as drawn, and the root's SHA-1 signature on the CA shows.
        assertTrue(registry.path(listOf(l, m, r)).constraints.weak)
    }

    /** An intermediate the wallet completes the chain with is checked even when no anchor is found above it. */
    @Test
    fun completedChainWithoutAnchorIsChecked() = runBlocking<Unit> {
        val nc = Ext(Extension.nameConstraints, true, NameConstraints(null, arrayOf(GeneralSubtree(GeneralName(GeneralName.dNSName, "blocked.tw")))))
        val m = mid(ca(), caUsage, nc)
        val l = leaf(signUsage, san(GeneralName(GeneralName.dNSName, "www.blocked.tw")))
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addIntermediate(m, "Constraint CA", "test")
        val d = registry.decide(TrustRole.DOCUMENT, listOf(l))
        assertEquals(TrustTier.T4, d.tier, d.toString())
        assertTrue(TrustLabel.CERTIFICATE_CONSTRAINT in d.labels)
        // The same chain sent complete gives the same result.
        assertEquals(d, registry.decide(TrustRole.DOCUMENT, listOf(l, m)))
    }

    /** The subject's emailAddress is held to rfc822Name constraints only when there is no subjectAltName (RFC 5280 4.2.1.10). */
    @Test
    fun legacyEmailOnlyWithoutSubjectAltName() {
        val nc = Ext(Extension.nameConstraints, true, NameConstraints(arrayOf(GeneralSubtree(GeneralName(GeneralName.rfc822Name, "allowed.tw"))), null))
        val m = mid(ca(), caUsage, nc)
        val r = root()
        fun check(vararg ext: Ext) = CertificateConstraints.check(
            listOf(leaf(*ext, subject = "CN=Mail,O=Test,C=TW,E=legacy@elsewhere.tw"), m, r), CertificatePurpose.DOCUMENT, now, anchored = true,
        )
        assertFalse(check(signUsage, san(GeneralName(GeneralName.rfc822Name, "current@allowed.tw"))).failed)
        assertTrue(check(signUsage).failed)
    }
}
