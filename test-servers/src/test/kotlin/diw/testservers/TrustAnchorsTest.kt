package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.profile.bonds.TwPkiAnchors
import diw.wallet.core.trust.BuiltInAnchors
import diw.wallet.core.trust.BuiltInPublicRoots
import diw.wallet.core.trust.BuiltInTestAnchors
import diw.wallet.core.trust.Pkix
import diw.wallet.core.trust.SystemTrustStore
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AccessDescription
import org.bouncycastle.asn1.x509.AuthorityInformationAccess
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.Date

/** Built-in Taiwan GPKI anchors, the platform's certificate store, and the built-in public and mainland China roots. */
class TrustAnchorsTest {
    @Test
    fun builtInAnchorsAreValidNow() {
        val now = Clock.System.now()
        assertEquals(11, BuiltInAnchors.all.size)
        for (a in BuiltInAnchors.all) {
            val c = a.certificate
            assertTrue(c.validityNotBefore < now && now < c.validityNotAfter, "${a.name} is not valid now")
        }
        // Citizen certificates identify persons (verifiers and document signers): never an issuer anchor.
        val moica = BuiltInAnchors.all.filter { "MOICA" in it.name }
        assertEquals(2, moica.size)
        assertTrue(moica.all { it.roles == setOf(TrustRole.VERIFIER, TrustRole.DOCUMENT) })
    }

    @Test
    fun gpkiIdentifiesButDoesNotList() = runBlocking<Unit> {
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        assertTrue(registry.seedBuiltInAnchors() > 0)
        assertEquals(0, registry.seedBuiltInAnchors(), "seeding twice adds nothing")
        // A verifier whose certificate chains to MOICA G3 (a person): identity verified, T2, not official.
        val verifier = registry.decide(TrustRole.VERIFIER, listOf(TwPkiAnchors.moicaG3))
        assertEquals(TrustTier.T2, verifier.tier)
        assertEquals(TrustEnvironment.PRODUCTION, verifier.environment)
        assertTrue(TrustLabel.IDENTITY_VERIFIED in verifier.labels)
        // The same chain cannot anchor an issuer.
        assertNull(registry.match(TrustRole.ISSUER, listOf(TwPkiAnchors.moicaG3)))
        assertTrue(registry.allAnchors().count { it.environment == TrustEnvironment.PRODUCTION } >= BuiltInAnchors.all.size)
    }

    @Test
    fun systemStore() = runBlocking<Unit> {
        val roots = SystemTrustStore.anchors()
        assertTrue(roots.isNotEmpty(), "the JDK store has roots")
        val root = roots.first { it.validityNotAfter > Clock.System.now() }
        assertEquals(root, SystemTrustStore.anchorOf(listOf(root), Clock.System.now()))
        assertNull(SystemTrustStore.anchorOf(listOf(TwPkiAnchors.moicaG3), Clock.System.now()).takeIf { TwPkiAnchors.grcaG3 !in roots })

        val off = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        assertNull(off.match(TrustRole.VERIFIER, listOf(root)))
        val on = TrustRegistry(EphemeralStorage(), EnvironmentPolicy(systemStoreEnabled = true))
        val d = on.decide(TrustRole.VERIFIER, listOf(root))
        assertEquals(TrustTier.T2, d.tier)
        assertEquals(TrustEnvironment.SYSTEM, d.environment)
        assertTrue(TrustLabel.SYSTEM_ANCHOR in d.labels)
        assertNotNull(d.anchorName)
        // Only issuers, verifiers and status list signers: never a wallet provider.
        assertNull(on.match(TrustRole.WALLET_PROVIDER, listOf(root)))
    }
    /**
     * Every built-in public root is what its entry says: the fingerprint matches, it is self-issued and its own key
     * signed it (SM2 with SM3 and the default SM2 ID for the national algorithm roots), and it was valid on the day
     * the list was generated. Expiry later is handled at run time: an expired root is no longer an anchor.
     */
    @Test
    fun builtInPublicRootsAreWhatTheySay() {
        val updated = Instant.parse(BuiltInPublicRoots.UPDATED + "T00:00:00Z")
        val bc = BouncyCastleProvider()
        val factory = java.security.cert.CertificateFactory.getInstance("X.509", bc)
        assertTrue(BuiltInPublicRoots.mainlandChina.count { !it.national } >= 15)
        for (r in BuiltInPublicRoots.all) {
            val c = r.certificate
            val sha = MessageDigest.getInstance("SHA-256").digest(c.encoded.toByteArray()).joinToString("") { "%02X".format(it) }
            assertEquals(r.sha256, sha, "${r.name} fingerprint")
            assertEquals(c.subject, c.issuer, "${r.name} is a root")
            assertTrue(c.validityNotBefore <= updated && updated <= c.validityNotAfter, "${r.name} was not valid on ${BuiltInPublicRoots.UPDATED}")
            val jca = factory.generateCertificate(c.encoded.toByteArray().inputStream()) as java.security.cert.X509Certificate
            jca.verify(jca.publicKey, bc)
            assertEquals(r.algorithm == "SM2", jca.sigAlgOID == "1.2.156.10197.1.501", "${r.name} signature algorithm")
        }
        // The e-invoice document signature issuer: the GDCA root as published for verifying electronic documents.
        assertTrue(BuiltInPublicRoots.mainlandChina.any { it.sha256 == "BFFF8FD04433487D6A8AA60C1A29767A9FC2BBB05E420F713A13B992891D3893" })
        // The national SM2 root, as both its 2012 issue and the 2054 re-issue of the same key.
        val national = BuiltInPublicRoots.mainlandChina.filter { it.national }
        assertTrue(national.size >= 17)
        assertTrue(national.any { it.sha256 == "9C28D3847414BFFF1A5749E7E2381146F82842083E8C592E16A612D04A5BA8CD" })
        assertTrue(national.any { it.sha256 == "4218EB3B3379E9AEC4B9BD9A5E3EE9F0CBA98DF97E53D9186E18A3CFF56BDAF3" })
    }

    /**
     * Real SM2 intermediates, as CFCA publishes them, validate to the built-in SM2 roots through the national-algorithm
     * PKIX path: CFCA CS SM2 CA as issued by the national root, and CFCA's OCAs under its own SM2 roots.
     */
    @Test
    fun builtInSm2RootsValidate() {
        val at = Instant.parse(BuiltInPublicRoots.UPDATED + "T00:00:00Z")
        val sm2 = BuiltInPublicRoots.mainlandChina.filter { it.national }
        fun root(name: String) = sm2.first { it.name == name }.certificate
        val roots = sm2.map { it.certificate }
        val national = roots.filter { it.subject == root("ROOTCA（國家 SM2 根，2042 年版）").subject }
        assertEquals(2, national.size)

        val underNational = pemChain("sm2-cfca-cs-under-rootca")
        assertTrue(Pkix.anchorOf(underNational, roots - root("CFCA CS SM2 CA"), at) in national)
        assertEquals(root("CFCA CS SM2 CA"), Pkix.anchorOf(pemChain("sm2-cfca-oca1"), roots, at))
        assertEquals(root("CFCA EV SM2 ROOT"), Pkix.anchorOf(pemChain("sm2-cfca-ev-oca"), roots, at))
        // Without the root that signed it, an SM2 chain leads nowhere.
        assertNull(Pkix.anchorOf(pemChain("sm2-cfca-ev-oca"), roots - root("CFCA EV SM2 ROOT"), at))
        assertNull(Pkix.anchorOf(underNational, roots - national.toSet() - root("CFCA CS SM2 CA"), at))
    }

    private fun pemChain(name: String): List<X509Cert> {
        val text = javaClass.getResource("/chains/$name.pem")!!.readText()
        return Regex("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", RegexOption.DOT_MATCHES_ALL).findAll(text).map {
            X509Cert(ByteString(java.util.Base64.getMimeDecoder().decode(it.groupValues[1])))
        }.toList()
    }

    /**
     * The National Immigration Administration signs its documents (entry and exit records, permit links) under BJCA
     * DocSign CA3 and BJCA Global Root CA3, a root outside CCADB that is pinned: such a document is a mainland China
     * CA document signature (T3) while that group is on.
     */
    @Test
    fun immigrationAdministrationDocumentChain() = runBlocking<Unit> {
        val at = Instant.parse("2026-10-11T00:00:00Z")
        val chain = pemChain("nia-document-signer")
        val ca3 = BuiltInPublicRoots.mainlandChina.first { it.name == "BJCA Global Root CA3" }
        assertEquals("AAA048773350488832AABDA6954B33EE28BB2773DD851AB3C4F6F1D2F9F3777B", ca3.sha256)
        assertEquals(ca3.certificate, Pkix.anchorOf(chain, BuiltInPublicRoots.mainlandChina.map { it.certificate }, at))
        val d = TrustRegistry(EphemeralStorage(), EnvironmentPolicy(mainlandChinaRootsEnabled = true)).decide(TrustRole.DOCUMENT, chain, at)
        assertEquals(TrustTier.T2, d.tier)
        assertTrue(TrustLabel.MAINLAND_CHINA_CA in d.labels, "labels: ${d.labels}")
        assertEquals("中國大陸憑證機構：BJCA Global Root CA3", d.anchorName)
    }

    /**
     * The certificate chains China's tax administration (invoice verification) and immigration administration served
     * on 2026-10-11 lead to CFCA EV ROOT: trusted as a mainland China CA (T3) while that group is on, not otherwise.
     */
    @Test
    fun mainlandChinaServiceChains() = runBlocking<Unit> {
        val at = Instant.parse("2026-10-11T00:00:00Z")
        val cfca = BuiltInPublicRoots.mainlandChina.first { it.name == "CFCA EV ROOT" }.certificate
        for (service in listOf("inv-veri.chinatax.gov.cn", "s.nia.gov.cn")) {
            val chain = pemChain(service)
            assertEquals(cfca, Pkix.anchorOf(chain, BuiltInPublicRoots.mainlandChina.map { it.certificate }, at), service)
            val on = TrustRegistry(EphemeralStorage(), EnvironmentPolicy(mainlandChinaRootsEnabled = true))
            val d = on.decide(TrustRole.VERIFIER, chain, at)
            assertEquals(TrustTier.T2, d.tier, service)
            assertEquals(TrustEnvironment.SYSTEM, d.environment)
            assertTrue(TrustLabel.MAINLAND_CHINA_CA in d.labels && TrustLabel.SYSTEM_ANCHOR in d.labels, "labels: ${d.labels}")
            assertEquals("中國大陸憑證機構：CFCA EV ROOT", d.anchorName)
            assertTrue(!d.official)
            val off = TrustRegistry(EphemeralStorage(), EnvironmentPolicy(mainlandChinaRootsEnabled = false))
            assertNull(off.match(TrustRole.VERIFIER, chain, at), "the group switched off: $service")
        }
    }

    private fun sm2Cert(subject: String, issuer: String, subjectKey: KeyPair, signer: PrivateKey, ca: Boolean): X509Cert {
        val bc = BouncyCastleProvider()
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(
            X500Name(issuer), BigInteger.valueOf(now), Date(now - 86_400_000L), Date(now + 365L * 86_400_000L), X500Name(subject), subjectKey.public,
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
            .addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature))
            .build(JcaContentSignerBuilder("SM3WITHSM2").setProvider(bc).build(signer))
        return X509Cert(ByteString(holder.encoded))
    }

    /** Chinese national algorithm chains (SM2 keys, SM3withSM2 signatures) validate to their SM2 root, and only to it. */
    @Test
    fun sm2ChainsValidate() {
        val gen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider()).apply { initialize(ECGenParameterSpec("sm2p256v1")) }
        val rootKey = gen.generateKeyPair()
        val leafKey = gen.generateKeyPair()
        val otherKey = gen.generateKeyPair()
        val root = sm2Cert("CN=Test SM2 Root,O=Test,C=CN", "CN=Test SM2 Root,O=Test,C=CN", rootKey, rootKey.private, ca = true)
        val leaf = sm2Cert("CN=leaf.example.cn,O=Test,C=CN", "CN=Test SM2 Root,O=Test,C=CN", leafKey, rootKey.private, ca = false)
        val impostor = sm2Cert("CN=Test SM2 Root,O=Test,C=CN", "CN=Test SM2 Root,O=Test,C=CN", otherKey, otherKey.private, ca = true)
        val now = Clock.System.now()
        assertEquals(root, Pkix.anchorOf(listOf(leaf), listOf(root), now))
        assertEquals(root, Pkix.anchorOf(listOf(leaf, root), listOf(root), now))
        // Same name, different key: the SM2 signature does not verify.
        assertNull(Pkix.anchorOf(listOf(leaf), listOf(impostor), now))
        // Not an anchor of an RSA or ECC store either.
        assertNull(Pkix.anchorOf(listOf(leaf), BuiltInPublicRoots.services.map { it.certificate }, now))
    }

    /** The Multipaz apps' issuers and readers are built in: test ones as TEST anchors (T3, marked), none official. */
    @Test
    fun multipazTestAnchorsAreBuiltIn() = runBlocking<Unit> {
        val now = Clock.System.now()
        assertEquals(18, BuiltInTestAnchors.all.size)
        assertEquals(BuiltInTestAnchors.all.size, BuiltInTestAnchors.all.map { it.certificate }.toSet().size, "no anchor twice")
        for (a in BuiltInTestAnchors.all) {
            val c = a.certificate
            assertTrue(c.validityNotBefore < now && now < c.validityNotAfter, "${a.name} is not valid now")
            // Apple publishes its issuing CA rather than the root.
            if (!a.name.startsWith("Apple")) assertEquals(c.subject, c.issuer, "${a.name} is a root")
        }
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.seedBuiltInAnchors()
        val test = registry.allAnchors().filter { it.environment == TrustEnvironment.TEST }
        assertEquals(setOf(TrustRole.ISSUER, TrustRole.STATUS_LIST, TrustRole.VERIFIER), test.map { it.role }.toSet())
        assertTrue(BuiltInTestAnchors.all.filter { !it.production }.all { a -> test.any { it.certificate == a.certificate } })
        assertTrue(test.none { it.official })
        // The production ID pass issuers of Google Wallet and Apple (as Multipaz Wallet lists them) are named, not official.
        val production = registry.allAnchors().filter { it.environment == TrustEnvironment.PRODUCTION }
        val passes = BuiltInTestAnchors.all.filter { it.production }
        assertEquals(3, passes.size)
        assertTrue(passes.all { a -> production.any { it.certificate == a.certificate && !it.official && it.role == TrustRole.ISSUER } })
        assertTrue(passes.none { a -> test.any { it.certificate == a.certificate } })
        val reader = BuiltInTestAnchors.all.first { it.name == "Multipaz Identity Reader CA" }.certificate
        assertTrue(test.none { it.role == TrustRole.ISSUER && it.certificate == reader }, "a reader CA never anchors an issuer")

        // No switch is needed: the default policy consults test anchors and marks the result.
        val pki = TestPki.create()
        registry.addAnchor(TrustRole.VERIFIER, TrustEnvironment.TEST, pki.readerRootCert, "Test Reader Root", official = false, source = "test")
        val d = registry.decide(TrustRole.VERIFIER, pki.readerKey("verifier.example").certChain.certificates)
        assertEquals(TrustTier.T3, d.tier)
        assertEquals(TrustEnvironment.TEST, d.environment)
        assertTrue(TrustLabel.TEST_ANCHOR in d.labels && !d.official)
    }

    private fun ecCert(subject: String, issuer: String, key: KeyPair, signer: PrivateKey, ca: Boolean, aia: String? = null): X509Cert {
        val now = System.currentTimeMillis()
        val b = JcaX509v3CertificateBuilder(
            X500Name(issuer), BigInteger.valueOf(System.nanoTime()), Date(now - 86_400_000L), Date(now + 365L * 86_400_000L), X500Name(subject), key.public,
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
            .addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature))
            .addExtension(Extension.subjectKeyIdentifier, false, JcaX509ExtensionUtils().createSubjectKeyIdentifier(key.public))
        if (aia != null) {
            b.addExtension(Extension.authorityInfoAccess, false, AuthorityInformationAccess(
                AccessDescription(AccessDescription.id_ad_caIssuers, GeneralName(GeneralName.uniformResourceIdentifier, aia)),
            ))
        }
        return X509Cert(ByteString(b.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer)).encoded))
    }

    /** A chain sent without its intermediate certificate is completed from the leaf's AIA caIssuers link. */
    @Test
    fun aiaCompletesMissingIntermediate() = runBlocking<Unit> {
        val gen = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val rootKey = gen.generateKeyPair()
        val midKey = gen.generateKeyPair()
        val leafKey = gen.generateKeyPair()
        val root = ecCert("CN=AIA Test Root,C=TW", "CN=AIA Test Root,C=TW", rootKey, rootKey.private, ca = true)
        val mid = ecCert("CN=AIA Test CA,C=TW", "CN=AIA Test Root,C=TW", midKey, rootKey.private, ca = true)
        val leaf = ecCert("CN=signer.example,C=TW", "CN=AIA Test CA,C=TW", leafKey, midKey.private, ca = false, aia = "http://aia.example/ca.cer")
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addAnchor(TrustRole.DOCUMENT, TrustEnvironment.USER, root, "AIA Test Root", official = false, source = "test")
        assertNull(registry.match(TrustRole.DOCUMENT, listOf(leaf)), "the leaf alone does not reach the root")
        assertEquals(TrustLabel.UNKNOWN_ANCHOR, registry.decide(TrustRole.DOCUMENT, listOf(leaf)).labels.single(), "no fetcher, no completion")

        val asked = ArrayList<String>()
        registry.issuerFetcher = { url -> asked.add(url); if (url == "http://aia.example/ca.cer") mid.encoded.toByteArray() else null }
        assertEquals(listOf(leaf, mid), registry.complete(listOf(leaf)))
        val d = registry.decide(TrustRole.DOCUMENT, listOf(leaf))
        assertEquals(TrustEnvironment.USER, d.environment)
        assertEquals("AIA Test Root", d.anchorName)
        assertTrue(d.reasons.any { "AIA" in it })
        assertEquals(listOf("http://aia.example/ca.cer"), asked, "a URL is downloaded once")

        // A certificate from the link that did not issue the leaf is not added.
        val other = ecCert("CN=Other CA,C=TW", "CN=AIA Test Root,C=TW", gen.generateKeyPair(), rootKey.private, ca = true)
        val fresh = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        fresh.issuerFetcher = { other.encoded.toByteArray() }
        assertEquals(listOf(leaf), fresh.complete(listOf(leaf)))
    }
}
