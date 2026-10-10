package diw.testservers

import org.multipaz.asn1.ASN1Integer
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.util.truncateToWholeSeconds
import java.io.File
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * Test PKI for the development servers. Everything here belongs to the TEST environment only.
 * - IACA + document signer: issues mdoc and SD-JWT VC credentials and signs status lists.
 * - Reader root + reader certificates: Verifier access certificates (x509_san_dns / x509_hash).
 * - Wallet provider root + signer: wallet instance and key attestations.
 * Keys are persisted under [dir] when given, so a wallet can import the anchors once.
 */
class TestPki private constructor(
    val iaca: AsymmetricKey.X509CertifiedExplicit,
    val documentSigner: AsymmetricKey.X509CertifiedExplicit,
    val readerRoot: AsymmetricKey.X509CertifiedExplicit,
    val walletProviderRoot: AsymmetricKey.X509CertifiedExplicit,
    val walletProviderSigner: AsymmetricKey.X509CertifiedExplicit,
) {
    val iacaCert: X509Cert get() = iaca.certChain.certificates.first()
    val readerRootCert: X509Cert get() = readerRoot.certChain.certificates.first()
    val walletProviderRootCert: X509Cert get() = walletProviderRoot.certChain.certificates.first()

    private val readerKeys = mutableMapOf<String, AsymmetricKey.X509CertifiedExplicit>()

    /** Verifier access certificate with a dNSName SAN, chained to the reader root (root included last). */
    suspend fun readerKey(dnsName: String): AsymmetricKey.X509CertifiedExplicit = readerKeys[dnsName] ?: run {
        val key = Crypto.createEcPrivateKey(EcCurve.P256)
        val root = readerRootCert
        val cert = MdocUtil.generateReaderCertificate(
            readerRootKey = readerRoot,
            readerKey = key.publicKey,
            subject = X500Name.fromName("C=TW,O=DIW Test Verifier,CN=$dnsName"),
            dnsName = dnsName,
            serial = ASN1Integer.fromRandom(128),
            validFrom = root.validityNotBefore,
            validUntil = root.validityNotAfter,
        )
        AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(cert, root)), key).also { readerKeys[dnsName] = it }
    }

    companion object {
        suspend fun create(dir: File? = null): TestPki {
            if (dir != null && File(dir, "iaca.pem").exists()) return load(dir)
            val now = Clock.System.now().truncateToWholeSeconds()
            val from = now - 1.days
            val until = now + 730.days

            val iacaPriv = Crypto.createEcPrivateKey(EcCurve.P256)
            val iacaCert = MdocUtil.generateIacaCertificate(
                iacaKey = AsymmetricKey.anonymous(iacaPriv),
                subject = X500Name.fromName("C=TW,O=DIW MY WALLET TEST,CN=DIW TEST IACA"),
                serial = ASN1Integer.fromRandom(128),
                validFrom = from, validUntil = until,
                issuerAltNameUrl = "https://issuer.test.diw.invalid",
                crlUrl = "https://issuer.test.diw.invalid/crl",
            )
            val iaca = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(iacaCert)), iacaPriv)

            val dsPriv = Crypto.createEcPrivateKey(EcCurve.P256)
            val dsCert = MdocUtil.generateDsCertificate(
                iacaKey = iaca, dsKey = dsPriv.publicKey,
                subject = X500Name.fromName("C=TW,O=DIW MY WALLET TEST,CN=DIW TEST Document Signer"),
                serial = ASN1Integer.fromRandom(128), validFrom = from, validUntil = until,
            )
            val ds = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(dsCert)), dsPriv)

            val readerPriv = Crypto.createEcPrivateKey(EcCurve.P256)
            val readerCert = MdocUtil.generateReaderRootCertificate(
                readerRootKey = AsymmetricKey.anonymous(readerPriv),
                subject = X500Name.fromName("C=TW,O=DIW MY WALLET TEST,CN=DIW TEST Verifier Root"),
                serial = ASN1Integer.fromRandom(128), validFrom = from, validUntil = until,
                crlUrl = "https://verifier.test.diw.invalid/crl",
            )
            val reader = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(readerCert)), readerPriv)

            val wpPriv = Crypto.createEcPrivateKey(EcCurve.P256)
            val wpCert = MdocUtil.generateIacaCertificate(
                iacaKey = AsymmetricKey.anonymous(wpPriv),
                subject = X500Name.fromName("C=TW,O=DIW MY WALLET TEST,CN=DIW TEST Wallet Provider Root"),
                serial = ASN1Integer.fromRandom(128), validFrom = from, validUntil = until,
                issuerAltNameUrl = "https://wallet-provider.test.diw.invalid",
                crlUrl = "https://wallet-provider.test.diw.invalid/crl",
            )
            val wpRoot = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(wpCert)), wpPriv)
            val wpsPriv = Crypto.createEcPrivateKey(EcCurve.P256)
            val wpsCert = MdocUtil.generateDsCertificate(
                iacaKey = wpRoot, dsKey = wpsPriv.publicKey,
                subject = X500Name.fromName("C=TW,O=DIW MY WALLET TEST,CN=DIW TEST Wallet Provider"),
                serial = ASN1Integer.fromRandom(128), validFrom = from, validUntil = until,
            )
            val wps = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(wpsCert)), wpsPriv)

            val pki = TestPki(iaca, ds, reader, wpRoot, wps)
            if (dir != null) pki.save(dir)
            return pki
        }

        private fun load(dir: File): TestPki {
            fun key(name: String, chainNames: List<String>): AsymmetricKey.X509CertifiedExplicit {
                val certs = chainNames.map { X509Cert.fromPem(File(dir, "$it.pem").readText()) }
                val priv = EcPrivateKey.fromPem(File(dir, "$name.key.pem").readText(), certs.first().ecPublicKey)
                return AsymmetricKey.X509CertifiedExplicit(X509CertChain(certs), priv)
            }
            return TestPki(
                iaca = key("iaca", listOf("iaca")),
                documentSigner = key("ds", listOf("ds")),
                readerRoot = key("reader-root", listOf("reader-root")),
                walletProviderRoot = key("wallet-provider-root", listOf("wallet-provider-root")),
                walletProviderSigner = key("wallet-provider", listOf("wallet-provider")),
            )
        }
    }

    fun save(dir: File) {
        dir.mkdirs()
        fun put(name: String, k: AsymmetricKey.X509CertifiedExplicit) {
            File(dir, "$name.pem").writeText(k.certChain.certificates.first().toPem())
            File(dir, "$name.key.pem").writeText(k.privateKey.toPem())
        }
        put("iaca", iaca)
        put("ds", documentSigner)
        put("reader-root", readerRoot)
        put("wallet-provider-root", walletProviderRoot)
        put("wallet-provider", walletProviderSigner)
    }

    val validFrom: Instant get() = documentSigner.certChain.certificates.first().validityNotBefore
    val validUntil: Instant get() = documentSigner.certChain.certificates.first().validityNotAfter
}
