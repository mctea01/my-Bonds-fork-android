package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.ProtocolException
import kotlinx.coroutines.runBlocking
import org.multipaz.mdoc.rical.Rical
import org.multipaz.mdoc.rical.RicalCertificateInfo
import org.multipaz.mdoc.rical.SignedRical
import org.multipaz.mdoc.vical.SignedVical
import org.multipaz.mdoc.vical.Vical
import org.multipaz.mdoc.vical.VicalCertificateInfo
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

class SignedMdocTrustListsTest {
    private suspend fun vical(pki: TestPki, id: Long, expiryDays: Int = 30): ByteArray {
        val now = Clock.System.now()
        return SignedVical(
            Vical(
                version = "1.0",
                vicalProvider = "DIW Test Provider",
                date = now,
                nextUpdate = now + 7.days,
                notAfter = now + expiryDays.days,
                vicalIssueID = id,
                certificateInfos = listOf(VicalCertificateInfo(pki.iacaCert, listOf("org.iso.18013.5.1.mDL"))),
                vicalUrl = "https://example.test/vical",
                extensions = emptyMap(),
            ),
            pki.walletProviderSigner.certChain,
        ).generate(pki.walletProviderSigner)
    }

    private suspend fun rical(pki: TestPki, id: Long): ByteArray {
        val now = Clock.System.now()
        return SignedRical(
            Rical(
                type = Rical.RICAL_TYPE_READER_AUTHENTICATION,
                version = "1.0",
                provider = "DIW Test Provider",
                date = now,
                nextUpdate = now + 7.days,
                notAfter = now + 30.days,
                certificateInfos = listOf(RicalCertificateInfo(pki.readerRootCert, name = "DIW Reader CA")),
                id = id,
                latestRicalUrl = "https://example.test/rical",
                extensions = emptyMap(),
            ),
            pki.walletProviderSigner.certChain,
        ).generate(pki.walletProviderSigner)
    }

    @Test
    fun verifiedListsRequireIndependentPublisherTrust() = runBlocking<Unit> {
        val pki = TestPki.create()
        val storage = EphemeralStorage()
        val registry = TrustRegistry(storage, EnvironmentPolicy())
        val encoded = vical(pki, 1)
        assertFailsWith<ProtocolException> {
            registry.importSignedMdocTrustList("vical", encoded, "Issuer list", "https://example.test/vical")
        }
        registry.addAnchor(TrustRole.TRUST_LIST_PROVIDER, TrustEnvironment.USER,
            pki.walletProviderRootCert, "Signed list publisher", false, "manual")
        registry.importSignedMdocTrustList("vical", encoded, "Issuer list", "https://example.test/vical")
        assertNotNull(registry.match(TrustRole.ISSUER, listOf(pki.documentSigner.certChain.certificates.first())))
    }

    @Test
    fun refusesRollbackAndExpiredLists() = runBlocking<Unit> {
        val pki = TestPki.create()
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addAnchor(TrustRole.TRUST_LIST_PROVIDER, TrustEnvironment.USER,
            pki.walletProviderRootCert, "Signed list publisher", false, "manual")
        registry.importSignedMdocTrustList("vical", vical(pki, 2), "Issuer list", "https://example.test/vical")
        val rollback = assertFailsWith<ProtocolException> {
            registry.importSignedMdocTrustList("vical", vical(pki, 1), "Issuer list", "https://example.test/vical")
        }
        assertEquals("stale_trust_list", rollback.code)
        assertFailsWith<ProtocolException> {
            registry.importSignedMdocTrustList("vical", vical(pki, 3, expiryDays = -1), "Issuer list", "https://example.test/vical")
        }
    }

    @Test
    fun ricalOnlyAuthorizesVerifierCertificates() = runBlocking<Unit> {
        val pki = TestPki.create()
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addAnchor(TrustRole.TRUST_LIST_PROVIDER, TrustEnvironment.USER,
            pki.walletProviderRootCert, "Signed list publisher", false, "manual")
        registry.importSignedMdocTrustList("rical", rical(pki, 1), "Reader list", "https://example.test/rical")
        assertNotNull(registry.match(TrustRole.VERIFIER, pki.readerKey("localhost").certChain.certificates))
        assertNull(registry.match(TrustRole.ISSUER, listOf(pki.readerRootCert)))
    }
}
