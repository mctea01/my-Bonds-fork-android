package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.ProtocolException
import kotlinx.coroutines.delay
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
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

class SignedMdocTrustListsTest {
    private suspend fun vical(pki: TestPki, id: Long, expiryDays: Int = 30, lifetime: Duration = expiryDays.days, nextUpdate: Duration = 7.days): ByteArray {
        val now = Clock.System.now()
        return SignedVical(
            Vical(
                version = "1.0",
                vicalProvider = "DIW Test Provider",
                date = now,
                nextUpdate = now + nextUpdate,
                notAfter = now + lifetime,
                vicalIssueID = id,
                certificateInfos = listOf(VicalCertificateInfo(pki.iacaCert, listOf("org.iso.18013.5.1.mDL"))),
                vicalUrl = "https://example.test/vical",
                extensions = emptyMap(),
            ),
            pki.walletProviderSigner.certChain,
        ).generate(pki.walletProviderSigner)
    }

    private suspend fun rical(pki: TestPki, id: Long, nextUpdate: Duration = 7.days): ByteArray {
        val now = Clock.System.now()
        return SignedRical(
            Rical(
                type = Rical.RICAL_TYPE_READER_AUTHENTICATION,
                version = "1.0",
                provider = "DIW Test Provider",
                date = now,
                nextUpdate = now + nextUpdate,
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

    @Test
    fun expiredListStopsTrustButCanBeRefreshedAndRemoved() = runBlocking<Unit> {
        val pki = TestPki.create()
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addAnchor(TrustRole.TRUST_LIST_PROVIDER, TrustEnvironment.USER,
            pki.walletProviderRootCert, "Signed list publisher", false, "manual")
        val issuerChain = listOf(pki.documentSigner.certChain.certificates.first())
        registry.importSignedMdocTrustList("vical", vical(pki, 1, lifetime = 2.seconds), "Issuer list", "https://example.test/vical")
        assertNotNull(registry.match(TrustRole.ISSUER, issuerChain))
        delay(2500)
        assertNull(registry.match(TrustRole.ISSUER, issuerChain), "an expired VICAL must not authorize issuers")
        val expired = registry.mdocTrustLists().single()
        assertTrue(expired.expired)
        assertEquals("https://example.test/vical", expired.source)

        val result = registry.refreshDueMdocTrustLists { vical(pki, 2) }
        assertEquals(1, result.refreshed)
        assertTrue(result.failures.isEmpty())
        assertNotNull(registry.match(TrustRole.ISSUER, issuerChain))

        assertTrue(registry.removeMdocTrustList(registry.mdocTrustLists().single()))
        assertTrue(registry.mdocTrustLists().isEmpty())
        assertNull(registry.match(TrustRole.ISSUER, issuerChain))
    }

    @Test
    fun oneFailingListDoesNotStopTheRefresh() = runBlocking<Unit> {
        val pki = TestPki.create()
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addAnchor(TrustRole.TRUST_LIST_PROVIDER, TrustEnvironment.USER,
            pki.walletProviderRootCert, "Signed list publisher", false, "manual")
        registry.importSignedMdocTrustList("vical", vical(pki, 1, nextUpdate = (-1).days), "Broken list", "https://broken.example/vical")
        registry.importSignedMdocTrustList("rical", rical(pki, 1, nextUpdate = (-1).days), "Reader list", "https://example.test/rical")
        registry.importSignedMdocTrustList("vical", vical(pki, 1), "Fresh list", "https://fresh.example/vical")
        val fetched = mutableListOf<String>()
        val result = registry.refreshDueMdocTrustLists { url ->
            fetched += url
            if (url.contains("broken")) throw IllegalStateException("unreachable") else rical(pki, 2)
        }
        assertEquals(1, result.refreshed)
        assertEquals(1, result.failures.size)
        assertTrue(result.failures.single().startsWith("Broken list"))
        assertTrue("https://fresh.example/vical" !in fetched, "lists that are not due are left alone")
        assertEquals(2L, registry.mdocTrustLists().first { it.kind == "rical" }.issue)
    }
}
