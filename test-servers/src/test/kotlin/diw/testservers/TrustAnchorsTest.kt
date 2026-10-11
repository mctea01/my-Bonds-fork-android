package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.profile.bonds.TwPkiAnchors
import diw.wallet.core.trust.BuiltInAnchors
import diw.wallet.core.trust.SystemTrustStore
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import kotlinx.coroutines.runBlocking
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/** Built-in Taiwan GPKI anchors and the platform's certificate store. */
class TrustAnchorsTest {
    @Test
    fun builtInAnchorsAreValidNow() {
        val now = Clock.System.now()
        assertEquals(11, BuiltInAnchors.all.size)
        for (a in BuiltInAnchors.all) {
            val c = a.certificate
            assertTrue(c.validityNotBefore < now && now < c.validityNotAfter, "${a.name} is not valid now")
        }
        // Citizen certificates identify persons: never an issuer anchor.
        val moica = BuiltInAnchors.all.filter { "MOICA" in it.name }
        assertEquals(2, moica.size)
        assertTrue(moica.all { it.roles == setOf(TrustRole.VERIFIER) })
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
        assertEquals(TrustTier.T3, d.tier)
        assertEquals(TrustEnvironment.SYSTEM, d.environment)
        assertTrue(TrustLabel.SYSTEM_ANCHOR in d.labels)
        assertNotNull(d.anchorName)
        // Only issuers, verifiers and status list signers: never a wallet provider.
        assertNull(on.match(TrustRole.WALLET_PROVIDER, listOf(root)))
    }
}
