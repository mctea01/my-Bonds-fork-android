package diw.testservers

import diw.wallet.core.credential.ClaimSensitivity
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.status.StatusAssurance
import diw.wallet.core.status.StatusFinding
import diw.wallet.core.status.StatusPolicy
import diw.wallet.core.status.StatusVerdict
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.JkuKeys
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.trust.UserDidTrust
import diw.wallet.core.util.ProtocolException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import kotlinx.coroutines.runBlocking
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

/** Accepting a credential status by the risk of the use, claim sensitivity and DIDs the user trusts. */
class StatusPolicyTest {
    private val now = Clock.System.now()

    private fun status(
        state: RevocationCheckState,
        assurance: StatusAssurance = StatusAssurance.TRUSTED,
        referenced: Boolean = true,
        age: kotlin.time.Duration = kotlin.time.Duration.ZERO,
    ) = CredentialStatus(state, assurance == StatusAssurance.TRUSTED, TrustEnvironment.PRODUCTION, now - age, assurance = assurance, referenced = referenced)

    private fun verdicts(s: CredentialStatus?) = RiskLevel.entries.map { StatusPolicy.decide(s, it, now).verdict }

    @Test
    fun revokedIsNeverAccepted() {
        assertEquals(List(3) { StatusVerdict.REJECT }, verdicts(status(RevocationCheckState.INVALID)))
        assertEquals(StatusFinding.REVOKED, StatusPolicy.finding(status(RevocationCheckState.INVALID)))
    }

    @Test
    fun unknownStatusDependsOnRisk() {
        // The mashbean sandbox case: the list cannot be read at all.
        val unknown = status(RevocationCheckState.UNKNOWN, StatusAssurance.UNVERIFIED)
        assertEquals(StatusFinding.UNKNOWN, StatusPolicy.finding(unknown))
        assertEquals(listOf(StatusVerdict.ACCEPT, StatusVerdict.CAUTION, StatusVerdict.REJECT), verdicts(unknown))
        assertEquals(listOf(StatusVerdict.CAUTION, StatusVerdict.CAUTION, StatusVerdict.REJECT), verdicts(null))
    }

    @Test
    fun listAssuranceDependsOnRisk() {
        // A TWDIW list read with a jku key the issuer cannot be tied to.
        val tls = status(RevocationCheckState.VALID, StatusAssurance.TLS_ONLY)
        assertEquals(StatusFinding.VALID_TLS_ONLY, StatusPolicy.finding(tls))
        assertEquals(listOf(StatusVerdict.ACCEPT, StatusVerdict.ACCEPT, StatusVerdict.CAUTION), verdicts(tls))
        val unverified = status(RevocationCheckState.VALID, StatusAssurance.UNVERIFIED)
        assertEquals(listOf(StatusVerdict.ACCEPT, StatusVerdict.CAUTION, StatusVerdict.REJECT), verdicts(unverified))
        assertEquals(List(3) { StatusVerdict.ACCEPT }, verdicts(status(RevocationCheckState.VALID)))
    }

    @Test
    fun suspendedAndNoStatus() {
        assertEquals(listOf(StatusVerdict.CAUTION, StatusVerdict.REJECT, StatusVerdict.REJECT), verdicts(status(RevocationCheckState.SUSPENDED)))
        val none = status(RevocationCheckState.UNKNOWN, StatusAssurance.UNVERIFIED, referenced = false)
        assertEquals(StatusFinding.NO_STATUS, StatusPolicy.finding(none))
        assertEquals(listOf(StatusVerdict.ACCEPT, StatusVerdict.ACCEPT, StatusVerdict.CAUTION), verdicts(none))
    }

    @Test
    fun staleResultsNeedAttention() {
        val old = status(RevocationCheckState.VALID, age = 2.hours)
        val high = StatusPolicy.decide(old, RiskLevel.HIGH, now)
        assertEquals(StatusVerdict.CAUTION, high.verdict)
        assertEquals(true, high.stale)
        assertEquals(StatusVerdict.ACCEPT, StatusPolicy.decide(old, RiskLevel.MEDIUM, now).verdict)
        assertEquals(StatusVerdict.CAUTION, StatusPolicy.decide(status(RevocationCheckState.VALID, age = 7.days), RiskLevel.LOW, now).verdict)
        // A stale revocation is still a revocation.
        assertEquals(StatusVerdict.REJECT, StatusPolicy.decide(status(RevocationCheckState.INVALID, age = 30.days), RiskLevel.LOW, now).verdict)
        assertEquals(30.hours / 60, StatusPolicy.refreshAfter(RiskLevel.HIGH))
    }

    @Test
    fun testListsNeverPass() {
        val test = CredentialStatus(RevocationCheckState.VALID, true, TrustEnvironment.TEST, now)
        val d = StatusPolicy.decide(test, RiskLevel.LOW, now)
        assertEquals(StatusVerdict.CAUTION, d.verdict)
        assertEquals(true, d.test)
    }

    @Test
    fun claimSensitivity() {
        assertEquals(RiskLevel.HIGH, ClaimSensitivity.of(listOf("personal_administrative_number")))
        assertEquals(RiskLevel.HIGH, ClaimSensitivity.of(listOf("org.iso.18013.5.1", "portrait")))
        assertEquals(RiskLevel.HIGH, ClaimSensitivity.of("idNumber"))
        assertEquals(RiskLevel.HIGH, ClaimSensitivity.of("身分證字號"))
        assertEquals(RiskLevel.HIGH, ClaimSensitivity.of(listOf("address", "street_address")))
        assertEquals(RiskLevel.MEDIUM, ClaimSensitivity.of("family_name"))
        assertEquals(RiskLevel.MEDIUM, ClaimSensitivity.of("姓名"))
        assertEquals(RiskLevel.MEDIUM, ClaimSensitivity.of(listOf("nationalities", "0")))
        assertEquals(RiskLevel.LOW, ClaimSensitivity.of("age_over_18"))
        assertEquals(RiskLevel.LOW, ClaimSensitivity.of("membership_level"))
        assertEquals(RiskLevel.HIGH, ClaimSensitivity.ofAll(listOf(listOf("given_name"), listOf("portrait"))))
        assertEquals(RiskLevel.LOW, ClaimSensitivity.ofAll(emptyList()))
    }

    @Test
    fun userTrustedDids() = runBlocking<Unit> {
        val storage = EphemeralStorage()
        val trust = UserDidTrust(storage)
        val did = "did:web:issuer.example.com"
        assertNull(trust.decide(did, TrustRole.ISSUER))
        trust.put(did, "Example Corp", setOf(TrustRole.ISSUER), 1_700_000_000)
        val d = trust.decide(did, TrustRole.ISSUER)!!
        assertEquals(TrustTier.T2, d.tier)
        assertEquals(TrustEnvironment.USER, d.environment)
        assertEquals(false, d.official)
        assertEquals(setOf(TrustLabel.USER_ANCHOR), d.labels)
        assertEquals("Example Corp", d.anchorName)
        // Only for the roles the user chose, and kept in storage.
        assertNull(trust.decide(did, TrustRole.VERIFIER))
        assertEquals(1, UserDidTrust(storage).all().size)
        trust.remove(did)
        assertNull(UserDidTrust(storage).decide(did, TrustRole.ISSUER))
    }

    /** A key set is fetched over HTTPS only, even when the test environment allows local HTTP for its servers. */
    @Test
    fun jkuIsHttpsOnly() = runBlocking<Unit> {
        var fetched = 0
        val http = HttpClient(MockEngine { fetched++; respond("""{"keys":[]}""") })
        val policy = EnvironmentPolicy(testEnvironmentEnabled = true, allowInsecureLoopbackHttp = true)
        val keys = JkuKeys(http, TrustRegistry(EphemeralStorage(), policy), DidTrust.NONE)
        for (url in listOf("http://127.0.0.1:8080/jwks", "http://10.0.2.2/jwks", "http://192.168.1.20/jwks")) {
            val e = assertFailsWith<ProtocolException> { keys.resolve(url, "key-1", "did:web:127.0.0.1", TrustRole.STATUS_LIST) }
            assertEquals("invalid_key", e.code)
        }
        assertEquals(0, fetched, "nothing is fetched over plain HTTP")
    }
}
