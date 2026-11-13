package diw.testservers

import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.KeyRequest
import diw.wallet.core.oid4vci.Oid4vciClient
import diw.wallet.core.oid4vci.PublicClientWalletProvider
import diw.wallet.core.oid4vp.PreparedExtended
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.util.DiwJson
import diw.wallet.core.w3c.W3cVcCredential
import diw.wallet.core.w3c.bbs.BbsFeature
import diw.wallet.core.zk.native.ZkNative
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonArray
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import java.net.ServerSocket
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * bbs-2023 end to end: the test issuer signs ldp_vc credentials (a did:key bound one, and keyless ones with each
 * optional feature through the DIW extension), the wallet derives a selectively disclosed proof per request, and the
 * test verifier checks proof, holder binding, presentation header and pseudonym.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Bbs2023E2eTest {
    private val port = ServerSocket(0).use { it.localPort }
    private val base = "http://localhost:$port"
    private lateinit var servers: TestServers
    private lateinit var server: io.ktor.server.engine.EmbeddedServer<*, *>

    @BeforeAll
    fun loadNative() {
        val packaged = ZkNative::class.java.getResource("/zk/native") != null
        assumeTrue(packaged || System.getProperty("diw.zkNative") == "require", "ZK native library not built")
        ZkNative.load(Files.createTempDirectory("diw-bbs-e2e").toFile())
    }

    @BeforeTest
    fun start() = runBlocking {
        servers = TestServers(base, TestPki.create()).init()
        server = servers.start(port, wait = false)
    }

    @AfterTest
    fun stop() {
        server.stop(100, 500)
    }

    private suspend fun offer(config: String): String {
        val text = servers.httpClient.post("$base/issuer/offers") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                putJsonArray("configuration_ids") { add(config) }
                put("grant", "pre-authorized")
            }.toString())
        }.bodyAsText()
        return DiwJson.parseToJsonElement(text).jsonObject["offer_uri"]!!.jsonPrimitive.content
    }

    private suspend fun issue(w: WalletFixture, config: String): W3cVcCredential {
        val c = Oid4vciClient(w.httpClient, w.trust, w.env, PublicClientWalletProvider("diw-wallet-test"), w.documentStore)
        val session = c.startFromOffer(offer(config))
        c.authorizePreAuthorized(session, null)
        val keys = KeyRequest(w.secureArea, { SoftwareCreateKeySettings.Builder().build() }, count = 1, keyStorage = "software")
        val r = c.issue(session, config, keys)
        assertIs<IssuanceResult.Issued>(r, "issuance: $r")
        val cred = r.credentials.single()
        assertIs<W3cVcCredential>(cred)
        assertTrue(cred.isCertified)
        return cred
    }

    private fun dcql(holderBinding: Boolean) = buildJsonObject {
        putJsonArray("credentials") {
            addJsonObject {
                put("id", "card")
                put("format", "ldp_vc")
                putJsonObject("meta") { putJsonArray("type_values") { addJsonArray { add("TestCard") } } }
                put("require_cryptographic_holder_binding", holderBinding)
                putJsonArray("claims") {
                    addJsonObject { putJsonArray("path") { add("credentialSubject"); add("name") } }
                }
            }
        }
    }

    /** Presents the card to a new verifier session and returns the verifier's result and the vp_token sent. */
    private suspend fun present(w: WalletFixture, holderBinding: Boolean = true, prefix: String = "x509_san_dns"): JsonObject {
        val text = servers.httpClient.post("$base/verifier/sessions") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("client_id_prefix", prefix); put("response_mode", "direct_post.jwt")
                put("dcql_query", dcql(holderBinding))
            }.toString())
        }.bodyAsText()
        val o = DiwJson.parseToJsonElement(text).jsonObject
        val prepared = w.holder.prepare(w.holder.resolveUri(o["uri"]!!.jsonPrimitive.content))
        assertIs<PreparedExtended>(prepared)
        val line = prepared.prepared.lines.single()
        assertNotNull(line.bbs)
        // The consent line lists the issuer's mandatory members, which every presentation discloses.
        assertTrue("validFrom" in line.claims && "validUntil" in line.claims && "name" in line.claims, "consent: ${line.claims}")
        if (holderBinding && prefix == "x509_san_dns") lastClaims = line.claims
        assertTrue(w.holder.respondDefault(prepared) is PresentationOutcome.Posted)
        return DiwJson.parseToJsonElement(servers.httpClient.get("$base/verifier/sessions/${o["id"]!!.jsonPrimitive.content}").bodyAsText()).jsonObject
    }

    private var lastClaims: List<String> = emptyList()

    private fun assertPassed(r: JsonObject) = assertEquals("passed", r["status"]!!.jsonPrimitive.content, "verifier result: $r")

    private fun credential(r: JsonObject) = r["credentials"]!!.jsonArray.single().jsonObject

    private fun claims(r: JsonObject) = credential(r)["claims"]!!.jsonObject

    private suspend fun wallet() = WalletFixture().init(servers.pki)

    @Test
    fun didBoundBaselineDisclosesOnlyRequestedClaims() = runBlocking<Unit> {
        val w = wallet()
        val cred = issue(w, "w3c_ldp_vc")
        assertNull(cred.bbsSecrets)
        assertTrue(cred.keyBound)
        val r = present(w)
        assertPassed(r)
        val claims = claims(r)
        assertEquals("王小明", claims["credentialSubject.name"]?.jsonPrimitive?.content, "claims: $claims")
        assertNull(claims["credentialSubject.birthDate"], "claims: $claims")
        assertNull(claims["credentialSubject.memberLevel"], "claims: $claims")
        assertNull(claims["pseudonym"])
        // The holder DID goes into the presentation, so the consent line names it.
        assertTrue("id" in lastClaims, "consent: $lastClaims")
    }

    @Test
    fun anonymousHolderBindingNeedsNoHolderDid() = runBlocking<Unit> {
        val w = wallet()
        val cred = issue(w, "w3c_ldp_vc_private")
        assertEquals(BbsFeature.ANONYMOUS_HOLDER_BINDING, cred.bbsSecrets?.feature)
        assertTrue(cred.bbsHolderBound)
        val first = present(w)
        assertPassed(first)
        val claims = claims(first)
        assertNull(claims["credentialSubject.id"], "claims: $claims")
        assertNull(claims["credentialSubject.nationality"], "claims: $claims")
        assertTrue("id" !in lastClaims, "consent: $lastClaims")
        assertPassed(present(w))
    }

    @Test
    fun holderBoundPseudonymIsStablePerVerifier() = runBlocking<Unit> {
        val w = wallet()
        val cred = issue(w, "w3c_ldp_vc_pseudonym")
        assertEquals(BbsFeature.HOLDER_BINDING_PSEUDONYM, cred.bbsSecrets?.feature)
        assertNotNull(cred.bbsSecrets?.nymSecret)
        val a = present(w)
        val b = present(w)
        val other = present(w, prefix = "x509_hash")
        listOf(a, b, other).forEach { assertPassed(it) }
        val nymA = claims(a)["pseudonym"]!!.jsonPrimitive.content
        assertEquals(nymA, claims(b)["pseudonym"]!!.jsonPrimitive.content)
        assertNotEquals(nymA, claims(other)["pseudonym"]!!.jsonPrimitive.content)
    }

    @Test
    fun pseudonymWithoutHolderBinding() = runBlocking<Unit> {
        val w = wallet()
        val cred = issue(w, "w3c_ldp_vc_nym")
        assertEquals(BbsFeature.PSEUDONYM, cred.bbsSecrets?.feature)
        // Not holder bound: a request that needs holder binding finds no credential, one that does not is answered.
        val r = present(w, holderBinding = false)
        assertPassed(r)
        assertNotNull(claims(r)["pseudonym"])
    }
}
