package diw.testservers

import diw.wallet.core.did.DidKeys
import diw.wallet.core.profile.bonds.BondsAgePackage
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerdict
import diw.wallet.core.profile.bonds.BondsAgeVerifier
import diw.wallet.core.util.DiwJson
import diw.wallet.core.zk.OpenAcAgeCheck
import diw.wallet.core.zk.OpenAcAgeVerifier
import diw.wallet.core.zk.ZkResult
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import java.net.ServerSocket
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/** The Bonds-compatible age verifier: request shape, statement checks, server verification and the relay round trip. */
class BondsAgeServiceTest {
    private val port = ServerSocket(0).use { it.localPort }
    private val base = "http://localhost:$port"
    private val seen = mutableListOf<OpenAcAgeCheck>()
    private var answer = true
    private val engine = object : OpenAcAgeVerifier {
        override suspend fun verify(check: OpenAcAgeCheck): ZkResult<Boolean> {
            seen += check
            return ZkResult.Ok(answer && check.prepareProof.contentEquals(byteArrayOf(1, 2, 3)))
        }
    }
    private lateinit var servers: TestServers
    private lateinit var server: io.ktor.server.engine.EmbeddedServer<*, *>

    @BeforeTest
    fun start() = runBlocking {
        servers = TestServers(base, TestPki.create(), ageVerifier = engine).init()
        server = servers.start(port, wait = false)
    }

    @AfterTest
    fun stop() {
        server.stop(100, 500)
    }

    private suspend fun session(source: String, mode: String): JsonObject = DiwJson.parseToJsonElement(
        servers.httpClient.post("$base/api/zkp/sessions") {
            contentType(ContentType.Application.Json)
            setBody("""{"credentialSource":"$source","minimumAge":20,"purpose":"test","mode":"$mode"}""")
        }.bodyAsText(),
    ).jsonObject

    private suspend fun issuerDid() = DidKeys.didKeyJwkJcs(Crypto.createEcPrivateKey(EcCurve.P256).publicKey)

    private suspend fun post(request: BondsAgeRequest, body: String): HttpResponse = servers.httpClient.post(request.responseUrl!!) {
        contentType(ContentType.Application.Json); setBody(body)
    }

    private fun pkg(request: BondsAgeRequest, issuer: String, prepare: ByteArray = byteArrayOf(1, 2, 3)) =
        BondsAgePackage(request, "birthdate", BondsAgeRequest.FORMAT_ROC, issuer, prepare, byteArrayOf(4, 5), 1200, 300, Clock.System.now())

    @Test
    fun serverModeChecksTheStatementAndTheProofs() = runBlocking<Unit> {
        val config = servers.httpClient.get("$base/api/zkp/config").bodyAsText()
        assertTrue("\"native\"" in config && "\"relay\"" in config)
        val s = session("selfIssued", "server")
        val request = BondsAgeRequest.parse(s["request"]!!.jsonPrimitive.content, setOf("localhost:$port"))
        assertEquals(20, request.minimumAge)
        assertTrue(request.isFresh(Clock.System.now()))
        assertEquals(s["responseUrl"]!!.jsonPrimitive.content, request.responseUrl)
        // Without the test host allowance a plain http response address is refused, as Bonds does.
        assertTrue(runCatching { BondsAgeRequest.parse(s["request"]!!.jsonPrimitive.content) }.isFailure)

        val issuer = issuerDid()
        val other = BondsAgeRequest.create(20, request.source, "x", request.responseUrl)
        val wrong = post(request, pkg(other, issuer).encode())
        assertEquals(HttpStatusCode.BadRequest, wrong.status)
        assertFalse(BondsAgeVerdict.parse(wrong.bodyAsText())!!.accepted)

        val ok = post(request, pkg(request, issuer).encode())
        val verdict = BondsAgeVerdict.parse(ok.bodyAsText())!!
        assertEquals(HttpStatusCode.OK, ok.status)
        assertTrue(verdict.accepted, verdict.toString())
        assertEquals(request.nonce, seen.single().nonce)
        assertEquals(request.cutoffValue(BondsAgeRequest.FORMAT_ROC), seen.single().cutoff)
        assertEquals(HttpStatusCode.Conflict, post(request, pkg(request, issuer).encode()).status)
        val state = DiwJson.parseToJsonElement(servers.httpClient.get("$base/api/zkp/sessions/${s["sessionId"]!!.jsonPrimitive.content}?token=${s["token"]!!.jsonPrimitive.content}").bodyAsText()).jsonObject
        assertEquals("done", state["state"]!!.jsonPrimitive.content)
        assertNull(state["package"], "server mode never hands the package out")
        assertEquals(HttpStatusCode.NotFound, servers.httpClient.get("$base/api/zkp/sessions/${s["sessionId"]!!.jsonPrimitive.content}?token=wrong").status)
    }

    @Test
    fun governmentCardsNeedTheIssuerAndAValidProof() = runBlocking<Unit> {
        val request = BondsAgeRequest.parse(session("government", "server")["request"]!!.jsonPrimitive.content, setOf("localhost:$port"))
        val bad = BondsAgeVerdict.parse(post(request, pkg(request, issuerDid(), byteArrayOf(9)).encode()).bodyAsText())!!
        assertFalse(bad.accepted)
        assertEquals(BondsAgeVerifier.PROOF_INVALID, bad.reason)

        val again = BondsAgeRequest.parse(session("government", "server")["request"]!!.jsonPrimitive.content, setOf("localhost:$port"))
        val unlisted = BondsAgeVerdict.parse(post(again, pkg(again, issuerDid()).encode()).bodyAsText())!!
        assertTrue(unlisted.accepted, "test servers accept an unanchored issuer and say so")
        assertTrue(unlisted.reason!!.startsWith(BondsAgeVerifier.ACCEPTED_UNLISTED))
    }

    @Test
    fun relayModeReturnsTheCreatorsVerdictToTheHolder() = runBlocking<Unit> {
        val s = session("selfIssued", "relay")
        val id = s["sessionId"]!!.jsonPrimitive.content
        val token = s["token"]!!.jsonPrimitive.content
        val request = BondsAgeRequest.parse(s["request"]!!.jsonPrimitive.content, setOf("localhost:$port"))
        val holder = async { post(request, pkg(request, issuerDid()).encode()) }
        var posted: String? = null
        repeat(50) {
            if (posted == null) {
                val state = DiwJson.parseToJsonElement(servers.httpClient.get("$base/api/zkp/sessions/$id?token=$token").bodyAsText()).jsonObject
                posted = state["package"]?.jsonPrimitive?.content
                if (posted == null) delay(100)
            }
        }
        val received = BondsAgePackage.parse(posted!!, request)
        assertTrue(received.prepareProof.contentEquals(byteArrayOf(1, 2, 3)))
        assertTrue(seen.isEmpty(), "a relay never verifies on the server")
        val answer = BondsAgeVerdict("accepted", true, null, 20, 4321)
        assertEquals(HttpStatusCode.OK, servers.httpClient.post("$base/api/zkp/sessions/$id/verdict?token=$token") { setBody(answer.encode()) }.status)
        val response = holder.await()
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(answer, BondsAgeVerdict.parse(response.bodyAsText()))
        assertEquals(HttpStatusCode.Conflict, servers.httpClient.post("$base/api/zkp/sessions/$id/verdict?token=$token") { setBody(answer.encode()) }.status)
    }
}
