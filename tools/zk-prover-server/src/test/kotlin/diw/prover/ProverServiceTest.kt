package diw.prover

import diw.wallet.core.zk.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.*

class ProverServiceTest {
    private val token = "test-token-0123456789abcdef"

    private fun statement(binding: Byte = 7) = ZkPdfStatement(
        ZkPdfStatement.PHONE, ByteArray(32) { binding },
        listOf(ZkPdfStatement.Window("content", ByteArray(32) { 1 }, 2, byteArrayOf(1, 2), byteArrayOf(3), null)),
        emptyList(), listOf(ZkPdfStatement.Slot(0, 0, 1)),
        listOf(ZkPdfStatement.DigitTable(byteArrayOf(70, 49), 1, IntArray(10) { it + 48 })),
        listOf(ZkPdfStatement.Predicate(0, 0, 0, 20260101)),
    )

    private val witness = ZkPdfWitness(listOf("private page".encodeToByteArray()), listOf(ByteArray(16) { 3 }))

    private fun output(mid: Byte = 5) = ZkPdfProofOutput(
        listOf(ZkPdfSegment("sha_content", 0, ByteArray(64) { 9 }, ByteArray(32) { 8 })),
        listOf(ByteArray(32) { mid }), listOf("record".encodeToByteArray()), listOf(ByteArray(32) { 4 }), 12,
    )

    /** Proves by returning [made]; verifies by attesting [attested] for the statement whose binding byte is 7. */
    private inner class FakeEngine(
        val made: ZkPdfProofOutput = output(),
        val attested: ZkPdfVerifiedOutput? = ZkPdfVerifiedOutput(output().midOuts, output().claimDigests),
        val gate: CompletableDeferred<Unit>? = null,
    ) : ZkPdfEngine {
        var proved: ZkPdfStatement? = null
        override suspend fun check(statement: ZkPdfStatement, witness: ZkPdfWitness) = ZkResult.Ok(ZkPdfCost(1, 14656))
        override suspend fun prove(statement: ZkPdfStatement, witness: ZkPdfWitness, progress: (String, Int, Int) -> Unit): ZkResult<ZkPdfProofOutput> {
            proved = statement
            assertContentEquals("private page".encodeToByteArray(), witness.privateData.single())
            progress("sha_content", 0, 1)
            gate?.await()
            return ZkResult.Ok(made)
        }
        override suspend fun verify(statement: ZkPdfStatement, segments: List<ZkPdfSegment>): ZkResult<ZkPdfVerifiedOutput?> =
            ZkResult.Ok(if (statement.binding[0] == 7.toByte()) attested else null)
        override fun ready(composition: String, prover: Boolean) = true
    }

    @Test
    fun requestAndResponseRoundTrip() {
        val request = ZkPdfRemote.Request(ZkPdfRemote.newId(), statement(), witness)
        val parsed = ZkPdfRemote.parseRequest(ZkPdfRemote.parse(ZkPdfRemote.encodeRequest(request).toString().encodeToByteArray()))
        assertEquals(request.id, parsed.id)
        assertEquals(ZkPdfRemote.encodeRequest(request), ZkPdfRemote.encodeRequest(parsed))
        val response = ZkPdfRemote.Response(request.id, output())
        val back = ZkPdfRemote.parseResponse(ZkPdfRemote.encodeResponse(response))
        assertEquals(ZkPdfRemote.encodeResponse(response), ZkPdfRemote.encodeResponse(back))
        assertFailsWith<IllegalArgumentException> { ZkPdfRemote.parseRequest(JsonObject(mapOf("v" to JsonPrimitive(2)))) }
        assertFailsWith<IllegalArgumentException> { ZkPdfRemote.parse("[1]".encodeToByteArray()) }
    }

    @Test
    fun hostAddressesNeedHttpsOutsidePrivateNetworks() {
        assertNull(ZkProverHost.problem("https://prover.example.org"))
        assertNull(ZkProverHost.problem("http://192.168.1.20:8787"))
        assertNull(ZkProverHost.problem("http://localhost:8787"))
        assertNotNull(ZkProverHost.problem("http://prover.example.org"))
        assertNotNull(ZkProverHost.problem("http://8.8.8.8"))
        assertNotNull(ZkProverHost.problem("ftp://192.168.1.2"))
        // A build whose HTTP stack refuses clear text (Android release) only takes https.
        assertNotNull(ZkProverHost.problem("http://192.168.1.20:8787") { false })
        assertNull(ZkProverHost.problem("https://192.168.1.20:8787") { false })
    }

    @Test
    fun remoteProofIsVerifiedOnTheRequestingDevice() = testApplication {
        val hosted = FakeEngine()
        application { prover(ProverService(hosted, token, CoroutineScope(SupervisorJob() + Dispatchers.Default))) }
        val host = ZkProverHost("test", "http://localhost", token)
        val steps = mutableListOf<String>()
        val accepted = RemoteZkPdfEngine(host, FakeEngine(), client, pollMillis = 10).prove(statement(), witness) { k, d, t -> steps += "$k $d/$t" }
        assertTrue(accepted is ZkResult.Ok, accepted.toString())
        assertContentEquals(ByteArray(32) { 7 }, hosted.proved!!.binding)
        // A proof the local verifier rejects (another binding) or whose outputs differ is never accepted.
        assertTrue(RemoteZkPdfEngine(host, FakeEngine(), client, pollMillis = 10).prove(statement(binding = 6), witness) { _, _, _ -> } is ZkResult.Failed)
        val differing = FakeEngine(attested = ZkPdfVerifiedOutput(output(mid = 6).midOuts, output().claimDigests))
        assertTrue(RemoteZkPdfEngine(host, differing, client, pollMillis = 10).prove(statement(), witness) { _, _, _ -> } is ZkResult.Failed)
        assertTrue(steps.isEmpty() || steps.all { it == "sha_content 0/1" })
    }

    @Test
    fun accessTokenAndOneProofAtATime() = testApplication {
        val gate = CompletableDeferred<Unit>()
        application { prover(ProverService(FakeEngine(gate = gate), token, CoroutineScope(SupervisorJob() + Dispatchers.Default))) }
        val body = ZkPdfRemote.encodeRequest(ZkPdfRemote.Request(ZkPdfRemote.newId(), statement(), witness)).toString()
        assertEquals(HttpStatusCode.Unauthorized, client.get("/v1/health").status)
        assertEquals(HttpStatusCode.Unauthorized, client.post("/v1/zkpdf/jobs") { bearerAuth("wrong-token-0123456789abcdef"); setBody(body) }.status)
        assertEquals(HttpStatusCode.BadRequest, client.post("/v1/zkpdf/jobs") { bearerAuth(token); setBody("{}") }.status)
        val first = client.post("/v1/zkpdf/jobs") { bearerAuth(token); setBody(body) }
        assertEquals(HttpStatusCode.Accepted, first.status)
        val id = kotlinx.serialization.json.Json.parseToJsonElement(first.bodyAsText()).let { (it as JsonObject)["id"]!!.jsonPrimitive.content }
        assertEquals(HttpStatusCode.TooManyRequests, client.post("/v1/zkpdf/jobs") { bearerAuth(token); setBody(body) }.status)
        assertEquals(HttpStatusCode.NoContent, client.delete("/v1/zkpdf/jobs/$id") { bearerAuth(token) }.status)
        var state = ""
        repeat(100) {
            if (state != "cancelled") {
                state = (kotlinx.serialization.json.Json.parseToJsonElement(client.get("/v1/zkpdf/jobs/$id") { bearerAuth(token) }.bodyAsText())
                    as JsonObject)["state"]!!.jsonPrimitive.content
                if (state != "cancelled") runBlocking { kotlinx.coroutines.delay(10) }
            }
        }
        assertEquals("cancelled", state)
        assertEquals(HttpStatusCode.Accepted, client.post("/v1/zkpdf/jobs") { bearerAuth(token); setBody(body) }.status)
        assertEquals(HttpStatusCode.NotFound, client.get("/v1/zkpdf/jobs/unknown") { bearerAuth(token) }.status)
    }
}
