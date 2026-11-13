package diw.testservers.zkpassport

import diw.wallet.core.zkpassport.ZkPassportPairedClient
import diw.wallet.core.zkpassport.ZkPassportProver
import diw.wallet.core.zkpassport.ZkPassportRemote
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.addJsonObject
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Proving on the owner's prover (diw-wallet-server DESIGN 3.9 and 3.10) against a scripted prover; fictional data. */
class ZkPassportRemoteTest {
    private val chip = ZkPassportProver.Chip(byteArrayOf(0x77, 0x01), byteArrayOf(0x61, 0x03), byteArrayOf(0x75))
    private val job = ZkPassportProver.Job(query = buildJsonObject { }, domain = "demo.example.org", scope = "adult", devMode = true)
    private val id = "0123456789abcdef0123456789abcdef"

    private val result = buildJsonObject {
        putJsonArray("proofs") {
            addJsonObject { put("name", "sig_check_dsc"); put("proof", "0xab"); put("vkey", "vk"); put("vkey_hash", "0x01"); put("version", "0.22.0") }
        }
        putJsonArray("messages") { addJsonObject { put("method", "done"); put("params", buildJsonObject { }) } }
        put("query_result", buildJsonObject { })
    }

    @Test
    fun aJobIsSentPolledAndReadBack() = runBlocking {
        val sent = mutableListOf<Pair<String, String>>()
        var body: JsonObject? = null
        val states = ArrayDeque(listOf(
            buildJsonObject { put("state", "queued") },
            buildJsonObject { put("state", "registry") },
            buildJsonObject { put("state", "proving"); put("index", 1); put("total", 4); put("name", "sig_check_dsc") },
            buildJsonObject { put("state", "done"); put("result", result) },
        ))
        val transport = ZkPassportRemote.Transport { method, path, b ->
            sent += method to path
            if (method == "POST") {
                body = b
                202 to buildJsonObject { put("id", id) }
            } else {
                200 to states.removeFirst()
            }
        }
        val progress = mutableListOf<ZkPassportProver.Progress>()
        val proved = ZkPassportRemote.prove(transport, chip, job) { progress += it }
        assertEquals("0x01", proved.proofs.single().vkeyHash)
        assertEquals(listOf("done"), proved.messages.map { it.first })
        assertEquals(ZkPassportProver.Progress.Proving(1, 4, "sig_check_dsc"), progress.last())
        val b = assertNotNull(body)
        assertEquals(Base64.getEncoder().encodeToString(chip.sod), b["sod"]!!.jsonPrimitive.content)
        assertNull(b["dg2"], "DG2 stays on the phone")
        assertNull(b["rpc"], "the prover uses its own node")
        assertEquals("POST" to "/zkpassport/v1/jobs", sent.first())
        assertTrue(sent.drop(1).all { it == "GET" to "/zkpassport/v1/jobs/$id" })
    }

    @Test
    fun failuresKeepTheirCodes() = runBlocking {
        val failed = ZkPassportRemote.Transport { method, _, _ ->
            if (method == "POST") 202 to buildJsonObject { put("id", id) }
            else 200 to buildJsonObject { put("state", "failed"); put("code", "proof:x:acir_input") }
        }
        assertEquals("proof:x:acir_input", assertFailsWith<ZkPassportProver.Failure> { ZkPassportRemote.prove(failed, chip, job) {} }.code)
        val refused = ZkPassportRemote.Transport { _, _, _ -> 401 to null }
        assertEquals("remote_unauthorized", assertFailsWith<ZkPassportProver.Failure> { ZkPassportRemote.prove(refused, chip, job) {} }.code)
        val busy = ZkPassportRemote.Transport { _, _, _ -> 429 to null }
        assertEquals("remote_busy", assertFailsWith<ZkPassportProver.Failure> { ZkPassportRemote.prove(busy, chip, job) {} }.code)
        val lost = ZkPassportRemote.Transport { method, _, _ -> if (method == "POST") 202 to buildJsonObject { put("id", id) } else 404 to null }
        assertEquals("remote_lost", assertFailsWith<ZkPassportProver.Failure> { ZkPassportRemote.prove(lost, chip, job) {} }.code)
    }

    @Test
    fun cancellingDeletesTheJob() = runBlocking {
        val deleted = CompletableDeferred<String>()
        val polled = CompletableDeferred<Unit>()
        val transport = ZkPassportRemote.Transport { method, path, _ ->
            when (method) {
                "POST" -> 202 to buildJsonObject { put("id", id) }
                "DELETE" -> { deleted.complete(path); 200 to buildJsonObject { put("state", "cancelled") } }
                else -> { polled.complete(Unit); 200 to buildJsonObject { put("state", "queued") } }
            }
        }
        val running = launch { runCatching { ZkPassportRemote.prove(transport, chip, job) {} } }
        withTimeout(10_000) { polled.await() }
        running.cancel()
        assertEquals("/zkpassport/v1/jobs/$id", withTimeout(10_000) { deleted.await() })
    }

    @Test
    fun pairingCodesNameAPrivateHttpsProver() {
        val p = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 1 })
        val c = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 2 })
        val good = "diw-prover://v1?u=https%3A%2F%2F192.168.1.20%3A8090&p=$p&c=$c"
        val parsed = assertNotNull(ZkPassportPairedClient.parse(good))
        assertEquals("https://192.168.1.20:8090", parsed.first)
        for (bad in listOf(
            "diw-prover://v1?u=http%3A%2F%2F192.168.1.20%3A8090&p=$p&c=$c",
            "diw-prover://v1?u=https%3A%2F%2F8.8.8.8%3A8090&p=$p&c=$c",
            "diw-prover://v1?u=https%3A%2F%2Fprover.example.org%3A8090&p=$p&c=$c",
            "diw-prover://v1?u=https%3A%2F%2F192.168.1.20%3A8090&p=$p",
            "diw-prover://v1?u=https%3A%2F%2F192.168.1.20%3A8090&p=AAAA&c=$c",
            "https://192.168.1.20:8090",
        )) assertNull(ZkPassportPairedClient.parse(bad), bad)
    }
}
