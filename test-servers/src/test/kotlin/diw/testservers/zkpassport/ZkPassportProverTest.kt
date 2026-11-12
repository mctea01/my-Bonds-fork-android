package diw.testservers.zkpassport

import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.bindings.nativeInfo
import diw.wallet.core.zk.native.bindings.oprfBlind
import diw.wallet.core.zk.native.bindings.oprfEvaluate
import diw.wallet.core.zk.native.bindings.oprfFinalize
import diw.wallet.core.zk.native.bindings.oprfPublicKey
import diw.wallet.core.zk.native.bindings.zkpassportCertificates
import diw.wallet.core.zkpassport.ZkPassportOprfClient
import diw.wallet.core.zkpassport.ZkPassportProver
import diw.wallet.core.zkpassport.ZkPassportRegistry
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.nio.file.Files
import java.util.zip.GZIPInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The device prover against a mocked registry serving zkPassport's real certificate package and 0.21.1 manifest
 * (the fixtures of native/zkpassport-verify). The chip files are synthetic, so input generation finds no CSCA and
 * the run stops there; what is checked is the order of the checks and that each failure is named.
 */
class ZkPassportProverTest {
    private val data = File("../native/zkpassport-verify/tests/data")
    private fun gz(name: String) = File(data, name).readBytes()
    private fun text(name: String) = GZIPInputStream(gz(name).inputStream()).use { it.readBytes().decodeToString() }

    private val dg1 = byteArrayOf(0x61, 0x5B, 0x5F, 0x1F, 0x58) +
        ("P<TWNLIN<<CHE<CHUAN".padEnd(44, '<') + "3123456780TWN9001155M3001017" + "A123456789<<<<" + "24").encodeToByteArray()
    private val chip = ZkPassportProver.Chip(sod = byteArrayOf(0x77, 0x03, 0x30, 0x01, 0x00), dg1 = dg1, dg2 = null)
    private val job = ZkPassportProver.Job(
        query = buildJsonObject { putJsonObject("age") { put("gte", 18) } },
        domain = "example.org",
        circuitVersion = "0.21.1",
        nowSeconds = 1_788_000_000,
    )

    private fun native(): Boolean {
        val packaged = ZkNative::class.java.getResource("/zk/native") != null
        assumeTrue(packaged || System.getProperty("diw.zkNative") == "require", "ZK native library not built")
        val directory = Files.createTempDirectory("diw-zkpassport-prove").toFile()
        return ZkNative.load(directory) is ZkResult.Ok<*> && "zkpdf" in nativeInfo().features
    }

    /** The registry with [latest] as the certificate root on chain; records the URLs fetched. */
    private fun registry(latest: String, fetched: MutableList<String>) = HttpClient(MockEngine { request ->
        val url = request.url.toString()
        fetched.add(url)
        when {
            request.method == HttpMethod.Post -> {
                val call = Json.parseToJsonElement(request.body.toByteArray().decodeToString()).jsonObject
                val input = call["params"]!!.toString()
                val result = when {
                    ZkPassportRegistry.LATEST_ROOT in input -> latest
                    ZkPassportRegistry.IS_ROOT_VALID in input -> "0x" + "1".padStart(64, '0')
                    else -> "0x"
                }
                respond("""{"jsonrpc":"2.0","id":1,"result":"$result"}""", HttpStatusCode.OK, headersOf("Content-Type", "application/json"))
            }
            url.startsWith(ZkPassportRegistry.MAINNET_CERTIFICATES) -> respond(gz("certificates-1398607f.json.gz"), HttpStatusCode.OK)
            url.startsWith(ZkPassportRegistry.MAINNET_CIRCUITS + "/by-version/0.21.1/") -> respond(gz("manifest-0.21.1.json.gz"), HttpStatusCode.OK)
            else -> respond("", HttpStatusCode.NotFound)
        }
    })

    private fun prover(http: HttpClient, crs: File?, ready: Boolean = true) =
        ZkPassportProver(http, Files.createTempDirectory("diw-zkpassport-cache").toFile(), { crs }, { ready })

    @Test fun refusesWithoutTheNativeBackendOrTheCrs() = runBlocking<Unit> {
        val http = registry("0x" + "1".repeat(64), ArrayList())
        val tmp = Files.createTempDirectory("diw-zkpassport-crs").toFile()
        assertEquals("native_unavailable", assertFailsWith<ZkPassportProver.Failure> { prover(http, tmp, ready = false).prove(chip, job) }.code)
        assertEquals("crs_missing", assertFailsWith<ZkPassportProver.Failure> { prover(http, null).prove(chip, job) }.code)
    }

    @Test fun checksTheRegistryBeforeGeneratingInputs() = runBlocking<Unit> {
        assumeTrue(native(), "zkPDF backend not built")
        val root = Json.parseToJsonElement(zkpassportCertificates(text("certificates-1398607f.json.gz"))).jsonObject["root"]!!.jsonPrimitive.content
        val crs = Files.createTempDirectory("diw-zkpassport-crs").toFile()

        // A package that does not hash to the root on chain is refused.
        val wrong = ArrayList<String>()
        val other = "0x" + "2".repeat(64)
        assertEquals("certificates_root", assertFailsWith<ZkPassportProver.Failure> { prover(registry(other, wrong), crs).prove(chip, job) }.code)
        assertTrue(wrong.any { it.endsWith("/$other.json") })

        // With the right root the manifest is checked next, then the synthetic chip fails input generation.
        val fetched = ArrayList<String>()
        // The code carries the native reason after "inputs:", shown to the holder.
        val code = assertFailsWith<ZkPassportProver.Failure> { prover(registry(root, fetched), crs).prove(chip, job) }.code
        assertTrue(code == "inputs" || code.startsWith("inputs:"), code)
        assertTrue(fetched.any { it.endsWith("/$root.json") })
        assertTrue(fetched.any { it.contains("/by-version/0.21.1/manifest.json") })
        assertTrue(fetched.none { it.contains("/by-hash/") }, "no circuit is fetched before inputs exist")
    }

    @Test fun proofsBeforeCircuitsZeroTwentyTwoNeedBarretenbergFive() {
        // zkPassport's SDK picks bb.js 5 below 0.22.0 and 6 from it; this app ships only Barretenberg 6.
        kotlin.test.assertTrue(diw.wallet.core.zkpassport.ZkPassport.legacyBackend("0.21.0"))
        kotlin.test.assertTrue(diw.wallet.core.zkpassport.ZkPassport.legacyBackend("0.9.30"))
        kotlin.test.assertFalse(diw.wallet.core.zkpassport.ZkPassport.legacyBackend("0.22.0"))
        kotlin.test.assertFalse(diw.wallet.core.zkpassport.ZkPassport.legacyBackend("1.0.0"))
        kotlin.test.assertFalse(diw.wallet.core.zkpassport.ZkPassport.legacyBackend("next"))
    }

    @Test fun saltsAreFreshFieldElements() {
        val a = ZkPassportProver.salt().toBigInteger()
        val b = ZkPassportProver.salt().toBigInteger()
        assertTrue(a != b && a.bitLength() <= 248 && b.bitLength() <= 248)
    }

    /** A diw-wallet-server stand-in answering with the native OPRF under [secret]; [answerSecret] can differ. */
    private fun oprfServer(secret: String, answerSecret: String = secret, token: String = "t".repeat(16)) = HttpClient(MockEngine { request ->
        val url = request.url.toString()
        when {
            url.endsWith("/oprf/v1/key") -> respond("""{"key_id":"1","pk":${oprfPublicKey(secret)}}""", HttpStatusCode.OK)
            url.endsWith("/oprf/v1/evaluate") && request.headers["Authorization"] != "Bearer $token" -> respond("", HttpStatusCode.Unauthorized)
            url.endsWith("/oprf/v1/evaluate") -> {
                val body = Json.parseToJsonElement(request.body.toByteArray().decodeToString()).jsonObject
                respond(oprfEvaluate(answerSecret, buildJsonObject { put("blinded_query", body["blinded_query"]!!) }.toString()), HttpStatusCode.OK)
            }
            else -> respond("", HttpStatusCode.NotFound)
        }
    })

    @Test fun oprfAnswersAreCheckedAgainstTheServersKey() = runBlocking<Unit> {
        assumeTrue(native(), "zkPDF backend not built")
        val secret = "0x1234567890abcdef"
        val query = "0x25d736ccb33e663ca64bf23add154cb740c5fa863b518da3c1a584f856b48986"
        val client = ZkPassportOprfClient.connect(oprfServer(secret), "https://diw.example.org/", "t".repeat(16))
        assertEquals("1", client.keyId)
        val blinded = Json.parseToJsonElement(oprfBlind(query)).jsonObject
        val answer = client.evaluate(blinded["blinded_query"] as JsonObject)
        val request = buildJsonObject {
            put("query", query)
            put("beta", blinded["beta"]!!)
            put("pk", client.publicKey)
            listOf("response_blinded", "dlog_e", "dlog_s").forEach { put(it, answer[it]!!) }
        }
        val done = Json.parseToJsonElement(oprfFinalize(request.toString())).jsonObject
        assertTrue(done["output"]!!.jsonPrimitive.content.startsWith("0x"))

        // An answer under another key names it, and a wrong token is refused.
        val other = ZkPassportOprfClient.connect(oprfServer(secret, answerSecret = "0x99"), "https://diw.example.org", "t".repeat(16))
        assertEquals("oprf_key_changed", assertFailsWith<ZkPassportProver.Failure> { other.evaluate(blinded["blinded_query"] as JsonObject) }.code)
        val denied = ZkPassportOprfClient.connect(oprfServer(secret), "https://diw.example.org", "x".repeat(16))
        assertEquals("oprf_denied", assertFailsWith<ZkPassportProver.Failure> { denied.evaluate(blinded["blinded_query"] as JsonObject) }.code)
        assertEquals("oprf_unavailable", assertFailsWith<ZkPassportProver.Failure> {
            ZkPassportOprfClient.connect(HttpClient(MockEngine { respond("", HttpStatusCode.NotFound) }), "https://diw.example.org", null)
        }.code)
    }
}
