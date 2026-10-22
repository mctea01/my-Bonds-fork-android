package diw.testservers.zk.bench

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.profile.bonds.BondsAgeCredential
import diw.wallet.core.profile.bonds.BondsAgePackage
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerifier
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.Jcs
import diw.wallet.core.w3c.SdJwtDisclosures
import diw.wallet.core.zk.OpenAcAgeInput
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.JvmZkEnvironment
import diw.wallet.core.zk.native.OpenAcAgeNativeProver
import diw.wallet.core.zk.native.OpenAcAgeNativeVerifier
import diw.wallet.core.zk.native.bindings.ZkCancelToken
import diw.wallet.core.zk.native.bindings.verifyAgePresentation
import diw.wallet.core.zk.ZkPlatformInfo
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respondError
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.util.toBase64Url
import java.io.File
import java.nio.file.Files
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Clock

/** Synthetic OpenAC desktop measurements through the wallet native prover. */
class OpenAcZkBenchmark {
    private suspend fun key(): HolderKey {
        val area = SoftwareSecureArea.create(EphemeralStorage())
        return HolderKey(area, area.createKey(null, SoftwareCreateKeySettings.Builder().build()), shared = true)
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun prepareShowReblindAndVerifyLinked() = runBlocking<Unit> {
        assumeTrue(System.getProperty("diw.bench") == "true", "Use -Pbench=true")
        val data = System.getenv("DIW_OPENAC_DATA")?.let(::File)?.takeIf { File(it, "zk-assets").isDirectory }
        assumeTrue(data != null, "OpenAC assets not provided")
        val issuer = key()
        val holder = key()
        val issuerDid = DidKeys.didKeyJwkJcs(issuer.publicKey)
        val h = holder.publicKey as EcPublicKeyDoubleCoordinate
        val disclosure = JsonArray(listOf(JsonPrimitive(ByteArray(16).toBase64Url()), JsonPrimitive("birthdate"), JsonPrimitive("0830306")))
            .toString().encodeToByteArray().toBase64Url()
        val header = buildJsonObject { put("alg", "ES256"); put("typ", "vc+sd-jwt") }
        val payload = buildJsonObject {
            put("iss", issuerDid)
            put("nbf", 1)
            put("exp", 4102444800)
            putJsonObject("cnf") { putJsonObject("jwk") { put("kty", "EC"); put("crv", "P-256"); put("x", h.x.toBase64Url()); put("y", h.y.toBase64Url()) } }
            putJsonObject("vc") {
                putJsonObject("credentialSubject") {
                    put("_sd_alg", "sha-256")
                    putJsonArray("_sd") { add(JsonPrimitive(SdJwtDisclosures.digest(disclosure))) }
                }
            }
        }
        val input = Jcs.canonicalize(header).encodeToByteArray().toBase64Url() + "." + Jcs.canonicalize(payload).encodeToByteArray().toBase64Url()
        val compact = input + "." + issuer.signingKey("ES256").sign(input.encodeToByteArray()).toCoseEncoded().toBase64Url() + "~$disclosure~"

        val material = BondsAgeCredential.twdiw(compact, DidResolver(HttpClient(MockEngine { respondError(HttpStatusCode.ServiceUnavailable) })))
        assertEquals(issuerDid, material.issuerDid)
        val now = Clock.System.now()
        val nonce = ByteArray(32) { (it * 7).toByte() }.toBase64Url()
        val request = BondsAgeRequest.parse(
            """{"a":18,"b":"6F9619FF-8B86-D011-B42D-00C04FC964FF","c":"$nonce","d":"2008-10-23","p":"test","s":"g","t":${now.epochSeconds},"u":"https://verifier.mashbean.net/r","v":1}""",
        )
        val work = Files.createTempDirectory("openac-benchmark").toFile()
        val assets = File(work, "zk-assets").apply { mkdirs() }
        File(data!!, "zk-assets").listFiles().orEmpty().filter { it.isFile }.forEach { source ->
            Files.createSymbolicLink(File(assets, source.name).toPath(), source.toPath().toAbsolutePath())
        }
        val client = HttpClient()
        val env = JvmZkEnvironment(work, client) { ZkPlatformInfo("linux-x86_64", 8192, 7000, 50000, true) }
        val output = File(System.getProperty("diw.bench.output"), "openac.jsonl")
        output.parentFile.mkdirs()
        output.writeText("")
        try {
            assertTrue(env.loadNative() is ZkResult.Ok, "Native backend could not load")
            val prover = env.ageProver
            assertTrue(prover is OpenAcAgeNativeProver, "OpenAC prover is unavailable")
            for (run in listOf("first", "warm")) {
                val runNonce = ByteArray(32) { if (run == "first") 7 else 9 }.toBase64Url()
                val marks = mutableListOf<Long>()
                val started = System.nanoTime()
                val result = prover.prove(
                    OpenAcAgeInput(material.sdJwt, material.issuerKeyX, material.issuerKeyY, runNonce,
                        BondsAgeCredential.deviceSignature(runNonce, holder), cacheKey = "synthetic-benchmark") {
                        request.cutoffValue(it)
                    },
                ) { marks += System.nanoTime() }
                val ended = System.nanoTime()
                // Do not include result.toString(): it can contain private proof input.
                assertTrue(result is ZkResult.Ok, "OpenAC benchmark proof failed")
                val proof = result.value
                assertEquals(4, marks.size, "Unexpected native phase sequence")
                val intervals = (marks + ended).zipWithNext { a, b -> (b - a) / 1_000_000 }
                val peak = File("/proc/self/status").takeIf { it.isFile }?.readLines()
                    ?.firstOrNull { it.startsWith("VmHWM:") }?.split(Regex("\\s+"))?.getOrNull(1)?.toLongOrNull()
                val record = buildJsonObject {
                    put("run", run)
                    put("total_ms", (ended - started) / 1_000_000)
                    put("prepare_phase_ms", intervals[0])
                    put("show_phase_ms", intervals[1])
                    put("reblind_both_ms", intervals[2])
                    put("verify_linked_phase_ms", intervals[3])
                    put("prepare_proof_bytes", proof.prepareProof.size)
                    put("show_proof_bytes", proof.showProof.size)
                    if (peak != null) put("jvm_process_peak_rss_kib", peak)
                }
                output.appendText(record.toString() + "\n")
            }
            prover.clearCache()
        } finally {
            env.close()
            client.close()
            work.deleteRecursively()
        }
    }
}
