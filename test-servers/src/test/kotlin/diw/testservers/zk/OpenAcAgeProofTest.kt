package diw.testservers.zk

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.profile.bonds.BondsAgeCredential
import diw.wallet.core.profile.bonds.BondsAgePackage
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.util.Jcs
import diw.wallet.core.w3c.SdJwtDisclosures
import diw.wallet.core.zk.OpenAcAgeInput
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.JvmZkEnvironment
import diw.wallet.core.zk.native.OpenAcAgeNativeProver
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

/**
 * A complete OpenAC age proof through the wallet's own code: a TWDIW-shaped card (did:key jwk_jcs issuer, cnf holder
 * key, ROC birth date), the native prover with its scratch layout, the Bonds package, and an independent check of the
 * posted proofs. Needs a build with -Pdiw.zkFeatures=openac and the verified assets in DIW_OPENAC_DATA/zk-assets.
 */
class OpenAcAgeProofTest {
    private suspend fun key(): HolderKey {
        val area = SoftwareSecureArea.create(EphemeralStorage())
        return HolderKey(area, area.createKey(null, SoftwareCreateKeySettings.Builder().build()), shared = true)
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun twdiwShapedCardProvesAgeAndTheProofVerifiesElsewhere() = runBlocking<Unit> {
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
        val work = Files.createTempDirectory("openac-env").toFile()
        val env = JvmZkEnvironment(data!!, HttpClient()) { ZkPlatformInfo("linux-x86_64", 16384, 12000, 50000, true) }
        try {
            assertIs<ZkResult.Ok<*>>(env.loadNative())
            val prover = assertIs<OpenAcAgeNativeProver>(env.ageProver)
            val steps = mutableListOf<String>()
            val result = prover.prove(
                OpenAcAgeInput(material.sdJwt, material.issuerKeyX, material.issuerKeyY, request.nonce,
                    BondsAgeCredential.deviceSignature(request.nonce, holder), cacheKey = "g:card") { request.cutoffValue(it) },
            ) { steps += it }
            val proof = assertIs<ZkResult.Ok<diw.wallet.core.zk.OpenAcAgeProof>>(result, "$result after $steps").value
            assertEquals("birthdate", proof.claimName)
            assertEquals(BondsAgeRequest.FORMAT_ROC, proof.claimFormat)
            assertEquals(4, steps.size)
            assertTrue(File(data, "zk-work").listFiles().orEmpty().isEmpty(), "the scratch tree is removed")

            // The same card again: Prepare comes from the cache, only the reblinds and Show run, the proof is fresh.
            val again = ByteArray(32) { 1 }.toBase64Url()
            val second = assertIs<ZkResult.Ok<diw.wallet.core.zk.OpenAcAgeProof>>(prover.prove(
                OpenAcAgeInput(material.sdJwt, material.issuerKeyX, material.issuerKeyY, again,
                    BondsAgeCredential.deviceSignature(again, holder), cacheKey = "g:card") { request.cutoffValue(it) },
            ) {}).value
            println("OpenAC first: prepare ${proof.prepareMs} ms, show ${proof.showMs} ms; cached: prepare ${second.prepareMs} ms, show ${second.showMs} ms")
            assertTrue(second.prepareMs < proof.prepareMs, "cached Prepare: ${second.prepareMs} ms against ${proof.prepareMs} ms")
            assertFalse(second.prepareProof.contentEquals(proof.prepareProof), "each presentation is reblinded")
            prover.clearCache()
            assertFalse(File(data, "zk-cache").exists())
            val pkg = BondsAgePackage(request, proof.claimName, proof.claimFormat, material.issuerDid, proof.prepareProof, proof.showProof,
                proof.prepareMs, proof.showMs, now)
            assertTrue(pkg.encode().contains(Base64.Default.encode(proof.showProof)))

            // A verifier with only the verifying keys and the posted proofs.
            val keys = File(work, "circom/keys").apply { mkdirs() }
            listOf("prepare_verifying.key", "show_verifying.key").forEach { Files.createSymbolicLink(File(keys, it).toPath(), File(data, "zk-assets/$it").toPath()) }
            File(keys, "prepare_proof.bin").writeBytes(proof.prepareProof)
            File(keys, "show_proof.bin").writeBytes(proof.showProof)
            val docs = File(work, "circom").path
            fun accepts(cutoff: Long, x: String = material.issuerKeyX, n: String = request.nonce) = ZkCancelToken().use { t ->
                verifyAgePresentation(docs, n, proof.claimName, proof.claimFormat.toUByte(), cutoff.toULong(), x, material.issuerKeyY, t)
            }
            assertTrue(accepts(request.cutoffValue(proof.claimFormat)))
            assertFalse(accepts(830305), "a cutoff before the birth date is not proved")
            assertFalse(accepts(request.cutoffValue(proof.claimFormat), n = ByteArray(32).toBase64Url()))
            assertFalse(accepts(request.cutoffValue(proof.claimFormat), x = (holder.publicKey as EcPublicKeyDoubleCoordinate).x.toBase64Url()))
        } finally {
            env.close()
            work.deleteRecursively()
        }
    }
}
