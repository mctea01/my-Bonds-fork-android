package diw.testservers.zkpdf

import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.bindings.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.nio.file.Files
import kotlin.test.*

/** Only the committed fictional PDFs are used. Assertions never print records. */
class ZkPdfCircuitTest {
    private fun JsonObject.bytes(key: String) = getValue(key).jsonArray.map { it.jsonPrimitive.int.toByte() }.toByteArray()
    private fun JsonObject.uint(key: String) = getValue(key).jsonPrimitive.content.toUInt()
    private fun JsonObject.byte(key: String) = getValue(key).jsonPrimitive.content.toUByte()
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.list(key: String) = getValue(key).jsonArray.map { it.jsonObject }
    private fun JsonObject.keyStream() = if (get("key_stream") == JsonNull) null else bytes("key_stream")
    private fun record(o: JsonObject) = ZkPdfRecord(o.bytes("font"), o.byte("kind"),
        o.getValue("strings").jsonArray.map { a -> a.jsonArray.map { it.jsonPrimitive.int.toByte() }.toByteArray() })
    private fun fonts(o: JsonObject) = o.list("digit_tables").map { f ->
        ZkPdfDigitTable(f.bytes("font"), f.byte("width"), f.getValue("codes").jsonArray.map { it.jsonPrimitive.content.toUInt() }) }
    private fun predicates(o: JsonObject) = o.list("predicates").map { p ->
        ZkPdfPredicateInput(p.byte("kind"), p.uint("slot"), p.byte("format"), p.uint("cutoff")) }
    private fun input(o: JsonObject, assets: String) = ZkPdfProveInput(
        o.text("composition"), o.bytes("binding"), o.list("windows").map { w ->
            ZkPdfWindowInput(w.text("role"), w.bytes("mid_in"), w.bytes("head"), w.bytes("private_data"), w.bytes("tail"), w.keyStream()) },
        o.list("anchors").map { ZkPdfAnchorInput(record(it.getValue("record").jsonObject), it.uint("ordinal")) },
        o.list("slots").map { ZkPdfSlotInput(it.uint("slot"), it.uint("before_anchor"), it.uint("after_anchor"), it.bytes("salt")) },
        fonts(o), predicates(o), assets)
    private fun spec(o: JsonObject) = ZkPdfVerifierSpec(
        o.text("composition"), o.bytes("binding"), o.list("windows").map { w ->
            ZkPdfWindowPublic(w.text("role"), w.bytes("mid_in"), w.uint("blocks"), w.bytes("head"), w.bytes("tail"), w.keyStream()) },
        o.list("anchors").map { ZkPdfAnchorPublic(record(it.getValue("record").jsonObject), it.uint("ordinal"), it.uint("total")) },
        o.list("slots").map { ZkPdfSlotPublic(it.uint("slot"), it.uint("before_anchor"), it.uint("after_anchor")) },
        fonts(o), predicates(o))

    @Test fun syntheticDocumentThroughUniffi() = runBlocking<Unit> {
        val packaged = ZkNative::class.java.getResource("/zk/native") != null
        assumeTrue(packaged || System.getProperty("diw.zkNative") == "require", "ZK native library not built")
        val directory = Files.createTempDirectory("diw-zkpdf-native").toFile()
        try {
            assertIs<ZkResult.Ok<*>>(ZkNative.load(directory))
            assumeTrue("zkpdf" in nativeInfo().features, "zkPDF backend not built")
            val assets = System.getenv("ZKPDF_ASSETS_DIR")
            assumeTrue(!assets.isNullOrEmpty(), "zkPDF assets not installed")
            val fixture = javaClass.getResourceAsStream("/zkpdf/student.json")!!.use {
                Json.parseToJsonElement(it.readBytes().decodeToString()).jsonObject }
            val request = input(fixture.getValue("input").jsonObject, assets!!)
            val policy = spec(fixture.getValue("spec").jsonObject)
            val plan = zkpdfCheck(request)
            assertEquals(6u, plan.totalSegments)
            for (ordinal in listOf(0u, 2u, UInt.MAX_VALUE)) {
                val invalid = request.copy(anchors = listOf(request.anchors.first().copy(ordinal = ordinal)) + request.anchors.drop(1), assetsDir = "")
                assertEquals("anchor_ordinal", assertFailsWith<ZkException.InvalidInput> { zkpdfCheck(invalid) }.reason)
                ZkCancelToken().use { token ->
                    assertEquals("anchor_ordinal", assertFailsWith<ZkException.InvalidInput> {
                        zkpdfProve(invalid, token, object : ZkProgress {
                            override fun onProgress(kind: String, index: UInt, total: UInt) { error("unexpected_progress") }
                        })
                    }.reason)
                }
            }
            var completed = 0u
            ZkCancelToken().use { token ->
                val result = zkpdfProve(request, token, object : ZkProgress {
                    override fun onProgress(kind: String, index: UInt, total: UInt) {
                        assertEquals(plan.totalSegments, total)
                        assertEquals(completed + 1u, index)
                        assertTrue(kind in setOf("sha_content", "sha_opaque", "inflate0", "lex", "claim", "pred"))
                        completed = index
                    }
                })
                assertEquals(plan.totalSegments, completed)
                val verified = zkpdfVerify(policy, result.bundle, assets)
                assertTrue(verified.midOuts.zip(result.midOuts).all { (a, b) -> a.contentEquals(b) })
                assertTrue(verified.claimDigests.zip(result.claimDigests).all { (a, b) -> a.contentEquals(b) })
                val changedPolicy = policy.copy(anchors = listOf(policy.anchors.first().copy(ordinal = 2u, total = 2u)) + policy.anchors.drop(1))
                assertFailsWith<ZkException.InvalidInput> { zkpdfVerify(changedPolicy, result.bundle, assets) }
                val first = result.bundle.segments.first()
                val changed = first.proof.copyOf().apply { this[100] = (this[100].toInt() xor 1).toByte() }
                val tampered = result.bundle.copy(segments = listOf(first.copy(proof = changed)) + result.bundle.segments.drop(1))
                assertFailsWith<ZkException.InvalidInput> { zkpdfVerify(policy, tampered, assets) }
            }
            ZkCancelToken().use { cancelled ->
                cancelled.cancel()
                assertFailsWith<ZkException.Cancelled> {
                    zkpdfProve(request, cancelled, object : ZkProgress {
                        override fun onProgress(kind: String, index: UInt, total: UInt) { error("unexpected_progress") }
                    })
                }
            }
        } finally { directory.deleteRecursively() }
    }
}
