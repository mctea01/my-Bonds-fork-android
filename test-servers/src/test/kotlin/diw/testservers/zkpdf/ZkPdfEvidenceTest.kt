package diw.testservers.zkpdf

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.zkpdf.*
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.*
import diw.wallet.core.zk.*
import diw.wallet.core.zk.native.FileZkAssetStore
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.ZkPdfNativeEngine
import diw.wallet.core.zk.native.bindings.nativeInfo
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.io.File
import java.nio.file.Files
import java.util.zip.Inflater
import kotlin.test.*
import kotlin.time.Instant

/**
 * WP4 holder and verifier over the committed fictional PDFs. The fake engine stands in for the native prover: it
 * computes the outgoing SHA-256 states and field commitments from the private bytes, and accepts a bundle only for
 * the exact statement it proved, so these tests show that the verifier rebuilds the holder's statement and rejects
 * every mutation from p4-circuits.md 3.10 that is checked outside the circuit. The native test runs the real proof.
 */
class ZkPdfEvidenceTest {
    private fun resource(name: String) = javaClass.getResourceAsStream("/zkpdf/$name")!!.use { it.readBytes() }
    private val now = Instant.parse("2026-11-01T00:00:00Z")

    private val student = ZkPdfProfile(
        "test.student-status/1", "仿在學證明", listOf("Qr"),
        listOf(
            ZkPdfFieldRule("name", "姓名", listOf("姓名"), listOf("學號"), ZkPdfNormalize.TEXT),
            ZkPdfFieldRule("studentId", "學號", listOf("學號"), listOf("出生日期"), ZkPdfNormalize.COMPACT),
            ZkPdfFieldRule("birthDate", "出生日期", listOf("出生日期"), listOf("科系"), ZkPdfNormalize.DATE),
        ),
        test = true,
    )
    private val travel = ZkPdfProfile(
        "test.travel-record/1", "仿出入境記錄", emptyList(),
        listOf(
            ZkPdfFieldRule("name", "姓名", listOf("姓名"), listOf("證件號"), ZkPdfNormalize.TEXT),
            ZkPdfFieldRule("birthDate", "出生日期", listOf("出生日期"), listOf("序號"), ZkPdfNormalize.DATE),
        ),
        test = true,
    )
    private val profiles = mapOf(student.id to student, travel.id to travel)
    private val holder = buildJsonObject { put("kty", "EC"); put("crv", "P-256"); put("x", "aG9sZGVyLXg"); put("y", "aG9sZGVyLXk") }
    private val other = buildJsonObject { put("kty", "EC"); put("crv", "P-256"); put("x", "b3RoZXIteA"); put("y", "b3RoZXIteQ") }
    private val birthCutoff = ZkPdfPredicate(ZkPdfPredicate.DATE_LE, "birthDate", 20050101)

    private suspend fun trust(): DocumentTrustSource {
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy(testEnvironmentEnabled = true))
        registry.addAnchor(TrustRole.DOCUMENT, TrustEnvironment.TEST, X509Cert(ByteString(resource("test-root.cer"))),
            "DIW Synthetic Test Root", official = false, source = "synthetic-fixture")
        return object : DocumentTrustSource {
            override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision = registry.decide(role, chain, at)
            override suspend fun fetchIssuerCertificates(url: String) = emptyList<ByteArray>()
        }
    }

    private val noTrust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision =
            TrustRegistry(EphemeralStorage(), EnvironmentPolicy(testEnvironmentEnabled = true)).decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String) = emptyList<ByteArray>()
    }

    /** Accepts only the statement it proved, as the native verifier holds each segment to its public inputs. */
    private class FakeEngine : ZkPdfEngine {
        var proven: String? = null
        var output: ZkPdfProofOutput? = null
        var ready = true

        override fun ready(composition: String, prover: Boolean) = ready

        override suspend fun check(statement: ZkPdfStatement, witness: ZkPdfWitness) = ZkResult.Ok(ZkPdfCost(6, 6L * 16256))

        override suspend fun prove(statement: ZkPdfStatement, witness: ZkPdfWitness, progress: (String, Int, Int) -> Unit): ZkResult<ZkPdfProofOutput> {
            val midOuts = statement.windows.mapIndexed { i, w ->
                val blocks = w.head + witness.privateData[i] + w.tail
                assertEquals(w.blocks * 64, blocks.size)
                var state = Sha256State.ofBytes(w.midIn)
                for (b in 0 until w.blocks) state = state.compress(blocks.copyOfRange(b * 64, b * 64 + 64))
                state.toBytes()
            }
            val content = statement.windows.first()
            val raw = witness.privateData.first().let { data ->
                content.keyStream?.let { k -> ByteArray(data.size) { (data[it].toInt() xor k[it].toInt()).toByte() } } ?: data
            }
            val plain = Inflater().run { setInput(raw); val out = ByteArray(65536); val n = inflate(out); end(); out.copyOf(n) }
            val records = ZkPdfLexer.records(plain)
            val ops = statement.anchors.map { a -> records.indexOfFirst { it == a.record } }
            val sources = List(12) { slot ->
                statement.slots.firstOrNull { it.slot == slot }?.let { s ->
                    records.subList(ops[s.beforeAnchor] + 1, ops[s.afterAnchor]).fold(ByteArray(0)) { acc, r -> acc + r.encoded() }
                } ?: ByteArray(0)
            }
            val digests = List(12) { slot ->
                if (statement.slots.any { it.slot == slot }) ZkPdfOpening(slot, witness.salts[slot], sources[slot]).commitment() else ByteArray(32)
            }
            progress("sha_content", 1, 1)
            proven = fingerprint(statement)
            return ZkResult.Ok(ZkPdfProofOutput(listOf(ZkPdfSegment("sha_content", 0, ByteArray(16256) { 1 }, ByteArray(64))),
                midOuts, sources, digests, 1).also { output = it })
        }

        override suspend fun verify(statement: ZkPdfStatement, segments: List<ZkPdfSegment>): ZkResult<ZkPdfVerifiedOutput?> {
            val out = output ?: return ZkResult.Ok(null)
            val sameSegments = segments.size == out.segments.size && segments.zip(out.segments).all { (a, b) ->
                a.kind == b.kind && a.index == b.index && a.proof.contentEquals(b.proof) && a.publicInputs.contentEquals(b.publicInputs)
            }
            return ZkResult.Ok(if (sameSegments && fingerprint(statement) == proven) ZkPdfVerifiedOutput(out.midOuts, out.claimDigests) else null)
        }

        private fun fingerprint(s: ZkPdfStatement): String = buildString {
            fun h(b: ByteArray?) = b?.joinToString("") { "%02x".format(it) } ?: "-"
            append(s.composition).append(h(s.binding))
            s.windows.forEach { append(it.role, h(it.midIn), it.blocks, h(it.head), h(it.tail), h(it.keyStream)) }
            s.anchors.forEach { append(h(it.record.encoded()), it.ordinal, it.total) }
            s.slots.forEach { append(it.slot, it.beforeAnchor, it.afterAnchor) }
            s.digitTables.forEach { append(h(it.font), it.width, it.codes.joinToString(",")) }
            s.predicates.forEach { append(it.kind, it.slot, it.format, it.cutoff) }
        }
    }

    private suspend fun created(name: String, profile: ZkPdfProfile, engine: ZkPdfEngine): ZkPdfCreated {
        val pdf = resource(name)
        val plan = ZkPdfPlanner.plan(pdf, profile, listOf(birthCutoff))
        val result = ZkPdfProofs.create(pdf, plan, holder, ZkPdfStatement.PHONE, engine, { _, _, _ -> }, now)
        return assertIs<ZkResult.Ok<ZkPdfCreated>>(result).value
    }

    private fun disclosed(created: ZkPdfCreated, evidence: JsonObject = created.evidence.toJson()): MutableMap<String, JsonElement> =
        created.disclosures().toMap().toMutableMap().also { it[ZkPdfEvidence.CLAIM] = evidence }

    private suspend fun verify(map: Map<String, JsonElement>, engine: ZkPdfEngine?, trust: DocumentTrustSource, key: JsonObject = holder) =
        ZkPdfVerifier.verify(map.getValue(ZkPdfEvidence.CLAIM) as JsonObject, map, key, profiles::get, engine, trust, now)

    @Test fun z1HolderAndVerifierAgreeOnBothFixtures() = runBlocking<Unit> {
        val trust = trust()
        for ((name, profile) in listOf("student.pdf" to student, "travel-rc4.pdf" to travel)) {
            val engine = FakeEngine()
            val created = created(name, profile, engine)
            assertEquals(mapOf("name" to "林測試", "birthDate" to "2004-02-29").filterKeys { k -> profile.field(k) != null },
                created.values.filter { it.name != "studentId" }.associate { it.name to it.value })
            // Round trip through JSON text, as the disclosure travels.
            val json = Json.parseToJsonElement(created.evidence.toJson().toString()).jsonObject
            val result = verify(disclosed(created, json), engine, trust)
            assertEquals(Check.PASS, result.check, result.summary)
            assertTrue(result.fields.all { it.check == Check.PASS })
            assertEquals(listOf("出生日期不晚於 2005-01-01"), result.predicates.map { it.text })
            // The masked file never carries the private window bytes.
            val masked = created.evidence.masked
            val plain = resource(name)
            created.evidence.windows.forEach { w ->
                assertTrue(masked.copyOfRange(w.offset, w.offset + w.length).all { it == 0.toByte() })
                assertFalse(plain.copyOfRange(w.offset, w.offset + w.length).all { it == 0.toByte() })
            }
        }
    }

    @Test fun hiddenFieldsAndUntrustedSigners() = runBlocking<Unit> {
        val engine = FakeEngine()
        val created = created("student.pdf", student, engine)
        val map = disclosed(created)
        map.remove("studentId"); map.remove("zkOpen:studentId"); map.remove("zkOpen:name")
        val result = verify(map, engine, trust())
        assertEquals(Check.WARN, result.check)
        assertEquals(listOf("學號"), result.hidden)
        assertEquals(Check.NOT_CHECKED, result.fields.single { it.claim == "name" }.check)
        val untrusted = verify(disclosed(created), engine, noTrust)
        assertEquals(Check.WARN, untrusted.check, untrusted.summary)
        assertTrue(untrusted.fields.all { it.check == Check.PASS })
    }

    @Test fun z2PublicByteAndHeadTailTamperingFails() = runBlocking<Unit> {
        val engine = FakeEngine()
        val created = created("student.pdf", student, engine)
        val trust = trust()
        val content = created.evidence.windows.first()
        val positions = listOf(200, content.offset - 3, content.offset + content.length + 2, created.evidence.masked.size - 300)
        for (p in positions) {
            val masked = created.evidence.masked.copyOf().also { it[p] = (it[p] + 1).toByte() }
            val result = verify(disclosed(created, rebuilt(created.evidence, masked = masked)), engine, trust)
            assertEquals(Check.FAIL, result.check, "position $p")
        }
        val changedOut = created.evidence.windows.mapIndexed { i, w ->
            if (i == 0) ZkPdfEvidenceWindow(w.role, w.offset, w.length, w.blocks, w.midOut.copyOf().also { it[5] = (it[5] + 1).toByte() }) else w
        }
        assertEquals(Check.FAIL, verify(disclosed(created, rebuilt(created.evidence, windows = changedOut)), engine, trust).check)
    }

    @Test fun z3WindowsThatAreNotTheTemplateStreamsFail() = runBlocking<Unit> {
        val engine = FakeEngine()
        val created = created("student.pdf", student, engine)
        val moved = created.evidence.windows.mapIndexed { i, w ->
            if (i == 1) ZkPdfEvidenceWindow(w.role, w.offset + 64, w.length, w.blocks, w.midOut) else w
        }
        assertEquals(Check.FAIL, verify(disclosed(created, rebuilt(created.evidence, windows = moved)), engine, trust()).check)
        val noImage = ZkPdfProfile("test.student-status/1", student.title, emptyList(), student.fields, test = true)
        val result = ZkPdfVerifier.verify(created.evidence.toJson(), disclosed(created), holder, { noImage }, engine, trust(), now)
        assertEquals(Check.FAIL, result.check)
    }

    @Test fun z4AndZ7AnchorsSlotsAndPinnedTemplates() = runBlocking<Unit> {
        val engine = FakeEngine()
        val created = created("student.pdf", student, engine)
        val trust = trust()
        val e = created.evidence
        val reordered = rebuilt(e, anchors = e.anchors.mapIndexed { i, a -> if (i == 0) ZkPdfAnchorPlan("", a.record, 2, 2) else a })
        assertEquals(Check.FAIL, verify(disclosed(created, reordered), engine, trust).check)
        val swapped = rebuilt(e, slots = e.slots.map { if (it.slot == 0) ZkPdfEvidenceSlot("studentId", 0, it.beforeAnchor, it.afterAnchor) else it })
        assertEquals(Check.FAIL, verify(disclosed(created, swapped), engine, trust).check)
        val unknown = disclosed(created, created.evidence.toJson().let { JsonObject(it + ("profile" to JsonPrimitive("test.unknown/1"))) })
        assertEquals(Check.NOT_CHECKED, verify(unknown, engine, trust).check)
        engine.ready = false
        assertEquals(Check.NOT_CHECKED, verify(disclosed(created), engine, trust).check)
        assertEquals(Check.NOT_CHECKED, verify(disclosed(created), null, trust).check)
    }

    @Test fun z5OpeningsBindSlotAndBytes() = runBlocking<Unit> {
        val engine = FakeEngine()
        val created = created("student.pdf", student, engine)
        val trust = trust()
        val opening = created.openings.getValue("name")
        val other = created.openings.getValue("studentId")
        val variants = listOf(
            ZkPdfOpening(other.slot, opening.salt, opening.source),
            ZkPdfOpening(opening.slot, opening.salt, opening.source.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }),
            other,
        )
        for (v in variants) {
            val map = disclosed(created).also { it["zkOpen:name"] = v.toJson() }
            val result = verify(map, engine, trust)
            assertEquals(Check.FAIL, result.fields.single { it.claim == "name" }.check)
            assertEquals(Check.FAIL, result.check)
        }
        val lied = disclosed(created).also { it["name"] = JsonPrimitive("王測試") }
        assertEquals(Check.FAIL, verify(lied, engine, trust).fields.single { it.claim == "name" }.check)
    }

    @Test fun z6BindingIsTheCredentialKey() = runBlocking<Unit> {
        val engine = FakeEngine()
        val created = created("student.pdf", student, engine)
        assertEquals(Check.FAIL, verify(disclosed(created), engine, trust(), key = other).check)
        val rebound = rebuilt(created.evidence, binding = ZkPdfProofs.binding(other))
        assertEquals(Check.FAIL, verify(disclosed(created, rebound), engine, trust(), key = other).check)
    }

    @Test fun z10Rc4KeyStreamComesFromTheFile() = runBlocking<Unit> {
        val engine = FakeEngine()
        val created = created("travel-rc4.pdf", travel, engine)
        val trust = trust()
        assertEquals(Check.PASS, verify(disclosed(created), engine, trust).check)
        // Corrupting the /U check value makes the empty password fail, so no key stream can be derived.
        val masked = created.evidence.masked
        val marker = "/U <".encodeToByteArray()
        val at = (0..masked.size - marker.size).first { i -> marker.indices.all { masked[i + it] == marker[it] } }
        // A hex digit changed to another hex digit keeps the file parseable.
        val changed = masked.copyOf().also { it[at + 4] = if (it[at + 4] == '0'.code.toByte()) '1'.code.toByte() else '0'.code.toByte() }
        assertEquals(Check.FAIL, verify(disclosed(created, rebuilt(created.evidence, masked = changed)), engine, trust).check)
    }

    @Test fun z11ProofCoversTheSignedRevisionOnly() = runBlocking<Unit> {
        val engine = FakeEngine()
        val created = created("student-modified.pdf", student, engine)
        val full = resource("student-modified.pdf")
        assertTrue(created.evidence.masked.size < full.size)
        assertEquals(Check.PASS, verify(disclosed(created), engine, trust()).check)
    }

    @Test fun z14UnverifiedOutputIsNotWritten() = runBlocking<Unit> {
        val pdf = resource("student.pdf")
        val plan = ZkPdfPlanner.plan(pdf, student)
        val lying = object : ZkPdfEngine by FakeEngine() {
            val inner = FakeEngine()
            override suspend fun prove(statement: ZkPdfStatement, witness: ZkPdfWitness, progress: (String, Int, Int) -> Unit): ZkResult<ZkPdfProofOutput> {
                val out = (inner.prove(statement, witness, progress) as ZkResult.Ok).value
                return ZkResult.Ok(ZkPdfProofOutput(out.segments, out.midOuts, out.claimRecords, out.claimDigests.map { ByteArray(32) }, 1))
            }
        }
        assertIs<ZkResult.Failed>(ZkPdfProofs.create(pdf, plan, holder, ZkPdfStatement.PHONE, lying, { _, _, _ -> }, now))
    }

    @Test fun malformedEvidenceIsRejected() = runBlocking<Unit> {
        val engine = FakeEngine()
        val created = created("student.pdf", student, engine)
        val json = created.evidence.toJson()
        for (key in listOf("v", "binding", "document", "windows", "segments", "composition")) {
            val broken = JsonObject(json - key)
            assertEquals(Check.FAIL, verify(disclosed(created, broken), engine, trust()).check, key)
        }
        val big = JsonObject(json + ("document" to buildJsonObject { put("size", ZkPdfEvidence.MAX_DOCUMENT + 1); put("zlib", "eJw") }))
        assertEquals(Check.FAIL, verify(disclosed(created, big), engine, trust()).check)
    }

    private fun rebuilt(
        e: ZkPdfEvidence,
        masked: ByteArray = e.masked,
        windows: List<ZkPdfEvidenceWindow> = e.windows,
        anchors: List<ZkPdfAnchorPlan> = e.anchors,
        slots: List<ZkPdfEvidenceSlot> = e.slots,
        binding: ByteArray = e.binding,
    ): JsonObject = ZkPdfEvidence(e.profile, e.composition, binding, masked, windows, anchors, slots, e.predicates, e.segments, e.createdAt).toJson()

    /** The real prover and verifier: needs the packaged native library with zkpdf and the installed assets. */
    @Test fun nativeProofThroughEvidence() = runBlocking<Unit> {
        val packaged = ZkNative::class.java.getResource("/zk/native") != null
        assumeTrue(packaged || System.getProperty("diw.zkNative") == "require", "ZK native library not built")
        val assets = System.getenv("ZKPDF_ASSETS_DIR")
        assumeTrue(!assets.isNullOrEmpty(), "zkPDF assets not installed")
        val directory = Files.createTempDirectory("diw-zkpdf-evidence").toFile()
        try {
            assertIs<ZkResult.Ok<*>>(ZkNative.load(directory))
            assumeTrue("zkpdf" in nativeInfo().features, "zkPDF backend not built")
            val client = HttpClient(MockEngine { error("No network expected") })
            FileZkAssetStore.bundled(File(assets!!), client).use { store ->
                val engine = ZkPdfNativeEngine(store)
                assertTrue(engine.ready(ZkPdfStatement.PHONE, true))
                val pdf = resource("student.pdf")
                val plan = ZkPdfPlanner.plan(pdf, student, listOf(birthCutoff))
                val cost = assertIs<ZkResult.Ok<ZkPdfCost>>(engine.check(ZkPdfProofs.statement(plan, ZkPdfStatement.PHONE, ZkPdfProofs.binding(holder)),
                    ZkPdfWitness(plan.privateData, ZkPdfPlanner.salts(plan.slots.size)))).value
                var last = 0
                val created = assertIs<ZkResult.Ok<ZkPdfCreated>>(
                    ZkPdfProofs.create(pdf, plan, holder, ZkPdfStatement.PHONE, engine, { _, index, total -> assertEquals(cost.segments, total); last = index }, now),
                ).value
                assertEquals(cost.segments, last)
                val trust = trust()
                val json = Json.parseToJsonElement(created.evidence.toJson().toString()).jsonObject
                val result = verify(disclosed(created, json), engine, trust)
                assertEquals(Check.PASS, result.check, result.summary)
                assertEquals(3, result.fields.count { it.check == Check.PASS })
                // Z9: a cutoff before the birth date cannot be proven; the same bundle under another cutoff is rejected.
                val stricter = JsonObject(json + ("predicates" to buildJsonArray {
                    addJsonObject { put("kind", "DATE_LE"); put("claim", "birthDate"); put("cutoff", 20040228) }
                }))
                assertEquals(Check.FAIL, verify(disclosed(created, stricter), engine, trust).check)
                val tooEarly = ZkPdfPlanner.plan(pdf, student, listOf(ZkPdfPredicate(ZkPdfPredicate.DATE_LE, "birthDate", 20040228)))
                assertIs<ZkResult.Failed>(ZkPdfProofs.create(pdf, tooEarly, holder, ZkPdfStatement.PHONE, engine, { _, _, _ -> }, now))
                // Z2 against real proofs: one public byte before the content window.
                val masked = created.evidence.masked.copyOf().also { it[200] = (it[200] + 1).toByte() }
                assertEquals(Check.FAIL, verify(disclosed(created, rebuilt(created.evidence, masked = masked)), engine, trust).check)
            }
        } finally {
            directory.deleteRecursively()
        }
    }
}
