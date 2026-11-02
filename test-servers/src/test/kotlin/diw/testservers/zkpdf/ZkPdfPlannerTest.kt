package diw.testservers.zkpdf

import diw.wallet.core.document.pdf.PdfException
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.zkpdf.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import kotlin.test.*

/**
 * The planner must derive from the committed fictional PDFs exactly the circuit input that the frozen fixtures
 * (student.json, travel-rc4.json) were built with. Assertions compare bytes and never print document content.
 */
class ZkPdfPlannerTest {
    private fun resource(name: String) = javaClass.getResourceAsStream("/zkpdf/$name")!!.use { it.readBytes() }
    private fun fixture(name: String) = Json.parseToJsonElement(resource(name).decodeToString()).jsonObject
    private fun JsonObject.bytes(key: String) = getValue(key).jsonArray.map { it.jsonPrimitive.int.toByte() }.toByteArray()
    private fun JsonObject.int(key: String) = getValue(key).jsonPrimitive.int
    private fun JsonObject.list(key: String) = getValue(key).jsonArray.map { it.jsonObject }

    private val student = ZkPdfProfile(
        "test.student-status/1", "Synthetic student status", listOf("Qr"),
        listOf(
            ZkPdfFieldRule("name", "Name", listOf("姓名"), listOf("學號"), ZkPdfNormalize.TEXT),
            ZkPdfFieldRule("birthDate", "Birth date", listOf("出生日期"), listOf("科系"), ZkPdfNormalize.DATE),
        ),
        test = true,
    )

    private val travel = ZkPdfProfile(
        "test.travel-record/1", "Synthetic travel record", emptyList(),
        listOf(
            ZkPdfFieldRule("name", "Name", listOf("姓名"), listOf("證件號"), ZkPdfNormalize.TEXT),
            ZkPdfFieldRule("birthDate", "Birth date", listOf("出生日期"), listOf("序號"), ZkPdfNormalize.DATE),
        ),
        test = true,
    )

    private fun assertMatchesFixture(plan: ZkPdfPlan, json: JsonObject) {
        val input = json.getValue("input").jsonObject
        val spec = json.getValue("spec").jsonObject
        val windows = input.list("windows")
        val specWindows = spec.list("windows")
        assertEquals(windows.size, plan.layout.windows.size)
        plan.layout.windows.forEachIndexed { i, w ->
            assertEquals(windows[i].getValue("role").jsonPrimitive.content, w.role)
            assertContentEquals(windows[i].bytes("mid_in"), w.midIn, "mid_in $i")
            assertContentEquals(windows[i].bytes("head"), w.head, "head $i")
            assertContentEquals(windows[i].bytes("tail"), w.tail, "tail $i")
            assertContentEquals(windows[i].bytes("private_data"), plan.privateData[i], "private_data $i")
            if (windows[i]["key_stream"] == JsonNull) assertNull(w.keyStream)
            else assertContentEquals(windows[i].bytes("key_stream"), w.keyStream, "key_stream $i")
            assertEquals(specWindows[i].int("blocks"), w.blocks)
        }
        val anchors = spec.list("anchors")
        assertEquals(anchors.size, plan.anchors.size)
        plan.anchors.forEachIndexed { i, a ->
            val record = anchors[i].getValue("record").jsonObject
            assertContentEquals(record.bytes("font"), a.record.font)
            assertEquals(record.int("kind"), a.record.kind)
            val strings = record.getValue("strings").jsonArray.map { s -> s.jsonArray.map { it.jsonPrimitive.int.toByte() }.toByteArray() }
            assertEquals(strings.size, a.record.strings.size)
            strings.zip(a.record.strings).forEach { (x, y) -> assertContentEquals(x, y) }
            assertEquals(anchors[i].int("ordinal"), a.ordinal)
            assertEquals(anchors[i].int("total"), a.total)
        }
        val slots = spec.list("slots")
        assertEquals(slots.map { Triple(it.int("slot"), it.int("before_anchor"), it.int("after_anchor")) },
            plan.slots.map { Triple(it.slot, it.beforeAnchor, it.afterAnchor) })
        val tables = input.list("digit_tables")
        assertEquals(tables.size, plan.layout.digitTables.size)
        plan.layout.digitTables.forEachIndexed { i, t ->
            assertContentEquals(tables[i].bytes("font"), t.font)
            assertEquals(tables[i].int("width"), t.width)
            assertContentEquals(tables[i].getValue("codes").jsonArray.map { it.jsonPrimitive.int }.toIntArray(), t.codes)
        }
        val predicates = input.list("predicates")
        assertEquals(predicates.map { Triple(it.int("kind"), it.int("slot"), it.int("cutoff")) },
            plan.predicates.map { (p, slot) -> Triple(p.kind, slot, p.cutoff) })
    }

    @Test fun studentPlanMatchesFrozenFixture() = runBlocking<Unit> {
        val pdf = resource("student.pdf")
        val plan = ZkPdfPlanner.plan(pdf, student, listOf(ZkPdfPredicate(ZkPdfPredicate.DATE_LE, "birthDate", 20050101)))
        assertTrue(plan.unavailable.isEmpty())
        assertMatchesFixture(plan, fixture("student.json"))
        assertNotNull(ZkPdfDates.parse(plan.slots[1].value.replace("-", "/")))
    }

    @Test fun rc4PlanMatchesFrozenFixture() = runBlocking<Unit> {
        val pdf = resource("travel-rc4.pdf")
        val plan = ZkPdfPlanner.plan(pdf, travel, listOf(ZkPdfPredicate(ZkPdfPredicate.DATE_LE, "birthDate", 20050101)))
        assertTrue(plan.unavailable.isEmpty())
        assertNotNull(plan.layout.windows.single().keyStream)
        assertMatchesFixture(plan, fixture("travel-rc4.json"))
    }

    @Test fun layoutIsTheSameWithoutPrivateBytes() = runBlocking<Unit> {
        val pdf = resource("student.pdf")
        val holder = ZkPdfPlanner.layout(pdf, student)
        val masked = pdf.copyOf()
        for (w in holder.windows) masked.fill(0, w.fileOffset, w.fileOffset + w.length)
        // The verifier takes each window's outgoing state from the proof; here it is computed from the real file.
        val outs = holder.windows.map { w ->
            var state = Sha256State.ofBytes(w.midIn)
            val message = Sha256Chain.message(pdf, holder.byteRange)
            for (b in w.firstBlock until w.firstBlock + w.blocks) state = state.compress(message.block(b))
            state.toBytes()
        }
        val verifier = ZkPdfPlanner.layout(masked, student, midOuts = outs)
        val wrong = outs.mapIndexed { i, o -> if (i == 0) o.copyOf().also { it[0] = (it[0] + 1).toByte() } else o }
        val drifted = ZkPdfPlanner.layout(masked, student, midOuts = wrong)
        assertFalse(drifted.windows[1].midIn.contentEquals(holder.windows[1].midIn))
        assertEquals(holder.windows.size, verifier.windows.size)
        holder.windows.zip(verifier.windows).forEach { (a, b) ->
            assertEquals(a.firstBlock, b.firstBlock)
            assertEquals(a.blocks, b.blocks)
            assertContentEquals(a.midIn, b.midIn)
            assertContentEquals(a.head, b.head)
            assertContentEquals(a.tail, b.tail)
        }
    }

    @Test fun missingLabelsAreReportedNotGuessed() = runBlocking<Unit> {
        val profile = ZkPdfProfile("test.student-status/2", "Synthetic", emptyList(), listOf(
            ZkPdfFieldRule("name", "Name", listOf("姓名"), listOf("學號"), ZkPdfNormalize.TEXT),
            ZkPdfFieldRule("other", "Other", listOf("不存在的標籤"), listOf("科系"), ZkPdfNormalize.TEXT),
        ), test = true)
        val plan = ZkPdfPlanner.plan(resource("student.pdf"), profile)
        assertEquals(setOf("other"), plan.unavailable.keys)
        assertEquals(listOf("name"), plan.slots.map { it.claim })
        assertFailsWith<PdfException> {
            ZkPdfPlanner.plan(resource("student.pdf"), profile, listOf(ZkPdfPredicate(ZkPdfPredicate.DATE_GE, "other", 20000101)))
        }
    }

    @Test fun lexerRejectsWhatTheCircuitRejects() = runBlocking<Unit> {
        for (name in listOf("student-inline-image.pdf", "student-actual-text.pdf")) {
            assertFailsWith<PdfException>(name) { ZkPdfPlanner.plan(resource(name), student) }
        }
        assertFailsWith<PdfException> { ZkPdfLexer.records("BT (x) Tj ET".encodeToByteArray()) }
        assertFailsWith<PdfException> { ZkPdfLexer.records("BT /F1 1 Tf (x) ET".encodeToByteArray()) }
        val records = ZkPdfLexer.records("BT /F1 12 Tf [(a\\)b) 3 (c)] TJ <00 41> Tj ET".encodeToByteArray())
        assertEquals(2, records.size)
        assertEquals(listOf("a\\)b", "c"), records[0].strings.map { it.decodeToString() })
        assertEquals(1, records[1].kind)
    }

    @Test fun modifiedRevisionPlansTheSignedBytes() = runBlocking<Unit> {
        val pdf = resource("student-modified.pdf")
        val range = ZkPdfPlanner.signature(PdfFile(pdf)).byteRange
        assertTrue(range[2] + range[3] < pdf.size)
        val plan = ZkPdfPlanner.plan(pdf, student)
        assertTrue(plan.layout.windows.all { it.fileOffset + it.length <= range[2] + range[3] })
    }

    @Test fun datesFollowThePredicateFormat() {
        assertEquals(20040229, ZkPdfDates.yyyymmdd("2004年2月29日"))
        assertNull(ZkPdfDates.yyyymmdd("2005年2月29日"))
        assertNull(ZkPdfDates.yyyymmdd("04/02/29"))
        assertEquals("2004-02-09", ZkPdfNormalize.DATE.apply("2004.2.9"))
        assertEquals("A B", ZkPdfNormalize.TEXT.apply("  A \n B "))
        assertFailsWith<IllegalArgumentException> { ZkPdfPredicate(ZkPdfPredicate.DATE_LE, "x", 2005) }
        val json = student.toJson()
        assertEquals(json, ZkPdfProfile.parse(json).toJson())
    }
}
