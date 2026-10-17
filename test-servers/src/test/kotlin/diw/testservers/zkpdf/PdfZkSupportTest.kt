package diw.testservers.zkpdf

import diw.testservers.fixtures.PdfComposer
import diw.wallet.core.document.pdf.*
import diw.wallet.core.document.zkpdf.*
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.util.zip.InflaterInputStream
import kotlin.test.*

class PdfZkSupportTest {
    @Test fun signedRevisionUsesItsOwnCrossReferences() = runBlocking<Unit> {
        val original = ZkPdfFixture.pdf()
        val later = ZkPdfFixture.replaceContent(original)
        val signed = PdfZkSupport.signedRevision(later, intArrayOf(0, 10, 15, original.size - 15))
        assertTrue(signed.bytes.contentEquals(original))
        assertTrue(PdfTextExtractor.extract(signed) == PdfTextExtractor.extract(PdfFile(original)))
        assertTrue(PdfTextExtractor.extract(signed) != PdfTextExtractor.extract(PdfFile(later)))
        assertEquals(1, signed.revisions.size)
        val encrypted = ZkPdfFixture.encrypt(original)
        val encryptedUpdated = ZkPdfFixture.appendPublicMarker(encrypted)
        val covered = PdfZkSupport.signedRevision(encryptedUpdated, intArrayOf(0, 10, 15, encrypted.size - 15))
        assertTrue(PdfTextExtractor.extract(covered) == PdfTextExtractor.extract(signed))
        assertTrue(covered.getObject(covered.size) is PdfNull)
        assertTrue(PdfFile(encryptedUpdated).getObject(covered.size) is PdfDict)
        assertFailsWith<PdfException> { PdfZkSupport.signedRevision(later, intArrayOf(0, 10, 15, original.size - 20)) }
        assertFailsWith<PdfException> { PdfZkSupport.signedRevision(later, intArrayOf(0, 10, Int.MAX_VALUE, 1)) }
    }

    @Test fun rawStreamExtentAndVerifiedRc4Keystream() = runBlocking<Unit> {
        val bytes = ZkPdfFixture.encrypt(ZkPdfFixture.pdf())
        val pdf = PdfFile(bytes)
        val number = PdfZkSupport.pageContentObject(pdf, 0)
        val extent = PdfZkSupport.streamExtent(pdf, number)
        val ciphertext = bytes.sliceArray(extent)
        val stream = pdf.getObject(number) as PdfStream
        val key = assertNotNull(PdfZkSupport.rc4KeyStream(pdf, number, ciphertext.size))
        val encoded = ByteArray(key.size) { (key[it].toInt() xor ciphertext[it].toInt()).toByte() }
        assertTrue(encoded.contentEquals(stream.data))
        val plain = InflaterInputStream(ByteArrayInputStream(encoded)).use { it.readBytes() }
        assertTrue(plain.contentEquals(ZkPdfFixture.content.toByteArray()))
        assertTrue(plain.contentEquals(pdf.decode(stream)))
        assertTrue(PdfZkSupport.rc4KeyStream(pdf, number, 0)!!.isEmpty())
        assertFailsWith<PdfException> { PdfZkSupport.rc4KeyStream(pdf, number, ciphertext.size + 1) }
        assertFailsWith<PdfException> { PdfZkSupport.rc4KeyStream(pdf, number, -1) }
        assertFailsWith<PdfException> { PdfZkSupport.streamExtent(pdf, pdf.size + 10) }
        assertFailsWith<PdfException> { PdfZkSupport.pageContentObject(PdfFile(ZkPdfFixture.pdf(arrayContents = true)), 0) }
        assertFailsWith<PdfException> { PdfZkSupport.streamExtent(PdfFile(ZkPdfFixture.pdf(wrongLength = true)), 4) }
    }

    @Test fun keystreamRejectsOtherHandlersAndBadUserChecks() = runBlocking<Unit> {
        val original = ZkPdfFixture.pdf()
        val variants = listOf(original, ZkPdfFixture.encrypt(original, user = "synthetic-user"),
            ZkPdfFixture.encrypt(original, bits = 40), ZkPdfFixture.encrypt(original, aes = true),
            ZkPdfFixture.corruptUserCheck(ZkPdfFixture.encrypt(original)))
        for (bytes in variants) {
            val pdf = PdfFile(bytes, "synthetic-user")
            assertNull(PdfZkSupport.rc4KeyStream(pdf, 4, 1))
        }
    }

    @Test fun decodersShareWinAnsiDifferencesAndCmaps() = runBlocking<Unit> {
        val decoders = PdfZkSupport.fontDecoders(PdfFile(ZkPdfFixture.pdf()), 0)
        val simple = decoders.getValue("F1")
        val cid = decoders.getValue("F2")
        assertEquals(1, simple.kind)
        assertEquals(2, cid.kind)
        assertTrue(simple.decode("\\101\\050\\102\\051\\040\\061".toByteArray(), true) == "A(B) 1")
        assertTrue(simple.decode("E1".toByteArray(), false) == "Á")
        assertTrue(simple.decode("(A)\\\r\nB".toByteArray(), true) == "(A)B")
        assertTrue(cid.decode("20 00 2001 1000 1009".toByteArray(), false) == "測試09")
        assertContentEquals(IntArray(10) { 48 + it }, simple.digitCodes())
        assertContentEquals(IntArray(10) { 0x1000 + it }, cid.digitCodes())
        assertFailsWith<PdfException> { simple.decode("sensitive)trailing".toByteArray(), true) }
        val failure = assertFailsWith<PdfException> { cid.decode("sensitive".toByteArray(), false) }
        assertEquals("Unsupported or malformed zkPDF input", failure.message)
        assertNull(failure.cause)
        assertFailsWith<PdfException> { cid.decode("20".toByteArray(), false) }
        val unsupported = PdfZkSupport.fontDecoders(PdfFile(ZkPdfFixture.pdf(differences = "225 /UnknownSyntheticGlyph")), 0)
        assertFailsWith<PdfException> { unsupported.getValue("F1").decode("E1".toByteArray(), false) }
    }

    @Test fun digitTablesRequireEveryDigitToHaveOneCode() = runBlocking<Unit> {
        val duplicate = PdfFile(ZkPdfFixture.pdf(differences = "65 /zero"))
        assertNull(PdfZkSupport.fontDecoders(duplicate, 0).getValue("F1").digitCodes())
        val duplicateCid = ZkPdfFixture.cmap.replace("<2000> <6E2C>", "<2000> <0030>")
        assertNull(PdfZkSupport.fontDecoders(PdfFile(ZkPdfFixture.pdf(cmapText = duplicateCid)), 0).getValue("F2").digitCodes())
        val missingCid = ZkPdfFixture.cmap.replace("<1000> <0030>", "<1000> <0041>")
        assertNull(PdfZkSupport.fontDecoders(PdfFile(ZkPdfFixture.pdf(cmapText = missingCid)), 0).getValue("F2").digitCodes())
    }

    @Test fun runsPreserveRawSourceAndExistingLayout() = runBlocking<Unit> {
        val pdf = PdfFile(ZkPdfFixture.pdf())
        val runs = PdfTextExtractor.runs(pdf, 0)
        val decoders = PdfZkSupport.fontDecoders(pdf, 0)
        assertEquals(listOf(0, 1, 2), runs.map { it.op })
        assertEquals(listOf("F1", "F1", "F2"), runs.map { it.font })
        assertEquals(60.0, runs[0].x)
        assertEquals(780.0, runs[0].y)
        assertTrue(runs[0].raw.contentEquals("Synthetic \\(A\\):".toByteArray()))
        for (run in runs) assertTrue(decoders.getValue(run.font).decode(run.raw, run.literal) == run.text)
        assertTrue(PdfTextExtractor.layoutRuns(runs) == PdfTextExtractor.extract(pdf))
        assertEquals("PdfTextRun(op=0)", runs[0].toString())
        val placed = PdfFile(ZkPdfFixture.pdf("""
            BT /F1 12 Tf 18 TL 1 0 0 1 60 780 Tm [(A) -600 (B)] TJ
            1 0 0 1 60 780 Tm (A) Tj (C) ' 0 0 (D) " ET
        """.trimIndent()))
        assertTrue(PdfTextExtractor.layoutRuns(PdfTextExtractor.runs(placed, 0)) == PdfTextExtractor.extract(placed))
        val encrypted = PdfFile(ZkPdfFixture.encrypt(ZkPdfFixture.pdf()))
        assertTrue(PdfTextExtractor.layoutRuns(PdfTextExtractor.runs(encrypted, 0)) == PdfTextExtractor.extract(encrypted))
    }

    @Test fun runsRejectAmbiguousArraysWithoutChangingExtraction() = runBlocking<Unit> {
        for (array in listOf("[(A) <42>]", "[(\\1)(2)]", "[<4><2>]")) {
            val pdf = PdfFile(ZkPdfFixture.pdf("BT /F1 12 Tf 60 780 Td $array TJ ET"))
            assertTrue(PdfTextExtractor.extract(pdf).isNotEmpty())
            val error = assertFailsWith<PdfException> { PdfTextExtractor.runs(pdf, 0) }
            assertEquals("Unsupported or malformed zkPDF input", error.message)
            assertNull(error.cause)
        }
        val raw = "BT /F1 12 Tf 60 780 Td [(A)(\\101)] TJ ET"
        val runs = PdfTextExtractor.runs(PdfFile(ZkPdfFixture.pdf(raw)), 0)
        assertTrue(runs.single().raw.contentEquals("A\\101".toByteArray()))
        val malformed = PdfFile(ZkPdfFixture.pdf("BT /F1 12 Tf (synthetic-private-input"))
        val error = assertFailsWith<PdfException> { PdfTextExtractor.runs(malformed, 0) }
        assertEquals("Unsupported or malformed zkPDF input", error.message)
    }

    @Test fun p3ComposerLayoutRemainsIdenticalAcrossPages() = runBlocking<Unit> {
        val bytes = PdfComposer.compose("合成證明", listOf(PdfComposer.Block.Heading("合成文件"),
            PdfComposer.Block.Field("測試欄位", "2026"), PdfComposer.Block.Paragraph("合成段落 abc 123。".repeat(300))))
        val pdf = PdfFile(bytes)
        val pages = PdfTextExtractor.pages(pdf)
        assertTrue(pages.size > 1)
        val fromRuns = pages.indices.joinToString("\n\n") { PdfTextExtractor.layoutRuns(PdfTextExtractor.runs(pdf, it)) }
        assertTrue(fromRuns == PdfTextExtractor.extract(pdf))
    }
}
