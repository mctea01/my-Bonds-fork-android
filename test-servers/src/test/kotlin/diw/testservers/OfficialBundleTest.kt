package diw.testservers

import diw.testservers.fixtures.OfficialLetter
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.official.ApprovalFile
import diw.wallet.core.document.official.OfficialBundles
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Which files go with an official document: hints for and against, confirmed by the holder afterwards. */
class OfficialBundleTest {
    private val letter = OfficialLetter(
        sender = "測試機關", recipient = "測試受文機關", subject = "測試主旨", copies = listOf("副本機關甲"),
    ).toXml()

    private fun exchangeForm(vararg receivers: String): ByteArray = buildString {
        append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!DOCTYPE 交換表單 SYSTEM \"104_roster_utf8.dtd\"[]>\n<交換表單>\n")
        receivers.forEach { append("<全銜>").append(it).append("</全銜><機關代碼>○○○○○○○○○○</機關代碼>\n") }
        append("<本別><收發處理本別 代碼=\"正本\"></收發處理本別></本別>\n</交換表單>\n")
    }.encodeToByteArray()

    @Test
    fun exchangeFormWithTheSameNameAndReceivers() {
        val m = OfficialBundles.match("獎懲令.di", letter, "獎懲令.sw", exchangeForm("測試受文機關"))
        assertTrue(m.suggested)
        assertEquals(2, m.evidence.size)
        assertTrue(m.evidence.any { it.text == "檔名相同（獎懲令）" })
        assertTrue(m.evidence.any { it.supports && it.text.startsWith("交換表單的 1 個發送對象中，有 1 個") })
    }

    @Test
    fun exchangeFormListingOnlyACopyReceiver() {
        val m = OfficialBundles.match("a.di", letter, "b.sw", exchangeForm("副本機關甲", "其他機關"))
        assertTrue(m.suggested)
        assertTrue(m.evidence.single().text.startsWith("交換表單的 2 個發送對象中，有 1 個"))
    }

    @Test
    fun exchangeFormForOtherReceiversIsNotSuggested() {
        val m = OfficialBundles.match("獎懲令.di", letter, "獎懲令.sw", exchangeForm("無關機關"))
        assertTrue(m.supported, "the same file name still counts for it")
        assertTrue(m.contradicted)
        assertFalse(m.suggested)
    }

    @Test
    fun anotherDocumentIsNotSuggested() {
        val other = OfficialLetter(sender = "測試機關", recipient = "測試受文機關", subject = "另一份").toXml()
        val m = OfficialBundles.match("a.di", letter, "a.di.bak", other)
        assertFalse(m.suggested)
        assertTrue(m.evidence.any { !it.supports && "另一份公文" in it.text })
    }

    @Test
    fun unrelatedFileHasNoHints() {
        val m = OfficialBundles.match("a.di", letter, "photo.jpg", ByteArray(0))
        assertTrue(m.evidence.isEmpty())
        assertFalse(m.suggested)
    }

    @Test
    fun mainDocumentsAndForms() {
        assertTrue(OfficialBundles.isMain("a.di", letter))
        assertFalse(OfficialBundles.isMain("a.sw", exchangeForm("x")))
        assertFalse(OfficialBundles.isMain("a.xml", exchangeForm("x")), "an exchange form is not a document by its root either")
        assertFalse(OfficialBundles.isMain("a.di", "not xml".encodeToByteArray()))
        assertTrue(OfficialBundles.isExchangeFile("A.SW"))
        assertFalse(OfficialBundles.isExchangeFile("a.pdf"))
    }

    @Test
    fun escapedZipNames() {
        assertEquals("獎懲令.di", OfficialBundles.decodeZipName("#U734e#U61f2#U4ee4.di"))
        assertEquals("plain.sw", OfficialBundles.decodeZipName("plain.sw"))
    }

    // ---- online approval (.si): XMLDSig References name each file of the case with its digest

    /** Old Word file: the OLE compound file signature and filler (synthetic, not a real document). */
    private val oldWord = byteArrayOf(0xD0.toByte(), 0xCF.toByte(), 0x11, 0xE0.toByte(), 0xA1.toByte(), 0xB1.toByte(), 0x1A, 0xE1.toByte()) + ByteArray(504) { 1 }

    /** Page image: a little-endian TIFF header and filler. */
    private val tiff = byteArrayOf(0x49, 0x49, 0x2A, 0x00, 0x08, 0, 0, 0) + ByteArray(64) { 2 }

    /** A .doc that is really OOXML (a ZIP with [Content_Types].xml), as some offices name it. */
    private val docx: ByteArray = ByteArrayOutputStream().also { out ->
        ZipOutputStream(out).use { z ->
            z.putNextEntry(ZipEntry("[Content_Types].xml"))
            z.write("<Types><Override ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>".encodeToByteArray())
            z.closeEntry()
            z.putNextEntry(ZipEntry("word/document.xml")); z.write("<w:document/>".encodeToByteArray()); z.closeEntry()
        }
    }.toByteArray()

    private fun approval(files: Map<String, ByteArray>): ByteArray = buildString {
        append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<線上簽核 Id=\"sign_1\"><線上簽核資訊><簽核點定義 URI=\"#FLOW_1\">")
        append("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>")
        files.forEach { (name, bytes) ->
            val d = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes))
            append("<Reference URI=\"$name\"><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>$d</DigestValue></Reference>")
        }
        append("<Reference URI=\"#Sign_info_0\"><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>AAAA</DigestValue></Reference>")
        append("</SignedInfo><SignatureValue>AA==</SignatureValue></Signature></簽核點定義></線上簽核資訊></線上簽核>")
    }.encodeToByteArray()

    private val draft = OfficialLetter(sender = "測試機關", recipient = "測試受文機關", subject = "測試主旨（稿）").toXml()
    private val case = mapOf("函1來文.di" to letter, "函1來文附件.doc" to oldWord, "稿v1.di" to draft, "函稿附件1v1.doc" to docx, "稿-文稿頁面檔.tiff" to tiff)
    private val si = approval(case)

    @Test
    fun approvalReferencesSkipItsOwnElements() {
        val a = ApprovalFile.of("案例.si", si)!!
        assertEquals(case.keys.toList(), a.names)
        assertEquals(true, a.lists("稿-文稿頁面檔.tiff", tiff))
        assertEquals(false, a.lists("稿-文稿頁面檔.tiff", tiff + 0.toByte()), "same name, other content")
        assertEquals(null, a.lists("other.pdf", tiff))
        assertEquals(null, ApprovalFile.of("a.di", letter), "a document is not an approval")
    }

    @Test
    fun approvalSuggestsAttachmentsPagesAndDrafts() {
        val approvals = listOf(ApprovalFile.of("案例.si", si)!!)
        for ((name, bytes) in case - "函1來文.di") {
            val m = OfficialBundles.match("函1來文.di", letter, name, bytes, approvals)
            assertTrue(m.suggested, "$name: ${m.evidence}")
            assertTrue(m.evidence.any { it.supports && "內容雜湊相符" in it.text })
        }
        val self = OfficialBundles.match("函1來文.di", letter, "案例.si", si, approvals)
        assertTrue(self.suggested, self.evidence.toString())
        assertTrue(self.evidence.any { it.text == "簽核檔列出這份公文，內容雜湊相符" })
    }

    @Test
    fun approvalWithOtherContentIsAgainst() {
        val approvals = listOf(ApprovalFile.of("案例.si", si)!!)
        val m = OfficialBundles.match("函1來文.di", letter, "函1來文附件.doc", oldWord + 9.toByte(), approvals)
        assertFalse(m.suggested)
        assertTrue(m.evidence.any { !it.supports && "內容不同" in it.text })
        val changed = OfficialBundles.match("函1來文.di", letter + " ".encodeToByteArray(), "案例.si", si)
        assertTrue(changed.evidence.any { !it.supports && "可能是另一個版本" in it.text })
    }

    @Test
    fun officeFilesAndPageImagesAreRecognised() {
        assertEquals(DocumentFormat.OFFICE, DocumentInspector.sniff(oldWord, "a.doc"))
        assertEquals(DocumentFormat.OFFICE, DocumentInspector.sniff(docx, "函稿附件1v1.doc"), "OOXML named .doc is not a plain ZIP")
        assertEquals(DocumentFormat.IMAGE, DocumentInspector.sniff(tiff, "p.tiff"))
        assertEquals(DocumentFormat.IMAGE, DocumentInspector.sniff(byteArrayOf(0x4D, 0x4D, 0x00, 0x2A) + ByteArray(8), "p.tif"))
    }
}
