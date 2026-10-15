package diw.testservers

import diw.testservers.fixtures.OfficialLetter
import diw.wallet.core.document.official.OfficialBundles
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
}
