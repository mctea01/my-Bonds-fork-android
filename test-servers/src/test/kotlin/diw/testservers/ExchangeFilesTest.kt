package diw.testservers

import diw.testservers.fixtures.OfficialLetter
import diw.wallet.core.document.XmlTree
import diw.wallet.core.document.official.ExchangeFiles
import diw.wallet.core.document.official.OfficialBundles
import diw.wallet.core.document.official.OfficialDocuments
import diw.wallet.core.document.official.OfficialEntry
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The exchange envelope (.en), encrypted exchange form (.esw) and confirmation message of the document exchange. */
class ExchangeFilesTest {
    private val letter = OfficialLetter(sender = "測試機關", recipient = "測試受文機關", subject = "測試主旨").toXml()

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun envelope(mainHash: String, subject: String = "測試主旨") = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE g2b2c-envelope SYSTEM "104_g2b2c_envelope.dtd">
        <g2b2c-envelope>
          <senderinfo><object type="addressbook"><orgid>A00000000A</orgid><unitid>U01</unitid><orgname>測試機關</orgname>
            <note><doctype>函</doctype><docdate>1150101</docdate><docword>測字第1150000001號</docword><docpriority>普通件</docpriority></note></object></senderinfo>
          <receiverlist><object type="addressbook"><orgid>B00000000B</orgid><unitid></unitid><orgname>測試受文機關</orgname></object></receiverlist>
          <serviceid>SVC-001</serviceid>
          <applicationid>APP-123</applicationid>
          <subject>$subject</subject>
          <expiredate>20260131</expiredate>
          <filelist>
            <print><file needsig="true"><filename>獎懲令.di</filename><hash algorithm="sha256">$mainHash</hash></file></print>
            <others><file><filename>附件1.pdf</filename><hash>00ff</hash><note><文字>附件一</文字></note></file></others>
          </filelist>
        </g2b2c-envelope>
    """.trimIndent().encodeToByteArray()

    private val encryptList = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE g2b2c-encrypt-list SYSTEM "104_g2b2c_encrypt-list.dtd">
        <g2b2c-encrypt-list><receivercardlist>
          <receiverobject><orgid>B00000000B</orgid><unitid>U02</unitid>
            <cardlist type="GCA"><cardnum>GCA0001</cardnum><EncryptedData Method="RSA" MimeType="base64"><CipherData>${Base64.getEncoder().encodeToString(ByteArray(256))}</CipherData></EncryptedData></cardlist>
          </receiverobject>
        </receivercardlist></g2b2c-encrypt-list>
    """.trimIndent().encodeToByteArray()

    private val message = """
        <?xml version="1.0" encoding="UTF-8"?>
        <g2b2c-msg>
          <senderinfo><object><orgid>B00000000B</orgid><unitid></unitid><orgname>測試受文機關</orgname></object></senderinfo>
          <receiverlist><object><orgid>A00000000A</orgid><unitid>U01</unitid><orgname>測試機關</orgname></object></receiverlist>
          <exchangeid>EX-1</exchangeid><processid>P-1</processid><msgtime>20260102103000</msgtime><msgcode>0</msgcode><msgnote>已收文</msgnote>
        </g2b2c-msg>
    """.trimIndent().encodeToByteArray()

    private fun fields(doc: diw.wallet.core.document.official.OfficialDocument) =
        doc.sections.flatMap { it.entries }.filterIsInstance<OfficialEntry.Field>()

    @Test
    fun envelopeReadsPartiesAndFiles() {
        val doc = assertNotNull(OfficialDocuments.parse(envelope(hex(MessageDigest.getInstance("SHA-256").digest(letter)))))
        assertEquals("信封檔", doc.title)
        assertEquals("測試主旨", doc.subject)
        assertEquals(listOf("發文單位", "受文單位", "交換資訊", "封裝檔案"), doc.sections.map { it.title })
        val f = fields(doc)
        assertTrue(f.any { it.label == "發文單位" && it.value == "測試機關（A00000000A U01）" })
        assertTrue(f.any { it.label == "公文資訊" && "發文字號 測字第1150000001號" in it.value })
        assertTrue(f.any { it.label == "呈現檔" && it.value.startsWith("獎懲令.di（需簽章）") })
        assertTrue(f.any { it.label == "其他檔案" && it.value.startsWith("附件1.pdf，附件一") })
        val root = XmlTree.parse(envelope("x"))!!.root
        assertEquals(listOf("呈現檔", "其他檔案"), ExchangeFiles.envelopeFiles(root).map { it.role })
    }

    @Test
    fun encryptedFormListsReceiversWithoutDecrypting() {
        val doc = assertNotNull(OfficialDocuments.parse(encryptList))
        assertEquals("加密交換表單檔", doc.title)
        val r = ExchangeFiles.receivers(XmlTree.parse(encryptList)!!.root).single()
        assertEquals("B00000000B", r.orgId)
        assertEquals(256, r.cards.single().cipherBytes)
        assertTrue(fields(doc).any { it.label == "GCA 憑證卡" && "GCA0001" in it.value && "256 位元組" in it.value })
        assertTrue(doc.sections.last().entries.single() is OfficialEntry.Paragraph)
    }

    @Test
    fun confirmationMessageIsReadable() {
        val doc = assertNotNull(OfficialDocuments.parse(message))
        assertEquals("交換確認訊息檔", doc.title)
        val f = fields(doc)
        assertTrue(f.any { it.label == "訊息代碼" && it.value == "0（使用者確認收文）" })
        assertTrue(f.any { it.label == "原發文單位" && it.value.startsWith("測試機關") })
    }

    @Test
    fun envelopeWithTheDocumentsHashBelongsToIt() {
        val good = envelope(hex(MessageDigest.getInstance("SHA-256").digest(letter)))
        val m = OfficialBundles.match("獎懲令.di", letter, "獎懲令.en", good)
        assertTrue(m.suggested)
        assertTrue(m.evidence.any { it.supports && it.text == "信封檔列出這份公文，雜湊相符" })
        assertTrue(m.evidence.any { it.supports && it.text == "信封檔的主旨與公文相同" })

        val b64 = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(letter))
        assertTrue(OfficialBundles.match("獎懲令.di", letter, "x.en", envelope(b64)).suggested, "base64 hashes are read too")
    }

    @Test
    fun envelopeForAnotherVersionIsNotSuggested() {
        val m = OfficialBundles.match("獎懲令.di", letter, "獎懲令.en", envelope(hex(ByteArray(32)), subject = "其他主旨"))
        assertFalse(m.suggested)
        assertTrue(m.evidence.any { !it.supports && it.text == "信封檔列出同名檔案，但雜湊不同" })
    }

    @Test
    fun exchangeFilesAreNotMainDocuments() {
        assertFalse(OfficialBundles.isMain("a.en", envelope("00")))
        assertFalse(OfficialBundles.isMain("a.xml", encryptList), "an exchange form is not a document even under another name")
        assertTrue(OfficialBundles.isExchangeFile("公文.esw"))
        assertTrue(OfficialBundles.isMain("a.di", letter))
        assertNull(XmlTree.parse("not xml".encodeToByteArray()))
    }
}
