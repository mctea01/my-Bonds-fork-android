package diw.testservers

import diw.testservers.fixtures.OfficialLetter
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.derived.DocumentFields
import diw.wallet.core.document.official.OfficialDocuments
import diw.wallet.core.document.official.OfficialEntry
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import kotlinx.coroutines.runBlocking
import org.multipaz.crypto.X509Cert
import org.multipaz.util.toBase64
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

/** Official documents (DTD 104 series) read into fields, paragraphs and approval steps instead of raw XML. */
class OfficialDocumentTest {
    private val noTrust = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision =
            TrustDecision.unknown("no anchors in this test")
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
    }

    private fun fields(doc: diw.wallet.core.document.official.OfficialDocument, section: String? = null): Map<String, String> =
        doc.sections.first { it.title == section }.entries.filterIsInstance<OfficialEntry.Field>().associate { it.label to it.value }

    @Test
    fun letterWithByteOrderMark() = runBlocking<Unit> {
        val letter = OfficialLetter(
            sender = "測試機關", senderCode = "A00000000A", address = "臺北市測試路1號", contact = "承辦人：王小明",
            recipient = "測試受文機關", subject = "測試主旨", explanations = listOf("第一點說明", "第二點說明"),
            wordPrefix = "測試", serial = "0000123", copies = listOf("副本機關甲", "副本機關乙"),
        )
        val bytes = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + letter.toXml()
        val doc = assertNotNull(OfficialDocuments.parse(bytes))
        assertEquals("函", doc.kind)
        assertEquals("測試機關 函", doc.title)
        assertEquals("測試主旨", doc.subject)
        val f = fields(doc)
        assertEquals("測試機關", f["發文機關"])
        assertEquals("王小明", f["承辦人"])
        assertEquals("測試受文機關", f["受文者"])
        assertEquals("普通件", f["速別"])
        assertEquals("副本機關甲、副本機關乙", f["副本"])
        assertTrue(f["發文字號"]!!.startsWith("測試字第") && f["發文字號"]!!.endsWith("0000123號"))
        assertFalse("附件" in f, "an empty attachment line is left out")
        val paragraphs = doc.sections.first().entries.filterIsInstance<OfficialEntry.Paragraph>()
        assertEquals("主旨：", paragraphs[0].heading)
        assertEquals("說明：", paragraphs[1].heading)
        assertEquals(listOf("一、" to "第一點說明", "二、" to "第二點說明"), paragraphs[1].items.map { it.number to it.text })

        val report = DocumentInspector.inspect(bytes, "letter.di", noTrust)
        assertEquals("測試主旨", report.title)
        assertTrue(report.notes.any { it.contains("台灣電子公文（函）") })
    }

    @Test
    fun memoWithNestedItemsAndCategory() = runBlocking<Unit> {
        val xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE 簽 SYSTEM "104_5_utf8.dtd">
            <簽>
              <發文機關><全銜>測試科</全銜><機關代碼/></發文機關>
              <文號><年度>115</年度><流水號>0000001</流水號><支號/></文號>
              <主旨><文字>測試簽主旨</文字></主旨>
              <段落 段名="說明：">
                <文字/>
                <條列 序號="一、"><文字>甲</文字>
                  <條列 序號="(一)"><文字>甲之一</文字></條列>
                </條列>
                <條列 序號="二、"><文字/></條列>
              </段落>
              <段落 段名="擬辦："/>
              <署名/>
              <年月日>115年10月15日</年月日>
            </簽>
        """.trimIndent().encodeToByteArray()
        val doc = assertNotNull(OfficialDocuments.parse(xml))
        assertEquals("測試科 簽", doc.title)
        val f = fields(doc)
        assertEquals("1150000001", f["文號"])
        assertEquals("115年10月15日", f["日期"])
        val p = doc.sections.first().entries.filterIsInstance<OfficialEntry.Paragraph>()
        assertEquals(listOf("主旨：", "說明："), p.map { it.heading }, "an empty 擬辦 paragraph is left out")
        val item = p[1].items.single()
        assertEquals("甲", item.text)
        assertEquals("(一)" to "甲之一", item.items.single().let { it.number to it.text })

        val order = """
            <?xml version="1.0" encoding="utf-8"?>
            <!DOCTYPE 令 SYSTEM "104_1_utf8.dtd"[]>
            <令><發文機關><全銜>測試部</全銜></發文機關><令類別 代碼="獎懲令"/><主旨><文字>核定獎懲</文字></主旨></令>
        """.trimIndent().encodeToByteArray()
        val o = assertNotNull(OfficialDocuments.parse(order))
        assertEquals("獎懲令", o.category)
        assertEquals("測試部 獎懲令", o.title)
        val claims = DocumentFields.fromOfficial(o).associate { it.name to it.value }
        assertEquals("令（獎懲令）", claims["officialKind"])
        assertEquals("核定獎懲", claims["officialSubject"])
    }

    @Test
    fun noticeWithInternalSubsetDoesNotLoadExternalEntities() = runBlocking<Unit> {
        val secret = File.createTempFile("diw-xxe", ".txt").apply { writeText("SECRET-CONTENT"); deleteOnExit() }
        val xml = """
            <?xml version="1.0" encoding="utf-8"?>
            <!DOCTYPE 會勘通知單 SYSTEM "104_B_utf8.dtd"[
            <!ENTITY 文書訊息表單 SYSTEM "message.dm" NDATA DM>
            <!NOTATION DM SYSTEM "文書訊息表單">
            <!ENTITY leak SYSTEM "${secret.toURI()}">
            ]>
            <會勘通知單>
              <發文機關><全銜>測試局</全銜><機關代碼>A00000000A</機關代碼></發文機關>
              <聯絡人及電話><姓名>王小明</姓名><職稱>技士</職稱><電話>02-12345678</電話></聯絡人及電話>
              <發文日期><年月日>中華民國115年10月15日</年月日></發文日期>
              <會勘事由><文字>測試會勘&leak;</文字></會勘事由>
              <會勘時間><年月日>115年10月20日</年月日><星期>二</星期><時分>上午10時</時分></會勘時間>
              <會勘地點><文字>測試地點</文字></會勘地點>
              <主持人><姓名>李主任</姓名></主持人>
              <出席者><全銜>甲單位</全銜><全銜>乙單位</全銜></出席者>
              <備註><段落 段名="備註："><文字>請準時出席</文字></段落></備註>
            </會勘通知單>
        """.trimIndent().encodeToByteArray()
        val doc = assertNotNull(OfficialDocuments.parse(xml))
        assertEquals("測試局 會勘通知單", doc.title)
        assertFalse(doc.toString().contains("SECRET-CONTENT"), "external entities are never loaded")
        val f = fields(doc)
        assertEquals("技士 王小明（02-12345678）", f["聯絡人"])
        assertEquals("115年10月20日（星期二） 上午10時", f["會勘時間"])
        assertEquals("測試地點", f["會勘地點"])
        assertEquals("李主任", f["主持人"])
        assertEquals("甲單位、乙單位", f["出席者"])
        val p = doc.sections.first().entries.filterIsInstance<OfficialEntry.Paragraph>()
        assertEquals(listOf("會勘事由：", "備註："), p.map { it.heading })
    }

    @Test
    fun formsAndCoSigningAgencies() = runBlocking<Unit> {
        val co = """
            <?xml version="1.0" encoding="utf-8"?>
            <!DOCTYPE 跨機關陳核會稿交換表單 SYSTEM "104_consultation_utf8.dtd"[]>
            <跨機關陳核會稿交換表單>
              <全銜>受陳機關</全銜><機關代碼>A00000000B</機關代碼>
              <跨機關陳核會稿文號><文號><年度>115</年度><流水號>0000009</流水號><支號/></文號></跨機關陳核會稿文號>
              <壓縮檔案名稱><檔案名稱>A00000000A1151015100001.zip</檔案名稱></壓縮檔案名稱>
              <傳送機關><全銜>傳送機關</全銜><機關代碼>A00000000A</機關代碼></傳送機關>
              <會陳狀態 代碼="2"/>
              <速別 代碼="速件"/>
            </跨機關陳核會稿交換表單>
        """.trimIndent().encodeToByteArray()
        val c = fields(assertNotNull(OfficialDocuments.parse(co)))
        assertEquals("外會", c["會陳狀態"])
        assertEquals("1150000009", c["跨機關陳核會稿文號"])
        assertEquals("A00000000A1151015100001.zip", c["壓縮檔案名稱"])
        assertEquals("傳送機關", c["傳送機關"])

        val sw = """
            <?xml version="1.0" encoding="utf-8"?>
            <!DOCTYPE 交換表單 SYSTEM "104_roster_utf8.dtd"[]>
            <交換表單>
              <全銜>正本機關</全銜><機關代碼>A1</機關代碼><單位代碼>U1</單位代碼><本別><收發處理本別 代碼="正本"/></本別>
              <全銜>副本機關</全銜><機關代碼>A2</機關代碼><單位代碼/><本別><收發處理本別 代碼="副本"/></本別>
            </交換表單>
        """.trimIndent().encodeToByteArray()
        val roster = assertNotNull(OfficialDocuments.parse(sw)).sections.single().entries.filterIsInstance<OfficialEntry.Field>()
        assertEquals(listOf("正本" to "正本機關（A1 U1）", "副本" to "副本機關（A2）"), roster.map { it.label to it.value })

        val dm = """<?xml version="1.0" encoding="utf-8"?><!DOCTYPE 文書訊息表單 SYSTEM "104_DM_utf8.dtd"[]><文書訊息表單><文書訊息代碼 代碼="1"/><訊息備註>修正重發</訊息備註></文書訊息表單>"""
        val m = fields(assertNotNull(OfficialDocuments.parse(dm.encodeToByteArray())))
        assertEquals("代碼 1", m["訊息代碼"])
        assertEquals("修正重發", m["訊息備註"])

        val joint = """
            <?xml version="1.0" encoding="utf-8"?>
            <會銜公文會辦單>
              <發文機關><全銜>主辦局</全銜></發文機關><發文機關><全銜>會辦部</全銜></發文機關>
              <公文類別 代碼="會銜公文會辦單"/>
              <會辦機關>
                <全銜>會辦部</全銜>
                <決行><姓名>李決行</姓名><職稱>部長</職稱></決行>
                <收文字號><字>主管</字><文號><年度>115</年度><流水號>0000001</流水號></文號></收文字號>
              </會辦機關>
            </會銜公文會辦單>
        """.trimIndent().encodeToByteArray()
        val j = assertNotNull(OfficialDocuments.parse(joint))
        assertEquals("主辦局、會辦部 會銜公文會辦單", j.title)
        val part = fields(j, "會辦機關：會辦部")
        assertEquals("部長 李決行", part["決行人"])
        assertEquals("主管字第1150000001號", part["收文字號"])

        assertNull(OfficialDocuments.parse("<root><a>1</a></root>".encodeToByteArray()), "other XML is not an official document")
        assertNull(OfficialDocuments.parse("not xml".encodeToByteArray()))
    }

    @Test
    fun onlineApprovalSteps() = runBlocking<Unit> {
        val pki = TestPki.create()
        val cert = pki.readerKey("approver.example").certChain.certificates.first().encoded.toByteArray().toBase64()
        fun point(id: String, info: String, name: String, action: String, opinion: String, time: String, next: String?) = """
            <簽核點定義 URI="#FLOW_$id" Id="Sign_$id">
              <Signature Id="ds_$id"><SignedInfo><Reference URI="#$info"/></SignedInfo><SignatureValue>AA==</SignatureValue>
                <KeyInfo><X509Data><X509Certificate>$cert</X509Certificate></X509Data></KeyInfo></Signature>
              <Object Id="$info">
                <異動資訊>
                  <簽核人員><單位>測試科</單位><職稱>科員</職稱><姓名>$name</姓名><角色>承辦人員</角色></簽核人員>
                  <異動別>$action</異動別><簽核意見>$opinion</簽核意見><簽章時間>$time</簽章時間>
                  ${next?.let { "<次位簽核人員><簽核人員><單位>測試科</單位><職稱>科長</職稱><姓名>$it</姓名></簽核人員></次位簽核人員>" } ?: ""}
                </異動資訊>
                <簽核資訊><簽核文件夾 Id="DOC_$id"><簽核文稿清單 文稿數="1"><文稿 類型="簽"><名稱>創簽</名稱><文稿類型>簽</文稿類型></文稿></簽核文稿清單>
                  <檔案清單 檔案數="1"><電子檔案資訊><檔案名稱>簽1150000001v1.di</檔案名稱><檔案大小>604</檔案大小><檔案格式>DI</檔案格式></電子檔案資訊></檔案清單>
                </簽核文件夾></簽核資訊>
              </Object>
            </簽核點定義>
        """
        val si = """
            <?xml version="1.0" encoding="utf-8"?>
            <!DOCTYPE 線上簽核 SYSTEM "104_sign_utf8.dtd"[]>
            <線上簽核 Id="sign_1150000001">
              <線上簽核流程 Id="FlowInfo">
                <簽核流程 Id="FLOW_承辦" 異動別="呈核"/>
                <簽核流程 Id="FLOW_會辦" 異動別="會辦"><分會點><簽核流程 Id="FLOW_會辦1" 異動別="會辦"/></分會點></簽核流程>
                <簽核流程 Id="FLOW_科長" 異動別="決行"/>
              </線上簽核流程>
              <線上簽核資訊 Id="signInfo">
                ${point("承辦", "info1", "王承辦", "呈核", "敬請核示", "11510151030", "陳科長")}
                ${point("科長", "info2", "陳科長", "決行", "可", "11510151500", null)}
              </線上簽核資訊>
            </線上簽核>
        """.trimIndent().encodeToByteArray()
        val doc = assertNotNull(OfficialDocuments.parse(si))
        assertEquals("線上簽核", doc.title)
        assertEquals(listOf("承辦" to 0, "會辦" to 0, "會辦1" to 1, "科長" to 0), doc.flow.map { it.name to it.depth })
        assertEquals(2, doc.steps.size)
        val first = doc.steps[0]
        assertEquals("測試科 科員 王承辦", first.signer)
        assertEquals("民國115年10月15日 10:30", first.time)
        assertEquals(listOf("敬請核示"), first.opinions)
        assertEquals(listOf("測試科 科長 陳科長"), first.next)
        assertEquals("approver.example", first.certificate)
        assertEquals(listOf("創簽（簽）"), first.drafts)
        assertEquals(listOf("簽1150000001v1.di（604 位元組）"), first.files)
        assertEquals("1150000001", fields(doc)["簽核編號"])
        val claims = DocumentFields.fromOfficial(doc).associate { it.name to it.value }
        assertEquals("測試科 科員 陳科長", claims["officialDecidedBy"])
        assertEquals("民國115年10月15日 15:00", claims["officialDecidedAt"])

        val report = DocumentInspector.inspect(si, "approval.si", noTrust)
        assertTrue(report.notes.any { it.contains("線上簽核") })
    }
}
