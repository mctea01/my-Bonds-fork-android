package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.OpenCertInfo
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.DocumentFields
import diw.wallet.core.document.derived.EntryExitCertificate
import kotlinx.datetime.LocalDate
import diw.testservers.fixtures.OfficialLetter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Claims of derived credentials come from the document's content, not from what the holder types. */
class DocumentFieldsTest {
    @Test
    fun labelValuePairsOfATextLayer() {
        val text = """
            入出國日期證明書
            姓名：測試人員    出生日期：民國 083年03月06日
            證號: AB1234567
            網址：https://example.gov.tw/verify
            備註：
            Name: Test Person
        """.trimIndent()
        val fields = DocumentFields.fromText(text).associate { it.name to it.value }
        assertEquals("測試人員", fields["姓名"])
        assertEquals("民國 083年03月06日", fields["出生日期"])
        assertEquals("AB1234567", fields["證號"])
        assertEquals("https://example.gov.tw/verify", fields["網址"])
        assertEquals("Test Person", fields["Name"])
        assertFalse("備註" in fields, "empty values are left out")
        assertFalse(fields.keys.any { it.startsWith("https") })
        assertEquals("入出國日期證明書", DocumentFields.titleFromText(text))
    }

    @Test
    fun certificateWithSentencesColumnsAndBilingualLabels() {
        val text = """
                        中华人民共和国
            地址：测试省测试市大学路1号              邮编(Zip Code)：100000
            电话(telephone)：+86-000-12345678                    https://example.edu.cn
            学籍（在学）证明
            NO.202600000001
            学生：测试人，性别：女，出生于 2006 年 01 月 02 日，学号：
            123456789，证件号码:A0000000。于 2024 年 09 月入学，现在测试学院学习。
                                         打印日期/Date: 2026-10-12
            Telephone:+ 86 000 12345678 E-mail：office@example.edu.cn
            验证密钥(Verification Code)：ABCDEF0123456789
        """.trimIndent()
        val fields = DocumentFields.fromText(text).associate { it.name to it.value }
        assertEquals("测试省测试市大学路1号", fields["地址"])
        assertEquals("100000", fields["邮编(Zip Code)"])
        assertEquals("+86-000-12345678", fields["电话(telephone)"])
        assertEquals("202600000001", fields["documentNumber"])
        assertEquals("测试人", fields["学生"])
        assertEquals("女", fields["性别"])
        assertEquals("123456789", fields["学号"], "a label ending its line takes the start of the next line")
        assertEquals("A0000000", fields["证件号码"])
        assertEquals("2026-10-12", fields["打印日期/Date"])
        assertEquals("+ 86 000 12345678", fields["Telephone"])
        assertEquals("office@example.edu.cn", fields["E-mail"])
        assertEquals("ABCDEF0123456789", fields["验证密钥(Verification Code)"])
        assertEquals("2006 年 01 月 02 日", fields["出生日期"])
        assertEquals("2024 年 09 月", fields["入學年月"])
        assertEquals("学籍（在学）证明", DocumentFields.titleFromText(text))
    }

    @Test
    fun officialLetterFields() {
        val letter = OfficialLetter(
            sender = "測試市政府", recipient = "測試公司", subject = "函復貴公司申請案", wordPrefix = "測府字", serial = "1150000001",
        )
        val xml = letter.toXml().decodeToString()
        val fields = DocumentFields.fromOfficialLetter(xml).associate { it.name to it.value }
        assertEquals("測試市政府", fields["letterSender"])
        assertEquals("測試公司", fields["letterRecipient"])
        assertEquals("函復貴公司申請案", fields["letterSubject"])
        assertTrue(fields["letterNumber"]!!.startsWith("測府字字第"), fields.toString())
    }

    @Test
    fun openCertsFieldsAndSuggestedClaims() {
        val info = OpenCertInfo(
            version = "open-attestation/2.0", name = "Bachelor of Testing", issuers = listOf("Test University"), identityProofs = emptyList(),
            fields = linkedMapOf(
                "id" to "CERT-001", "name" to "Bachelor of Testing", "issuedOn" to "2026-06-30", "recipient.name" to "Test Person",
                "\$template.name" to "TEMPLATE", "issuers.0.name" to "Test University", "issuers.0.documentStore" to "0xabc",
                "admissionDate" to "2022-09-01", "additionalData.note" to "x", "programme" to "Testing",
            ),
            integrity = Check.PASS, issuerVerified = Check.NOT_CHECKED,
        )
        val report = DocumentReport(DocumentFormat.OPENCERTS, "00", 1, openCert = info, checkedAt = 0)
        val claims = DerivedCredentials.suggestedClaims(report, "cert.opencert", "使用者自行匯入")
        val byName = claims.associate { it.name to it.value }
        assertEquals("Bachelor of Testing", byName[DerivedCredentials.CLAIM_TITLE])
        assertEquals("Test Person", byName["recipientName"])
        assertEquals("CERT-001", byName["documentId"])
        assertEquals("2026-06-30", byName["issuedOn"])
        assertEquals("Test University", byName["documentIssuer"])
        assertEquals("2022-09-01", byName["admissionDate"])
        assertEquals("Testing", byName["programme"])
        assertFalse(claims.any { it.name.startsWith("\$template") || it.name.startsWith("issuers.") || it.name.startsWith("additionalData") })
        assertEquals(claims.size, claims.map { it.name }.toSet().size, "claim names are unique")
        assertEquals("受領人", DerivedCredentials.labelOf(claims.first { it.name == "recipientName" }))
    }
    /**
     * An entry and exit record (synthetic, in the layout the National Immigration Agency prints): the person, the
     * certificate and a table whose two halves share each text line. Trips are read by item number, and whether the
     * person was in Taiwan on a day follows from the movements up to it.
     */
    @Test
    fun entryExitRecord() {
        val text = """
            入出國日期證明書
            CERTIFICATE OF ENTRY AND EXIT DATES
            發證時間:2030/04/01 本證明書共 1 頁 頁次:1
            Date of Issue:2030/04/01 09:30:00 This document is composed of:1 page(s)
            證明書序號(Serial Number):000000000001 Page Number:1
            姓名: 測試旅客
            Name: CE SHIH LU KE
            國籍: 中華民國 性別:男
            Nationality: R.O.C.(Taiwan) Gender:Male
            護照號碼或統一證號: A100000001 出生日期<年/月/日>:1990/01/02
            Passport No. or ID/UI No: A100000001 Date of Birth(Year/Month/Day):1990/01/02
            茲證明上列人員之 2026/01/01 至 2030/04/01 入出境證明如下:
            項次 出境日期<年/月/日> 入境日期<年/月/日> 項次 出境日期<年/月/日> 入境日期<年/月/日>
            Item Exit Dates Entry Dates Item Exit Dates Entry Dates
            (Year/Month/Day) (Year/Month/Day) (Year/Month/Day) (Year/Month/Day)
            1 2030/03/01 ---------- 4 2027/01/10 2027/01/20
            2 2029/05/02 2029/05/09 5 以下空白 Blank Below
            3 2028/07/03 2028/07/30
            內政部移民署
        """.trimIndent()
        val c = assertNotNull(EntryExitCertificate.parse(text))
        assertEquals("測試旅客", c.name)
        assertEquals("CE SHIH LU KE", c.englishName)
        assertEquals("中華民國", c.nationality)
        assertEquals("男", c.gender)
        assertEquals("A100000001", c.idNumber)
        assertEquals(LocalDate(1990, 1, 2), c.birthDate)
        assertEquals("000000000001", c.serialNumber)
        assertEquals("2030/04/01 09:30:00", c.issuedAt)
        assertEquals(LocalDate(2026, 1, 1), c.periodFrom)
        assertEquals(LocalDate(2030, 4, 1), c.periodTo)
        assertEquals(listOf(1, 2, 3, 4), c.trips.map { it.item })
        assertNull(c.trips.first().entry)
        assertEquals(LocalDate(2030, 3, 1), c.latestExit)
        assertEquals(LocalDate(2029, 5, 9), c.latestEntry)
        assertEquals(false, c.returnedFromLatestTrip)
        assertEquals(false, c.inTaiwanAtEnd)
        assertEquals(true, c.inTaiwanOn(LocalDate(2026, 6, 1)), "before the first exit")
        assertEquals(false, c.inTaiwanOn(LocalDate(2027, 1, 15)))
        assertEquals(true, c.inTaiwanOn(LocalDate(2027, 1, 20)), "back on the day of entry")
        assertEquals(false, c.inTaiwanOn(LocalDate(2028, 7, 3)), "left on that day")
        assertNull(c.inTaiwanOn(LocalDate(2025, 12, 31)), "before the queried period")
        assertNull(c.inTaiwanOn(LocalDate(2030, 4, 2)), "after the queried period")

        val claims = DocumentFields.fromEntryExit(text).associate { it.name to it.value }
        assertEquals("2030-03-01", claims["latestExitDate"])
        assertEquals("2029-05-09", claims["latestEntryDate"])
        assertEquals("false", claims["returnedFromLatestTrip"])
        assertEquals("false", claims["inTaiwanAtPeriodEnd"])
        assertEquals("4", claims["entryExitCount"])
        assertTrue(claims["entryExitRecords"]!!.startsWith("1. 出境 2030-03-01，入境 無；2. 出境 2029-05-02"))
        assertEquals("true", DocumentFields.inTaiwanOn(c, LocalDate(2028, 8, 1))?.value)
        // The suggested claims use the structure only, without the bilingual label pairs of the general reading.
        val report = DocumentReport(DocumentFormat.PDF, "00", 1, checkedAt = 0)
        val suggested = DerivedCredentials.suggestedClaims(report, "a.pdf", null, text).map { it.name }
        assertTrue("Name" !in suggested && "姓名" !in suggested && "name" in suggested, suggested.toString())
        assertNull(EntryExitCertificate.parse("在學證明\n1 2020/01/01 2020/01/02"))
    }
}
