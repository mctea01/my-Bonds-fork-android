package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.OpenCertInfo
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.document.derived.DocumentFields
import diw.wallet.core.document.official.OfficialLetter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
}
