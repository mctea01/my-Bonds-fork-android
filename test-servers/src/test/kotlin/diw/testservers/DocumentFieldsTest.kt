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
        assertEquals("true", DocumentFields.insideOn(c, LocalDate(2028, 8, 1))?.value)
        // The suggested claims use the structure only, without the bilingual label pairs of the general reading.
        val report = DocumentReport(DocumentFormat.PDF, "00", 1, checkedAt = 0)
        val suggested = DerivedCredentials.suggestedClaims(report, "a.pdf", null, text).map { it.name }
        assertTrue("Name" !in suggested && "姓名" !in suggested && "name" in suggested, suggested.toString())
        assertNull(EntryExitCertificate.parse("在學證明\n1 2020/01/01 2020/01/02"))
    }

    /**
     * A mainland China entry and exit record (synthetic, in the layout of the National Immigration Administration's
     * signed PDF): every row is read, across the page break and down to the oldest, with the document name wrapped
     * around each row and the flight number missing for crossings by land or sea.
     */
    @Test
    fun mainlandEntryExitRecord() {
        val text = """
            中华人民共和国出入境管理局
            出入境记录查询结果（电子文件）
            编号：T000000000001 查询日期：2030年04月01日
            查询人姓名: 测试旅客 ，性别: 女 ，出生日期: 1990年01月02日 ，
            台湾居民来往大陆通行证号码: 00000001 ，通过中华人民共和国出入境管理局出入境记
            录查询系统查询，其本人在 2010 年 01 月 01 日至 2030 年 04 月 01 日期间有下列
            出入境记录：
            序号 出境/入境 出入境日期 证件名称 证件号码 出入境口岸 航班号
            台湾居民来往大陆
            1 出境 2030-03-01 0000000102 厦门高崎机场 MF880
            通行证
            台湾居民来往大陆
            2 入境 2029-05-02 0000000102 福州机场 AE211
            通行证
            台湾居民来往大陆
            3 出境 2015-07-03 0000000101 同益港
            通行证
            第 1 页 / 共  2 页

            台湾居民来往大陆
            4 入境 2015-07-01 0000000101 同益港
            通行证
            台湾居民来往大陆
            5 出境 2012-01-20 0000000101 西九龙口岸
            通行证
            台湾居民来往大陆
            6 入境 2012-01-10 0000000101 上海浦东机场 CI501
            通行证
            1.本电子文件原件为PDF格式的数据电文，左上角图标处载有电子签名认证数据。
            制作日期：2030年04月01日10时30分
            第 2 页 / 共  2 页
        """.trimIndent()
        assertNull(EntryExitCertificate.parse(text), "not the Taiwan certificate")
        val c = assertNotNull(diw.wallet.core.document.derived.MainlandEntryExitRecord.parse(text))
        assertEquals("T000000000001", c.number)
        assertEquals(LocalDate(2030, 4, 1), c.queryDate)
        assertEquals("测试旅客", c.name)
        assertEquals("女", c.gender)
        assertEquals(LocalDate(1990, 1, 2), c.birthDate)
        assertEquals("台湾居民来往大陆通行证", c.documentLabel)
        assertEquals("00000001", c.documentNumber)
        assertEquals(LocalDate(2010, 1, 1), c.periodFrom)
        assertEquals(LocalDate(2030, 4, 1), c.periodTo)
        assertEquals("2030年04月01日10时30分", c.madeAt)
        assertEquals(2, c.pages)
        assertEquals((1..6).toList(), c.movements.map { it.item })
        assertTrue(c.movements.all { it.documentName == "台湾居民来往大陆通行证" }, c.movements.map { it.documentName }.toString())
        val oldest = c.movements.last()
        assertEquals(LocalDate(2012, 1, 10), oldest.date)
        assertEquals("上海浦东机场", oldest.port)
        assertEquals("CI501", oldest.flight)
        assertEquals("0000000101", oldest.documentNumber)
        assertEquals("西九龙口岸", c.movements[4].port)
        assertNull(c.movements[4].flight)
        assertEquals(LocalDate(2029, 5, 2), c.latestArrival)
        assertEquals(LocalDate(2030, 3, 1), c.latestDeparture)
        assertEquals(false, c.insideAtEnd)
        assertEquals(true, c.insideOn(LocalDate(2012, 1, 15)))
        assertEquals(false, c.insideOn(LocalDate(2013, 1, 1)))
        assertEquals(true, c.insideOn(LocalDate(2015, 7, 2)))
        assertEquals(false, c.insideOn(LocalDate(2015, 7, 3)), "left on that day")
        assertEquals(false, c.insideOn(LocalDate(2011, 6, 1)), "before the first arrival")
        assertNull(c.insideOn(LocalDate(2009, 12, 31)), "before the queried period")

        val claims = DocumentFields.fromMainlandEntryExit(text).associate { it.name to it.value }
        assertEquals("6", claims["entryExitCount"])
        assertEquals("false", claims["inMainlandAtPeriodEnd"])
        assertTrue(claims["entryExitRecords"]!!.endsWith("6. 入境 2012-01-10 上海浦东机场 CI501"), claims["entryExitRecords"])
        val day = assertNotNull(DocumentFields.insideOn(c, LocalDate(2029, 6, 1)))
        assertEquals("inMainlandOn_2029-06-01", day.name)
        assertEquals("true", day.value)
        assertEquals(c, diw.wallet.core.document.derived.MovementRecord.parse(text))
        val report = DocumentReport(DocumentFormat.PDF, "00", 1, checkedAt = 0)
        val suggested = DerivedCredentials.suggestedClaims(report, "a.pdf", null, text).map { it.name }
        assertTrue("entryExitRecords" in suggested && "查询人姓名" !in suggested, suggested.toString())
    }

    @Test
    fun studentStatusProof() {
        // The layout of a mainland university proof (e签宝), with fictitious values; lines wrap inside words.
        val text = """
                        中华人民共和国
                          浙江  杭州

            地址：浙江省杭州市测试区测试路1号              邮编(Zip Code)：310000
            Address:1 Test Road,Test District,Hangzhou,Zhejiang Province,P.R.CHINA
            电话(telephone)：+86-0591-00000000                    https://www.example.edu.cn

            学籍（在学）证明
            NO.200000000001
            学生：测试生，性别：女，出生于 2006 年 03 月 04 日，学号：
            100000001，证件号码:00000001。于 2024 年 09 月入学，现在计算
            机与大数据学院,软件工程专业四年普通全日制本科学习。

            PROOF OF STUDENT STATUS
            The Academic Affairs Office of Example University hereby certifies
            that TEST, STUDENT,female,born on March 4, 2006,Student ID No.
            100000001,ID No. 00000001,has been studying in College of
            Computer and Data Science since September 2024 ,majoring in the
            Regular four-year full-time undergraduate program of Software
            Engineering.
                                                         示例大学教务处
                                  Academic Affairs Office of Example University
                                                         打印日期/Date: 2030-10-12

            示例大学教务处 Academic Affairs Office of Example University
            咨询电话:+860591 00000000 电子邮箱：office@example.edu.cn
            Telephone:+ 860591 00000000 E-mail：office@example.edu.cn
            验证密钥(Verification Code)：0123456789ABCDEF
            验证官网(Verification URL)：http://verify.example.edu.cn/pc/anti-counterfeit
        """.trimIndent()
        assertNull(diw.wallet.core.document.derived.MainlandPermitLink.parse(text))
        val c = assertNotNull(diw.wallet.core.document.derived.StudentStatusProof.parse(text))
        assertEquals("学籍（在学）证明", c.title)
        assertEquals("200000000001", c.number)
        assertEquals("测试生", c.name)
        assertEquals("TEST, STUDENT", c.englishName)
        assertEquals("女", c.gender)
        assertEquals(LocalDate(2006, 3, 4), c.birthDate)
        assertEquals("100000001", c.studentId)
        assertEquals("00000001", c.idNumber)
        assertEquals("2024-09", c.enrolled)
        assertEquals("计算机与大数据学院", c.college)
        assertEquals("软件工程", c.major)
        assertEquals("四年普通全日制本科", c.programme)
        assertEquals("College of Computer and Data Science", c.collegeEnglish)
        assertEquals("Software Engineering", c.majorEnglish)
        assertEquals("Regular four-year full-time undergraduate program", c.programmeEnglish)
        assertEquals("示例大学", c.school)
        assertEquals("示例大学教务处", c.office)
        assertEquals("Academic Affairs Office of Example University", c.officeEnglish)
        assertEquals(LocalDate(2030, 10, 12), c.printDate)
        assertEquals("浙江省杭州市测试区测试路1号", c.address)
        assertEquals("310000", c.zipCode)
        assertEquals("+86-0591-00000000", c.phone)
        assertEquals("+860591 00000000", c.contactPhone)
        assertEquals("office@example.edu.cn", c.email)
        assertEquals("https://www.example.edu.cn", c.website)
        assertEquals("0123456789ABCDEF", c.verificationCode)
        assertEquals("http://verify.example.edu.cn/pc/anti-counterfeit", c.verificationUrl)
        val report = DocumentReport(DocumentFormat.PDF, "00", 1, checkedAt = 0)
        val suggested = DerivedCredentials.suggestedClaims(report, "a.pdf", null, text).associate { it.name to it.value }
        assertEquals("软件工程", suggested["major"])
        assertEquals("在學", suggested["studentStatus"])
        assertTrue("学生" !in suggested && "Telephone" !in suggested, suggested.keys.toString())
    }

    @Test
    fun mainlandPermitLink() {
        // The layout of the National Immigration Administration's permit association, with fictitious values.
        val text = """
            中华人民共和国出入境管理局
            台湾居民来往大陆通行证与居住证关联查询结果
            编号：J000000000001
                经系统核验，      台湾      居民，姓名:   测试人   ，性别:    女    ，出
            生日期: 1990年01月02日 ，同时持用或曾持用下列证件：
                台湾居民来往大陆通行证号码：   00000001   ，有效期至： 2035年05月06日 ；
                台湾居民居住证号码：  830000199001020000  ；
                请为该凭证持有人办理相关事务依法提供服务便利。
            1.本电子文件原件为PDF格式的数据电文，左上角图标处载有电子签名认证数据。通过电子签名认证的为有
              效数据电文，否则为无效数据电文。
            5.本电子文件从查询日期起，30天内有效。

            2030年07月16日
            第 1 页 / 共  1 页
        """.trimIndent()
        assertNull(diw.wallet.core.document.derived.MainlandEntryExitRecord.parse(text))
        assertNull(diw.wallet.core.document.derived.StudentStatusProof.parse(text))
        val c = assertNotNull(diw.wallet.core.document.derived.MainlandPermitLink.parse(text))
        assertEquals("J000000000001", c.number)
        assertEquals("测试人", c.name)
        assertEquals("女", c.gender)
        assertEquals(LocalDate(1990, 1, 2), c.birthDate)
        assertEquals("台湾", c.residentOf)
        assertEquals(2, c.permits.size)
        assertEquals("台湾居民来往大陆通行证", c.travelPermit?.name)
        assertEquals("00000001", c.travelPermit?.number)
        assertEquals(LocalDate(2035, 5, 6), c.travelPermit?.validUntil)
        assertEquals("830000199001020000", c.residencePermit?.number)
        assertNull(c.residencePermit?.validUntil)
        assertEquals(LocalDate(2030, 7, 16), c.queryDate)
        assertEquals(30, c.validDays)
        assertEquals(LocalDate(2030, 8, 14), c.validUntil)
        assertEquals(1, c.pages)
        val report = DocumentReport(DocumentFormat.PDF, "00", 1, checkedAt = 0)
        val suggested = DerivedCredentials.suggestedClaims(report, "a.pdf", null, text).associate { it.name to it.value }
        assertEquals("true", suggested["permitsLinked"])
        assertEquals("2030-08-14", suggested["recordValidUntil"])
        assertTrue("生日期" !in suggested, suggested.keys.toString())
    }
}
