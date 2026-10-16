package diw.wallet.core.document.derived

import diw.wallet.core.profile.bonds.MyDataText
import kotlinx.datetime.LocalDate

/** A certificate read from a PDF text layer into its parts, for the structured preview and the derived claims. */
sealed interface ParsedCertificate {
    /** The claims a derived credential of the document carries, in the order they are shown. */
    fun claims(): List<DerivedClaim>

    companion object {
        /** The certificate [text] holds, of any kind the wallet reads as a structure; null for other documents. */
        fun parse(text: String): ParsedCertificate? = StudentStatusProof.parse(text) ?: MainlandPermitLink.parse(text)
    }
}

/**
 * A proof of student status issued by a mainland China university (学籍（在学）证明, as universities issue it
 * through e签宝): a Chinese paragraph stating the student, the date of entry and the college, major and programme
 * of study, the same in English, the issuing office with the print date, the school's contact lines and the code
 * for the school's verification page. Lines wrap anywhere, so the paragraphs are read joined.
 */
data class StudentStatusProof(
    val title: String,
    val number: String?,
    val school: String?,
    val office: String?,
    val officeEnglish: String?,
    val name: String?,
    val englishName: String?,
    val gender: String?,
    val birthDate: LocalDate?,
    val studentId: String?,
    val idNumber: String?,
    /** Year and month of entry ("2025-09"). */
    val enrolled: String?,
    val college: String?,
    val major: String?,
    /** The programme as printed ("四年普通全日制本科"). */
    val programme: String?,
    val collegeEnglish: String?,
    val majorEnglish: String?,
    val programmeEnglish: String?,
    val printDate: LocalDate?,
    val address: String?,
    val zipCode: String?,
    val phone: String?,
    val website: String?,
    val contactPhone: String?,
    val email: String?,
    val verificationCode: String?,
    val verificationUrl: String?,
) : ParsedCertificate {
    override fun claims(): List<DerivedClaim> = buildList {
        name?.let { add(DerivedClaim("name", it, "姓名")) }
        englishName?.let { add(DerivedClaim("englishName", it, "英文姓名")) }
        gender?.let { add(DerivedClaim("gender", it, "性別")) }
        birthDate?.let { add(DerivedClaim("birthDate", it.toString(), "出生日期")) }
        studentId?.let { add(DerivedClaim("studentId", it, "學號")) }
        idNumber?.let { add(DerivedClaim("idNumber", it, "證件號碼")) }
        school?.let { add(DerivedClaim("school", it, "學校")) }
        add(DerivedClaim("studentStatus", "在學", "學籍狀態"))
        enrolled?.let { add(DerivedClaim("enrollmentMonth", it, "入學年月")) }
        college?.let { add(DerivedClaim("college", it, "學院")) }
        major?.let { add(DerivedClaim("major", it, "專業")) }
        programme?.let { add(DerivedClaim("programme", it, "學制")) }
        collegeEnglish?.let { add(DerivedClaim("collegeEnglish", it, "學院（英文）")) }
        majorEnglish?.let { add(DerivedClaim("majorEnglish", it, "專業（英文）")) }
        programmeEnglish?.let { add(DerivedClaim("programmeEnglish", it, "學制（英文）")) }
        number?.let { add(DerivedClaim("certificateNumber", it, "證明編號")) }
        office?.let { add(DerivedClaim("issuingOffice", it, "出具單位")) }
        printDate?.let { add(DerivedClaim("printDate", it.toString(), "列印日期")) }
        verificationCode?.let { add(DerivedClaim("verificationCode", it, "驗證密鑰")) }
        verificationUrl?.let { add(DerivedClaim("verificationUrl", it, "驗證網址")) }
    }

    companion object {
        private val titles = listOf("学籍（在学）证明", "学籍(在学)证明", "在学证明", "在读证明", "学籍证明", "在學證明", "學籍證明", "在讀證明")
        private const val HAN = "[\\u4e00-\\u9fff]"
        private const val DATE = "(\\d{4})\\s*年\\s*(\\d{1,2})\\s*月\\s*(\\d{1,2})\\s*日"

        /** True when [text] is a proof of student status in the layout described above. */
        fun recognize(text: String): Boolean {
            val t = MyDataText.halfWidth(text)
            val compact = t.replace(Regex("\\s+"), "")
            val title = titles.any { MyDataText.halfWidth(it).replace(" ", "") in compact }
            return title && (Regex("(学号|學號):").containsMatchIn(compact) || Regex("(入学|入學)").containsMatchIn(compact))
        }

        fun parse(text: String): StudentStatusProof? {
            if (!recognize(text)) return null
            val t = MyDataText.halfWidth(text)
            val lines = t.lines().map { it.trim() }.filter { it.isNotEmpty() }
            // The Chinese paragraph joined without spaces (it wraps inside words), the English one with spaces.
            val zh = lines.joinToString("").replace(Regex("\\s+"), "")
            val englishStart = lines.indexOfFirst { it.contains("PROOF OF", ignoreCase = true) || it.contains("hereby certif", ignoreCase = true) }
            val en = if (englishStart >= 0) lines.drop(englishStart).joinToString(" ").replace(Regex("\\s+"), " ") else ""
            fun zhField(label: String) = Regex("(?:$label):([^,;。]+?)(?=[,;。]|$)").find(zh)?.groupValues?.get(1)?.trim()?.ifEmpty { null }
            fun lineField(label: String) = lines.firstNotNullOfOrNull { l ->
                Regex("(?:$label)\\s*:\\s*(.+?)(?=\\s{3,}|\\s+$HAN{2,}[^\\s:]*:|$)").find(l)?.groupValues?.get(1)?.trim()?.ifEmpty { null }
            }
            // The title as printed (full-width brackets), not the half-width copy the fields are read from.
            val title = text.lines().map { it.trim() }.firstOrNull { l ->
                titles.any { MyDataText.halfWidth(it).replace(" ", "") in MyDataText.halfWidth(l).replace(" ", "") }
            } ?: "学籍（在学）证明"
            val study = Regex("现在($HAN+?学院|$HAN+?系)[,]?($HAN+?)专业($HAN*?)学习").find(zh)
                ?: Regex("現在($HAN+?學院|$HAN+?系)[,]?($HAN+?)專業($HAN*?)學習").find(zh)
            val programme = study?.groupValues?.get(3)?.ifEmpty { null }
            val officeLine = lines.lastOrNull { Regex("^$HAN{2,20}(大学|大學|学院|學院)$HAN{0,8}(教务处|教務處|研究生院|学生处|學生處|教务部|教務部)$").matches(it.replace(" ", "")) }
                ?.replace(" ", "")
            val school = officeLine?.let { Regex("^($HAN{2,20}?(大学|大學|学院|學院))").find(it)?.groupValues?.get(1) }
                ?: Regex("($HAN{2,20}(大学|大學))").find(zh)?.groupValues?.get(1)
            val officeEnglish = lines.firstOrNull { it.matches(Regex("^(Academic Affairs Office|Graduate School|Office of [A-Za-z ]+) of [A-Za-z ]+$")) }
            val birth = Regex("出生(?:于|於)$DATE").find(zh)
            val entry = Regex("(?:于|於)(\\d{4})年(\\d{1,2})月(?:入学|入學)").find(zh)
            val englishName = Regex("certifies that\\s+(.+?)\\s*,\\s*(?:male|female)\\b", RegexOption.IGNORE_CASE).find(en)?.groupValues?.get(1)?.trim()
            val enStudy = Regex("studying in (.+?) since .+?,\\s*majoring in (?:the )?(.+?) of (.+?)\\.", RegexOption.IGNORE_CASE).find(en)
            return StudentStatusProof(
                title = title,
                number = Regex("NO\\.\\s*([A-Za-z0-9-]{4,40})").find(t)?.groupValues?.get(1),
                school = school,
                office = officeLine,
                officeEnglish = officeEnglish,
                name = zhField("学生|學生|姓名"),
                englishName = englishName,
                gender = zhField("性别|性別"),
                birthDate = birth?.let { date(it.groupValues[1], it.groupValues[2], it.groupValues[3]) },
                studentId = zhField("学号|學號"),
                idNumber = zhField("证件号码|證件號碼|身份证号|身份證號"),
                enrolled = entry?.let { "${it.groupValues[1]}-${it.groupValues[2].padStart(2, '0')}" },
                college = study?.groupValues?.get(1),
                major = study?.groupValues?.get(2),
                programme = programme,
                collegeEnglish = enStudy?.groupValues?.get(1)?.trim(),
                majorEnglish = enStudy?.groupValues?.get(3)?.trim(),
                programmeEnglish = enStudy?.groupValues?.get(2)?.trim(),
                printDate = Regex("打印日期\\s*(?:/\\s*Date)?\\s*:\\s*(\\d{4})-(\\d{1,2})-(\\d{1,2})").find(t)?.let { date(it.groupValues[1], it.groupValues[2], it.groupValues[3]) },
                address = lineField("地址"),
                zipCode = lineField("邮编(?:\\(Zip Code\\))?|郵遞區號"),
                phone = lineField("电话(?:\\(telephone\\))?|電話"),
                website = lines.firstNotNullOfOrNull { l -> Regex("(https?://[A-Za-z0-9./_-]+)").findAll(l).map { it.value }.firstOrNull { "anti-counterfeit" !in it && "verif" !in it.lowercase() } },
                contactPhone = lineField("咨询电话|諮詢電話"),
                email = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}").find(t)?.value,
                verificationCode = lineField("验证密钥(?:\\(Verification Code\\))?|驗證密鑰"),
                verificationUrl = lineField("验证官网(?:\\(Verification URL\\))?|驗證官網"),
            )
        }

        private fun date(y: String, m: String, d: String): LocalDate? = runCatching { LocalDate(y.toInt(), m.toInt(), d.toInt()) }.getOrNull()
    }
}
