package diw.wallet.core.credential

import diw.wallet.core.status.RiskLevel

/**
 * How sensitive a requested claim is, from its name: identifiers that single a person out for life (national ID
 * and document numbers, portraits, biometrics, addresses, health and account data) are high; plain identity data
 * (names, birth dates, contact details) is medium; anything else, age thresholds included, is low. Names are
 * compared on their last path segment, without case, underscores or hyphens, and in Chinese by keyword.
 */
object ClaimSensitivity {
    private val HIGH = setOf(
        "idnumber", "nationalid", "nationalidentifier", "personalidnumber", "personaladministrativenumber",
        "administrativenumber", "documentnumber", "passportnumber", "socialsecuritynumber", "taxidnumber",
        "healthinsurancenumber", "portrait", "picture", "photo", "signatureusualmark", "fingerprint", "biometric",
        "address", "residentaddress", "streetaddress", "residentstreet", "residenthousenumber", "housenumber",
        "formatted", "birthplace", "placeofbirth", "accountnumber", "iban", "cardnumber", "bankaccount",
        "health", "diagnosis", "medical",
    )
    private val HIGH_ZH = listOf("身分證", "身份證", "證號", "護照", "照片", "相片", "指紋", "地址", "住址", "戶籍", "出生地", "病", "健保", "帳號", "卡號")

    private val MEDIUM = setOf(
        "name", "givenname", "familyname", "middlename", "fullname", "birthfamilyname", "birthgivenname",
        "familynamebirth", "givennamebirth", "birthdate", "dateofbirth", "ageinyears", "agebirthyear", "sex", "gender",
        "nationality", "nationalities", "email", "emailaddress", "phone", "phonenumber", "mobilephonenumber",
        "residentcity", "residentpostalcode", "postalcode", "height", "weight",
    )
    private val MEDIUM_ZH = listOf("姓名", "姓", "名字", "生日", "出生", "性別", "國籍", "電話", "手機", "郵件", "信箱", "年齡")

    fun of(path: List<String>): RiskLevel = of(path.lastOrNull { it.toIntOrNull() == null } ?: path.lastOrNull().orEmpty())

    fun of(name: String): RiskLevel {
        val key = name.lowercase().filter { it.isLetterOrDigit() }
        return when {
            key in HIGH || HIGH_ZH.any { it in name } -> RiskLevel.HIGH
            key in MEDIUM || MEDIUM_ZH.any { it in name } -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
    }

    /** The highest sensitivity among [paths]; LOW for none. */
    fun ofAll(paths: Collection<List<String>>): RiskLevel = paths.fold(RiskLevel.LOW) { acc, p -> RiskLevel.max(acc, of(p)) }
}
