package diw.wallet.app.legal

import diw.wallet.app.res.Res
import diw.wallet.app.res.legal_language
import diw.wallet.app.tr

/** A block of a legal text: a paragraph or a bulleted list. */
sealed class LegalBlock {
    data class Paragraph(val text: String) : LegalBlock()
    data class Bullets(val items: List<String>) : LegalBlock()
}

class LegalSection(val heading: String, val blocks: List<LegalBlock>)

/**
 * A legal text shown in the app and published under docs/legal/[path]. Raising [version] asks every user to read and
 * decide again on the next start; fix typos without raising it. The translations of a text share its [id] and
 * [version], so a consent holds whatever language the text was read in.
 */
class LegalDocument(
    val id: String,
    val title: String,
    val version: Int,
    val effectiveDate: String,
    val summary: List<String>,
    val sections: List<LegalSection>,
    /** "zh" (the original, Traditional Chinese) or "en" (its translation). */
    val language: String = "zh",
) {
    /** Where the published form lives below docs/legal: the Chinese original at the top, translations in a folder per language. */
    val path: String get() = (if (language == "zh") "" else "$language/") + id + ".md"

    /** The published Markdown form (docs/legal), generated from this text so both stay the same. */
    fun toMarkdown(): String = buildString {
        val en = language == "en"
        append("# ").append(title).append("\n\n")
        append(if (en) "Version $version, effective $effectiveDate" else "版本 $version・生效日期 $effectiveDate").append("\n\n")
        if (en) append("> ").append(LegalTexts.TRANSLATION_NOTE).append("\n\n")
        append(if (en) "## Key points" else "## 重點摘要").append("\n\n")
        summary.forEach { append("- ").append(it).append('\n') }
        sections.forEachIndexed { i, s ->
            append("\n## ").append(i + 1).append(". ").append(s.heading).append("\n\n")
            s.blocks.forEachIndexed { j, b ->
                if (j > 0) append('\n')
                when (b) {
                    is LegalBlock.Paragraph -> append(b.text).append('\n')
                    is LegalBlock.Bullets -> b.items.forEach { append("- ").append(it).append('\n') }
                }
            }
        }
    }
}

/**
 * Services run by one central operator, each behind its own statement. Without the holder's consent to the current
 * statement the wallet does not contact the service; the standard paths are not affected.
 */
enum class Integration(val id: String, val available: Boolean = true) {
    TWDIW("twdiw"),
    MS_VERIFIED_ID("microsoft-verified-id"),
    MOBILE_MOICA("mobile-moica"),
    MYDATA("mydata"),
    /** zkPassport verification of others (docs/design/zkpassport.md Z2). Reading e-passports by NFC does not depend on it. */
    ZKPASSPORT("zkpassport"),
}

/** The statement of an [integration]: [name] as the UI shows it and the statement itself. */
class IntegrationStatement(val integration: Integration, val name: String, val operator: String, val document: LegalDocument)

internal class SectionsBuilder {
    val sections = ArrayList<LegalSection>()
    fun section(heading: String, vararg blocks: LegalBlock) {
        sections.add(LegalSection(heading, blocks.toList()))
    }
}

internal fun p(text: String) = LegalBlock.Paragraph(text)
internal fun list(vararg items: String) = LegalBlock.Bullets(items.toList())

internal fun document(
    id: String, title: String, version: Int, date: String, summary: List<String>, language: String = "zh",
    build: SectionsBuilder.() -> Unit,
) = LegalDocument(id, title, version, date, summary, SectionsBuilder().apply(build).sections, language)

/** The legal texts of one language. */
internal class LegalTextSet(
    val language: String,
    val developer: String,
    val terms: LegalDocument,
    val privacy: LegalDocument,
    val statements: List<IntegrationStatement>,
) {
    val all: List<LegalDocument> get() = listOf(terms, privacy) + statements.map { it.document }
}

/**
 * The legal texts in the language of the app: the Traditional Chinese original ([LegalTextsZh]) or its English
 * translation ([LegalTextsEn]), where the Chinese text prevails. The developer and contact details are those of the
 * published app; forks that publish their own builds must replace them. No e-mail address is published in the
 * repository: private contact goes through the one on the app store listing.
 */
object LegalTexts {
    const val SOURCE_URL = "https://github.com/mctea01/my-Bonds-fork-android"
    const val ISSUES_URL = "$SOURCE_URL/issues"
    /** Where the published Markdown versions live (docs/legal on the main branch). */
    const val PUBLISHED_URL = "$SOURCE_URL/blob/main/docs/legal"
    /** The languages the texts are published in; the first is the original. */
    val LANGUAGES = listOf("zh", "en")
    /** At the top of every translated text. */
    const val TRANSLATION_NOTE = "This English text is a translation of the Traditional Chinese original. If the two differ, the Chinese text prevails."

    /** "en" when the app is in English; otherwise, and before the app strings are loaded, the Chinese original. */
    val language: String get() = if (tr(Res.string.legal_language) == "en") "en" else "zh"

    internal fun texts(language: String): LegalTextSet = if (language == "en") LegalTextsEn.set else LegalTextsZh.set

    private val current: LegalTextSet get() = texts(language)

    /** The developer's name in the language of the app. */
    val DEVELOPER: String get() = current.developer
    val terms: LegalDocument get() = current.terms
    val privacy: LegalDocument get() = current.privacy
    val statements: List<IntegrationStatement> get() = current.statements

    fun statement(integration: Integration): IntegrationStatement = statements.first { it.integration == integration }

    /** Every text in the language of the app: the terms, the privacy policy and the statements. */
    val all: List<LegalDocument> get() = current.all

    /** Every text in every language, as published under docs/legal. */
    val published: List<LegalDocument> get() = LANGUAGES.flatMap { texts(it).all }

    fun byId(id: String): LegalDocument? = all.firstOrNull { it.id == id }

    /** The folder of the web versions in the language of the app. */
    val onlineFolder: String get() = if (language == "zh") PUBLISHED_URL else "$PUBLISHED_URL/$language"

    /** The web version of [doc] on GitHub. */
    fun onlineUrl(doc: LegalDocument): String = "$PUBLISHED_URL/${doc.path}"
}

/** Every legal text of the app in Traditional Chinese, the original the translations follow. */
internal object LegalTextsZh {
    /** The developer's name in this language (LIN, CHE-CHUAN in English). */
    const val DEVELOPER = "林哲全"
    private const val SOURCE_URL = LegalTexts.SOURCE_URL
    private const val ISSUES_URL = LegalTexts.ISSUES_URL

    private const val DATE = "2026-11-05"

    val terms = document(
        "terms-of-use", "DIW MY WALLET 用戶協議", 1, DATE,
        listOf(
            "DIW MY WALLET 是個人開發者免費提供的開源錢包與電子文件工具，並非數位發展部、內政部、國家發展委員會、Microsoft、歐盟或任何發證機關發行、認證或背書的應用程式。",
            "領取、出示與簽署可能把你選擇的資料及必要的協定資訊傳給第三方；證件或簽章的有效性並非由本 App 保證。",
            "請確認查驗對象、出示欄位及待簽文件，並妥善保管裝置、金鑰與 PIN。自行製作的衍生憑證不等同機關核發的證件。",
            "本 App 依現況免費提供；責任限制僅在法律允許範圍內適用，不排除依法不得免除的責任。",
        ),
    ) {
        section(
            "協議當事人與接受方式",
            p("DIW MY WALLET（以下稱「本 App」）包括由個人開發者${DEVELOPER}（以下稱「開發者」）發布的 Android、Windows 與 Linux 版本。" +
                "你使用前應有機會閱讀本協議及「隱私權政策」；首次啟動時，須以兩個獨立勾選框分別同意本協議與隱私權政策，才能繼續使用。不接受其中任一文件時，無法使用本 App。" +
                "隱私權政策的同意是對本 App 資料處理方式的必要確認，不取代專門服務的個別啟用同意。"),
            p("本 App 的預定使用對象為年滿 18 歲者，不以未成年人為對象。未滿 18 歲者不應自行啟用或使用本 App；如因特定情況確有使用必要，應先確認相關法律、發證機關及服務條款是否容許，" +
                "並取得法定代理人必要的同意及協助。法定代理人的同意不表示任何第三方服務必然允許未成年人使用。"),
        )
        section(
            "用詞定義",
            list(
                "「你」或「使用者」：安裝或操作本 App 的人；在證件出示情境中也可能稱為「持有人」。",
                "「發證端」或「發行端」：核發、提供或管理數位證件的機關、組織及其服務；兩詞在本協議中同義。",
                "「查驗方」：要求你出示證件、接收資料或驗證證明的個人、機關、組織及其系統。",
                "「第三方服務」：非由開發者營運的發證、查驗、簽章、時戳、身分驗證、查詢或中繼服務；包括你自行設定的服務端。",
                "「專門聲明」：針對特定服務額外說明資料流向、風險與啟用選擇的文件；同意某份聲明僅啟用對應功能。",
            ),
        )
        section(
            "功能與使用範圍",
            p("本 App 可依支援的公開標準與相容協定領取、保存、出示及查驗數位證件；匯入與保存電子文件；檢查電子簽章、撤銷狀態與時戳；以憑證卡、憑證檔或遠端服務簽署文件；建立自行簽發的衍生憑證；" +
                "以及在支援的情況下產生零知識證明。支援的格式包括 OpenID4VCI、OpenID4VP、ISO/IEC 18013-5、ISO/IEC 18013-7、SD-JWT VC、" +
                "ISO mdoc 與 W3C VC 等。各版本功能可能不同，部分功能需要相機、NFC、藍牙、USB、網路或第三方服務。"),
            p("本 App 可能處理臺灣地區、中國大陸及其他地區來源的電子證件或文件；支援與否依檔案格式、技術協定及實際功能判斷。技術上能匯入、驗證或顯示某份文件，不代表開發者認定該文件在任何特定地區具有法律效力，" +
                "也不表示取得其發證機關的認證或背書。"),
            p("開發者得因維護、資安、法規、相容性或其他合理原因新增、調整、暫停或移除功能；對於已發布版本，不能保證未來所有第三方服務持續可用。涉及必要法律文件變更時，依第 12 節處理。"),
        )
        section(
            "獨立性、相容性與名稱",
            p("本 App 不是數位發展部、內政部、國家發展委員會、Microsoft、歐盟（含 EUDI Wallet 相關計畫）或任何其他發證機關發行、認證、授權或背書的 App。" +
                "上述機關或廠商與本 App 不因技術相容而成立合作、代理、隸屬或服務委託關係。與其服務互通，不表示本 App 取得其官方身分或相關資格。"),
            p("某些功能依公開文件、開源程式或可觀察的協定行為進行相容實作，可能因對方修改規範、驗證機制或存取政策而中斷。部分離線證件格式或協定與個人開發者的 Bonds 開源專案相容，僅表示技術相容；" +
                "Bonds 不提供本 App 的中央服務，也不因此構成合作或背書。"),
            p("本 App 提及的政府機關、標準、產品、服務名稱、標誌或商標，僅用於識別服務或說明相容性；相關權利歸各自權利人所有，除非另有明確書面依據，不表示任何授權、認可或關聯。"),
        )
        section(
            "開放原始碼授權",
            p("本 App 專案的原始碼依其儲存庫所載 Apache License 2.0 及適用的第三方元件授權提供。你使用、修改與再散布原始碼的權利，依相應開源授權決定；本協議不變更或剝奪該等授權。" +
                "此協議說明開發者發布版本的使用條件與風險；第三方自行修改或發布的版本，其附加功能、資料處理與發布行為應由各該發布者說明及負責，但不影響法律所定責任。"),
            p("原始碼：${SOURCE_URL}"),
        )
        section(
            "使用者應注意事項",
            list(
                "僅在合法且有權的範圍內保存、領取、出示、查驗及簽署證件或文件；不得冒用身分、偽造資料或未經授權存取他人系統。",
                "為裝置設置適當的存取保護，妥善保管 App PIN、憑證卡、讀卡設備與相關密碼；裝置或憑證遺失時，應視情況向核發機關申請停用、撤銷或補發。",
                "出示前確認查驗方及資料用途，核對即將揭露的欄位與必要協定資訊；簽署前核對文件內容、檔名與官方確認畫面。無法確認查驗對象或簽署內容時，請勿繼續。",
                "重要文件應另外保留可驗證的原始檔及必要備份；使用測試環境、第三方服務及自行建立的服務端時，請先評估可靠性與資料安全。",
                "使用第三方服務時，也須遵守該服務適用的規則及法律。",
            ),
        )
        section(
            "證件、檢查結果與電子簽章的法律效力",
            p("證件的發行、身分資料正確性、有效期間、撤銷及受理條件，由核發機關、查驗方及適用法規決定。本 App 顯示的 T1 至 T4 信任等級、憑證鏈、簽章、狀態或撤銷檢查結果，" +
                "屬依當時可取得資料所做的技術性判定；受資料來源、設定、連線狀態及實作限制影響，不等於官方認證、法律鑑定或保證證件必然有效。"),
            p("由文件內容自行產生的衍生憑證（包括 Bonds 格式相容的身分證卡）為使用者簽發的聲明，不是政府機關核發的國民身分證、官方電子證件或其替代品。查驗方得依法律與自身規則決定是否接受。"),
            p("電子文件及電子簽章的效力，依文件及交易實際適用的法律、憑證條件與相關情況判定；在依法適用臺灣地區法律時，並應參照《電子簽章法》等相關規定。不因本 App 顯示「驗證成功」便自動取得任何特定法律效力。" +
                "測試環境產生的資料不得當作正式憑證或正式簽署結果使用；其個別證據價值仍以適用法律判斷。"),
        )
        section(
            "第三方服務與專門聲明",
            p("本 App 可依你的操作或相關驗證功能連線至發證端、查驗方、文件網站、簽章與時戳服務、信任或狀態清單、區塊鏈節點，以及你自行設定的服務端。此類服務的資料處理、服務條件及保存措施，" +
                "由實際營運者依其規定辦理；開發者不能控制其營運，也不代替其履行應負的法定義務。"),
            p("數位憑證皮夾（TWDIW）、Microsoft Entra Verified ID、行動自然人憑證、MyData 及未來實際上線的 zkPassport 相容功能，設有各自專門聲明。" +
                "你可以逐項選擇不同意；不同意僅停用對應整合功能，其他功能不受影響。已完成的領取、出示、簽署或第三方已接收的資料，不會因日後撤回而自動消除。詳見各專門聲明及隱私權政策。"),
        )
        section(
            "風險、免責與責任",
            p("本 App 免費並依「現況」及「現有狀態」提供。除法律另有強制規定或開發者另以書面明確承諾外，開發者不對特定第三方的可用性、標準相容性、資料即時性或特定用途適合性作額外保證。請特別注意裝置毀損、" +
                "金鑰無法復原、證件失效、傳輸被攔截、第三方服務中斷、簽章或驗證失敗等風險。"),
            p("因使用本 App 發生損害時，各方責任應依具體事實、可歸責程度及適用法律認定。**本協議不預先免除或限制開發者因故意、重大過失，或其他依法不得免除、限制的責任**；" +
                "亦不限制使用者依法享有的請求權或消費者權益。前述風險說明不表示使用者須自行承擔依法應由開發者負責的損害。"),
        )
        section(
            "資料、金鑰與停止使用",
            p("證件、文件、金鑰、設定及互動紀錄原則上儲存在你使用的裝置內。你可依 App 提供的功能刪除資料並停止使用；Android 解除安裝通常會移除 App 私有資料，電腦版可能須另行刪除其資料資料夾。" +
                "已匯出、另行備份或傳送給第三方的資料，不會因此一併刪除；金鑰及文件刪除後可能無法恢復。詳細方式見隱私權政策。"),
            p("開發者得因法律、資安、技術維護或停止維護等原因，停止發布、更新或提供部分版本；不表示開發者可以遠端取得你裝置上的資料。"),
        )
        section(
            "各項服務的同意及撤回",
            p("專門聲明可在「設定 > 法律聲明與同意」個別同意、拒絕或撤回。撤回後停止與該專門服務有關的後續功能請求及依該整合啟動的自動查詢；已開始、已傳送、已完成的交易，以及第三方先前依法或依其政策保存的資料，" +
                "不會被追溯撤銷。若需刪除第三方資料，應向該第三方提出請求。"),
            p("本協議及隱私權政策屬使用本 App 前均須同意的基礎文件，不適用上述「僅停用單一功能」機制；若不再接受其必要條件，可停止使用本 App。"),
        )
        section(
            "文件更新",
            p("本協議如有實質變更，會調整版本與生效日期，並在你下次開啟 App 時要求重新確認；僅修正不影響權利義務的文字錯誤時，版本號可能維持不變。修訂不追溯更改已完成行為的法律效果。" +
                "歷次公開文字可在專案 GitHub 的 `docs/legal` 目錄查閱。"),
        )
        section(
            "準據法與爭議處理",
            p("本協議以臺灣地區現行有效之法律為準據法。涉及不同地區之法律關係者，仍應依適用的法律衝突規範及強制規定處理。因本協議所生的爭議，由依法具有管轄權的法院處理；**消費者保護法等法律另有規定者，" +
                "從其規定**。本條不約定特定管轄法院，亦不排除其他依法不得排除的權利及保障。"),
        )
        section(
            "聯絡方式",
            p("一般建議及問題請至 GitHub Issues：${ISSUES_URL} 。涉及個人資料、憑證、漏洞或其他安全資訊時，請勿公開張貼，" +
                "請使用 Google Play 商店中本 App 頁面列出的開發者電子郵件私下聯絡。"),
        )
    }

    val privacy = document(
        "privacy-policy", "DIW MY WALLET 隱私權政策", 1, DATE,
        listOf(
            "本 App 不需開發者帳號，沒有廣告、使用分析、當機回報或內建追蹤服務；開發者目前不營運接收錢包證件、文件或使用紀錄的後端伺服器。",
            "證件、金鑰、文件、設定及同意紀錄主要儲存在裝置的 App 私有空間並受保護；但主動出示、簽署、查詢或背景驗證等功能，可能把必要資料傳給第三方。",
            "部分 HTTP 查詢及 Bonds 格式相容的離線傳輸沒有傳輸層加密；第三方仍可能取得 IP 位址、查詢對象或你同意出示的資料。",
            "數位憑證皮夾、Microsoft Entra Verified ID、行動自然人憑證、MyData 等功能須另外選擇啟用。你可撤回各項同意，但已傳出的資料不會因此從第三方刪除。",
        ),
    ) {
        section(
            "適用範圍及名詞",
            p("本政策說明個人開發者${DEVELOPER}發布的 DIW MY WALLET（以下稱「本 App」，包含 Android、Windows 及 Linux 版）如何在裝置上處理資料，" +
                "以及在何種情境下將資料送往第三方。相關名詞如「使用者」「持有人」「發證端（發行端）」「查驗方」及「第三方服務」，依「用戶協議」第 2 節定義。"),
            p("本政策為透明說明 App 實際資料流程、保存及使用者選擇而制定，並參照臺灣地區現行《個人資料保護法》所重視的告知與當事人權益原則。是否因特定處理活動而由開發者或其他營運者承擔法定個資義務，" +
                "仍應依實際控制、取得與使用資料的事實及適用法律認定；本政策不以文字預先排除依法應負的責任，也不代表所有第三方均由開發者控制。"),
            p("本 App 的資料流程與開發者透過 GitHub Issues、電子郵件直接接收你提供的資訊，屬不同情境；第三方另有自己的隱私權政策與法定義務。"),
        )
        section(
            "開發者實際取得的資料",
            p("本 App 不要求建立開發者帳號；依目前設計，不含廣告、應用程式使用分析、當機回報或使用者追蹤 SDK，也不會預設把錢包內的證件、私鑰、文件或互動紀錄上傳到開發者營運的伺服器。" +
                "本 App 沒有預設的自有後端；使用者自行填入的服務端不是開發者當然營運的服務。"),
            p("你若主動透過 GitHub Issues 或電子郵件聯絡，開發者會取得你提供的名稱、聯絡資訊、問題描述及附件，並可能依解決問題與安全通報之合理需要使用和保存；GitHub、" +
                "電子郵件服務提供者也會依各自政策處理。請勿在公開 Issues 張貼身分證號、憑證、金鑰、私人文件或其他敏感內容。你可透過原聯絡管道提出與該聯絡資料有關的請求，開發者將依適用法律及實際持有情況處理。"),
            p("即使開發者不接收錢包資料，只要 App 依功能把資料從裝置傳出，Google Play 資料安全申報仍可能將該傳送視為「收集」；這與開發者是否親自保存資料是兩個不同問題。"),
        )
        section(
            "本機保存的資料及用途",
            list(
                "**證件與憑證資料：** 數位證件、識別欄位、照片或卡面圖片、發證資訊、狀態查詢結果與自行簽發的衍生憑證。",
                "**私鑰與保護資訊：** 錢包及簽署所需的私鑰；Android 優先使用可用的 Android Keystore／StrongBox，否則可能以 App PIN 保護軟體金鑰。" +
                "安全能力依裝置及使用的金鑰類型而異。",
                "**電子文件與驗證資料：** 匯入或下載的 PDF、電子公文、OpenCerts 等檔案，以及簽章、憑證鏈、時戳、撤銷資訊、驗證結果、zkPDF 證據等。",
                "**互動紀錄：** 對象、互動時間、使用的證件及揭露欄位名稱；依目前設計不在此紀錄保存欄位值。證件或文件本身仍可能含有完整個資。",
                "**設定與快取：** 使用者自行選擇保存的 MyData 身分證統一編號與出生日期、使用者自行指定的服務端位址、信任清單與翻譯快取等。",
                "**法律文件同意紀錄：** 每份文件版本、同意或不同意的結果及時間，只保存於裝置。",
            ),
            p("這些資料用於本機顯示、查驗、簽署、信任判斷、功能設定及保留你的選擇。資料原則上位於 App 私有儲存空間，Android 版以裝置金鑰、電腦版以 App PIN 所提供的保護機制加密；" +
                "並非每種金鑰在所有設備上均可使用硬體隔離。Android 版已停用本 App 的系統自動備份；你主動匯出文件、使用其他備份工具或交付第三方時，不在此限制範圍內。"),
        )
        section(
            "裝置以外的資料傳送",
            p("資料傳送發生於使用者發起相關操作，或本 App 為完成證件／文件狀態、信任判斷及其他已啟用功能而執行必要查詢時；並非所有查詢都需要每次另外按下出示確認。連線對象通常能取得來源 IP 位址、" +
                "連線時間及請求內容，並可能據此推知持有證件的發證單位。其實際保存期限與用途依接收者的政策與法規決定。"),
            list(
                "**領取證件：** 傳送授權所需資料、持有者 DID 或公鑰、金鑰證明及發證端所要求的資訊；你在發證端網頁填寫的資料由相應網站接收。",
                "**出示證件與查驗：** 依選擇向查驗方或對方裝置傳送憑證、你同意揭露的欄位、持有者識別資訊、協定必要資訊及出示證明；QR Code、NFC 或藍牙可能作為建立連線或直接傳送資料的媒介。" +
                "不同協定可能揭露不同的中繼資料，不應將「只傳選擇的欄位」理解為完全沒有其他必要協定資料。",
                "**狀態、發證資訊及信任查詢：** 可依設定向發證端、DID 主機及第三方發布者取得憑證狀態、DID 文件、OCSP、CRL、發證端資訊、Adobe AATL、歐盟 EUTL、" +
                "mdoc 信任清單及測試用信任錨點；部分查詢會自動發生，部分更新可在設定關閉。",
                "**文件時戳：** 向你選擇的時戳機構（預設為 DigiCert）傳送時戳請求，其中含待處理文件內容計算出的 SHA-256 雜湊值，不傳送完整文件；請求亦可能包含協定必要欄位。",
                "**文件簽署：** 本機憑證卡可在裝置上進行簽章。遠端 CSC 服務可能收到待簽雜湊值、說明文字（可能含檔名）、登入或授權資訊。行動自然人憑證簽署另見其專門聲明。",
                "**OpenCerts 線上查驗：** 向公開以太坊節點與 DNS over HTTPS 查詢服務傳送證書儲存庫或網域相關查詢；在你選擇「發證機構樣式」後，" +
                "整份證書會經 HTTPS 傳給證書指定的顯示網站，該網站可能含第三方程式及自己的資料處理方式。",
                "**DID 解析：** 遇到 `did:ion` 等需要外部解析的情況時，可向 Microsoft DID 解析服務或相關主機請求 DID 文件。",
                "**外部文件網站：** 你在 App 內瀏覽器開啟政府或其他文件來源網站時，由該網站直接接收你所輸入的資料；本 App 保存你主動下載或匯入的檔案。",
                "**零知識證明：** zkPDF 等證明可在裝置上運算；使用 zkTLS 或其他需連線的流程時，可能連線目標網站、公證、中繼或查驗服務，傳送證明、必要協定資訊及你同意提供的資料。" +
                "特定證明或證據格式可能包含文件內容或簽署版本，不能概括視為絕不傳送文件。",
                "**自行設定的服務端：** 沒有預設服務端。你自行填入服務端位址並使用其功能時，該營運者可能接收中繼訊息、zkTLS 查驗資料、存取權杖，或行動自然人憑證簽署所需的身分證統一編號、檔名相關說明、" +
                "簽署屬性與回傳憑證等。傳送是否可被服務端讀取，視具體功能及加密方式而定。",
                "**系統 Credential Manager：** Android 版可在裝置上向 Android／Google Play 服務的系統選擇器登錄可出示證件的名稱、圖片及顯示欄位，" +
                "使其他 App 或網站能要求使用證件。此處為裝置系統整合，並非表示資料必然已上傳開發者伺服器。",
            ),
            p("上述功能可能涉及姓名、電子郵件地址、身分證統一編號與其他使用者識別碼、地址、出生日期、國籍、性別、照片、檔案和文件等；若你選擇傳送的證件或文件本身含有財務、健康等資訊，接收方也可能因此取得相關內容。" +
                "是否須在應用程式商店申報特定資料類別，應依實際傳送內容與平台定義判定。"),
        )
        section(
            "傳輸方式與剩餘風險",
            p("大部分線上領取、出示及遠端簽章連線使用 HTTPS，ISO/IEC 18013-5 的近距離出示依相關協定建立加密通道。但**並非所有傳輸均經過傳輸層加密**："),
            list(
                "部分時戳、OCSP、CRL、憑證或相關查詢可能使用第三方提供的 HTTP 位址，旁觀者可能知道請求的對象、憑證序號或雜湊等資料，也可能干擾傳輸；簽署的回應可輔助完整性驗證，" +
                "但不表示所有 HTTP 內容皆安全或能保護查詢隱私。",
                "與 Bonds 格式相容的部分藍牙或區域網路離線出示，不提供連線層加密；附近或同區網的第三人可能攔截你揭露的欄位，應避免用於不可信的環境或傳送高敏感資訊。",
                "使用者指定的測試服務或本機／區域網路端點，可能允許 HTTP；是否能安全使用取決於網路環境。",
            ),
            p("開發者會以程式設計上的安全措施降低風險，但不保證所有第三方通訊或接收端均符合相同的安全標準。"),
        )
        section(
            "專門服務與個別選擇",
            p("下列整合須先閱讀及選擇是否同意各自的專門聲明：數位發展部數位憑證皮夾（TWDIW）、Microsoft Entra Verified ID、內政部行動自然人憑證，以及數位發展部 MyData。" +
                "zkPassport 相容功能另有專門聲明，列出已提供的部分；未實際提供的功能不因預先展示文字而啟用。"),
            p("不同意或撤回某份專門聲明，只停止該特定整合的後續連線與功能，其他相容標準的功能仍可使用。先前已保存的證件或文件原則上保留在裝置內；先前傳給第三方的資料與已完成的簽署、出示或申請，" +
                "不會因撤回而自動刪除或失效。你可在「設定 > 法律聲明與同意」重新選擇。"),
        )
        section(
            "裝置權限",
            list(
                "**相機：** 用於掃描 QR Code。",
                "**NFC：** 用於感應讀取憑證卡，以及近距離出示或查驗。",
                "**藍牙：** 用於近距離傳輸；Android 11 以下系統可能另要求位置權限以使用藍牙功能，但本 App 不以該權限讀取或記錄地理位置。",
                "**生物辨識：** 用於裝置上的使用者確認；本 App 不另行取得或保存生物特徵範本。",
                "**USB：** 用於連接相容的晶片讀卡機。",
                "**網路：** 用於上述由你發起或功能所需的第三方連線。",
            ),
            p("拒絕個別權限可能使相應功能不可使用，通常不影響其他功能。權限需求依作業系統與版本而異。"),
        )
        section(
            "保存、刪除及資料主體權益",
            p("本機證件、文件、紀錄及設定原則上保留至你刪除、重設或移除 App 為止。可透過 App 提供的刪除操作移除對應項目；Android 解除安裝通常會刪除 App 的私有資料，" +
                "Windows／Linux 使用者可能還須移除 App 的資料資料夾。刪除可能無法復原。你自行匯出、其他工具備份或第三方已取得的資料，不會隨之刪除。"),
            p("你可利用本 App 功能查看、匯出或刪除裝置內資料；若涉及應更正的發證資料，請向原發證機關提出。若資料已由查驗方、文件網站、簽章機構、MyData 或自行設定的服務端接收，應向該實際持有者詢問閱覽、" +
                "更正、停止利用及刪除等權利之行使方式。開發者無法代第三方刪除資料，亦不能保證其刪除期限。"),
            p("對於開發者透過 GitHub 或電子郵件直接收取的聯絡資料，你可以循第 14 節管道提出查詢、更正、停止使用或刪除請求；開發者依實際持有情形及適用法律處理，必要時得依法保留相關紀錄。"),
        )
        section(
            "資料保護法令及責任歸屬說明",
            p("臺灣地區現行《個人資料保護法》第 8 條所定告知義務，以公務或非公務機關實際向當事人蒐集個資的情境為前提。依目前提供的設計事實，本 App 主要是由你在自己的裝置上管理資料、" +
                "直接向第三方發送請求的工具，開發者通常不接收該等錢包資料；然而是否有蒐集、處理、利用或其他義務，仍須就實際功能、控制能力、事故處理與接收者個別判斷，不能僅因使用「本機處理」便概括排除。"),
            p("本政策對本機資料類別、使用功能、對象、期間、地區與不提供資料的影響已依實際流程逐項說明，不應被解讀為開發者自稱每一項資料的唯一蒐集者。對於依法由開發者實際持有的聯絡資料，" +
                "當事人依法享有的權利不受本政策限制。個資法第 3 條及其他強制規定所定權利，亦不因使用本 App 而預先拋棄。"),
            p("本 App 可能處理來自臺灣地區、中國大陸及其他地區的證件或文件。此類技術相容不表示該文件在不同地區具有相同法律效力，也不表示開發者替所有第三方決定其資料處理的適用法律。跨地區傳輸及相關責任，" +
                "仍須依實際使用情境、營運者及各地適用規定個別認定。"),
            p("本 App 可能被境外使用者下載，或與境外服務相容；但某項外國個資法（包括 GDPR）是否適用，須依實際營業活動、是否以當地使用者為服務對象、資料處理角色與相關地域要件認定。" +
                "本政策不宣稱已獲 GDPR 認證，亦不排除依法應遵守的境外義務。"),
        )
        section(
            "未成年人",
            p("本 App 的預定使用對象為**年滿 18 歲**者，不以未成年人為對象。未成年人不應自行啟用或使用本 App；法定代理人同意不能免除第三方另有的年齡限制。" +
                "如發現開發者透過直接聯絡管道取得不應保存的未成年個人資料，可依第 14 節要求處理。"),
        )
        section(
            "安全措施與使用者提醒",
            p("本 App 提供本機加密、可用時的硬體金鑰保護、出示確認及技術性信任判定，但無法完全排除裝置遭入侵、金鑰遺失、惡意查驗、錯誤憑證或第三方資料外洩。請啟用螢幕鎖定，妥善保管 PIN，" +
                "只從 Google Play 或本專案 GitHub 的可信發布位置取得版本，並確認實際接收者及傳輸內容。"),
        )
        section(
            "第三方政策與未來營運變更",
            p("第三方發證端、查驗方、政府網站、信任資訊發布者、Microsoft、時戳服務及使用者自行部署的服務端各自決定其資料處理方式。開發者不因提供開源服務端程式而自動成為該服務端的營運者；" +
                "但任何自行營運或代管服務端的人，仍須依實際資料處理履行其義務。"),
            p("若未來開發者自行提供預設或公開服務端、帳號、雲端備份、遙測或其他接收資料的功能，應在功能啟用或上線前更新本政策、資料安全申報及必要的同意方式，說明營運者、資料類別、用途、保存期間、刪除及聯絡管道。"),
        )
        section(
            "政策更新與確認",
            p("本政策實質變更時，會更新版本及生效日期，並在下次啟動 App 時要求你重新閱讀與確認；僅修正不影響實質內容的錯字，版本號可能不變。你必須分別同意本政策與用戶協議才能使用 App；" +
                "但**同意本政策不取代個別服務所需的同意，也不使第三方自動取得超出功能所需的使用權限**。歷次版本可由 GitHub 專案 `docs/legal` 目錄查閱。"),
        )
        section(
            "聯絡方式",
            p("一般意見請至 GitHub Issues：${ISSUES_URL} 。個資權利、資安漏洞或含敏感資訊的事項，請勿公開張貼，" +
                "請使用 Google Play 本 App 商店頁面所列的開發者電子郵件私下聯絡。"),
        )
    }

    private val twdiw = document(
        "twdiw", "數位憑證皮夾（TWDIW）專門聲明", 1, DATE,
        listOf(
            "數位憑證皮夾（TWDIW）平台由數位發展部營運；發行、查驗及臨櫃互動可能另外涉及各機關、組織與公開區塊鏈節點。",
            "**本 App 並非官方數位憑證皮夾，也未獲數位發展部發行、認證或背書。** 為相容特定介面，可能以 `moda_dw` 識別碼及相容 User-Agent 連線，不代表本 App 真的是官方客戶端。",
            "依目前相容設計，TWDIW 卡片共用持有者金鑰及相關識別資訊，可能讓不同查驗方將出示紀錄關聯；平台也可能拒絕非官方實作。",
            "你可不同意或撤回，只停用 TWDIW 整合；已保存卡片不因此刪除，其他標準協定功能不受影響。",
        ),
    ) {
        section(
            "服務內容與關係",
            p("數位憑證皮夾（Taiwan Digital Identity Wallet，TWDIW）為數位發展部建置的數位憑證平台。你選擇啟用後，本 App 可依支援的相容流程瀏覽卡片目錄、" +
                "前往申請及領取平台發行端的卡片、出示給登錄查驗方（包括靜態 QR Code 與自訂欄位）、使用相關臨櫃條碼服務，並參考平台信任清單判斷發行端與查驗方。"),
            p("本 App 是個人開發者${DEVELOPER}提供的第三方相容工具，不是數位發展部的官方 App；數位發展部、發證機關或查驗方不因技術互通而成為本 App 的合作方、授權方或保證人。"),
        )
        section(
            "營運者及資料流向",
            list(
                "**領取：** 本 App 可能向 `wallet.gov.tw` 相關發行端傳送持有者 DID、公鑰、簽章證明、平台或發行端要求的識別資訊；你在發行端網站輸入的資料則由該網站處理。",
                "**出示：** 向平台登錄的查驗方傳送你所選欄位、持有者 DID 與出示證明；使用自訂欄位或靜態 QR Code 時，也可能傳送你填寫的內容及必要協定資訊。",
                "**臨櫃服務：** 依具體流程向服務方系統提交所需出示內容，並由相關平台或服務方取得條碼或確認結果。",
                "**平台信任及狀態：** 下載正式與官方測試環境的信任資料，向 Arbitrum One 公開節點（如 `arb1.arbitrum.io`）查詢鏈上註冊資訊；已保存的 TWDIW 卡片，" +
                "依目前設計可能每 12 小時重新檢查發行端，並定期查詢狀態。",
            ),
            p("各接收者可取得相關請求、來源 IP 位址及連線時間；根據請求內容，也可能推知你與哪些機關或組織互動。實際資料保存方式取決於相應營運者。"),
        )
        section(
            "中央化、識別與隱私風險",
            list(
                "平台控制其信任登錄及相關服務介面；發行端與查驗方各自管理證件發行、受理、停用或撤銷。任何一方停止服務或改變規則，都可能造成相關功能失效。",
                "依目前相容設計，TWDIW 卡片共用一把持有者金鑰，相關持有者 DID 或可重複識別資訊可能讓不同查驗方比對並關聯多次出示；**選擇性揭露欄位不等於匿名或不可追蹤**。",
                "平台、發行端、查驗方及節點營運者可能記錄請求時間、來源與相關識別資訊。",
                "使用測試環境、第三方查驗或臨櫃服務，不保證取得正式憑證或被特定業者接受。",
            ),
        )
        section(
            "非官方相容實作的重要告知",
            p("本 App 依公開標準、官方公開程式及實際介面行為實作相容流程。部分流程為與平台互通，可能在請求中使用官方皮夾識別碼 `moda_dw` 及相容的 User-Agent；" +
                "你可於「設定 > 互通」修改適用設定。"),
            p("**這些識別資訊可能使平台將請求視為來自官方皮夾類型，但本 App 實際上不是官方皮夾，亦未取得官方認證。** 相容性不能視為任何服務授權的證明；平台可能因身分辨識、服務條款、" +
                "安全政策或技術更新而拒絕、中斷或限制請求。請勿以本 App 的非官方身分向他人表示官方核准。正式使用前應確認相關服務規範及是否容許第三方客戶端。"),
        )
        section(
            "不同意或撤回後的影響",
            list(
                "停用 TWDIW 專屬卡片目錄、領卡、平台查驗與臨櫃整合；掃描對應 QR Code 或開啟相關連結時，提示此項整合尚未啟用。",
                "不因 TWDIW 整合而連線 `wallet.gov.tw` 或相應 Arbitrum 查詢節點，也不再使用平台信任清單重新判定相關 DID 或主動查詢 TWDIW 卡片狀態。",
                "已保存卡片保留在裝置上；依目前設計，無法出示給網址在 `wallet.gov.tw` 的平台查驗方。原有信任結果可能停留在最後更新時間，不能視為即時有效。",
                "OpenID4VCI、OpenID4VP、ISO/IEC 18013-5 等其他標準功能不因本項撤回而停用；但它們若獨立連線其他相同基礎網路營運者，仍依各自功能與政策運作。",
            ),
        )
        section(
            "同意與撤回",
            p("選擇「同意並啟用」代表你已閱讀上述非官方身分、資料流向與可關聯性風險，並要求本 App 啟用 TWDIW 相容功能；這不是使用其他 App 功能的前提。你可以在「設定 > 法律聲明與同意」撤回，" +
                "撤回後本 App 停止依本項整合發起新的服務請求。撤回前已完成或已送出的交易、對方取得的資料，不會因撤回而自動復原或刪除；如需向第三方行使資料權利，請洽實際接收者。"),
        )
    }

    private val msVerifiedId = document(
        "microsoft-verified-id", "Microsoft Entra Verified ID 專門聲明", 1, DATE,
        listOf(
            "Microsoft Entra Verified ID 是 Microsoft 提供的憑證服務；相關組織亦可能參與發行、查驗及保存資料。",
            "本 App 依公開文件及相容協定處理 Verified ID 請求，**不是 Microsoft Authenticator，也未獲 Microsoft 認證、授權或背書**。",
            "Verified ID 相容卡片依目前設計共用持有者金鑰及識別資訊，出示紀錄可能被不同查驗方關聯。",
            "不同意時停用 Verified ID 專屬領取、出示與狀態查詢，已存卡片保留；一般標準協定功能不受影響。",
        ),
    ) {
        section(
            "服務內容",
            p("Microsoft Entra Verified ID 是 Microsoft 提供給組織發行及查驗可驗證憑證的服務。你選擇啟用後，" +
                "本 App 可透過相容的 `openid-vc` 連結或 QR Code 領取組織發行的卡片，包括依流程登入組織、輸入自述欄位或出示其他卡片，亦可回應使用 Verified ID 服務的查驗請求。"),
        )
        section(
            "營運者與資料傳送",
            list(
                "**領取：** 相關請求及回應可能透過 Microsoft 的 Verified ID 雲端服務與組織系統傳遞，內容可包含持有者 DID、公鑰、授權權杖、使用者自述欄位，" +
                "以及你選擇提供的其他卡片或證明。",
                "**出示：** 可能傳送選定憑證與欄位、持有者 DID、簽章及必要協定資訊給 Microsoft 的服務與查驗組織。",
                "**身分與 DID 解析：** 本 App 可能讀取組織網域中的 Linked Domains 設定及 DID 文件；" +
                "解析 `did:ion` 時可向 Microsoft 解析端點（如 `discover.did.msidentity.com`）發送 DID 查詢。",
                "**狀態查詢：** 如服務有相關要求，本 App 可能向 Microsoft 或組織端查詢憑證撤銷狀態。",
            ),
            p("Microsoft 與各組織依其實際收到的資料、服務條款及隱私權政策分別處理；連線時可能取得你的 IP 位址、連線時間及相關識別資訊。"),
        )
        section(
            "服務及可追蹤性風險",
            list(
                "Microsoft 與相關組織可能得知領卡或查驗請求發生的時間與關聯對象；服務變更或停止時，可能無法繼續出示或驗證。",
                "憑證可由授權的發行組織撤銷；狀態依相應服務提供的資料及查詢結果而定。",
                "依目前相容設計，多張 Verified ID 卡片共用持有者金鑰；相同 DID 或可重複辨識的資訊可能讓查驗方跨情境關聯出示紀錄。只揭露選定欄位並不保證匿名。",
            ),
        )
        section(
            "非官方相容實作",
            p("本 App 是獨立開發的相容工具，不是 Microsoft Authenticator，與 Microsoft 沒有隸屬、合作、認證、授權或背書關係。Microsoft、Entra、" +
                "Verified ID 及 Microsoft Authenticator 等名稱或商標屬其權利人；本 App 僅為識別服務與說明互通用途而提及。"),
            p("相關協定或安全要求可能更新，Microsoft 或組織亦可能拒絕本 App 的非官方實作，開發者不保證所有請求均可使用。"),
        )
        section(
            "不同意或撤回後",
            list(
                "本 App 不處理 Verified ID 專屬的 `openid-vc` 領卡連結、QR Code 與特定出示請求，亦不依此整合連線 Microsoft 的 Verified ID 服務。",
                "已保存的 Verified ID 卡片不因此刪除，但不會依本項整合進行自動狀態查詢。",
                "一般 OpenID4VP 等標準請求仍可運作；如另有獨立 DID 解析或信任查詢功能，應依其一般資料流向及設定辦理，不將本項停用解讀為封鎖所有 Microsoft 網域。",
            ),
        )
        section(
            "同意與撤回",
            p("「同意並啟用」表示你了解上述跨服務傳送、非官方相容性及識別可關聯風險，並選擇使用此項整合。你可以在「設定 > 法律聲明與同意」撤回，停止此整合後續請求；撤回前已送出或完成的互動，" +
                "不因此失效或自動從 Microsoft 或組織系統刪除。其他 App 功能照常使用。"),
        )
    }

    private val mobileMoica = document(
        "mobile-moica", "行動自然人憑證簽署專門聲明", 1, DATE,
        listOf(
            "本功能透過內政部行動自然人憑證服務，讓你在官方「行動自然人憑證」App 確認簽署；本 App 並非內政部發布、認證或背書。",
            "**本專案開發者目前未取得內政部行動自然人憑證服務提供者（SP）帳號，亦未在其發布版本提供可直接使用的內建 SP。** 原始碼中的「內建 SP」介接程式僅為預留實作，" +
                "供未來依法取得授權的衍生版本（Fork）發布者自行評估配置，不代表本 App 已獲介接核准。",
            "真正提出簽章請求時，須由具合法資格的 SP 介接；如有合規配置，來源可能為使用者自行設定的服務端、持有授權者手動輸入的 SP，或衍生版本自行合法配置的 SP。**功能存在或使用者同意聲明，" +
                "不等於已取得 SP 授權或保證能完成簽章。**",
            "內政部會收到你的身分證統一編號、簽署說明（可能含檔名）、待簽屬性與文件雜湊值，不接收完整待簽文件；經服務端時，該營運者也可能取得上述資料及回傳結果。",
            "不同意時僅停用本項簽署方式，自然人憑證卡、憑證檔及其他簽署方式不受影響。",
        ),
    ) {
        section(
            "服務及確認流程",
            p("本專案提供行動自然人憑證簽署的**介接程式與操作入口**，但開發者目前沒有自己的 SP，也不保證官方發布版本已具備可用的介接來源。**只有在實際設定了具有合法介接資格的 SP，且相關服務可用時**，" +
                "你才能在文件簽署畫面選用此方式，由本 App 透過該 SP 向內政部服務發出請求。你須在官方行動自然人憑證 App 確認；內政部回傳憑證、簽章值及交易結果後，" +
                "本 App 再依支援程序驗證並將簽章寫入文件。"),
            list(
                "**推播確認：** 內政部向你登記的官方 App 推送確認要求；電腦版採用此方式。",
                "**App 對 App：** 在支援的手機上，以一次性票證開啟官方 App 完成確認後返回本 App；一次性票證不包含 SP 金鑰。",
            ),
            p("依目前設計，每次執行期間的首次簽署通常須先取得憑證、再進行簽署，因而可能需要兩次官方確認；憑證資料僅在本次執行的記憶體暫存，不保證跨次使用仍可沿用。"),
        )
        section(
            "SP 來源、申請資格與可辨識資訊",
            p("SP 是向內政部申請介接的服務提供者，具有服務代碼及相關金鑰。**帳號及金鑰的取得、使用及是否得委託他人介接，須以內政部核准的範圍、介接申請要點、契約及其他適用規範為準**；不能因帳號可以技術性使用，" +
                "就認為任何發布者、服務端或使用者都有權以該 SP 名義提供服務。"),
            p("**目前的發布事實：** 本專案開發者${DEVELOPER}尚未取得 SP 帳號或金鑰；本專案官方發布版本不提供由開發者持有的內建 SP，也沒有預設由開發者營運的 SP 服務端。" +
                "原始碼保留相關介接實作，是提供未來衍生版本的技術擴充可能，而非宣稱本版本已受內政部核准或已有可用的 SP。"),
            p("以下列出的是**在特定版本具備合法授權且實際配置後可能出現的來源**，並非本專案目前全部都有提供："),
            list(
                "**使用者設定的服務端 SP：** 你自行設定支援行動自然人憑證的 `diw-wallet-server` 部署位址，並使用其提供的存取權杖。資料路徑為「本 App → 服務端 → 內政部」，" +
                "SP 金鑰保存在服務端。SP 的實際持有人及資料處理者是經核准使用該 SP 的部署／營運單位，**不必然為本 App 開發者**；部署者仍須確認其介接與轉接方式符合核准條件。",
                "**衍生版本自行配置的內建 SP（未來預留）：** 原始碼保留可在建置時配置 SP 的技術流程，主要供未來已合法取得 SP 介接資格的 Fork 開發者評估。若其衍生版本實際配置，" +
                "請求可能由該版本直接送至內政部，以其經核准使用的 SP 名義提出。**本專案官方發布版本目前未配置這類 SP**；衍生版本的發布者必須自行確認申請資格、核准的系統及用途、是否允許此種客戶端部署方式，" +
                "以及必要的個資與資安義務。SP 秘密金鑰若嵌入公開程式，可能遭擷取，不應把程式碼可支援配置誤認為這種做法已獲允許。",
                "**手動輸入 SP（開發者與測試設定）：** 具備合法使用資格的人，可在「設定 > 開發者與測試」啟用「手動輸入 SP 帳號」，自行輸入服務代碼及 AES 金鑰，選擇對應環境，直接向內政部提出請求。" +
                "依目前設計，該金鑰只在本次執行記憶體使用，不寫入裝置。此入口僅供有權使用該 SP 的人使用，不得輸入未經授權取得的帳號或金鑰。",
            ),
            p("簽署畫面應讓你辨識本次選用的 **SP 來源、正式／測試環境，以及在可取得並經確認時的 SP 提供者名稱或識別資訊**。若只能顯示來源類型、無法確認實際持有人，請勿將其視為已核實 SP 身分。" +
                "手動輸入啟用時依目前設計預設採用手動來源；否則有設定服務端時優先使用其 SP，只有在該發布版本**實際配置且獲合法授權**時才可能出現內建 SP。**如沒有任何合法且可用的 SP，簽署功能就無法完成，" +
                "不應向使用者顯示為可直接使用。**"),
        )
        section(
            "正式與測試環境",
            list(
                "**正式環境：** 使用內政部正式介面 `fidoapi.moi.gov.tw`。若經由服務端 SP，依目前設計，本 App 對首次取得的憑證檢查是否為 MOICA G3 所簽發；" +
                "其他驗證依其實際支援機制辦理。這些技術檢查不取代對 SP 授權有效性的確認。",
                "**測試環境（UAT）：** 使用 `fido-test.moi.gov.tw`，仍須依內政部規定取得測試介接資格。測試憑證與測試簽章不得冒充正式簽署結果，" +
                "其法律上可能具有的個別證據價值仍依適用法律判斷。",
                "**來源與環境：** 未來衍生版本如自行合法配置內建 SP，依該版本的發布設定選擇環境；手動 SP 由有權使用者指定，服務端 SP 依服務端所公布的環境。" +
                "本 App 依目前設計會核對服務端提供的環境資訊與本次請求的一致性，但無法僅靠此檢查認定對方具有合法授權。",
            ),
        )
        section(
            "向內政部及服務端傳送的資料",
            p("本 App 會依簽章流程向內政部傳送下列資料，並由內政部依其規定處理："),
            list(
                "你的身分證統一編號。",
                "官方 App 可能顯示的簽署說明：`DIW MY WALLET 簽署：` 加上檔名，長度上限依目前設計為 60 字；**檔名本身可能含姓名、案件名稱或其他敏感資訊**。",
                "待簽的簽署屬性，包含文件的雜湊值及簽署所需資訊，不含完整文件內容。",
                "確認方式、時限及 SP 服務代碼等協定資訊。",
            ),
            p("內政部回傳憑證（可能包含姓名、身分識別欄位等）、簽章值及交易結果。直接介接時，本 App 依相關金鑰驗證回應；經服務端時，部分檢查可由服務端執行，並由本 App 在裝置上驗證支援的簽章與憑證鏈。"),
            p("**若透過你指定的服務端，該營運者也可接觸上述請求及回應資料。** 專案提供的服務端程式設計為暫存記憶體、避免持久化記錄並採取併發限制，但部署者可能自行修改程式、增加日誌或使用不同配置；" +
                "開發者無法驗證每個第三方服務端的實際保存期限或安全措施。請在選擇服務端前確認其營運者、隱私資訊及授權情形。"),
        )
        section(
            "主要風險及法律效力",
            list(
                "內政部及 SP 持有人可以由請求得知簽署時間、SP、身分證統一編號及可能含檔名的說明；服務端轉接時，其營運者也可能得知。",
                "內政部可能停用 SP、變更介面或限制未核准的使用方式；服務端亦可能停止服務，使簽署失敗。",
                "**僅在未來衍生版本實際配置 SP 時**，將 SP 秘密金鑰內建於公開 App 才會出現被擷取、遭濫用及連帶停權的風險。**本專案目前沒有內建 SP 金鑰，" +
                "也不建議任何衍生版本將正式環境 SP 秘密金鑰以可還原形式公開發布。**",
                "SP 僅代表介接服務來源，不代表 SP 持有人代替你在文件上簽名。文件簽署的效力仍須依憑證有效性、你在官方 App 的確認、簽章結果與《電子簽章法》等規定判斷，" +
                "不得僅以本 App 驗證結果或 SP 來源作保證。",
            ),
        )
        section(
            "非官方身分及 SP 責任",
            p("本 App 非內政部發布、認證、授權或背書的官方 App。**本專案開發者目前未取得 SP，原始碼內建 SP 的技術實作僅供未來 Fork 開發者參考與擴充，不表示已獲內政部介接核准。" +
                "** 介接功能參考開源程式及依法可取得的規格實作，不代表內政部准許任何 SP 帳號在本 App 上使用。實際提供 SP 的第三方服務端營運者、手動輸入者或衍生版本發布者，應依其角色確認核准資格、" +
                "介接範圍、金鑰保管及個資安全；使用者也不得使用未經授權的 SP 資訊。上述責任說明不排除任何一方因自身發布、設計或資料處理行為依法應負的責任。"),
        )
        section(
            "不同意或撤回後",
            list(
                "本 App 不提供本項行動自然人憑證文件簽署流程，也不因本功能發出內政部簽章請求或向你指定的服務端傳送此類請求。",
                "由其他網站自行導向官方行動自然人憑證 App 的登入、驗證流程，屬網站獨立發起的服務，不在本項停用範圍。",
                "本機自然人憑證卡、憑證檔、CSC 遠端簽章等其他方式不受影響。",
            ),
        )
        section(
            "同意與撤回",
            p("「同意並啟用」表示你了解 SP 來源、個資及檔名資料流向、正式與測試環境差異及非官方風險，並允許本項簽署整合在**具備合法且可用的 SP 來源時**供你選擇；**此同意不會提供 SP 帳號、" +
                "讓預留程式自動變成可用服務，或取代內政部所需的核准**。你可以隨時在「設定 > 法律聲明與同意」撤回，停止其後的本項簽署請求。已送出或完成的簽章與內政部、SP 或服務端先前依法保存的資料，" +
                "不會因撤回而自動取消或刪除。"),
        )
    }

    private val myData = document(
        "mydata", "MyData 專門聲明", 1, DATE,
        listOf(
            "個人化資料自主運用（MyData）平臺目前由**數位發展部**建置、運作及管理；個別資料則由提供資料的機關或組織負責。",
            "本 App 在內建瀏覽器開啟 MyData 網頁，可協助填入你自願保存的身分證統一編號與出生日期，並下載、解壓及保存文件。",
            "你在 MyData 網頁完成的身分驗證、同意及下載請求，由 MyData 與相應資料提供者依其規定處理；本 App 無法刪除這些第三方已有的紀錄。",
            "本 App 非數位發展部或資料提供機關發布、認證或背書；不同意時僅停用 MyData 整合，已保存的文件及衍生憑證保留。",
        ),
    ) {
        section(
            "功能與服務對象",
            p("MyData（個人化資料自主運用平臺）可讓使用者經身分驗證及同意後，取得機關或組織所提供的個人化文件。啟用後，你可在「文件 > 從網站取得」使用本 App 提供的 MyData 入口，" +
                "於 MyData 自身網站登入及下載可取得的戶政、財稅、勞健保等文件；部分文件可用於使用者自行製作 Bonds 格式相容的衍生憑證。"),
            p("衍生憑證是你自行產生的聲明，不是政府機關核發的國民身分證或正式數位證件。"),
        )
        section(
            "營運者、資料流程與保存",
            list(
                "**營運者：** MyData 平臺目前由數位發展部建置、運作及管理；文件內容由各資料提供機關或組織提供。相關身分驗證與資料使用紀錄依平台及各機關政策處理。",
                "**瀏覽器登入：** 本 App 在內建瀏覽器開啟 MyData 網頁；你在網頁選擇的自然人憑證、行動自然人憑證或其他驗證方式，及網頁上的同意、申請與資料處理，均由相關網站或服務負責。",
                "**本機自動填入：** 如你自行選擇保存身分證統一編號及出生日期，本 App 可依目前設計將其填入 MyData 的相應頁面，供 MyData 網頁處理；" +
                "並可使用身分證統一編號開啟下載後受保護的 PDF。本 App 不因這項設定而把資料傳送至其他非 MyData 的網站。",
                "**文件下載：** 本 App 可將 MyData 下載的 ZIP 於裝置上解開，保存其中支援的 PDF 文件，解壓完成後刪除 ZIP 檔。你另行匯出的文件不受 App 刪除操作控制。",
            ),
            p("MyData、資料提供者或其受託服務可得知你的登入、申請及存取時間、IP 位址及相關資料類別；詳細保存期限應依平台當時公開的服務條款及隱私權政策確認。"),
        )
        section(
            "隱私與功能風險",
            list(
                "MyData 平台及資料提供機關可能保存必要的使用紀錄；你在本 App 撤回此項同意，不會追溯刪除第三方紀錄。",
                "本機自動填入功能使用身分證統一編號與出生日期等敏感識別資訊，請妥善保護裝置與 App PIN；不再需要時可移除已保存的自動填入資料。",
                "MyData 網頁、登入規則、下載格式或 ZIP／PDF 保護方式改變時，自動填入、解壓或文件解析可能失敗；文件內容及法定用途以原提供機關與相關法規為準。",
                "下載的戶籍、所得、健康保險等文件可能包含高度敏感資訊；若再以其他功能出示、分享或建立證明，資料揭露風險由該次具體操作決定。",
            ),
        )
        section(
            "非官方相容實作",
            p("本 App 與數位發展部及資料提供機關沒有隸屬、合作、認證、授權或背書關係。網站導覽、協助填入及下載解析是對公開網站操作流程的相容實作；這不代表 MyData 授權本 App 為官方介接服務，" +
                "也不保證網站改版後持續可用。MyData 名稱僅用於識別被連線的服務。"),
        )
        section(
            "不同意或撤回後",
            list(
                "「取得文件」中的 MyData 入口及依 MyData 文件建立身分證卡的整合將停用，本 App 不依此功能開啟 MyData 網頁。",
                "先前保存的身分證統一編號及出生日期仍留在裝置中，但不再用於本項自動填入；可在「設定 > 文件與簽章」刪除。",
                "已下載的文件、使用者自行產生的衍生憑證與身分證卡不自動刪除，其他文件功能不受影響。",
            ),
        )
        section(
            "同意與撤回",
            p("選擇「同意並啟用」代表你了解 MyData 平台及資料提供者各自處理資料的情況，並選擇使用本 App 的整合功能；**這不取代 MyData 網頁上每一次必要的身分驗證或資料提供同意**。" +
                "你可在「設定 > 法律聲明與同意」撤回，停止本項整合後續請求；撤回前已下載的文件及第三方完成的操作不因撤回而自動失效或刪除。"),
        )
    }

    private val zkPassport = document(
        "zkpassport", "zkPassport 專門聲明", 2, "2026-11-06",
        listOf(
            "**目前提供的是「查驗他人」：** 本 App 產生 zkPassport 請求，對方以 zkPassport 相容 App 回傳零知識證明，本 App 在裝置上驗證。以本 App 回應他人請求的功能尚未提供。",
            "查驗時會連線第三方：zkPassport 傳送服務、電路下載伺服器，以及查詢以太坊註冊合約的公開節點（可在設定改為自訂節點）。它們可能看見你的 IP 位址、連線時間與部分中繼資訊。",
            "你只會得到對方證明揭露的欄位與條件結果，以及在你填寫的網域下固定的識別碼；請求中的網域由請求者自行填寫，持有者端無法確認其真實性。",
            "不同意時不使用 zkPassport 服務；電子護照的 NFC 讀取及本機驗證不受影響。",
        ),
    ) {
        section(
            "提供的功能",
            p("zkPassport 為第三方提供的電子護照零知識證明協定及相關服務。本 App 目前提供查驗端：你選擇要對方揭露的欄位（文件類型與發行國一律揭露）及年齡、國籍、發行國、綁定資料等條件，" +
                "本 App 產生請求連結與 QR Code；對方以 zkPassport 相容 App 讀取其電子護照晶片並產生證明，經傳送服務回傳，本 App 在裝置上檢查每份證明與其公開輸入。"),
            p("**尚未提供：** 以本 App 回應他人的 zkPassport 請求、雲端證明服務，以及 FaceMatch、制裁名單與加鹽唯一識別碼等條件。功能或資料流有實質變更時，會更新本聲明並再次請你選擇。"),
        )
        section(
            "第三方營運者及資料流向",
            list(
                "**傳送服務（`bridge.zkpassport.id`）：** 在你與對方之間轉送請求與證明。訊息以雙方交換的金鑰加密，但加密協定由第三方設計，本 App 無法保證其強度；服務仍可觀察 IP 位址、連線時間、" +
                "會話識別碼與傳輸大小。為讓對方 App 接受請求，本 App 連線時以你填寫的網域作為來源。",
                "**電路下載（`circuits2.zkpassport.id`）：** 下載證明版本對應的電路清單與驗證金鑰，並保存在本機快取；伺服器可能記錄你的 IP 位址、取得的版本與電路種類，並據此推知對方文件的簽章演算法。",
                "**以太坊公開節點：** 查詢 zkPassport 註冊合約，確認證明所用的憑證樹與電路清單在證明日期有效。預設使用公開節點服務（`ethereum-rpc.publicnode.com`，測試模式為 Sepolia 測試網節點），" +
                "可在設定改為自訂節點；節點營運者可能知道查詢的合約、時間與根值。",
                "**zkPassport 線上查驗 API（`verifier.zkpassport.id`，預設停用）：** 只有你在設定中啟用，且本機的 Barretenberg 驗證失敗時，才會把整份證明、請求條件與對方 App 回傳的結果送交該服務判斷；" +
                "這時結果會標示為由該服務判定。",
            ),
            p("對方 App 所連線的服務（例如其證明或下載流程）由對方的 App 決定，不在本聲明範圍內。"),
        )
        section(
            "你會得到的資料與限制",
            list(
                "**只採用證明承諾的值：** 顯示的欄位與條件來自已驗證證明的公開輸入；對方 App 另外附上的明文結果不會被採信。",
                "**識別碼：** 證明通常帶有由護照資料與網域、用途推導的未加鹽識別碼，在相同網域與用途下保持一致，可用來辨認同一份護照再次出示；它不是護照號碼，但仍屬可關聯的資訊，請妥善處理。",
                "**網域與請求者身分：** 請求中的網域由請求者自行填寫，對方 App 會顯示但無法確認；本 App 查驗時只確認證明是為該網域產生，不代表任何一方的真實身分已被確認。",
                "**信任範圍：** 驗證確認證明符合 zkPassport 註冊表中的憑證樹與電路；發行國的 CSCA 若也在本 App 的信任錨點中，會顯示較高信任。零知識證明只保證特定電路下的性質，**不等於任何身分或聲明已獲政府認可**。",
                "**測試模式：** 接受 zkPassport 測試護照的證明並使用測試網註冊表，結果會標示為測試，不應作為正式查驗。",
                "**服務可用性：** 第三方得依其規則變更或停止服務；服務或節點無法連線時，查驗會失敗而不會略過檢查。",
            ),
        )
        section(
            "非官方相容實作",
            p("本 App 與 zkPassport 及其營運者沒有合作、認證、授權、代理或背書關係。相容功能依其公開且適用授權的程式、電路與介面實作；開源授權並不當然構成第三方線上服務的使用許可或商標授權。" +
                "zkPassport 名稱僅用於識別所支援的協定或服務。"),
        )
        section(
            "不同意或撤回後",
            list(
                "本 App 不依本項整合連線 zkPassport 傳送服務、電路下載、以太坊節點或線上查驗服務，查驗分頁的 zkPassport 功能會顯示未啟用。",
                "獨立的電子護照 NFC 讀取、簽章本機驗證及文件保存不因本項不同意而停用。",
            ),
        )
        section(
            "同意與撤回",
            p("選擇「同意並啟用」代表你了解上述第三方處理資料的情況，並選擇使用本 App 的 zkPassport 查驗功能。你可在「設定 > 法律聲明與同意」撤回，停止後續請求；先前已送出的資料、" +
                "已完成的查驗或第三方紀錄不會因撤回而自動刪除。"),
        )
    }


    val statements: List<IntegrationStatement> = listOf(
        IntegrationStatement(Integration.TWDIW, "數位憑證皮夾", "數位發展部", twdiw),
        IntegrationStatement(Integration.MS_VERIFIED_ID, "Microsoft Verified ID", "Microsoft", msVerifiedId),
        IntegrationStatement(Integration.MOBILE_MOICA, "行動自然人憑證", "內政部", mobileMoica),
        IntegrationStatement(Integration.MYDATA, "MyData", "數位發展部", myData),
        IntegrationStatement(Integration.ZKPASSPORT, "zkPassport", "zkPassport", zkPassport),
    )

    val set = LegalTextSet("zh", DEVELOPER, terms, privacy, statements)
}
