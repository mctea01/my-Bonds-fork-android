package diw.wallet.app.legal

/** A block of a legal text: a paragraph or a bulleted list. */
sealed class LegalBlock {
    data class Paragraph(val text: String) : LegalBlock()
    data class Bullets(val items: List<String>) : LegalBlock()
}

class LegalSection(val heading: String, val blocks: List<LegalBlock>)

/**
 * A legal text shown in the app and published under docs/legal/[id].md. Raising [version] asks every user to read and
 * decide again on the next start; fix typos without raising it.
 */
class LegalDocument(
    val id: String,
    val title: String,
    val version: Int,
    val effectiveDate: String,
    val summary: List<String>,
    val sections: List<LegalSection>,
) {
    /** The published Markdown form (docs/legal), generated from this text so both stay the same. */
    fun toMarkdown(): String = buildString {
        append("# ").append(title).append("\n\n")
        append(LegalStrings.versionLine(version, effectiveDate)).append("\n\n")
        append("## ").append(LegalStrings.SUMMARY).append("\n\n")
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
    /**
     * Reserved for the zkPassport verification and responses (docs/design/zkpassport.md); its statement is published but
     * not asked for until the feature ships ([available]). Reading e-passports by NFC does not depend on it.
     */
    ZKPASSPORT("zkpassport", available = false),
}

/** The statement of an [integration]: [name] as the UI shows it and the statement itself. */
class IntegrationStatement(val integration: Integration, val name: String, val operator: String, val document: LegalDocument)

private class SectionsBuilder {
    val sections = ArrayList<LegalSection>()
    fun section(heading: String, vararg blocks: LegalBlock) {
        sections.add(LegalSection(heading, blocks.toList()))
    }
}

private fun p(text: String) = LegalBlock.Paragraph(text)
private fun list(vararg items: String) = LegalBlock.Bullets(items.toList())

private fun document(id: String, title: String, version: Int, date: String, summary: List<String>, build: SectionsBuilder.() -> Unit) =
    LegalDocument(id, title, version, date, summary, SectionsBuilder().apply(build).sections)

/**
 * Every legal text of the app in Traditional Chinese, kept in one place for translation. The developer and contact
 * details are those of the published app; forks that publish their own builds must replace them. No e-mail address is
 * published in the repository: private contact goes through the one on the app store listing.
 */
object LegalTexts {
    /** The developer's name in this language (LIN, CHE-CHUAN in English). */
    const val DEVELOPER = "林哲全"
    const val SOURCE_URL = "https://github.com/mctea01/my-Bonds-fork-android"
    const val ISSUES_URL = "$SOURCE_URL/issues"
    /** Where the published Markdown versions live (docs/legal on the main branch). */
    const val PUBLISHED_URL = "$SOURCE_URL/blob/main/docs/legal"

    private const val CONTACT = "一般問題請到本專案 GitHub 的 Issues（" + ISSUES_URL + "）回報。涉及個人資料或安全問題時，" +
        "請不要在公開的 Issue 張貼個人資料，改用 Google Play 商店頁面列出的開發者電子郵件私下聯絡。"
    private const val WITHDRAW = "同意表示你了解上述資料流向與風險，並要求本 App 代你與這項服務互動。同意不是使用本 App 的條件。" +
        "你可以隨時在「設定 > 法律聲明與同意」撤回，撤回後本 App 立即停止連線這項服務；撤回前已完成的互動不受影響。"
    private const val DATE = "2026-11-05"

    val terms = document(
        "terms-of-use", "用戶協議", 1, DATE,
        listOf(
            "本 App 是開放原始碼的錢包工具，不是數位發展部、內政部、Microsoft、歐盟或任何發證機關發行或背書的 App。",
            "證件與簽章的效力由發證機關與法律決定；App 顯示的信任與狀態是技術檢查的結果，不是法律保證。",
            "請保管好裝置、App PIN 與自然人憑證，出示與簽署前確認內容，只使用你本人或有權使用的證件與文件。",
            "本 App 免費並依現況提供，在法律允許的範圍內，開發者不負擔保責任。",
        ),
    ) {
        section(
            "接受本協議",
            p("DIW MY WALLET（以下稱「本 App」，包含 Android 版與電腦版）由個人開發者 $DEVELOPER（以下稱「開發者」）開發並發布。" +
                "使用本 App 前，請閱讀本協議與「隱私權政策」。你在初次啟動時選擇同意，即表示你同意本協議；不同意時請不要使用本 App。"),
            p("未成年人應由法定代理人閱讀並同意本協議後，在其協助下使用。"),
        )
        section(
            "服務內容",
            p("本 App 讓你在自己的裝置上保存與出示數位證件、查驗他人出示的證件，以及保存、檢查、加時戳與簽署電子文件。" +
                "功能依 OpenID4VCI、OpenID4VP、ISO/IEC 18013-5 與 18013-7、SD-JWT VC、W3C VC 等公開標準實作，並相容部分非標準的服務。"),
            p("開發者可能隨版本新增、修改或移除功能，不保證任何功能持續提供。"),
        )
        section(
            "與機關及廠商的關係",
            p("本 App 不是數位發展部、內政部、國家發展委員會、Microsoft、歐盟（包括 EUDI Wallet 計畫）或 Bonds 發行或背書的 App，" +
                "與它們以及任何發證端、查驗方或簽章服務沒有隸屬、合作或授權關係，也不代表它們的立場。相容功能依公開文件、開源程式與實際行為實作，對方隨時可能變更協定或拒絕非官方的錢包。"),
            p("本 App 提到的機關名稱、產品名稱與商標屬於各自的權利人，只用來說明相容的對象。"),
        )
        section(
            "開放原始碼授權",
            p("本 App 的原始碼以 Apache License 2.0 授權，你對原始碼的權利依該授權。本協議規範的是你使用開發者發布的 App 版本；" +
                "他人修改或自行建置的版本由其發布者負責。"),
        )
        section(
            "你的責任",
            list(
                "只保存與出示你本人或你有權使用的證件與文件，不得冒用他人身分，或偽造、竄改證件與文件。",
                "為裝置設定螢幕鎖定，保管好 App PIN、自然人憑證卡與其 PIN；裝置或卡片遺失時，盡快向發證機關申請停用或廢止。",
                "出示前確認查驗方的身分、用途與要交出的欄位；簽署前確認文件內容。",
                "遵守法律與第三方服務的條款，不以本 App 干擾、攻擊或未經授權存取任何系統。",
            ),
        )
        section(
            "證件、文件與簽章的效力",
            list(
                "證件的內容與效力由發證機關決定；撤銷、過期或停用的證件可能無法使用。",
                "App 顯示的信任等級（T1 到 T4）、證件狀態與簽章檢查結果，是依信任清單與公開資料所做的技術判定，" +
                    "可能因資料不完整、網路問題或第三方錯誤而不正確，不構成法律上的保證或認證。",
                "文件衍生憑證、Bonds 身分證卡等「自己製作」的證件，是你以自己的金鑰或自然人憑證所做的聲明，不是發證機關核發的證件，查驗方可自行決定是否接受。",
                "以自然人憑證或其他憑證完成的電子簽章，效力依電子簽章法與相關規定；你對自己簽署的內容負責。",
                "測試環境、測試伺服器與測試憑證的結果不具任何效力。",
            ),
        )
        section(
            "第三方服務",
            p("本 App 連線的發證端、查驗方、時戳機構、遠端簽章服務與政府網站由各自營運，使用時適用它們的條款與隱私權政策。" +
                "開發者無法控制，也不對第三方服務的可用性、內容或資料處理負責。"),
            p("數位憑證皮夾、Microsoft Entra Verified ID、行動自然人憑證與 MyData 由單一營運者集中提供，各有專門聲明；你不同意某份專門聲明時，本 App 停用該項功能，其他功能照常使用。"),
        )
        section(
            "免責與責任限制",
            p("本 App 免費提供，依「現況」及「現有」提供。在法律允許的最大範圍內，開發者不擔保本 App 沒有錯誤、不會中斷、適合特定用途，" +
                "或一定會被發證端、查驗方或其他服務接受。"),
            p("因使用或無法使用本 App 所生的損害，包括證件、金鑰或文件遺失，以及出示、查驗或簽署失敗，除開發者有故意或重大過失外，開發者不負賠償責任。" +
                "法律有強制規定者，從其規定。請自行保留重要文件的原檔，並向發證機關確認證件狀態。"),
        )
        section(
            "停止使用",
            p("你可以隨時停止使用並解除安裝本 App。為了遵守法律、處理安全問題，或你違反本協議時，開發者可以停止發布本 App 的部分或全部版本。"),
        )
        section(
            "協議變更",
            p("本協議變更時會更新版本與生效日期，並在你下次開啟 App 時請你重新閱讀與同意。歷次版本可在本專案 GitHub 的 docs/legal 查閱。"),
        )
        section(
            "準據法與管轄",
            p("本協議以中華民國法律為準據法。因本協議所生的爭議，由中華民國有管轄權的法院管轄；消費者保護法等法律另有規定者，從其規定。"),
        )
        section("聯絡方式", p(CONTACT))
    }

    val privacy = document(
        "privacy-policy", "隱私權政策", 1, DATE,
        listOf(
            "開發者沒有收集你資料的伺服器；本 App 不需要帳號，也沒有廣告、使用分析、當機回報或追蹤程式。",
            "證件、金鑰、文件與紀錄加密保存在你的裝置上，不會備份到雲端。",
            "只有在你使用某項功能，或為了確認證件與文件是否有效時，本 App 才會連線到發證端、查驗方、時戳機構與信任清單等第三方。",
            "數位憑證皮夾、Microsoft Verified ID、行動自然人憑證與 MyData 由中央營運者提供，另有專門聲明，你可以不同意並停用。",
        ),
    ) {
        section(
            "適用範圍",
            p("本政策說明 DIW MY WALLET（以下稱「本 App」，包含 Android 版與電腦版）如何處理你的個人資料。本 App 由個人開發者 $DEVELOPER（以下稱「開發者」）" +
                "開發，並以 Apache License 2.0 開放原始碼發布，所有處理方式都可以在原始碼中查證。本政策依中華民國個人資料保護法的告知事項撰寫，並參考歐盟一般資料保護規則（GDPR）的原則。"),
            p("本 App 連線的發證端、查驗方與其他服務是獨立的第三方，它們如何處理你的資料，依各自的隱私權政策與相關法令，不在本政策範圍內。"),
        )
        section(
            "開發者不收集的資料",
            p("開發者沒有接收本 App 資料的伺服器。本 App 不需要註冊帳號，不含廣告、使用分析、當機回報或其他追蹤程式，" +
                "也不會把你的證件、文件、出示紀錄、裝置識別碼或使用情形傳給開發者。"),
            p("你主動在 GitHub 回報問題或寄信給開發者時，開發者只會看到你自己提供的內容，並只用於回覆與修正問題。"),
            p("不過，你使用功能時，本 App 會依你的指示把資料傳給第三方（見第 4 節）。依應用程式商店（例如 Google Play 資料安全）的定義，這屬於 App 傳送到裝置外的資料，" +
                "可能包括姓名、電子郵件、身分證統一編號等證件號碼、地址、其他證件欄位、相片與檔案。這些資料由接收的發證端、查驗方或服務保存；" +
                "你出示給查驗方的資料，由查驗方依其政策保存。出示是你在同意畫面發起與確認的傳送，開發者不會取得或保存任何一份。"),
        )
        section(
            "保存在你裝置上的資料",
            list(
                "證件：你領取的數位證件、其中的個人資料欄位、卡面圖片與狀態查詢結果。",
                "金鑰：證件與錢包使用的私鑰，優先存放在裝置的硬體安全區（Android Keystore 或 StrongBox）；裝置不支援時使用以 App PIN 保護的軟體金鑰。",
                "文件：你匯入或下載的檔案、簽章檢查結果、時戳、撤銷資訊與衍生憑證。",
                "紀錄：你與誰互動、時間、使用的證件與欄位名稱；不記錄欄位的值。",
                "設定：包括你選擇保存的 MyData 身分證統一編號與出生日期，只用於填入 MyData 登入頁與開啟 MyData 的 PDF。",
                "快取：信任清單快照、欄位名稱翻譯與發行端資訊。",
                "同意紀錄：你同意本政策、用戶協議與各專門聲明的版本與時間。",
            ),
            p("這些資料以裝置金鑰（Android）或你的 App PIN（電腦版）加密，保存在 App 的私有空間。Android 版關閉了系統備份，不會上傳到雲端備份。" +
                "你可以在 App 內移除證件、文件與紀錄；解除安裝 App（電腦版另刪除 App 的資料資料夾）會刪除全部資料，刪除後無法復原。"),
        )
        section(
            "會傳送到裝置以外的資料",
            p("以下傳送只會在你使用某項功能時，或為了確認證件與文件是否有效時發生。每次連線，對方都會得知你的 IP 位址與連線時間。"),
            list(
                "領取證件：向發證端送出授權資料、持有者公鑰、金鑰證明，以及你在發證端頁面輸入或同意的資料。",
                "出示證件：只把你在同意畫面選擇的欄位與出示證明送給查驗方；面對面出示時，經 NFC、藍牙或 QR Code 直接傳給對方的裝置。",
                "狀態與信任查詢：讀取發證端公布的狀態清單、DID 文件、發行端資訊、OCSP、CRL 與憑證，下載 Adobe AATL、歐盟 EUTL、mdoc 簽署清單與測試用的信任錨點。" +
                    "這些服務可能由此得知你持有哪個發證端的證件。你可以在設定關閉自動更新狀態與部分信任清單。",
                "時戳：只把檔案的 SHA-256 雜湊值送給你選擇的時戳機構（預設 DigiCert），不送出檔案內容。",
                "簽署：自然人憑證卡在裝置上完成簽章；遠端簽章服務（CSC）會收到待簽資料的雜湊值與你在該服務的登入資訊。",
                "OpenCerts 線上查驗：向公開的以太坊節點與 DNS 查詢服務（例如 PublicNode、Cloudflare、Google）查詢證書的發證紀錄。",
                "did:ion 解析：遇到 did:ion 時，向 Microsoft 的 DID 解析服務查詢 DID 文件。",
                "文件來源網站：在 App 內開啟的機關網站，由該機關處理你在網頁上輸入的資料；本 App 只保存你下載的檔案。",
                "零知識證明：證明在裝置上產生；需要連線的證明（例如 zkTLS）會依查驗方的設定連線到目標網站與公證或中繼服務，查驗方只會收到證明與你同意揭露的內容。",
            ),
        )
        section(
            "傳輸安全",
            p("與發證端、查驗方及大多數服務的連線使用 HTTPS 加密。但以下傳送沒有經過傳輸層加密，請留意：時戳、OCSP、CRL 與憑證下載依各機構公布的 http 位址連線（內容本身有簽章，可防竄改，但看得到傳送了什麼）；" +
                "與 Bonds 相容的藍牙與區域網路離線出示沒有連線加密，附近的人可能截收你出示的欄位；測試環境可允許本機與區域網路的 http。" +
                "ISO/IEC 18013-5 的 NFC 與藍牙出示依標準加密。"),
        )
        section(
            "中央營運服務的專門聲明",
            p("數位憑證皮夾（TWDIW）、Microsoft Entra Verified ID、行動自然人憑證與 MyData 由單一營運者集中提供，使用時資料會經過該營運者。" +
                "這些功能各有專門聲明，你同意後才會啟用；不同意時，本 App 不會連線到該服務，其他功能照常使用。之後加入的同類服務（例如 zkPassport）也一樣。" +
                "你可以隨時在「設定 > 法律聲明與同意」變更。"),
        )
        section(
            "裝置權限",
            list(
                "相機：掃描 QR Code。",
                "NFC：讀取自然人憑證卡，以及感應出示與查驗。",
                "藍牙（Android 11 以下另需位置權限）：與 Bonds 等錢包離線出示與查驗。本 App 不讀取你的位置。",
                "生物辨識：使用金鑰前確認是你本人。",
                "USB：連接晶片讀卡機。",
                "網路：上一節列出的連線。",
            ),
            p("權限只在使用對應功能時要求；拒絕某項權限只會讓該功能無法使用。"),
        )
        section(
            "系統服務",
            p("Android 版透過 Google Play 服務的 Credential Manager，向系統登錄可出示的證件（證件名稱、圖片與用於選擇器顯示的欄位），" +
                "讓網頁或其他 App 以 Digital Credentials API 要求證件時，系統選擇器能列出本 App。這些資料由 Android 與 Google Play 服務在裝置上處理，適用 Google 的隱私權政策。"),
        )
        section(
            "個人資料保護法告知事項",
            list(
                "蒐集目的：提供你使用的數位證件保存、出示與查驗，以及文件保存、檢查與簽署等功能；處理都在你的裝置上進行。",
                "個人資料類別：依你保存的證件與文件而定，可能包括識別類（姓名、身分證統一編號、照片）、特徵類（出生日期、性別）、家庭情形（戶籍資料）、" +
                    "社會情況（學歷、勞健保）與財務情形（所得資料）等。",
                "利用期間：保存到你移除該資料或解除安裝本 App 為止。",
                "利用地區：你的裝置；傳送給第三方時，依該第三方所在地。",
                "利用對象：你選擇互動的發證端、查驗方與服務。",
                "你的權利：資料在你的裝置上，你可以直接查閱、匯出、補充與刪除。對第三方持有的資料，請向該第三方行使個人資料保護法第 3 條的權利。",
                "不提供的影響：不提供某項資料，只會讓需要它的功能無法使用。",
            ),
        )
        section(
            "兒童",
            p("本 App 不以 13 歲以下兒童為對象。未成年人使用證件時，請在法定代理人的同意與協助下使用。"),
        )
        section(
            "安全",
            p("本 App 採用加密儲存、硬體金鑰、出示前同意與信任判定等措施，但沒有任何系統能保證絕對安全。請為裝置設定螢幕鎖定，保管好 App PIN 與自然人憑證 PIN，" +
                "並只從 Google Play 或本專案的 GitHub 安裝本 App。發現安全問題時，請以電子郵件私下通知開發者。"),
        )
        section(
            "政策變更",
            p("本政策變更時會更新版本與生效日期，並在你下次開啟 App 時請你重新閱讀與同意。歷次版本可在本專案 GitHub 的 docs/legal 查閱。"),
        )
        section("聯絡方式", p(CONTACT))
    }

    private val twdiw = document(
        "twdiw", "數位憑證皮夾（TWDIW）專門聲明", 1, DATE,
        listOf(
            "數位憑證皮夾由數位發展部集中營運：信任清單、卡片目錄、發行端與查驗方都登錄在它的平台上。",
            "本 App 不是官方的「數位憑證皮夾」App；為了相容，連線時使用官方皮夾的識別碼 moda_dw，平台可能隨時拒絕。",
            "所有數位憑證皮夾卡片共用一把持有者金鑰，不同查驗方可能比對它，把你的出示串連起來。",
            "不同意時，本 App 不連線 wallet.gov.tw 與相關的區塊鏈節點；已保存的卡片保留，但不能領卡、出示給平台的查驗方或查詢狀態。",
        ),
    ) {
        section(
            "這項功能是什麼",
            p("數位憑證皮夾（Taiwan Digital Identity Wallet，TWDIW）是數位發展部建置的數位憑證平台。同意後，本 App 可以：瀏覽平台的卡片目錄並前往申請、" +
                "領取平台發行端的卡片、出示給平台登錄的查驗方（包括靜態 QR Code 與自訂欄位）、使用臨櫃服務（例如超商取貨）的條碼，並以平台的信任清單判定發行端與查驗方。"),
        )
        section(
            "營運者與資料流向",
            p("平台由數位發展部營運，卡片由各發行機關核發，查驗由各查驗方進行。使用這項功能時："),
            list(
                "領卡時，本 App 向 wallet.gov.tw 的發行端送出持有者 DID、公鑰與簽章證明，以及發行端要求的識別碼；你在發行端網頁輸入的資料由該機關處理。",
                "出示時，你選擇的欄位、持有者 DID 與出示證明會送到查驗方在平台登錄的位址；靜態 QR Code 的自訂欄位會連同你填寫的內容一起送出。",
                "臨櫃服務會把你的出示交給服務方的系統，再向平台取得取貨條碼。",
                "本 App 下載平台的信任清單（正式環境與官方測試環境），並向 Arbitrum One 的公開節點（arb1.arbitrum.io）查詢各組織的鏈上註冊；" +
                    "持有卡片時，每 12 小時重新查驗發行端，並定期查詢卡片狀態。",
                "這些連線都會讓平台、發行端、查驗方或節點營運者得知你的 IP 位址、時間，以及你與哪些機關互動。",
            ),
        )
        section(
            "中央化的風險",
            list(
                "平台決定哪些發行端與查驗方可信，也可以停用、撤銷或更改卡片；平台停止服務時，卡片可能無法再出示或查證。",
                "所有數位憑證皮夾卡片使用同一把持有者金鑰（與官方 App 相同），查驗方之間可能比對持有者 DID，把你在不同地方的出示串連起來。",
                "平台、發行端與查驗方可能記錄領卡與出示的時間與對象。",
            ),
        )
        section(
            "非官方的相容實作",
            p("本 App 不是數位發展部發布的「數位憑證皮夾」App，與數位發展部沒有合作或授權關係。數位憑證皮夾的部分流程與公開標準不同，" +
                "本 App 依官方開源程式與實際行為相容實作，連線時使用官方皮夾的識別碼 moda_dw 與相容的 User-Agent（可在「設定 > 互通」修改）。" +
                "這只是為了讓平台接受相容的流程，不代表本 App 是官方 App 或經過認可。平台變更或拒絕非官方錢包時，相關功能可能失效，開發者無法保證可用。"),
        )
        section(
            "不同意時",
            list(
                "本 App 不連線 wallet.gov.tw 與 Arbitrum 節點，也不使用數位憑證皮夾的信任清單判定任何 DID。",
                "不顯示卡片目錄與臨櫃服務；掃描或開啟數位憑證皮夾的 QR Code 與連結時，會提示這項功能已停用。",
                "已保存的卡片保留在裝置上，但不能出示給網址在 wallet.gov.tw 的查驗方，也不會自動查詢狀態；發行端的信任等級維持最後一次的結果。",
                "標準協議（OpenID4VCI、OpenID4VP、ISO/IEC 18013-5 等）與其他功能不受影響。",
            ),
        )
        section("同意的意思", p(WITHDRAW))
    }

    private val msVerifiedId = document(
        "microsoft-verified-id", "Microsoft Entra Verified ID 專門聲明", 1, DATE,
        listOf(
            "Verified ID 的領卡與出示經由 Microsoft 的雲端服務進行，Microsoft 與使用它的組織都會收到你的請求。",
            "本 App 依 Microsoft 公開的協定與開源程式相容實作，不是 Microsoft Authenticator，與 Microsoft 沒有合作關係。",
            "Verified ID 卡片共用一把持有者金鑰，不同查驗方可能比對它，把你的出示串連起來。",
            "不同意時，本 App 不處理 Verified ID 的領卡與出示請求；已保存的卡片保留。",
        ),
    ) {
        section(
            "這項功能是什麼",
            p("Microsoft Entra Verified ID 是 Microsoft 提供給組織的可驗證憑證服務。同意後，本 App 可以用 openid-vc 連結或 QR Code 領取組織發行的卡片" +
                "（包括登入組織帳號、填寫自述欄位與出示其他卡片），並出示給使用 Verified ID 的查驗方。"),
        )
        section(
            "營運者與資料流向",
            list(
                "領卡與出示的請求與回應經由 Microsoft 營運的 Verified ID 服務傳送，再交給發行或查驗的組織。",
                "領卡時送出持有者 DID 與公鑰、你登入組織帳號取得的權杖、你填寫的欄位，以及你選擇出示的其他卡片。",
                "出示時送出你選擇的卡片與欄位、持有者 DID 與簽章。",
                "本 App 會讀取組織網域上的 DID 設定（Linked Domains）確認組織身分，並以 Microsoft 的 DID 解析服務（discover.did.msidentity.com）解析 did:ion。",
                "Microsoft 依其隱私權聲明處理這些資料，組織依其政策處理。",
            ),
        )
        section(
            "中央化的風險",
            list(
                "Microsoft 可以看到哪個組織在何時向你發卡或查驗；服務變更或停止時，卡片可能無法再出示或驗證。",
                "組織可以撤銷卡片，撤銷狀態由 Microsoft 的服務提供。",
                "Verified ID 卡片使用同一把持有者金鑰，查驗方之間可能比對持有者 DID，把你在不同地方的出示串連起來。",
            ),
        )
        section(
            "非官方的相容實作",
            p("本 App 不是 Microsoft Authenticator，與 Microsoft 沒有合作、認證或授權關係；Microsoft、Entra 與 Verified ID 是 Microsoft 的商標。" +
                "相容功能依 Microsoft 的公開文件與開源錢包程式庫實作，Microsoft 變更協定時可能失效。"),
        )
        section(
            "不同意時",
            list(
                "openid-vc 連結與 QR Code 會提示這項功能已停用，本 App 不連線 Microsoft 的 Verified ID 服務。",
                "不處理 Verified ID 形式的出示請求；標準的 OpenID4VP 請求與其他功能不受影響。",
                "已保存的卡片保留在裝置上，但不會自動查詢狀態。",
            ),
        )
        section("同意的意思", p(WITHDRAW))
    }

    private val mobileMoica = document(
        "mobile-moica", "行動自然人憑證專門聲明", 1, DATE,
        listOf(
            "行動自然人憑證由內政部集中營運，簽章請求經由內政部的服務送到你的行動自然人憑證 App 確認。",
            "本 App 會以本 App 的服務提供者（SP）帳號，把你的身分證統一編號與待簽資料送給內政部，不送出文件內容。",
            "本 App 不是內政部的 App；簽章功能需要內政部核發的 SP 授權，可能隨時停止。",
            "不同意時，簽署畫面不提供行動自然人憑證；自然人憑證卡等其他簽署方式不受影響。",
        ),
    ) {
        section(
            "這項功能是什麼",
            p("簽署文件時可以選擇「行動自然人憑證」：本 App 透過內政部的行動自然人憑證服務送出簽章請求，你在官方的行動自然人憑證 App 確認後，簽章值回到本 App 寫入文件。"),
        )
        section(
            "營運者與資料流向",
            list(
                "本 App 向內政部的服務（fidoapi.moi.gov.tw；測試環境為 fido-test.moi.gov.tw）送出你的身分證統一編號、待簽資料（文件摘要與簽署屬性）與本 App 的 SP 識別碼，不送出文件內容。",
                "內政部把簽章請求推送到你的行動自然人憑證 App，並把你的憑證與簽章值傳回本 App。",
                "內政部依其規定記錄簽章請求的時間、SP 與結果。",
            ),
        )
        section(
            "中央化的風險",
            list(
                "內政部可以看到你在何時透過哪個 SP 簽章。",
                "服務、SP 授權或內政部的規定變更時，這項功能可能無法使用。",
                "SP 帳號由建置時內建；開發者測試時可在開發者設定自行輸入，只保存在記憶體。",
            ),
        )
        section(
            "非官方的相容實作",
            p("本 App 與內政部沒有隸屬關係，SP 帳號的使用依內政部的規定。簽章的效力依你的憑證與電子簽章法等規定。"),
        )
        section(
            "不同意時",
            list(
                "簽署畫面的「行動自然人憑證」顯示為停用，本 App 不連線內政部的行動自然人憑證服務。",
                "網站在登入時自行轉到行動自然人憑證 App 的流程，屬於該網站的功能，不受這項設定影響。",
                "自然人憑證卡、憑證檔、遠端簽章等其他簽署方式不受影響。",
            ),
        )
        section("同意的意思", p(WITHDRAW))
    }

    private val myData = document(
        "mydata", "MyData 專門聲明", 1, DATE,
        listOf(
            "MyData（個人化資料自主運用平台）由國家發展委員會營運，資料由各機關提供；你在 App 內開啟的是 MyData 自己的網頁。",
            "本 App 會自動解開 MyData 下載的 ZIP、保存其中的文件，並可使用你保存的身分證統一編號填入登入頁與開啟 PDF。",
            "MyData 與資料提供機關會依其規定記錄你申請的資料與時間。",
            "不同意時，「取得文件」不提供 MyData 項目；已保存的文件不受影響。",
        ),
    ) {
        section(
            "這項功能是什麼",
            p("同意後，可以在「文件 > 從網站取得」開啟 MyData 的項目，在 App 內登入並下載你的戶籍、所得、勞保、健保等資料，以及製作 Bonds 身分證卡用的國民身分證資料。"),
        )
        section(
            "營運者與資料流向",
            list(
                "你在 App 內的瀏覽器登入 MyData，驗證方式（自然人憑證、行動自然人憑證等）與同意事項都在 MyData 的網頁完成，MyData 與資料提供機關依其隱私權政策處理。",
                "你選擇保存身分證統一編號與出生日期時，本 App 只把它們填入 MyData 自己的登入頁，不會送到其他網站。",
                "下載的 ZIP 在裝置上解開後刪除，其中的 PDF 保存到「文件」，並以身分證統一編號開啟。",
            ),
        )
        section(
            "中央化的風險",
            list(
                "MyData 會記錄你申請了哪些資料與時間。",
                "網站改版時，自動下載與解析可能失效；文件內容以機關提供的原檔為準。",
            ),
        )
        section(
            "非官方的相容實作",
            p("本 App 與國家發展委員會及資料提供機關沒有合作關係；自動填入與下載依 MyData 的公開網頁實作。"),
        )
        section(
            "不同意時",
            list(
                "「取得文件」的 MyData 項目與從 MyData 製作身分證卡顯示為停用，本 App 不開啟 MyData 的網頁。",
                "已保存的 MyData 自動填入資料不會被使用，可以在「設定 > 文件與簽章」移除。",
                "已保存的文件、衍生憑證與身分證卡不受影響。",
            ),
        )
        section("同意的意思", p(WITHDRAW))
    }

    private val zkPassport = document(
        "zkpassport", "zkPassport 專門聲明", 1, DATE,
        listOf(
            "zkPassport 是第三方營運的電子護照零知識證明服務，不是本專案的服務；請求的傳送、電路與憑證資料都由它的伺服器提供。",
            "營運者看得到你的 IP 位址、連線時間與下載的電路，可由此推得你的證件國家；證明內容經過加密，傳送服務看不到。",
            "本 App 無法提供 FaceMatch 與加鹽的唯一識別碼；未加鹽的唯一識別碼對同一服務固定，發證國也能推算。",
            "不同意時，本 App 不連線 zkPassport 的服務；以 NFC 讀取電子護照與本機驗證不受影響。",
        ),
    ) {
        section(
            "這項功能是什麼",
            p("zkPassport 讓你用電子護照晶片的資料產生零知識證明，只證明年齡、國籍等條件，不交出護照內容。同意後，本 App 可以產生 zkPassport 請求查驗他人，" +
                "也可以用本 App 以 NFC 讀到的護照資料回應網站或 App 的 zkPassport 請求。"),
        )
        section(
            "營運者與資料流向",
            list(
                "傳送服務（bridge.zkpassport.id）：請求與證明經由它在雙方之間轉送；它看得到 IP 位址、時間、連線識別碼與資料大小，看不到加密的證明內容。",
                "電路、憑證包與制裁清單的下載服務：會得知你的 IP 位址與下載了哪些電路與憑證樹，可由此推得證件的國家與簽章演算法。",
                "以太坊節點：本 App 讀取 zkPassport 的鏈上註冊表確認憑證樹與電路，節點提供者看得到查詢的合約。",
                "查驗 API：只有在你啟用、而且本機驗證失敗時才會把整份證明與查詢結果送給 zkPassport 查驗，預設關閉。",
                "雲端證明器：只有在你同意對方要求的壓縮證明時才會把子證明（不是護照原始資料）交給 zkPassport 產生，預設不使用。",
                "zkPassport 依其服務條款與隱私權政策處理這些資料。",
            ),
        )
        section(
            "限制與風險",
            list(
                "FaceMatch 證明只接受 zkPassport 官方 App 產生，本 App 無法提供；需要 FaceMatch 或加鹽唯一識別碼的請求，只能改用官方 App 回應。",
                "未加鹽的唯一識別碼由護照資料、網域與用途計算，對同一服務固定、不同服務不同；但完整知道晶片資料的人（例如發證國）也能算出它。",
                "請求中的網域由建立請求的人填寫，本 App 會比對傳送服務回報的來源，不一致時會強烈提示；仍請確認你要回應的對象。",
                "zkPassport 的服務條款允許營運方隨時變更或停止服務；服務變更時相關功能可能失效。",
            ),
        )
        section(
            "非官方的相容實作",
            p("本 App 與 zkPassport 沒有合作或授權關係，依 zkPassport 以 Apache-2.0 公開的電路與程式相容實作。"),
        )
        section(
            "不同意時",
            list(
                "本 App 不連線 zkPassport 的傳送、下載、查驗與證明服務，zkPassport 的請求會提示這項功能已停用。",
                "以 NFC 讀取電子護照、本機驗證護照簽章與保存護照文件不依賴 zkPassport，不受影響。",
            ),
        )
        section("同意的意思", p(WITHDRAW))
    }

    val statements: List<IntegrationStatement> = listOf(
        IntegrationStatement(Integration.TWDIW, "數位憑證皮夾", "數位發展部", twdiw),
        IntegrationStatement(Integration.MS_VERIFIED_ID, "Microsoft Verified ID", "Microsoft", msVerifiedId),
        IntegrationStatement(Integration.MOBILE_MOICA, "行動自然人憑證", "內政部", mobileMoica),
        IntegrationStatement(Integration.MYDATA, "MyData", "國家發展委員會", myData),
        IntegrationStatement(Integration.ZKPASSPORT, "zkPassport", "zkPassport", zkPassport),
    )

    fun statement(integration: Integration): IntegrationStatement = statements.first { it.integration == integration }

    /** Every published text: the terms, the privacy policy and the statements. */
    val all: List<LegalDocument> get() = listOf(terms, privacy) + statements.map { it.document }

    fun byId(id: String): LegalDocument? = all.firstOrNull { it.id == id }
}
