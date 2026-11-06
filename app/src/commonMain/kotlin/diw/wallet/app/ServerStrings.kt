package diw.wallet.app

/**
 * Every user-facing text of the production server settings, its sharing and the choice between two parties' servers,
 * kept in one place for translation.
 */
object ServerStrings {
    const val POLICY_TITLE = "雙方都有服務端時"
    const val POLICY_PREFER_OWN = "優先用自己的服務端"
    const val POLICY_PREFER_OWN_DETAIL = "對方也列出你的服務端時走你的；否則用對方的。"
    const val POLICY_PREFER_PEER = "優先用對方的服務端"
    const val POLICY_PREFER_PEER_DETAIL = "對方的服務端連不上時，才改用你的。"
    const val POLICY_OWN_ONLY = "只用自己的服務端"
    const val POLICY_OWN_ONLY_DETAIL = "不經對方的服務端；對方沒有列出你的服務端時，請對方掃描你的服務端 QR Code。"
    const val POLICY_NOTE = "網站查驗與年齡查驗都只需要一方有服務端。網站查驗時兩方的服務端不同，查驗方會在兩台的中繼都開好房間，" +
        "出示方依上面的選擇挑一台；中繼只轉送加密資料，看不到查驗內容。年齡查驗的證明送到查驗方 QR Code 指定的服務端，由查驗方依自己的選擇挑選。"

    const val SHARE = "分享設定"
    const val SHARE_TITLE = "分享服務端設定"
    const val SHARE_INCLUDE_TOKEN = "包含存取權杖（只分享給可以使用你的服務端的人）"
    const val SHARE_NOTE = "對方用本錢包掃描，或貼上下方連結匯入。指紋隨設定一起分享，對方匯入時會和服務端實際的根憑證比對。"
    const val SHARE_PEER_NOTE = "請查驗方在等待畫面點「使用對方的服務端」，再掃描這個 QR Code。不含存取權杖。"
    const val SHARE_NOTHING = "尚未設定服務端，沒有可分享的內容"
    const val SHOW_MY_SERVER = "顯示我的服務端 QR Code"
    const val COPY_LINK = "複製連結"
    const val LINK_COPIED = "已複製服務端連結"
    const val CLOSE = "關閉"

    const val IMPORT = "匯入分享的設定"
    const val IMPORT_FIELD = "貼上 diw-server:// 連結"
    const val IMPORT_TITLE = "使用分享的服務端？"
    const val IMPORT_AS_MINE = "設為我的服務端"
    const val IMPORT_FOR_SESSION = "只用在這次查驗"
    const val IMPORT_CANCEL = "取消"
    const val IMPORT_TOKEN = "含存取權杖，匯入後會一併儲存。"
    const val IMPORT_REPLACES = "會取代目前的服務端："
    const val IMPORT_TRUST_NOTE = "設為你的服務端後，錢包會讀取服務端的根憑證；與分享的指紋相符時才會詢問是否信任。"

    const val USE_PEER = "使用對方的服務端"
    const val USE_PEER_NOTE = "兩支手機不在同一個網路、這支手機又沒有可用的服務端時，請出示方在網站查驗的同意畫面按「顯示我的服務端 QR Code」，" +
        "或在設定的「零知識證明」頁按「分享設定」，再由這裡掃描。"
    const val SCAN_PEER = "掃描對方的服務端 QR Code"

    const val FEDERATION_CONFIRMED = "信任聯盟確認："
    const val SETTINGS_DIGEST = "設定摘要："

    fun policyName(policy: ServerPolicy): String = when (policy) {
        ServerPolicy.PREFER_OWN -> POLICY_PREFER_OWN
        ServerPolicy.PREFER_PEER -> POLICY_PREFER_PEER
        ServerPolicy.OWN_ONLY -> POLICY_OWN_ONLY
    }

    fun policyDetail(policy: ServerPolicy): String = when (policy) {
        ServerPolicy.PREFER_OWN -> POLICY_PREFER_OWN_DETAIL
        ServerPolicy.PREFER_PEER -> POLICY_PREFER_PEER_DETAIL
        ServerPolicy.OWN_ONLY -> POLICY_OWN_ONLY_DETAIL
    }

    fun peerInUse(host: String) = "這次查驗使用對方的服務端 $host（只轉送，不加入信任）"
    fun peerForSession(host: String) = "已改用對方的服務端 $host，請出示方重新掃描新的 QR Code"
    fun shareFingerprintMismatch(host: String) = "$host 的簽章根憑證和分享的指紋不同，沒有加入信任。請向分享的人或業者確認。"
    fun shareFingerprintMatches() = "與分享的指紋相符。"
    fun federationVerified(anchor: String) = "由信任聯盟「$anchor」確認這台服務端的根憑證與網頁查驗端，不必再逐字比對指紋。"
    fun federationMismatch(anchor: String) = "信任聯盟「$anchor」登錄的根憑證或網頁查驗端與服務端回報的不同，請勿信任，並向業者確認。"
    fun ownOnlyNoRoute(host: String?) = if (host == null) {
        "你選了只用自己的服務端，但尚未設定服務端。請在設定的「零知識證明」頁填入，或改用其他選項。"
    } else {
        "你選了只用自己的服務端，但查驗方沒有列出 $host。請按「顯示我的服務端 QR Code」讓查驗方掃描，或改用其他選項。"
    }
    fun noPeerRelay(own: String?) = if (own == null) {
        "查驗方沒有提供中繼，兩支手機也不在同一個網路。若你有服務端，請按「顯示我的服務端 QR Code」讓查驗方掃描；或讓兩支手機連同一個 Wi-Fi。"
    } else {
        "查驗方沒有提供中繼，兩支手機也不在同一個網路。請按「顯示我的服務端 QR Code」讓查驗方掃描，改經你的服務端 $own 連線。"
    }
    const val AGE_NO_HOST = "沒有年齡查驗主機：請在設定的「零知識證明」頁填入服務端、掃描對方分享的服務端，或改用「附近」查驗。"
}

/** How two wallets with different production servers settle on one for a check between them. */
enum class ServerPolicy(val id: String) {
    PREFER_OWN("prefer_own"),
    PREFER_PEER("prefer_peer"),
    OWN_ONLY("own_only");

    companion object {
        fun of(id: String): ServerPolicy = entries.firstOrNull { it.id == id } ?: PREFER_OWN
    }
}
