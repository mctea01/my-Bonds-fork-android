package diw.wallet.app.legal

/** Interface strings of the first-start pages and the legal settings, kept together for translation. */
object LegalStrings {
    const val SUMMARY = "重點摘要"
    const val FULL_TEXT = "全文"
    const val OPEN_ONLINE = "在瀏覽器開啟網頁版"

    fun versionLine(version: Int, date: String) = "版本 $version・生效日期 $date"

    // Welcome
    const val WELCOME_TITLE = "歡迎使用 DIW MY WALLET"
    const val WELCOME_TEXT = "保存與出示數位證件、查驗他人證件，以及保存、檢查與簽署電子文件。本 App 預定提供年滿 18 歲者使用；開始前請閱讀以下說明。"
    val WELCOME_POINTS = listOf(
        "資料以本機保存為主" to "證件、金鑰與文件在裝置上受保護；使用領取、出示、簽署及查詢等功能時，必要資訊仍可能傳給第三方，開發者目前沒有預設接收錢包資料的伺服器。",
        "出示前確認資料" to "本 App 會依支援協定顯示查驗方及要揭露的欄位；請確認內容後再送出。必要的協定識別與驗證資訊也可能同時傳送。",
        "標準優先、整合可選" to "主要依公開標準運作；TWDIW、Verified ID、行動自然人憑證及 MyData 等專門整合須另行選擇啟用。",
    )
    const val WELCOME_START = "開始"

    // Terms and privacy
    const val BASICS_TITLE = "用戶協議與隱私權政策"
    const val BASICS_TEXT = "請閱讀並確認以下兩份文件。分別同意用戶協議及隱私權政策後，才能使用本 App。"
    const val BASICS_UPDATED = "用戶協議或隱私權政策已更新，請閱讀變更後的文件並再次確認。"
    const val AGREE_TERMS = "我已閱讀並同意「用戶協議」"
    const val AGREE_PRIVACY = "我已閱讀並同意「隱私權政策」"
    const val AGREE_CONTINUE = "同意並繼續"
    const val DISAGREE = "不同意"
    const val DISAGREE_TITLE = "需要完成確認才能使用"
    const val DISAGREE_TEXT = "未同意用戶協議或隱私權政策，將無法繼續使用本 App。你可以關閉 App；如曾使用本 App，裝置內可能已有保存的資料，請依隱私權政策說明刪除或移除。"
    const val BACK_TO_READING = "回到文件"

    // Statements
    const val STATEMENTS_TITLE = "專門聲明"
    const val STATEMENTS_INTRO = "以下整合功能會連線到各自的服務營運者。請逐項選擇是否啟用；不同意只停用該項整合，其他功能照常使用。日後可在設定中變更。"
    const val STATEMENTS_UPDATED = "此項專門聲明已更新，請閱讀並再次選擇是否啟用。"
    fun statementProgress(index: Int, total: Int) = "專門聲明 $index / $total"
    fun operatorLine(operator: String) = "營運者：$operator"
    const val ACCEPT_ENABLE = "同意並啟用"
    const val DECLINE_DISABLE = "不同意，停用這項功能"

    // Done
    const val DONE_TITLE = "設定完成"
    const val DONE_TEXT = "你可以在「設定 > 法律聲明與同意」重新閱讀文件或調整專門服務的啟用選擇。撤回不會自動刪除已傳給第三方的資料。"
    const val DONE_START = "開始使用"

    // Settings
    const val SETTINGS_SECTION = "法律聲明與同意"
    const val SETTINGS_BASICS = "用戶協議與隱私權政策"
    const val SETTINGS_STATEMENTS_TEXT = "各項整合功能須先同意專門聲明才會啟用。撤回後停止依該整合發起後續服務請求，已保存的證件與文件原則上保留；先前傳出的資料不會自動刪除。"
    const val SETTINGS_ONLINE = "公開網頁版"
    fun acceptedLine(version: Int, date: String) = "版本 $version・$date 同意"
    fun settingsSummary(enabled: Int, total: Int) = "已同意用戶協議與隱私權政策・專門聲明啟用 $enabled / $total"

    // Statement page and status
    fun enabledLine(version: Int, date: String) = "已同意，啟用中（版本 $version，$date）"
    const val DISABLED_LINE = "未同意，已停用"
    const val PENDING_LINE = "尚未決定，已停用"
    const val WITHDRAW = "撤回同意並停用"
    const val WITHDRAW_TITLE = "確定撤回同意？"
    fun withdrawText(name: String) =
        "撤回後，本 App 將停止依「$name」整合發起後續服務請求，相關功能會停用；已保存的證件與文件原則上保留。撤回前已送出或完成的互動，以及第三方已取得的資料，不會自動取消或刪除。之後可再次同意。"
    const val CANCEL = "取消"
    fun pendingLink(name: String) = "此連結需要先啟用「$name」。請先閱讀專門聲明並決定是否同意；同意後才會繼續開啟連結。"

    /** Shown where a feature of a switched-off service would be. */
    fun disabledRow(name: String) = "「$name」尚未啟用：你未同意其專門聲明。點選以檢視。"
    /** Message for a link, request or action that needs a switched-off service. */
    fun disabledMessage(name: String) = "「$name」未啟用。你可在「設定 > 法律聲明與同意」檢視並決定是否同意。"

    // Integrations that are not offered (yet) and service notes
    /** A reserved statement whose feature has not shipped; shown read-only in the legal settings. */
    fun notAvailableLine(name: String) = "「$name」整合功能尚未上線，目前無法啟用。點選可預覽聲明。"
    /** The signing screen when no SP account of the mobile citizen certificate is available, even with the statement accepted. */
    const val MOICA_SP_NOT_CONFIGURED = "目前沒有可用的行動自然人憑證服務提供者（SP）。本專案開發者未提供內建 SP；如需使用，須自行設定依法獲授權的服務端或 SP 來源。"
    /** The developer setting: what the built-in SP option of the source code is for. */
    const val MOICA_SP_FORK_ONLY = "內建 SP 為原始碼預留機制；只有衍生版本發布者依法取得授權並完成實際配置後，才能使用。"
    /** The holder picked the test environment of the mobile citizen certificate. */
    const val MOICA_SP_ENV_TEST = "你目前選擇測試環境；測試憑證不得作為正式簽署結果。"
    /** Bonds offline presentation: QR frames and the BLE link carry no session encryption. */
    const val BONDS_UNENCRYPTED_WARNING = "此離線傳輸不提供連線層加密，附近或同網路的人可能截取你出示的資料。請確認是否繼續。"
    const val BONDS_LINK_TITLE = "以藍牙傳送？"
    const val BONDS_LINK_SEND = "仍要傳送"

    /** Before the first request to the TWDIW platform after the statement was accepted. */
    const val TWDIW_COMPATIBILITY_TITLE = "非官方相容流程"
    const val TWDIW_COMPATIBILITY_WARNING = "此功能使用非官方相容流程，可能以官方皮夾識別資訊連線；本 App 並非官方皮夾，平台可能拒絕。請先閱讀專門聲明。"
    const val TWDIW_COMPATIBILITY_CONTINUE = "了解，繼續"
    const val READ_STATEMENT = "閱讀專門聲明"

    /** An SP whose holder could not be confirmed. */
    const val MOICA_SP_PROVIDER_UNKNOWN = "尚無法核實此 SP 的實際持有人或使用授權，請勿將其視為已獲官方認可。"
}
