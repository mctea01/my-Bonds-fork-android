package diw.wallet.app.legal

/** Interface strings of the first-start pages and the legal settings, kept together for translation. */
object LegalStrings {
    const val SUMMARY = "重點摘要"
    const val FULL_TEXT = "全文"
    const val OPEN_ONLINE = "在瀏覽器開啟網頁版"

    fun versionLine(version: Int, date: String) = "版本 $version・生效日期 $date"

    // Welcome
    const val WELCOME_TITLE = "歡迎使用 DIW MY WALLET"
    const val WELCOME_TEXT = "保存與出示數位證件、查驗他人證件，並保存、檢查與簽署電子文件。開始前，請閱讀並確認以下事項。"
    val WELCOME_POINTS = listOf(
        "資料留在這支裝置" to "證件、金鑰與文件加密保存在裝置上，開發者沒有收集資料的伺服器。",
        "出示什麼由你決定" to "每次出示前都會列出查驗方與要交出的欄位，經你同意才送出。",
        "標準優先" to "依 OpenID4VC、ISO/IEC 18013-5 等公開標準實作；中央營運的服務需另外同意才會啟用。",
    )
    const val WELCOME_START = "開始"

    // Terms and privacy
    const val BASICS_TITLE = "用戶協議與隱私權政策"
    const val BASICS_TEXT = "請閱讀以下兩份文件。同意後才能使用本 App。"
    const val BASICS_UPDATED = "用戶協議或隱私權政策已更新，請閱讀並再次確認。"
    const val AGREE_TERMS = "我已閱讀並同意「用戶協議」"
    const val AGREE_PRIVACY = "我已閱讀並同意「隱私權政策」"
    const val AGREE_CONTINUE = "同意並繼續"
    const val DISAGREE = "不同意"
    const val DISAGREE_TITLE = "需要同意才能使用"
    const val DISAGREE_TEXT = "不同意用戶協議與隱私權政策時無法使用本 App。你可以直接關閉 App；目前尚未保存任何證件或文件，解除安裝即可移除。"
    const val BACK_TO_READING = "回到文件"

    // Statements
    const val STATEMENTS_TITLE = "專門聲明"
    const val STATEMENTS_INTRO = "以下服務由單一營運者集中提供，使用時資料會經過該營運者。請逐項決定是否啟用；不同意的服務會停用，其他功能照常使用，之後可在設定變更。"
    const val STATEMENTS_UPDATED = "這份專門聲明已更新，請閱讀並再次決定。"
    fun statementProgress(index: Int, total: Int) = "專門聲明 $index / $total"
    fun operatorLine(operator: String) = "營運者：$operator"
    const val ACCEPT_ENABLE = "同意並啟用"
    const val DECLINE_DISABLE = "不同意，停用這項功能"

    // Done
    const val DONE_TITLE = "設定完成"
    const val DONE_TEXT = "你可以隨時在「設定 > 法律聲明與同意」重新閱讀文件，或變更各項服務的同意。"
    const val DONE_START = "開始使用"

    // Settings
    const val SETTINGS_SECTION = "法律聲明與同意"
    const val SETTINGS_BASICS = "用戶協議與隱私權政策"
    const val SETTINGS_STATEMENTS_TEXT = "中央營運的服務只有在你同意它的專門聲明後才會啟用。撤回同意後，本 App 立即停止連線該服務，已保存的證件與文件保留。"
    const val SETTINGS_ONLINE = "網頁版（可提供給 Google Play 等平台）"
    fun acceptedLine(version: Int, date: String) = "版本 $version・$date 同意"
    fun settingsSummary(enabled: Int, total: Int) = "已同意用戶協議與隱私權政策・專門聲明啟用 $enabled / $total"

    // Statement page and status
    fun enabledLine(version: Int, date: String) = "已同意，啟用中（版本 $version，$date）"
    const val DISABLED_LINE = "未同意，已停用"
    const val PENDING_LINE = "尚未決定，已停用"
    const val WITHDRAW = "撤回同意並停用"
    const val WITHDRAW_TITLE = "撤回同意？"
    fun withdrawText(name: String) = "撤回後，本 App 立即停止連線「$name」，相關功能顯示為停用；已保存的證件與文件保留。之後可以再次同意。"
    const val CANCEL = "取消"
    fun pendingLink(name: String) = "這個連結需要「$name」。同意後會接著開啟。"

    /** Shown where a feature of a switched-off service would be. */
    fun disabledRow(name: String) = "「$name」未啟用：你沒有同意它的專門聲明。點選檢視聲明。"
    /** Message for a link, request or action that needs a switched-off service. */
    fun disabledMessage(name: String) = "「$name」功能未啟用：你沒有同意它的專門聲明。可在「設定 > 法律聲明與同意」檢視並啟用。"
}
