package diw.testservers.zktls

import diw.wallet.core.zktls.ZkTlsProfile

/**
 * A synthetic record lookup for zkTLS tests: GET /record?serial=..&code=.. answers an HTML page whose status is FOUND
 * for [SERIAL] with any four-digit code, else NOT_FOUND. All data is invented. The page also carries a line that no
 * rule reveals, so tests can check that it never reaches the verifier.
 */
object ZkTlsRecordPage {
    const val PROFILE_ID = "diw.test.record/1"
    const val SERIAL = "Z900000001"
    const val CODE = "4321"
    const val NAME = "測試人員甲"
    const val DATE = "2026-01-02"
    const val HIDDEN = "hidden-detail-7f3a"

    fun profile(port: Int, host: String = "localhost"): ZkTlsProfile = ZkTlsProfile(
        id = PROFILE_ID,
        title = "測試紀錄查驗頁",
        host = host,
        port = port,
        request = ZkTlsProfile.Request(
            method = "GET",
            path = "/record",
            query = "serial={serial}&code={code}",
            inputs = listOf(
                ZkTlsProfile.Input("serial", "證號", "^[A-Z][0-9]{9}$"),
                ZkTlsProfile.Input("code", "驗證碼", "^[0-9]{4}$"),
            ),
        ),
        limits = ZkTlsProfile.Limits(maxSent = 1024, maxRecv = 4096),
        status = ZkTlsProfile.Status(reveal = "<p id=\"status\">(FOUND|NOT_FOUND)</p>", success = ">FOUND<"),
        fields = listOf(
            ZkTlsProfile.Field("name", "姓名", "<p id=\"name\">([^<]{1,40})</p>"),
            ZkTlsProfile.Field("date", "日期", "<p id=\"date\">([0-9]{4}-[0-9]{2}-[0-9]{2})</p>"),
        ),
    ).validated()

    /** The page for a request head. */
    fun respond(head: String): ByteArray {
        val target = head.lineSequence().first().split(' ').getOrNull(1).orEmpty()
        val query = target.substringAfter('?', "").split('&').associate { it.substringBefore('=') to it.substringAfter('=', "") }
        val found = target.startsWith("/record?") && query["serial"] == SERIAL && query["code"]?.matches(Regex("[0-9]{4}")) == true
        val body = if (found) {
            "<p id=\"status\">FOUND</p>\n<p id=\"name\">$NAME</p>\n<p id=\"date\">$DATE</p>\n<p id=\"note\">$HIDDEN</p>"
        } else {
            "<p id=\"status\">NOT_FOUND</p>\n<p id=\"note\">$HIDDEN</p>"
        }
        return "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>record</title></head><body>\n$body\n</body></html>\n".encodeToByteArray()
    }
}
